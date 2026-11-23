//! The gate against a tailnet in memory: no node, and no network.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use tokio::io::AsyncWriteExt as _;
use tokio::io::DuplexStream;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;

use super::*;

const HUB: &str = "nHubExampleCNTRL";
const LAPTOP: &str = "nLaptopExampleCNTRL";
const OTHER: &str = "nOtherExampleCNTRL";

const HUB_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
const LAPTOP_IP: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

fn id(id: &str) -> NodeId {
    id.parse().unwrap()
}

fn node(id: &str) -> Peer {
    Peer {
        id: id.to_owned(),
        key_expires: None,
        relayed: true,
    }
}

fn hub_address() -> Address {
    Address {
        node: id(HUB),
        ip: HUB_IP,
    }
}

struct Fake {
    nodes: Mutex<HashMap<Ipv4Addr, Peer>>,
    lookups_fail: AtomicBool,
    /// How many connects have begun.
    begun: AtomicUsize,
    /// A permit lets one connect finish.
    answering: Semaphore,
    /// The far end of each connection made.
    accepted: mpsc::UnboundedSender<DuplexStream>,
}

impl Fake {
    fn new(lookups_fail: bool) -> (Arc<Self>, mpsc::UnboundedReceiver<DuplexStream>) {
        let (accepted, accepting) = mpsc::unbounded_channel();
        let nodes = HashMap::from([(HUB_IP, node(HUB)), (LAPTOP_IP, node(LAPTOP))]);
        let fake = Self {
            nodes: Mutex::new(nodes),
            lookups_fail: AtomicBool::new(lookups_fail),
            begun: AtomicUsize::new(0),
            answering: Semaphore::new(0),
            accepted,
        };
        (Arc::new(fake), accepting)
    }

    fn look_up(&self, ip: Ipv4Addr) -> io::Result<Option<Peer>> {
        if self.lookups_fail.load(Ordering::SeqCst) {
            return Err(io::Error::other("no answer"));
        }
        Ok(self.nodes.lock().unwrap().get(&ip).cloned())
    }

    fn set(&self, ip: Ipv4Addr, node: Option<Peer>) {
        let mut nodes = self.nodes.lock().unwrap();
        match node {
            Some(node) => nodes.insert(ip, node),
            None => nodes.remove(&ip),
        };
    }
}

#[async_trait]
impl Tailnet for Fake {
    type Stream = DuplexStream;

    async fn owner(&self, ip: Ipv4Addr) -> io::Result<Option<Peer>> {
        self.look_up(ip)
    }

    async fn routed(&self, ip: Ipv4Addr) -> io::Result<Vec<Peer>> {
        Ok(self.look_up(ip)?.into_iter().collect())
    }

    async fn connect(&self, _: Ipv4Addr) -> io::Result<DuplexStream> {
        self.begun.fetch_add(1, Ordering::SeqCst);
        self.answering.acquire().await.unwrap().forget();
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        self.accepted.send(theirs).ok();
        Ok(ours)
    }
}

/// Every doubt refuses.
#[test]
fn a_node_is_identified_only_without_doubt() {
    let now = 1_800_000_000;
    let good = node(LAPTOP);
    let with = |change: fn(&mut Peer)| {
        let mut changed = node(LAPTOP);
        change(&mut changed);
        changed
    };
    let expired = with(|peer| peer.key_expires = Some(1_800_000_000));
    let unrelayed = with(|peer| peer.relayed = false);
    let unreadable = with(|peer| peer.id = String::new());
    let named = |routed: &[Peer], owner: Option<&Peer>| identify(owner, routed, now);

    let one = std::slice::from_ref(&good);
    assert_eq!(named(one, Some(&good)), Ok(id(LAPTOP)));
    // Go's zero time is a key that doesn't expire.
    for never in [Some(-62_135_596_800), Some(0), Some(now + 1), None] {
        let mut node = good.clone();
        node.key_expires = never;
        assert_eq!(named(one, Some(&node)), Ok(id(LAPTOP)), "{never:?}");
    }

    assert_eq!(named(one, None), Err(Unidentified::Unknown));
    // The source filter takes packets from whom the routes name, not whose the address is.
    assert_eq!(named(&[], Some(&good)), Err(Unidentified::NoRoute));
    assert_eq!(
        named(&[node(OTHER)], Some(&good)),
        Err(Unidentified::RoutedElsewhere)
    );
    assert_eq!(
        named(&[good.clone(), node(OTHER)], Some(&good)),
        Err(Unidentified::Ambiguous)
    );
    assert_eq!(named(one, Some(&expired)), Err(Unidentified::Expired));
    assert_eq!(named(one, Some(&unrelayed)), Err(Unidentified::Unroutable));
    assert_eq!(
        named(std::slice::from_ref(&unreadable), Some(&unreadable)),
        Err(Unidentified::BadId)
    );
}

/// A hub that echoes, on the far side of the gate.
async fn echoing() -> io::Result<DuplexStream> {
    let (local, hub) = tokio::io::duplex(1024);
    tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(hub);
        tokio::io::copy(&mut read, &mut write).await.ok();
    });
    Ok(local)
}

/// What the tailnet's access controls let reach the hub's port reaches the hub.
#[tokio::test]
async fn what_reaches_the_port_reaches_the_hub() {
    let (stream, mut laptop) = tokio::io::duplex(1024);
    let serving = tokio::spawn(serve_peer(stream, echoing));
    assert_eq!(Answer::read(&mut laptop).await.unwrap(), Answer::Welcome);
    drop(laptop);
    assert!(matches!(serving.await.unwrap(), Served::Ended(_)));
}

/// A peer told there's no hub that doesn't close may leave its socket for good, so it counts
/// as one.
#[tokio::test(start_paused = true)]
async fn a_peer_told_there_is_no_hub_that_does_not_close_is_counted() {
    let (stream, mut laptop) = tokio::io::duplex(1024);
    let no_hub = async || -> io::Result<DuplexStream> { Err(io::Error::other("stopped")) };
    let serving = tokio::spawn(serve_peer(stream, no_hub));
    assert_eq!(Answer::read(&mut laptop).await.unwrap(), Answer::NoHub);
    let Served::NoHub(ended) = serving.await.unwrap() else {
        panic!("served");
    };
    assert!(ended.may_strand());
    drop(laptop);
}

/// Connects the laptop to a hub that echoes, through the gate on both sides.
#[tokio::test(start_paused = true)]
async fn the_hub_is_reached_until_its_address_is_no_longer_its_node() {
    for after in [None, Some(node(OTHER))] {
        let (net, mut accepting) = Fake::new(false);
        net.answering.add_permits(1);
        let serving = tokio::spawn(async move {
            let stream = accepting.recv().await.unwrap();
            serve_peer(stream, echoing).await
        });

        let dialer = Dialer::new(net.clone());
        let stream = dialer.open(&hub_address()).await.unwrap();
        let (local, mut command) = tokio::io::duplex(1024);
        let laptops = net.clone();
        let carrying =
            tokio::spawn(
                async move { carry(laptops.as_ref(), HUB_IP, &id(HUB), stream, local).await },
            );
        command.write_all(b"hello").await.unwrap();
        let mut echoed = [0; 5];
        command.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
        tokio::time::sleep(RECHECK * 10).await;
        assert!(
            !serving.is_finished() && !carrying.is_finished(),
            "a healthy link ended"
        );

        let changed = tokio::time::Instant::now();
        net.set(HUB_IP, after);
        assert_eq!(carrying.await.unwrap(), Served::Revoked);
        assert!(changed.elapsed() <= RECHECK);
        serving.await.unwrap();
    }
}

#[tokio::test]
async fn only_the_node_the_address_names_is_taken_for_the_hub() {
    let (net, _accepting) = Fake::new(false);
    net.set(HUB_IP, Some(node(OTHER)));
    let dialer = Dialer::new(net.clone());
    let err = dialer.open(&hub_address()).await.unwrap_err();
    assert!(matches!(err, DialError::OtherNode { .. }), "{err}");
    assert_eq!(
        net.begun.load(Ordering::SeqCst),
        0,
        "connected to it anyway"
    );
}

/// The address can pass to another node while connecting.
#[tokio::test]
async fn the_hub_is_checked_again_once_connected() {
    let (net, mut accepting) = Fake::new(false);
    let dialer = Dialer::new(net.clone());
    let hub = hub_address();
    let meanwhile = async {
        while net.begun.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        net.set(HUB_IP, Some(node(OTHER)));
        net.answering.add_permits(1);
        let mut stream = accepting.recv().await.unwrap();
        Answer::Welcome.send(&mut stream).await.ok();
    };
    let (opened, ()) = tokio::join!(dialer.open(&hub), meanwhile);
    let err = opened.unwrap_err();
    assert!(matches!(err, DialError::OtherNode { .. }), "{err}");
}

/// Each cancelled connect would be a socket for the life of the node, and a daemon tries a
/// sleeping hub every few seconds.
#[tokio::test(start_paused = true)]
async fn a_hub_that_does_not_answer_costs_one_socket() {
    let (net, mut accepting) = Fake::new(false);
    let dialer = Dialer::new(net.clone());
    let hub = hub_address();
    for _ in 0..20 {
        let began = tokio::time::Instant::now();
        let err = dialer.open(&hub).await.unwrap_err();
        assert!(matches!(err, DialError::NoAnswer { .. }), "{err}");
        assert_eq!(began.elapsed(), DIAL);
    }
    assert_eq!(net.begun.load(Ordering::SeqCst), 1);

    // It wakes: the socket nobody waits for now is closed, and the next caller gets its own.
    net.answering.add_permits(2);
    let mut abandoned = accepting.recv().await.unwrap();
    assert_eq!(abandoned.read(&mut [0; 1]).await.unwrap(), 0);
    let answering = async {
        let mut stream = accepting.recv().await.unwrap();
        Answer::Welcome.send(&mut stream).await.unwrap();
        stream
    };
    let (opened, _stream) = tokio::join!(dialer.open(&hub), answering);
    opened.unwrap();
    assert_eq!(net.begun.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_hub_machine_without_a_hub_says_so() {
    let (net, mut accepting) = Fake::new(false);
    net.answering.add_permits(1);
    let dialer = Dialer::new(net);
    let hub = hub_address();
    let answering = async {
        let mut stream = accepting.recv().await.unwrap();
        Answer::NoHub.send(&mut stream).await.unwrap();
    };
    let (opened, ()) = tokio::join!(dialer.open(&hub), answering);
    assert_eq!(opened.unwrap_err().to_string(), "no hub is running there");
}

/// A node that is slow to answer, or starting over, is no reason to cut every link: only one
/// that goes on not answering for as long as a silent peer would ends them.
#[tokio::test(start_paused = true)]
async fn a_lookup_that_fails_for_a_while_ends_no_link() {
    let (net, _accepting) = Fake::new(false);
    let (stream, mut hub) = tokio::io::duplex(1024);
    let (local, _command) = tokio::io::duplex(1024);
    let laptops = net.clone();
    let carrying =
        tokio::spawn(async move { carry(laptops.as_ref(), HUB_IP, &id(HUB), stream, local).await });
    // The hub's heartbeats, as its relay would send them, keep the link itself alive.
    let beating = tokio::spawn(async move {
        loop {
            hub.write_all(&[0, 0]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    net.lookups_fail.store(true, Ordering::SeqCst);
    let failing = tokio::time::Instant::now();
    tokio::time::sleep(heartbeat::SILENCE - RECHECK).await;
    assert!(!carrying.is_finished(), "a slow lookup cut the link");
    // Answering again resets it.
    net.lookups_fail.store(false, Ordering::SeqCst);
    tokio::time::sleep(RECHECK * 2).await;
    net.lookups_fail.store(true, Ordering::SeqCst);
    tokio::time::sleep(heartbeat::SILENCE - RECHECK).await;
    assert!(!carrying.is_finished(), "an earlier failure counted again");
    assert_eq!(carrying.await.unwrap(), Served::Revoked);
    assert!(failing.elapsed() <= heartbeat::SILENCE * 3);
    beating.abort();
}
