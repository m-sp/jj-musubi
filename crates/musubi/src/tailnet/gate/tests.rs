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

fn allowing(ids: &[&str]) -> watch::Receiver<Allowed> {
    let ids: Vec<String> = ids.iter().map(|&id| id.to_owned()).collect();
    watch::channel(Allowed::parse(&ids).unwrap()).1
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
    assert_eq!(named(&[], Some(&good)), Err(Unidentified::Ambiguous));
    assert_eq!(
        named(&[node(OTHER)], Some(&good)),
        Err(Unidentified::Ambiguous)
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

/// Refused is refused before the hub hears of it.
#[tokio::test]
async fn nobody_reaches_the_hub_unless_listed() {
    let unknown = Ipv4Addr::new(100, 64, 0, 9);
    let mapped = IpAddr::V6(LAPTOP_IP.to_ipv6_mapped());
    for (case, allowed, from, lookups_fail) in [
        (
            "nobody is listed",
            watch::channel(Allowed::default()).1,
            IpAddr::V4(LAPTOP_IP),
            false,
        ),
        (
            "another is listed",
            allowing(&[OTHER]),
            IpAddr::V4(LAPTOP_IP),
            false,
        ),
        (
            "the tailnet knows no such node",
            allowing(&[LAPTOP]),
            IpAddr::V4(unknown),
            false,
        ),
        (
            "looking up fails",
            allowing(&[LAPTOP]),
            IpAddr::V4(LAPTOP_IP),
            true,
        ),
        ("the address is IPv6", allowing(&[LAPTOP]), mapped, false),
    ] {
        let (net, _accepting) = Fake::new(lookups_fail);
        let (stream, mut theirs) = tokio::io::duplex(1024);
        let serving = serve_peer(
            net.as_ref(),
            &allowed,
            stream,
            from,
            async || -> io::Result<DuplexStream> {
                panic!("{case}, and the hub was connected to");
            },
            |_, _| panic!("{case}, and it was admitted"),
        );
        // As a refused client does: reads the answer and closes.
        let refused = async {
            let answer = Answer::read(&mut theirs).await.unwrap();
            drop(theirs);
            answer
        };
        let (served, answer) = tokio::join!(serving, refused);
        assert_eq!(answer, Answer::NotAllowed, "{case}");
        let Served::Refused { ended, .. } = served else {
            panic!("{case}: {served:?}");
        };
        assert_eq!(ended, Ended::Closed, "{case}");
    }
}

/// A refused peer that doesn't close may leave its socket for good, so it counts as one.
#[tokio::test(start_paused = true)]
async fn a_refused_peer_that_does_not_close_is_counted() {
    let (net, _accepting) = Fake::new(false);
    let (stream, _theirs) = tokio::io::duplex(1024);
    let served = serve_peer(
        net.as_ref(),
        &allowing(&[OTHER]),
        stream,
        IpAddr::V4(LAPTOP_IP),
        async || -> io::Result<DuplexStream> { panic!("the hub was connected to") },
        |_, _| panic!("it was admitted"),
    )
    .await;
    let Served::Refused { why, ended } = served else {
        panic!("{served:?}");
    };
    assert_eq!(why, format!("musubi.tailnet.allow doesn't list {LAPTOP}"));
    assert!(ended.may_strand());
}

/// Connects the laptop to a hub that echoes, through the gate on both sides.
#[tokio::test(start_paused = true)]
async fn a_listed_node_reaches_the_hub_until_it_is_no_longer_that_node() {
    for after in [None, Some(node(OTHER))] {
        let (net, mut accepting) = Fake::new(false);
        net.answering.add_permits(1);
        let hubs = net.clone();
        let serving = tokio::spawn(async move {
            let stream = accepting.recv().await.unwrap();
            serve_peer(
                hubs.as_ref(),
                &allowing(&[LAPTOP]),
                stream,
                IpAddr::V4(LAPTOP_IP),
                async || {
                    let (local, hub) = tokio::io::duplex(1024);
                    tokio::spawn(async move {
                        let (mut read, mut write) = tokio::io::split(hub);
                        tokio::io::copy(&mut read, &mut write).await.ok();
                    });
                    Ok(local)
                },
                |_, _| {},
            )
            .await
        });

        let dialer = Dialer::new(net.clone(), id(LAPTOP));
        let stream = dialer.open(&hub_address()).await.unwrap();
        let (local, mut command) = tokio::io::duplex(1024);
        let laptops = net.clone();
        let carrying = tokio::spawn(async move {
            carry(laptops.as_ref(), HUB_IP, &id(HUB), stream, local, None).await
        });
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
        net.set(LAPTOP_IP, after);
        assert_eq!(serving.await.unwrap(), Served::Revoked);
        assert!(changed.elapsed() <= RECHECK);
        carrying.await.unwrap();
    }
}

#[tokio::test]
async fn only_the_node_the_address_names_is_taken_for_the_hub() {
    let (net, _accepting) = Fake::new(false);
    net.set(HUB_IP, Some(node(OTHER)));
    let dialer = Dialer::new(net.clone(), id(LAPTOP));
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
    let dialer = Dialer::new(net.clone(), id(LAPTOP));
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
    let dialer = Dialer::new(net.clone(), id(LAPTOP));
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
async fn refusals_say_what_to_do() {
    for (answer, says) in [
        (
            Answer::NotAllowed,
            "the hub refused this machine: add nLaptopExampleCNTRL to musubi.tailnet.allow on \
             the hub's machine",
        ),
        (Answer::NoHub, "no hub is running there"),
    ] {
        let (net, mut accepting) = Fake::new(false);
        net.answering.add_permits(1);
        let dialer = Dialer::new(net, id(LAPTOP));
        let hub = hub_address();
        let answering = async {
            let mut stream = accepting.recv().await.unwrap();
            answer.send(&mut stream).await.unwrap();
        };
        let (opened, ()) = tokio::join!(dialer.open(&hub), answering);
        assert_eq!(opened.unwrap_err().to_string(), says);
    }
}

/// Taking a machine off the list ends its connections at once, without a restart, and so
/// does a list that can't be read, which the hub takes as admitting nobody.
#[tokio::test(start_paused = true)]
async fn taking_a_node_off_the_list_ends_its_connections() {
    let (net, _accepting) = Fake::new(false);
    let (listing, allowed) = watch::channel(Allowed::parse(&[LAPTOP.to_owned()]).unwrap());
    let (stream, mut laptop) = tokio::io::duplex(1024);
    // Held, so that the hub side stays: the connection ends only by being revoked.
    let (local, _hub) = tokio::io::duplex(1024);
    let hubs = net.clone();
    let serving = tokio::spawn(async move {
        serve_peer(
            hubs.as_ref(),
            &allowed,
            stream,
            IpAddr::V4(LAPTOP_IP),
            async || Ok(local),
            |_, _| {},
        )
        .await
    });
    assert_eq!(Answer::read(&mut laptop).await.unwrap(), Answer::Welcome);
    // Another machine added keeps it, without a restart.
    listing.send_replace(Allowed::parse(&[LAPTOP.to_owned(), OTHER.to_owned()]).unwrap());
    tokio::time::sleep(RECHECK * 3).await;
    assert!(!serving.is_finished());
    let removed = tokio::time::Instant::now();
    listing.send_replace(Allowed::default());
    assert_eq!(serving.await.unwrap(), Served::Revoked);
    assert_eq!(removed.elapsed(), Duration::ZERO);
}

/// A node that is slow to answer, or starting over, is no reason to cut every link: only one
/// that goes on not answering for as long as a silent peer would ends them.
#[tokio::test(start_paused = true)]
async fn a_lookup_that_fails_for_a_while_ends_no_link() {
    let (net, _accepting) = Fake::new(false);
    let (stream, mut laptop) = tokio::io::duplex(1024);
    let (local, _hub) = tokio::io::duplex(1024);
    let hubs = net.clone();
    let serving = tokio::spawn(async move {
        serve_peer(
            hubs.as_ref(),
            &allowing(&[LAPTOP]),
            stream,
            IpAddr::V4(LAPTOP_IP),
            async || Ok(local),
            |_, _| {},
        )
        .await
    });
    assert_eq!(Answer::read(&mut laptop).await.unwrap(), Answer::Welcome);
    // The laptop's heartbeats, as its relay would send them, keep the link itself alive.
    let beating = tokio::spawn(async move {
        loop {
            laptop.write_all(&[0, 0]).await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    net.lookups_fail.store(true, Ordering::SeqCst);
    let failing = tokio::time::Instant::now();
    tokio::time::sleep(heartbeat::SILENCE - RECHECK).await;
    assert!(!serving.is_finished(), "a slow lookup cut the link");
    // Answering again resets it.
    net.lookups_fail.store(false, Ordering::SeqCst);
    tokio::time::sleep(RECHECK * 2).await;
    net.lookups_fail.store(true, Ordering::SeqCst);
    tokio::time::sleep(heartbeat::SILENCE - RECHECK).await;
    assert!(!serving.is_finished(), "an earlier failure counted again");
    assert_eq!(serving.await.unwrap(), Served::Revoked);
    assert!(failing.elapsed() <= heartbeat::SILENCE * 3);
    beating.abort();
}
