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
        tags: Vec::new(),
    }
}

/// No `musubi.tailnet.allow`: whatever the access controls let through.
fn unlisted() -> watch::Receiver<Option<Allowed>> {
    watch::channel(None).1
}

fn allowing(ids: &[&str]) -> watch::Receiver<Option<Allowed>> {
    let ids: Vec<String> = ids.iter().map(|&id| id.to_owned()).collect();
    watch::channel(Some(Allowed::parse(&ids).unwrap())).1
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
    let ambiguous = named(&[node(OTHER), good.clone(), node(OTHER)], Some(&good));
    assert_eq!(
        ambiguous,
        Err(Unidentified::Ambiguous(vec![LAPTOP.into(), OTHER.into()]))
    );
    assert_eq!(
        ambiguous.unwrap_err().to_string(),
        format!("more than one node has a route to that address: {LAPTOP}, {OTHER}")
    );
    // A node listed twice for its route is still one node, whether its address's or not.
    assert_eq!(
        named(&[good.clone(), good.clone()], Some(&good)),
        Ok(id(LAPTOP))
    );
    assert_eq!(
        named(&[node(OTHER), node(OTHER)], Some(&good)),
        Err(Unidentified::RoutedElsewhere)
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

/// With no list, what the tailnet's access controls let reach the hub's port reaches the hub,
/// unidentified: not even an address the hub couldn't tell the node of is refused.
#[tokio::test]
async fn without_a_list_what_reaches_the_port_reaches_the_hub() {
    let unknown = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9));
    let mapped = IpAddr::V6(LAPTOP_IP.to_ipv6_mapped());
    for (case, from, lookups_fail) in [
        ("a known node", IpAddr::V4(LAPTOP_IP), false),
        ("an address the tailnet doesn't know", unknown, false),
        ("lookups fail", IpAddr::V4(LAPTOP_IP), true),
        ("an IPv6 address", mapped, false),
    ] {
        let (stream, mut laptop) = tokio::io::duplex(1024);
        let (net, _accepting) = Fake::new(lookups_fail);
        let admitted = Arc::new(AtomicBool::new(false));
        let told = admitted.clone();
        let serving = tokio::spawn(async move {
            let admitted = move || told.store(true, Ordering::SeqCst);
            serve_peer(net.as_ref(), &unlisted(), stream, from, echoing, admitted).await
        });
        assert_eq!(
            Answer::read(&mut laptop).await.unwrap(),
            Answer::Welcome,
            "{case}"
        );
        drop(laptop);
        assert!(matches!(serving.await.unwrap(), Served::Ended(_)), "{case}");
        assert!(admitted.load(Ordering::SeqCst), "{case}");
    }
}

/// A peer told there's no hub that doesn't close may leave its socket for good, so it counts
/// as one.
#[tokio::test(start_paused = true)]
async fn a_peer_told_there_is_no_hub_that_does_not_close_is_counted() {
    let (stream, mut laptop) = tokio::io::duplex(1024);
    let no_hub = async || -> io::Result<DuplexStream> { Err(io::Error::other("stopped")) };
    let (net, _accepting) = Fake::new(false);
    let serving = tokio::spawn(async move {
        serve_peer(
            net.as_ref(),
            &unlisted(),
            stream,
            IpAddr::V4(LAPTOP_IP),
            no_hub,
            || {},
        )
        .await
    });
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
        let hubs = net.clone();
        let serving = tokio::spawn(async move {
            let stream = accepting.recv().await.unwrap();
            serve_peer(
                hubs.as_ref(),
                &unlisted(),
                stream,
                IpAddr::V4(LAPTOP_IP),
                echoing,
                || {},
            )
            .await
        });

        let dialer = Dialer::new(net.clone(), id(LAPTOP));
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
async fn a_hub_machine_without_a_hub_says_so() {
    let (net, mut accepting) = Fake::new(false);
    net.answering.add_permits(1);
    let dialer = Dialer::new(net, id(LAPTOP));
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

/// With a list, refused is refused before the hub hears of it, and told whether it was the
/// list that refused it or the hub couldn't tell which node it is.
#[tokio::test]
async fn nobody_reaches_the_hub_unless_listed() {
    let unknown = Ipv4Addr::new(100, 64, 0, 9);
    let mapped = IpAddr::V6(LAPTOP_IP.to_ipv6_mapped());
    for (case, allowed, from, lookups_fail, expected) in [
        (
            "nobody is listed",
            allowing(&[]),
            IpAddr::V4(LAPTOP_IP),
            false,
            Answer::NotAllowed,
        ),
        (
            "another is listed",
            allowing(&[OTHER]),
            IpAddr::V4(LAPTOP_IP),
            false,
            Answer::NotAllowed,
        ),
        (
            "the tailnet knows no such node",
            allowing(&[LAPTOP]),
            IpAddr::V4(unknown),
            false,
            Answer::Unidentified,
        ),
        (
            "looking up fails",
            allowing(&[LAPTOP]),
            IpAddr::V4(LAPTOP_IP),
            true,
            Answer::Unidentified,
        ),
        (
            "the address is IPv6",
            allowing(&[LAPTOP]),
            mapped,
            false,
            Answer::Unidentified,
        ),
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
            || panic!("{case}, and it was admitted"),
        );
        // As a refused client does: reads the answer and closes.
        let refused = async {
            let answer = Answer::read(&mut theirs).await.unwrap();
            drop(theirs);
            answer
        };
        let (served, answer) = tokio::join!(serving, refused);
        assert_eq!(answer, expected, "{case}");
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
        || panic!("it was admitted"),
    )
    .await;
    let Served::Refused { why, ended } = served else {
        panic!("{served:?}");
    };
    assert_eq!(why, format!("musubi.tailnet.allow doesn't list {LAPTOP}"));
    assert!(ended.may_strand());
}

#[tokio::test]
async fn a_hub_that_does_not_admit_this_machine_says_which_it_is() {
    let (net, mut accepting) = Fake::new(false);
    net.answering.add_permits(1);
    let dialer = Dialer::new(net, id(LAPTOP));
    let answering = async {
        let mut stream = accepting.recv().await.unwrap();
        Answer::NotAllowed.send(&mut stream).await.unwrap();
    };
    let hub = hub_address();
    let (opened, ()) = tokio::join!(dialer.open(&hub), answering);
    // The ID is what the daemon passes on, for the command to say what to do with.
    let err = opened.unwrap_err();
    assert!(
        matches!(&err, DialError::NotAllowed { own } if *own == id(LAPTOP)),
        "{err}"
    );
}

/// A machine the hub couldn't tell apart isn't told to add itself to a list it may be on.
#[tokio::test]
async fn a_hub_that_cannot_tell_which_machine_this_is_says_so() {
    let (net, mut accepting) = Fake::new(false);
    net.answering.add_permits(1);
    let dialer = Dialer::new(net, id(LAPTOP));
    let answering = async {
        let mut stream = accepting.recv().await.unwrap();
        Answer::Unidentified.send(&mut stream).await.unwrap();
    };
    let hub = hub_address();
    let (opened, ()) = tokio::join!(dialer.open(&hub), answering);
    let err = opened.unwrap_err();
    assert!(matches!(err, DialError::NotIdentified), "{err}");
}

/// Serves the laptop through the gate on the hub's side, with the hub side held, so that the
/// connection ends only by being revoked: the laptop beats, as its relay would, so that the
/// link itself stays alive. Returns the serving, the laptop's beating, and the hub's side.
async fn served_laptop(
    net: &Arc<Fake>,
    allowed: watch::Receiver<Option<Allowed>>,
) -> (
    tokio::task::JoinHandle<Served>,
    tokio::task::JoinHandle<()>,
    DuplexStream,
) {
    let (stream, mut laptop) = tokio::io::duplex(1024);
    let (local, hub) = tokio::io::duplex(1024);
    let hubs = net.clone();
    let serving = tokio::spawn(async move {
        serve_peer(
            hubs.as_ref(),
            &allowed,
            stream,
            IpAddr::V4(LAPTOP_IP),
            async || Ok(local),
            || {},
        )
        .await
    });
    assert_eq!(Answer::read(&mut laptop).await.unwrap(), Answer::Welcome);
    let beating = tokio::spawn(async move {
        while laptop.write_all(&[0, 0]).await.is_ok() {
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    (serving, beating, hub)
}

/// A listed node's connection ends once its address is another node's, or nobody's.
#[tokio::test(start_paused = true)]
async fn a_listed_node_reaches_the_hub_until_it_is_no_longer_that_node() {
    for after in [None, Some(node(OTHER))] {
        let (net, _accepting) = Fake::new(false);
        let (serving, _beating, _hub) = served_laptop(&net, allowing(&[LAPTOP])).await;
        tokio::time::sleep(RECHECK * 10).await;
        assert!(!serving.is_finished(), "a healthy link ended");
        let changed = tokio::time::Instant::now();
        net.set(LAPTOP_IP, after);
        assert_eq!(serving.await.unwrap(), Served::Revoked);
        assert!(changed.elapsed() <= RECHECK);
    }
}

/// On the hub as on a machine, lookups that fail for a while end no listed node's link, and a
/// change to the list while they fail, which checks the node at once, isn't taken for an
/// answer: the link ends once they have failed for as long as a silent peer would.
#[tokio::test(start_paused = true)]
async fn a_listed_node_outlasts_lookups_that_fail_for_a_while() {
    let (net, _accepting) = Fake::new(false);
    let (listing, allowed) = watch::channel(Some(Allowed::parse(&[LAPTOP.to_owned()]).unwrap()));
    let (serving, _beating, _hub) = served_laptop(&net, allowed).await;
    net.lookups_fail.store(true, Ordering::SeqCst);
    let failing = tokio::time::Instant::now();
    tokio::time::sleep(heartbeat::SILENCE - RECHECK).await;
    listing.send_replace(Some(
        Allowed::parse(&[LAPTOP.to_owned(), OTHER.to_owned()]).unwrap(),
    ));
    tokio::task::yield_now().await;
    assert!(!serving.is_finished(), "a slow lookup cut the link");
    assert_eq!(serving.await.unwrap(), Served::Revoked);
    assert!(failing.elapsed() <= heartbeat::SILENCE + RECHECK * 2);
}

/// Taking a machine off the list ends its connections at once, without a restart, and so
/// does a list that admits nobody, as one that can't be read does.
#[tokio::test(start_paused = true)]
async fn taking_a_node_off_the_list_ends_its_connections() {
    let (net, _accepting) = Fake::new(false);
    let (listing, allowed) = watch::channel(Some(Allowed::parse(&[LAPTOP.to_owned()]).unwrap()));
    let (serving, _beating, _hub) = served_laptop(&net, allowed).await;
    // Another machine added keeps it, without a restart, and so does unsetting the list.
    listing.send_replace(Some(
        Allowed::parse(&[LAPTOP.to_owned(), OTHER.to_owned()]).unwrap(),
    ));
    tokio::time::sleep(RECHECK * 3).await;
    listing.send_replace(None);
    tokio::time::sleep(RECHECK * 3).await;
    assert!(!serving.is_finished());
    let removed = tokio::time::Instant::now();
    listing.send_replace(Some(Allowed::default()));
    assert_eq!(serving.await.unwrap(), Served::Revoked);
    assert_eq!(removed.elapsed(), Duration::ZERO);
}

/// A connection made while no list was set isn't checked against one set later: it ends,
/// and the machine connects again, to be checked.
#[tokio::test(start_paused = true)]
async fn setting_a_list_ends_the_connections_it_did_not_check() {
    let (net, _accepting) = Fake::new(false);
    let (listing, allowed) = watch::channel(None);
    let (serving, _beating, _hub) = served_laptop(&net, allowed).await;
    tokio::time::sleep(RECHECK * 3).await;
    assert!(!serving.is_finished());
    let set = tokio::time::Instant::now();
    listing.send_replace(Some(Allowed::parse(&[LAPTOP.to_owned()]).unwrap()));
    assert_eq!(serving.await.unwrap(), Served::Revoked);
    assert_eq!(set.elapsed(), Duration::ZERO);
}

/// A tag on the list admits a node that has it, though the list doesn't name the node, for as
/// long as it has it: taking the tag from the node ends its connection as taking the node off
/// the list does, and it is refused after, told which tags it has.
#[tokio::test(start_paused = true)]
async fn a_tag_admits_a_node_for_as_long_as_it_has_it() {
    let (net, _accepting) = Fake::new(false);
    let tagged = |tags: &[&str]| Peer {
        tags: tags.iter().map(|&tag| tag.to_owned()).collect(),
        ..node(LAPTOP)
    };
    net.set(LAPTOP_IP, Some(tagged(&["tag:ci", "tag:sandbox"])));
    let allowed = allowing(&[OTHER, "tag:sandbox"]);
    let (serving, _beating, _hub) = served_laptop(&net, allowed.clone()).await;
    tokio::time::sleep(RECHECK * 3).await;
    assert!(!serving.is_finished());

    let untagged = tokio::time::Instant::now();
    net.set(LAPTOP_IP, Some(tagged(&["tag:ci"])));
    assert_eq!(serving.await.unwrap(), Served::Revoked);
    assert!(untagged.elapsed() <= RECHECK);

    let (stream, mut laptop) = tokio::io::duplex(1024);
    let serving = serve_peer(
        net.as_ref(),
        &allowed,
        stream,
        IpAddr::V4(LAPTOP_IP),
        async || -> io::Result<DuplexStream> { panic!("the hub was connected to") },
        || panic!("it was admitted"),
    );
    let refused = async {
        let answer = Answer::read(&mut laptop).await.unwrap();
        drop(laptop);
        answer
    };
    let (served, answer) = tokio::join!(serving, refused);
    assert_eq!(answer, Answer::NotAllowed);
    let Served::Refused { why, .. } = served else {
        panic!("{served:?}");
    };
    assert_eq!(
        why,
        format!("musubi.tailnet.allow lists neither {LAPTOP} nor its tags, tag:ci")
    );
}
