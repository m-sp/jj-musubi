//! Which node a machine takes for its hub over a tailnet, and which of what reaches a hub's
//! port, which the tailnet's access controls let through, the hub admits.
//!
//! tailscale-rs 0.7.1 drops a packet whose inner source address isn't routed to the WireGuard
//! peer that sent it (`ts_dataplane::DataPlane::process_inbound`), so the address a connection
//! comes from says which node it is. That filter goes by the peers' accepted routes and a
//! lookup by address by their tailnet addresses, so [`identify`] takes both, and they must
//! agree. It holds only while the node's bookkeeping does: after a panic in tailscale-rs, the
//! ids the filter compares can be dealt out again, so whoever holds the node stops trusting
//! it at a panic.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use musubi_transport::heartbeat;
use musubi_transport::heartbeat::Answer;
use musubi_transport::heartbeat::Ended;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWrite;
use tokio::sync::watch;

use super::address::Address;
use super::address::Allowed;
use super::address::NodeId;
use super::address::Tag;

/// How often a connection's node is identified again, so that one removed from the tailnet,
/// or whose address has passed to another, loses the connection.
const RECHECK: Duration = Duration::from_secs(5);

/// How long a caller waits to be connected and answered: less than the 15 seconds `musubi
/// list` waits for a hub, so that it can say why.
const DIAL: Duration = Duration::from_secs(10);

/// How long to spend writing an answer.
const ANSWER: Duration = Duration::from_secs(5);

/// What the gate needs to know of a node.
#[derive(Clone, Debug)]
pub struct Peer {
    /// Its stable ID.
    pub id: String,
    /// When its key expires, in Unix seconds: at or before zero, never.
    pub key_expires: Option<i64>,
    /// Whether it has a home relay. tailscale-rs sends what is for one without, by the next
    /// broader route, to whatever node has that: an exit node, say.
    pub relayed: bool,
    /// The tags the control server gives it, as `tag:<name>`.
    pub tags: Vec<String>,
}

/// A node, as an address was identified to be: its ID, and the tags it has, which
/// `musubi.tailnet.allow` may admit it by as well.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub node: NodeId,
    pub tags: Vec<Tag>,
}

/// A tailnet node, as the gate uses one.
#[async_trait]
pub trait Tailnet: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// The peer whose tailnet address `ip` is.
    async fn owner(&self, ip: Ipv4Addr) -> io::Result<Option<Peer>>;

    /// The peers with the most specific accepted route to `ip`.
    async fn routed(&self, ip: Ipv4Addr) -> io::Result<Vec<Peer>>;

    /// Connects to a hub's port at `ip`. Never cancelled: see [`Dialer`].
    async fn connect(&self, ip: Ipv4Addr) -> io::Result<Self::Stream>;
}

/// Why an address can't be taken to be a node's.
#[derive(Debug, PartialEq, Eq)]
pub enum Unidentified {
    Unknown,
    /// No node has a route to the address: its node is offline, or its routes aren't known
    /// yet.
    NoRoute,
    /// One node has the most specific route to the address, and it isn't the node whose
    /// address it is.
    RoutedElsewhere,
    /// More than one node's route covers the address as closely: their IDs, sorted.
    Ambiguous(Vec<String>),
    Expired,
    Unroutable,
    BadId,
    Lookup(String),
}

impl fmt::Display for Unidentified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("no node this machine may reach has that address"),
            Self::NoRoute => f.write_str(
                "no node has a route to that address: its node is offline, or its routes \
                 aren't known yet",
            ),
            Self::RoutedElsewhere => {
                f.write_str("another node's route covers that address, not its own node's")
            }
            Self::Ambiguous(nodes) => write!(
                f,
                "more than one node has a route to that address: {}",
                nodes.join(", ")
            ),
            Self::Expired => f.write_str("that node's key has expired"),
            Self::Unroutable => f.write_str("that node has no relay to reach it through yet"),
            Self::BadId => f.write_str("that node's ID can't be read"),
            Self::Lookup(why) => write!(f, "looking up that address failed: {why}"),
        }
    }
}

/// Which node an address is, at `now` in Unix seconds, given its `owner` by tailnet address
/// and those it is `routed` to. Whatever is in doubt is refused.
fn identify(owner: Option<&Peer>, routed: &[Peer], now: i64) -> Result<NodeId, Unidentified> {
    let owner = owner.ok_or(Unidentified::Unknown)?;
    // A node listed more than once is one node. tailscale-rs 0.7.1 lists a peer once more for
    // each of its routes on every change to it that control sends (`PeerDb::patch` takes the
    // peer out before `upsert`, which then adds its routes again); every copy has its stable
    // ID. Recheck this on upgrading tailscale-rs.
    let mut nodes: Vec<&str> = routed.iter().map(|peer| peer.id.as_str()).collect();
    nodes.sort_unstable();
    nodes.dedup();
    let only = match nodes[..] {
        [] => return Err(Unidentified::NoRoute),
        [only] => only,
        _ => {
            let nodes = nodes.into_iter().map(str::to_owned).collect();
            return Err(Unidentified::Ambiguous(nodes));
        }
    };
    if only != owner.id {
        return Err(Unidentified::RoutedElsewhere);
    }
    if owner.key_expires.is_some_and(|at| at > 0 && at <= now) {
        return Err(Unidentified::Expired);
    }
    if !owner.relayed {
        return Err(Unidentified::Unroutable);
    }
    owner.id.parse().map_err(|_| Unidentified::BadId)
}

/// Which node `ip` is now, and its tags. A tag that can't be read is left out.
async fn who<N: Tailnet>(net: &N, ip: Ipv4Addr) -> Result<Identity, Unidentified> {
    let lookup = |err: io::Error| Unidentified::Lookup(err.to_string());
    let owner = net.owner(ip).await.map_err(lookup)?;
    let routed = net.routed(ip).await.map_err(lookup)?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(i64::MAX, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    let node = identify(owner.as_ref(), &routed, now)?;
    let tags = owner
        .iter()
        .flat_map(|owner| &owner.tags)
        .filter_map(|tag| tag.parse().ok())
        .collect();
    Ok(Identity { node, tags })
}

/// How a connection to or from a hub went.
#[derive(Debug, PartialEq, Eq)]
pub enum Served {
    /// Turned away, for this reason, and how its connection ended: the peer, told, should
    /// close it, and one that doesn't may leave its socket for good.
    Refused {
        why: String,
        ended: Ended,
    },
    NoHub(Ended),
    /// The node at the other end stopped being the one its address names, or one the hub
    /// admits.
    Revoked,
    Ended(Ended),
}

/// Carries `local` over `stream` for as long as `ip` is still `node`.
pub async fn carry<N, S, L>(net: &N, ip: Ipv4Addr, node: &NodeId, stream: S, local: L) -> Served
where
    N: Tailnet,
    S: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    carry_listed(net, ip, node, Vec::new(), stream, local, None).await
}

/// Carries `local` over `stream` for as long as `ip` is still `node`, and, on a hub, for as
/// long as `allowed` admits it, by its ID or by the tags it has (`tags`, to begin with): a
/// list that is unset now admits it too.
async fn carry_listed<N, S, L>(
    net: &N,
    ip: Ipv4Addr,
    node: &NodeId,
    tags: Vec<Tag>,
    stream: S,
    local: L,
    allowed: Option<watch::Receiver<Option<Allowed>>>,
) -> Served
where
    N: Tailnet,
    S: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let changed = async {
        let mut allowed = allowed;
        let mut tags = tags;
        let admitted = |allowed: &Option<watch::Receiver<Option<Allowed>>>, tags: &[Tag]| {
            allowed.as_ref().is_none_or(|allowed| {
                allowed
                    .borrow()
                    .as_ref()
                    .is_none_or(|listed| listed.admits(node, tags))
            })
        };
        // Since when looking the node up has failed, with no answer since.
        let mut failing = None;
        loop {
            let allow_changed = async {
                match &mut allowed {
                    // A list that can no longer change: as it was.
                    Some(allowed) => {
                        if allowed.changed().await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = tokio::time::sleep(RECHECK) => {}
                () = allow_changed => {}
            }
            if !admitted(&allowed, &tags) {
                tracing::info!(
                    "musubi.tailnet.allow no longer admits {node}; ending its connection"
                );
                return;
            }
            match who(net, ip).await {
                Ok(now) if now.node == *node => {
                    failing = None;
                    // A tag it was admitted by may have been taken from it.
                    tags = now.tags;
                    if !admitted(&allowed, &tags) {
                        tracing::info!(
                            "{node} no longer has a tag musubi.tailnet.allow lists; ending \
                             its connection"
                        );
                        return;
                    }
                }
                Ok(now) => {
                    let now = now.node;
                    tracing::info!("{ip} is now {now}, not {node}; ending its connection");
                    return;
                }
                // The node didn't answer, as one busy or starting over doesn't: the link is
                // ended only if it goes on not answering for as long as a silent peer would.
                Err(Unidentified::Lookup(why)) => {
                    let since = *failing.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= heartbeat::SILENCE {
                        tracing::info!("ending {node}'s connection: {why}");
                        return;
                    }
                }
                Err(why) => {
                    tracing::info!("ending {node}'s connection: {why}");
                    return;
                }
            }
        }
    };
    tokio::select! {
        ended = heartbeat::relay(stream, local) => Served::Ended(ended),
        () = changed => Served::Revoked,
    }
}

/// Carries `local` over `stream`, from `from`, which no list was set to check, until one is.
async fn carry_unlisted<S, L>(
    from: IpAddr,
    stream: S,
    local: L,
    mut allowed: watch::Receiver<Option<Allowed>>,
) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let listed = async {
        if allowed.wait_for(Option::is_some).await.is_err() {
            // A list that can no longer change: as it was.
            std::future::pending::<()>().await;
        }
        tracing::info!(
            "musubi.tailnet.allow is set now; ending the connection from {from}, which it \
             didn't check"
        );
    };
    tokio::select! {
        ended = heartbeat::relay(stream, local) => Served::Ended(ended),
        () = listed => Served::Revoked,
    }
}

/// Serves what connected to a hub's port from `from`. The tailnet's access controls, which the
/// node enforces on every packet it receives, let it through. If `allowed` lists nodes,
/// nothing of it reaches the hub, not even a connection, unless it is a node the list names,
/// or that has a tag the list names. `admitted` hears of what is admitted.
pub async fn serve_peer<N, S, L>(
    net: &N,
    allowed: &watch::Receiver<Option<Allowed>>,
    mut stream: S,
    from: IpAddr,
    open_hub: impl AsyncFnOnce() -> io::Result<L>,
    admitted: impl FnOnce(),
) -> Served
where
    N: Tailnet,
    S: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let listed = allowed.borrow().clone();
    let identified = match (listed, from) {
        (None, _) => Ok(None),
        // The listener's is an IPv4 address.
        (Some(_), IpAddr::V6(_)) => {
            Err((Answer::Unidentified, format!("{from} is an IPv6 address")))
        }
        (Some(listed), IpAddr::V4(ip)) => match who(net, ip).await {
            Ok(now) if listed.admits(&now.node, &now.tags) => Ok(Some((ip, now))),
            Ok(now) if now.tags.is_empty() => Err((
                Answer::NotAllowed,
                format!("musubi.tailnet.allow doesn't list {}", now.node),
            )),
            Ok(now) => Err((
                Answer::NotAllowed,
                format!(
                    "musubi.tailnet.allow lists neither {} nor its tags, {}",
                    now.node,
                    now.tags
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
            Err(why) => Err((Answer::Unidentified, why.to_string())),
        },
    };
    let answer = async |stream: &mut S, answer: Answer| match tokio::time::timeout(
        ANSWER,
        answer.send(stream),
    )
    .await
    {
        Ok(sent) => sent.is_ok(),
        Err(_) => false,
    };
    let identified = match identified {
        Ok(identified) => identified,
        Err((refusal, why)) => {
            answer(&mut stream, refusal).await;
            let ended = until_closed(&mut stream).await;
            return Served::Refused { why, ended };
        }
    };
    admitted();
    let local = match open_hub().await {
        Ok(local) => local,
        Err(err) => {
            tracing::warn!("no hub to connect a tailnet connection to: {err}");
            answer(&mut stream, Answer::NoHub).await;
            return Served::NoHub(until_closed(&mut stream).await);
        }
    };
    if !answer(&mut stream, Answer::Welcome).await {
        return Served::Ended(Ended::Closed);
    }
    match identified {
        None => carry_unlisted(from, stream, local, allowed.clone()).await,
        Some((ip, Identity { node, tags })) => {
            carry_listed(net, ip, &node, tags, stream, local, Some(allowed.clone())).await
        }
    }
}

/// Waits for a peer that has been answered, and should close, to close: one that doesn't may
/// leave the socket for good, which tailscale-rs never frees.
async fn until_closed(stream: &mut (impl AsyncRead + Unpin)) -> Ended {
    let closed = async {
        let mut buf = [0; 512];
        while let Ok(read) = stream.read(&mut buf).await
            && read > 0
        {}
    };
    match tokio::time::timeout(heartbeat::LINGER, closed).await {
        Ok(()) => Ended::Closed,
        Err(_) => Ended::NotClosed,
    }
}

/// Why a hub wasn't reached.
#[derive(Debug)]
pub enum DialError {
    /// The hub doesn't admit this machine, `own`.
    NotAllowed {
        own: NodeId,
    },
    /// The hub couldn't tell which node this machine is, as it must before it admits only
    /// some.
    NotIdentified,
    NoHub,
    /// Another node has the hub's address.
    OtherNode {
        hub: Address,
        found: NodeId,
    },
    Unidentified {
        hub: Address,
        why: Unidentified,
    },
    NoAnswer {
        hub: Address,
    },
    Failed {
        hub: Address,
        why: io::Error,
    },
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAllowed { own } => write!(
                f,
                "the hub refused this machine: add {own} to musubi.tailnet.allow on the hub's \
                 machine"
            ),
            Self::NotIdentified => f.write_str(
                "the hub couldn't tell which tailnet node this machine is, to check it against \
                 musubi.tailnet.allow; if trying again in a minute doesn't help, the log on the \
                 hub's machine says why",
            ),
            Self::NoHub => f.write_str("no hub is running there"),
            Self::OtherNode { hub, found } => write!(
                f,
                "{} is now node {found}, not the hub's node {}",
                hub.ip, hub.node
            ),
            Self::Unidentified { hub, why } => {
                write!(f, "can't reach {} over the tailnet: {why}", hub.ip)
            }
            Self::NoAnswer { hub } => write!(
                f,
                "{} didn't answer over the tailnet within {} seconds",
                hub.ip,
                DIAL.as_secs()
            ),
            Self::Failed { hub, why } => {
                write!(f, "connecting to {} over the tailnet failed: {why}", hub.ip)
            }
        }
    }
}

impl std::error::Error for DialError {}

/// Connects to hubs.
///
/// tailscale-rs 0.7.1 has no way to close a connect that was cancelled: its socket sends SYNs
/// until the node goes. So a connect is never cancelled, whatever becomes of who asked for
/// it, and only one is made at a time to each address, which the next callers wait behind.
pub struct Dialer<N> {
    net: Arc<N>,
    own: NodeId,
    connecting: Mutex<HashMap<Ipv4Addr, Arc<tokio::sync::Mutex<()>>>>,
}

impl<N: Tailnet> Dialer<N> {
    /// A dialer for `net`, whose own ID is `own`.
    pub fn new(net: Arc<N>, own: NodeId) -> Self {
        Self {
            net,
            own,
            connecting: Mutex::default(),
        }
    }

    /// A link to `hub` that has been welcomed, for [`carry`], with the node checked to be the
    /// one the address names both before connecting and after.
    pub async fn open(&self, hub: &Address) -> Result<N::Stream, DialError> {
        match tokio::time::timeout(DIAL, self.open_unbounded(hub)).await {
            Ok(opened) => opened,
            Err(_) => Err(DialError::NoAnswer { hub: hub.clone() }),
        }
    }

    async fn open_unbounded(&self, hub: &Address) -> Result<N::Stream, DialError> {
        self.check(hub).await?;
        let failed = |why| DialError::Failed {
            hub: hub.clone(),
            why,
        };
        let mut stream = self.connect(hub.ip).await.map_err(failed)?;
        self.check(hub).await?;
        match Answer::read(&mut stream).await.map_err(failed)? {
            Answer::Welcome => Ok(stream),
            Answer::NotAllowed => Err(DialError::NotAllowed {
                own: self.own.clone(),
            }),
            Answer::NoHub => Err(DialError::NoHub),
            Answer::Unidentified => Err(DialError::NotIdentified),
        }
    }

    async fn check(&self, hub: &Address) -> Result<(), DialError> {
        match who(self.net.as_ref(), hub.ip).await {
            Ok(found) if found.node == hub.node => Ok(()),
            Ok(found) => Err(DialError::OtherNode {
                hub: hub.clone(),
                found: found.node,
            }),
            Err(why) => Err(DialError::Unidentified {
                hub: hub.clone(),
                why,
            }),
        }
    }

    async fn connect(&self, ip: Ipv4Addr) -> io::Result<N::Stream> {
        let turn = self
            .connecting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(ip)
            .or_default()
            .clone();
        let turn = turn.lock_owned().await;
        let net = self.net.clone();
        let (connected, waiting) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let stream = net.connect(ip).await;
            // Nobody waiting any more drops the stream, which closes it.
            drop(connected.send(stream));
            drop(turn);
        });
        waiting
            .await
            .unwrap_or_else(|_| Err(io::Error::other("the node stopped")))
    }
}

#[cfg(test)]
mod tests;
