//! Which node a machine takes for its hub over a tailnet, and serving what reaches a hub's
//! port, which the tailnet's access controls let through.
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

use super::address::Address;
use super::address::NodeId;

/// How often a hub's node is identified again, so that a link to one removed from the
/// tailnet, or whose address has passed to another, ends.
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
    /// Another node's route covers the address as closely.
    Ambiguous,
    Expired,
    Unroutable,
    BadId,
    Lookup(String),
}

impl fmt::Display for Unidentified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("no node this machine may reach has that address"),
            Self::Ambiguous => f.write_str("more than one node has a route to that address"),
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
    let [only] = routed else {
        return Err(Unidentified::Ambiguous);
    };
    if only.id != owner.id {
        return Err(Unidentified::Ambiguous);
    }
    if owner.key_expires.is_some_and(|at| at > 0 && at <= now) {
        return Err(Unidentified::Expired);
    }
    if !owner.relayed {
        return Err(Unidentified::Unroutable);
    }
    owner.id.parse().map_err(|_| Unidentified::BadId)
}

async fn who<N: Tailnet>(net: &N, ip: Ipv4Addr) -> Result<NodeId, Unidentified> {
    let lookup = |err: io::Error| Unidentified::Lookup(err.to_string());
    let owner = net.owner(ip).await.map_err(lookup)?;
    let routed = net.routed(ip).await.map_err(lookup)?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(i64::MAX, |since| {
            i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
        });
    identify(owner.as_ref(), &routed, now)
}

/// How a connection to or from a hub went.
#[derive(Debug, PartialEq, Eq)]
pub enum Served {
    NoHub(Ended),
    /// The hub's address stopped being its node's.
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
    let changed = async {
        // Since when looking the node up has failed, with no answer since.
        let mut failing = None;
        loop {
            tokio::time::sleep(RECHECK).await;
            match who(net, ip).await {
                Ok(now) if now == *node => failing = None,
                Ok(now) => {
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

/// Serves what connected to a hub's port. The tailnet's access controls, which the node
/// enforces on every packet it receives, decided that it may: the hub admits whatever they
/// let through.
pub async fn serve_peer<S, L>(
    mut stream: S,
    open_hub: impl AsyncFnOnce() -> io::Result<L>,
) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin,
    L: AsyncRead + AsyncWrite + Unpin,
{
    let answer = async |stream: &mut S, answer: Answer| match tokio::time::timeout(
        ANSWER,
        answer.send(stream),
    )
    .await
    {
        Ok(sent) => sent.is_ok(),
        Err(_) => false,
    };
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
    Served::Ended(heartbeat::relay(stream, local).await)
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
    connecting: Mutex<HashMap<Ipv4Addr, Arc<tokio::sync::Mutex<()>>>>,
}

impl<N: Tailnet> Dialer<N> {
    /// A dialer for `net`.
    pub fn new(net: Arc<N>) -> Self {
        Self {
            net,
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
            Answer::NoHub => Err(DialError::NoHub),
        }
    }

    async fn check(&self, hub: &Address) -> Result<(), DialError> {
        match who(self.net.as_ref(), hub.ip).await {
            Ok(found) if found == hub.node => Ok(()),
            Ok(found) => Err(DialError::OtherNode {
                hub: hub.clone(),
                found,
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
