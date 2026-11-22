//! The hub's side: a node of the hub's own, which other machines' daemons connect to.
//!
//! It runs only if `musubi.tailnet.allow` is set, and admits only the nodes it lists, which
//! it reads again every few seconds, so that adding a machine, or taking one away, needs no
//! restart. Each connection it admits is served as one to the hub's socket is.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;
use std::time::Instant;

use futures::FutureExt as _;
use musubi_transport::Transport;
use musubi_transport::heartbeat::Ended;
use tokio::io::DuplexStream;
use tokio::sync::Semaphore;
use tokio::sync::watch;

use super::address::Address;
use super::address::Allowed;
use super::address::NodeId;
use super::gate::Served;
use super::node::Node;
use super::node::StartError;
use super::settings::Allow;
use super::settings::Role;
use super::supervise::Generation;
use super::supervise::Over;
use crate::ui::Ui;

/// How often to read `musubi.tailnet.allow` again.
const REREAD: Duration = Duration::from_secs(5);

/// How many connections may be served at once, admitted or not.
const MAX_CONNECTIONS: usize = 256;

/// For how long a node, once started, says it's there to each peer it has served before, and
/// how often: as long as a peer goes on using a WireGuard session from before it started.
const WAVING: Duration = Duration::from_secs(185);
const WAVE: Duration = Duration::from_secs(5);

/// The buffer between a connection and the hub's service, each way.
const BUFFER: usize = 64 * 1024;

/// What the hub's node is doing, for the hub to say.
#[derive(Clone, PartialEq, Eq)]
enum Status {
    Starting,
    Login(String),
    Listening(Address),
}

/// Runs the hub's node, once `musubi.tailnet.allow` is known to be set, serving what it admits
/// through `transport`, which reaches the hub's service. Never returns. `default` is whether
/// this is the hub of this machine's: only it has a node, whose identity other machines pin.
/// If jj's config can't be read, whether the list is set can't be told, so nothing starts
/// until it can.
pub async fn host(ui: &Ui, transport: Arc<dyn Transport>, default: bool) {
    let mut said = None;
    let first = loop {
        match tokio::task::spawn_blocking(Allow::read).await {
            Ok(Allow::Unset) => return std::future::pending().await,
            Ok(Allow::Set(first)) => break first,
            Ok(Allow::Unknown(why)) => {
                if said.as_ref() != Some(&why) {
                    tracing::warn!("not on the tailnet until jj's config can be read: {why}");
                    said = Some(why);
                }
            }
            Err(err) => tracing::warn!("reading musubi.tailnet.allow: {err}"),
        }
        tokio::time::sleep(REREAD).await;
    };
    if !default {
        tracing::warn!(
            "not listening on the tailnet: only the hub run without --dir does, which other \
             machines pin"
        );
        return std::future::pending().await;
    }
    super::supervise::prepare();
    let (allowing, allowed) = watch::channel(admitting(Allow::Set(first)));
    let (status, mut statuses) = watch::channel(Status::Starting);
    let status = Arc::new(status);
    let hub = tokio::runtime::Handle::current();
    let ended = status.clone();
    let running = allowed.clone();
    super::supervise::spawn(
        "musubi-tailnet-hub",
        move |generation| {
            run(
                generation,
                running.clone(),
                status.clone(),
                transport.clone(),
                hub.clone(),
            )
            .boxed()
        },
        move |_| {
            ended.send_replace(Status::Starting);
        },
    );
    tokio::spawn(reread(allowing));
    // Whoever reads stdout may have stopped; the hub serves all the same.
    loop {
        let now = statuses.borrow_and_update().clone();
        match now {
            Status::Starting => {}
            Status::Login(url) => {
                writeln!(
                    ui.stdout(),
                    "To add this hub to the tailnet, log in at {url}"
                )
                .ok();
            }
            Status::Listening(address) => {
                let mut out = ui.stdout();
                out.write_all(instructions(&address).as_bytes())
                    .and_then(|()| out.flush())
                    .ok();
            }
        }
        if statuses.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

/// What to run on other machines to share a repository through the hub at `address`.
fn instructions(address: &Address) -> String {
    format!(
        "Over the tailnet:\n\
         To share a repository:               musubi create --hub {address}\n\
         To add another machine's copy of it: musubi join --hub {address}\n\
         To make a new copy of a hive:        musubi clone <name> [<dir>] --hub {address}\n"
    )
}

/// Whether `musubi hub` will put the hub serving the default directory on the tailnet:
/// whether `musubi.tailnet.allow` is set, as far as can be told.
pub fn listens() -> bool {
    !matches!(Allow::read(), Allow::Unset)
}

/// What `musubi.tailnet.allow` as read admits: nobody, unless it is set and every entry is a
/// node ID.
fn admitting(read: Allow) -> Allowed {
    match read {
        Allow::Set(Ok(allowed)) => allowed,
        Allow::Set(Err(why)) | Allow::Unknown(why) => {
            tracing::warn!("admitting no tailnet node: {why}");
            Allowed::default()
        }
        Allow::Unset => {
            tracing::warn!("musubi.tailnet.allow is unset; admitting no tailnet node");
            Allowed::default()
        }
    }
}

/// Reads `musubi.tailnet.allow` again every few seconds. A list that can't be read, or is
/// unset now, admits nobody.
async fn reread(allowing: watch::Sender<Allowed>) {
    let mut said = None;
    loop {
        tokio::time::sleep(REREAD).await;
        let read = tokio::task::spawn_blocking(Allow::read)
            .await
            .unwrap_or_else(|err| Allow::Unknown(err.to_string()));
        let failure = match &read {
            Allow::Set(Err(why)) | Allow::Unknown(why) => Some(why.clone()),
            Allow::Unset => Some("musubi.tailnet.allow is unset".to_owned()),
            Allow::Set(Ok(_)) => None,
        };
        // Said once, not every few seconds.
        if failure != said {
            if let Some(why) = &failure {
                tracing::warn!("admitting no tailnet node until it's fixed: {why}");
            }
            said = failure;
        }
        let read = match read {
            Allow::Set(Ok(allowed)) => allowed,
            _ => Allowed::default(),
        };
        allowing.send_if_modified(|allowed| {
            let changed = *allowed != read;
            *allowed = read;
            changed
        });
    }
}

async fn run(
    generation: Generation,
    allowed: watch::Receiver<Allowed>,
    status: Arc<watch::Sender<Status>>,
    transport: Arc<dyn Transport>,
    hub: tokio::runtime::Handle,
) -> Over {
    let login = |url| {
        status.send_replace(Status::Login(url));
    };
    let node = match Node::start(Role::Hub, generation.trust, login).await {
        Ok(node) => Arc::new(node),
        Err(StartError::Settings(why) | StartError::Other(why)) => return Over::Failed(why),
    };
    let listener = match node.listen().await {
        Ok(listener) => listener,
        Err(err) => return Over::Failed(format!("listening on the tailnet: {err}")),
    };
    let address = Address {
        node: node.id.clone(),
        ip: node.ip,
    };
    tracing::info!("listening on the tailnet as {address}");
    status.send_replace(Status::Listening(address));
    tokio::spawn(wave(node.clone(), allowed.clone()));
    let open_hub = move || {
        let (stream, served) = tokio::io::duplex(BUFFER);
        let transport = transport.clone();
        // On the hub's runtime, not the node's.
        hub.spawn(async move {
            let (read, write) = tokio::io::split(served);
            if let Err(err) = musubi_transport::stream::serve(transport, read, write).await {
                tracing::debug!("a tailnet connection ended: {err}");
            }
        });
        stream
    };
    let room = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let usage = generation.usage;
    let refusals = Arc::new(Mutex::new(Refusals::default()));
    let accepting = async {
        loop {
            let (stream, from) = match node.accept(&listener).await {
                Ok(accepted) => accepted,
                Err(err) => return format!("accepting on the tailnet: {err}"),
            };
            // Dropped unanswered, a connection may leave its socket for good, as one refused
            // may: each counts towards replacing the node, which frees them all.
            let permit = room.clone().try_acquire_owned();
            let turned_away = match &permit {
                Err(_) => Some(format!("{MAX_CONNECTIONS} connections already")),
                Ok(_) => refusals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .over(from),
            };
            if let Some(why) = turned_away {
                drop(stream);
                usage.ended(Ended::NotClosed);
                refusals
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .say(from, &why);
                continue;
            }
            let Ok(permit) = permit else { continue };
            let (node, allowed, open_hub, usage, refusals) = (
                node.clone(),
                allowed.clone(),
                open_hub.clone(),
                usage.clone(),
                refusals.clone(),
            );
            tokio::spawn(async move {
                let _permit = permit;
                let _in_use = usage.in_use();
                let opened = async || Ok::<DuplexStream, std::io::Error>(open_hub());
                let served = super::gate::serve_peer(
                    node.as_ref(),
                    &allowed,
                    stream,
                    from,
                    opened,
                    served_before,
                )
                .await;
                match served {
                    Served::Ended(ended) => {
                        usage.reached();
                        usage.ended(ended);
                    }
                    Served::Revoked => usage.ended(Ended::NotClosed),
                    Served::NoHub(ended) => usage.ended(ended),
                    Served::Refused { why, ended } => {
                        usage.ended(ended);
                        let mut refusals = refusals.lock().unwrap_or_else(PoisonError::into_inner);
                        refusals.refused(from);
                        refusals.say(from, &why);
                    }
                }
            });
        }
    };
    let why = tokio::select! {
        why = accepting => why,
        why = node.unhealthy() => why,
    };
    Over::Replace(why)
}

/// Where the hub's node records the peers it has served, by node ID, and at which address.
fn served_path() -> anyhow::Result<PathBuf> {
    Ok(Role::Hub.state_dir()?.join("served"))
}

fn read_served() -> BTreeMap<String, Ipv4Addr> {
    let Ok(path) = served_path() else {
        return BTreeMap::new();
    };
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let (node, ip) = line.split_once(' ')?;
            Some((node.to_owned(), ip.parse().ok()?))
        })
        .collect()
}

/// Records that `node`, at `ip`, has been served, unless it is recorded so already.
fn served_before(node: &NodeId, ip: Ipv4Addr) {
    static WRITING: Mutex<()> = Mutex::new(());
    let _writing = WRITING.lock().unwrap_or_else(PoisonError::into_inner);
    let mut served = read_served();
    if served.get(&node.to_string()) == Some(&ip) {
        return;
    }
    served.insert(node.to_string(), ip);
    let text = served.iter().fold(String::new(), |mut text, (node, ip)| {
        writeln!(text, "{node} {ip}").ok();
        text
    });
    if let Err(err) =
        served_path().and_then(|path| crate::config::write_private(&path, text.as_bytes()))
    {
        tracing::debug!("not recording the tailnet peers served: {err:#}");
    }
}

/// Says the node is there to each peer it has served before that is still allowed and still
/// at that address, for as long as one may go on using a session from before it started.
/// tailscale-rs re-handshakes only from a side that sends, so a client whose session predates
/// a restarted hub would otherwise wait out the session, minutes, before reaching it.
async fn wave(node: Arc<Node>, allowed: watch::Receiver<Allowed>) {
    let peers: Vec<(NodeId, Ipv4Addr)> = read_served()
        .into_iter()
        .filter_map(|(node, ip)| Some((node.parse().ok()?, ip)))
        .collect();
    let until = tokio::time::Instant::now() + WAVING;
    while tokio::time::Instant::now() < until {
        for (peer, ip) in &peers {
            let admitted = allowed.borrow().admits(peer);
            if admitted && super::gate::is(node.as_ref(), *ip, peer).await {
                node.wave(*ip).await.ok();
            }
        }
        tokio::time::sleep(WAVE).await;
    }
}

/// How many connections one address may have refused in a window, after which its next ones
/// are dropped unanswered, and how long the window is. Either way each counts towards
/// replacing the node, since its socket may never be freed: the limit is on the work and the
/// log lines a node that may not use the hub makes, not on what it costs, which only the
/// tailnet's access controls can stop.
const MAX_REFUSALS: u32 = 16;
const REFUSAL_WINDOW: Duration = Duration::from_secs(600);

/// The refusals of recent windows, by the address they came from.
#[derive(Default)]
struct Refusals {
    by_source: HashMap<IpAddr, Source>,
}

struct Source {
    /// When its window began, and how many it had refused in it.
    since: Instant,
    refused: u32,
    /// When it was last said why one was refused, and how many weren't said since.
    said: Option<Instant>,
    unsaid: u32,
}

impl Refusals {
    fn source(&mut self, from: IpAddr, now: Instant) -> &mut Source {
        // Forgets what is too old to matter, so that the map stays small.
        self.by_source
            .retain(|_, source| now.duration_since(source.since) < REFUSAL_WINDOW * 2);
        let source = self.by_source.entry(from).or_insert(Source {
            since: now,
            refused: 0,
            said: None,
            unsaid: 0,
        });
        if now.duration_since(source.since) >= REFUSAL_WINDOW {
            source.since = now;
            source.refused = 0;
        }
        source
    }

    /// Why `from`'s next connection is dropped unanswered, if it is.
    fn over(&mut self, from: IpAddr) -> Option<String> {
        let source = self.source(from, Instant::now());
        (source.refused >= MAX_REFUSALS).then(|| {
            format!(
                "{} refused in the last {} minutes",
                source.refused,
                REFUSAL_WINDOW.as_secs() / 60
            )
        })
    }

    fn refused(&mut self, from: IpAddr) {
        self.source(from, Instant::now()).refused += 1;
    }

    /// Logs why one of `from`'s connections was turned away, at most once a window.
    fn say(&mut self, from: IpAddr, why: &str) {
        let now = Instant::now();
        let source = self.source(from, now);
        if source
            .said
            .is_some_and(|said| now.duration_since(said) < REFUSAL_WINDOW)
        {
            source.unsaid += 1;
            return;
        }
        let unsaid = std::mem::take(&mut source.unsaid);
        source.said = Some(now);
        if unsaid > 0 {
            tracing::warn!(
                "turned away a tailnet connection from {from}: {why} ({unsaid} more not logged)"
            );
        } else {
            tracing::warn!("turned away a tailnet connection from {from}: {why}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One address can't keep a node busy, or fill its log, refusing it; while each socket
    /// of its still counts.
    #[test]
    fn refusals_from_one_address_are_capped() {
        let mut refusals = Refusals::default();
        let one = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9));
        let other = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));
        for _ in 0..MAX_REFUSALS {
            assert_eq!(refusals.over(one), None);
            refusals.refused(one);
        }
        assert!(refusals.over(one).is_some());
        assert_eq!(refusals.over(other), None);
        // A new window starts over.
        if let Some(earlier) = Instant::now().checked_sub(REFUSAL_WINDOW) {
            refusals.by_source.get_mut(&one).unwrap().since = earlier;
            assert_eq!(refusals.over(one), None);
        }
    }
}
