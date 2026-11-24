//! The hub's side: a node of the hub's own, which other machines' daemons connect to.
//!
//! It runs only if `musubi.tailnet.hub` is true. The node enforces the tailnet's access
//! controls on every packet it receives; of what they let through, it admits every node, or,
//! if `musubi.tailnet.allow` is set, only the nodes it lists, which it reads again every few
//! seconds, so that adding a machine, or taking one away, needs no restart. Each connection it
//! admits is served as one to the hub's socket is.

use std::collections::BTreeSet;
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
use super::gate::Served;
use super::node::Node;
use super::node::StartError;
use super::settings::Allow;
use super::settings::Role;
use super::settings::Switch;
use super::supervise::Generation;
use super::supervise::Over;
use crate::ui::Ui;

/// How often to read `musubi.tailnet.allow` again, and `musubi.tailnet.hub` while whether it
/// is on can't be told.
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

/// Runs the hub's node, once `musubi.tailnet.hub` is known to be true, serving what reaches it
/// through `transport`, which reaches the hub's service. Never returns. `default` is whether
/// this is the hub of this machine's: only it has a node, whose identity other machines pin.
/// If jj's config can't be read, whether the hub should be on the tailnet can't be told, so
/// nothing starts until it can.
pub async fn host(ui: &Ui, transport: Arc<dyn Transport>, default: bool) {
    let mut said = None;
    loop {
        match tokio::task::spawn_blocking(Switch::read).await {
            Ok(Switch::Off) => {
                if !matches!(
                    tokio::task::spawn_blocking(Allow::read).await,
                    Ok(Allow::Unset)
                ) {
                    tracing::warn!(
                        "not on the tailnet: musubi.tailnet.allow is set, but only \
                         `jj config set --user musubi.tailnet.hub true` puts the hub there"
                    );
                }
                return std::future::pending().await;
            }
            Ok(Switch::On) => break,
            Ok(Switch::Unknown(why)) => {
                if said.as_ref() != Some(&why) {
                    tracing::warn!("not on the tailnet until jj's config can be read: {why}");
                    said = Some(why);
                }
            }
            Err(err) => tracing::warn!("reading musubi.tailnet.hub: {err}"),
        }
        tokio::time::sleep(REREAD).await;
    }
    if !default {
        tracing::warn!(
            "not listening on the tailnet: only the hub run without --dir does, which other \
             machines pin"
        );
        return std::future::pending().await;
    }
    super::supervise::prepare();
    let first = tokio::task::spawn_blocking(Allow::read)
        .await
        .unwrap_or_else(|err| Allow::Unknown(err.to_string()));
    let (first, failure) = admitting(first);
    if let Some(why) = failure {
        tracing::warn!("admitting no tailnet node: {why}");
    }
    let (allowing, allowed) = watch::channel(first);
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
/// whether `musubi.tailnet.hub` is true, as far as can be told.
pub fn listens() -> bool {
    !matches!(Switch::read(), Switch::Off)
}

/// What `musubi.tailnet.allow` as read admits, of what the tailnet's access controls let
/// through: everything if it is unset, and nobody unless every entry is a node ID or a tag;
/// and, if it admits nobody for that, why.
fn admitting(read: Allow) -> (Option<Allowed>, Option<String>) {
    match read {
        Allow::Unset => (None, None),
        Allow::Set(Ok(allowed)) => (Some(allowed), None),
        Allow::Set(Err(why)) | Allow::Unknown(why) => (Some(Allowed::default()), Some(why)),
    }
}

/// Reads `musubi.tailnet.allow` again every few seconds. A list that can't be read admits
/// nobody.
async fn reread(allowing: watch::Sender<Option<Allowed>>) {
    let mut said = None;
    loop {
        tokio::time::sleep(REREAD).await;
        let read = tokio::task::spawn_blocking(Allow::read)
            .await
            .unwrap_or_else(|err| Allow::Unknown(err.to_string()));
        let (read, failure) = admitting(read);
        // Said once, not every few seconds.
        if failure != said {
            if let Some(why) = &failure {
                tracing::warn!("admitting no tailnet node until it's fixed: {why}");
            }
            said = failure;
        }
        allowing.send_if_modified(|allowed| {
            let changed = *allowed != read;
            *allowed = read;
            changed
        });
    }
}

async fn run(
    generation: Generation,
    allowed: watch::Receiver<Option<Allowed>>,
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
    tokio::spawn(wave(node.clone()));
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
    let mut listing = allowed.clone();
    let accepting = async {
        loop {
            let (stream, from) = match node.accept(&listener).await {
                Ok(accepted) => accepted,
                Err(err) => return format!("accepting on the tailnet: {err}"),
            };
            // A machine refused by the list before it changed may be admitted now.
            if listing.has_changed().unwrap_or(false) {
                listing.borrow_and_update();
                *refusals.lock().unwrap_or_else(PoisonError::into_inner) = Refusals::default();
            }
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
                let admitted = || {
                    if let IpAddr::V4(ip) = from {
                        served_before(ip);
                    }
                };
                let served = super::gate::serve_peer(
                    node.as_ref(),
                    &allowed,
                    stream,
                    from,
                    opened,
                    admitted,
                )
                .await;
                match served {
                    Served::Ended(ended) => {
                        usage.reached();
                        usage.ended(ended);
                    }
                    Served::NoHub(ended) => usage.ended(ended),
                    Served::Revoked => usage.ended(Ended::NotClosed),
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

/// Where the hub's node records the addresses it has served.
fn served_path() -> anyhow::Result<PathBuf> {
    Ok(Role::Hub.state_dir()?.join("served"))
}

fn read_served() -> BTreeSet<Ipv4Addr> {
    let Ok(path) = served_path() else {
        return BTreeSet::new();
    };
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.parse().ok())
        .collect()
}

/// Records that `ip` has been served, unless it is recorded so already.
fn served_before(ip: Ipv4Addr) {
    static WRITING: Mutex<()> = Mutex::new(());
    let _writing = WRITING.lock().unwrap_or_else(PoisonError::into_inner);
    let mut served = read_served();
    if !served.insert(ip) {
        return;
    }
    let text = served.iter().fold(String::new(), |mut text, ip| {
        writeln!(text, "{ip}").ok();
        text
    });
    if let Err(err) =
        served_path().and_then(|path| crate::config::write_private(&path, text.as_bytes()))
    {
        tracing::debug!("not recording the tailnet peers served: {err:#}");
    }
}

/// Says the node is there to each address it has served before, for as long as a peer there
/// may go on using a session from before it started. tailscale-rs re-handshakes only from a
/// side that sends, so a client whose session predates a restarted hub would otherwise wait
/// out the session, minutes, before reaching it. An address that is another node's now gets
/// a handshake it may ignore.
async fn wave(node: Arc<Node>) {
    let peers = read_served();
    let until = tokio::time::Instant::now() + WAVING;
    while tokio::time::Instant::now() < until {
        for ip in &peers {
            node.wave(*ip).await.ok();
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

    /// Unset, the list leaves it to the access controls; set but unreadable, or unknown, it
    /// admits nobody, and says why, rather than everything.
    #[test]
    fn a_list_that_is_unset_admits_everything_and_one_that_cannot_be_read_nobody() {
        let node: super::super::address::NodeId = "nExample1CNTRL".parse().unwrap();
        assert_eq!(admitting(Allow::Unset), (None, None));
        let listed = Allowed::parse(&["nExample1CNTRL".to_owned()]).unwrap();
        assert_eq!(
            admitting(Allow::Set(Ok(listed.clone()))),
            (Some(listed), None)
        );
        for read in [
            Allow::Set(Err("bad entry".to_owned())),
            Allow::Unknown("jj's config can't be read".to_owned()),
        ] {
            let (allowed, why) = admitting(read);
            assert!(!allowed.unwrap().admits(&node, &[]));
            assert!(why.is_some());
        }
    }
}
