//! The hub's side: a node of the hub's own, which other machines' daemons connect to.
//!
//! It runs only if `musubi.tailnet.hub` is true, and admits whatever reaches it: the node
//! enforces the tailnet's access controls on every packet it receives, and they are the hub's
//! whole access control over the tailnet, as a restricted key is over ssh. Each connection is
//! served as one to the hub's socket is.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use futures::FutureExt as _;
use musubi_transport::Transport;
use musubi_transport::heartbeat::Ended;
use tokio::io::DuplexStream;
use tokio::sync::Semaphore;
use tokio::sync::watch;

use super::address::Address;
use super::gate::Served;
use super::node::Node;
use super::node::StartError;
use super::settings::Role;
use super::settings::Switch;
use super::supervise::Generation;
use super::supervise::Over;
use crate::ui::Ui;

/// How often to read `musubi.tailnet.hub` again while whether it is on can't be told.
const REREAD: Duration = Duration::from_secs(5);

/// How many connections may be served at once.
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
            Ok(Switch::Off) => return std::future::pending().await,
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
    let (status, mut statuses) = watch::channel(Status::Starting);
    let status = Arc::new(status);
    let hub = tokio::runtime::Handle::current();
    let ended = status.clone();
    super::supervise::spawn(
        "musubi-tailnet-hub",
        move |generation| run(generation, status.clone(), transport.clone(), hub.clone()).boxed(),
        move |_| {
            ended.send_replace(Status::Starting);
        },
    );
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

async fn run(
    generation: Generation,
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
    let accepting = async {
        loop {
            let (stream, from) = match node.accept(&listener).await {
                Ok(accepted) => accepted,
                Err(err) => return format!("accepting on the tailnet: {err}"),
            };
            // Dropped unanswered, a connection may leave its socket for good: each counts
            // towards replacing the node, which frees them all.
            let Ok(permit) = room.clone().try_acquire_owned() else {
                drop(stream);
                usage.ended(Ended::NotClosed);
                tracing::warn!(
                    "turned away a tailnet connection from {from}: {MAX_CONNECTIONS} \
                     connections already"
                );
                continue;
            };
            if let IpAddr::V4(ip) = from {
                served_before(ip);
            }
            let (open_hub, usage) = (open_hub.clone(), usage.clone());
            tokio::spawn(async move {
                let _permit = permit;
                let _in_use = usage.in_use();
                let opened = async || Ok::<DuplexStream, std::io::Error>(open_hub());
                match super::gate::serve_peer(stream, opened).await {
                    Served::Ended(ended) => {
                        usage.reached();
                        usage.ended(ended);
                    }
                    Served::NoHub(ended) => usage.ended(ended),
                    Served::Revoked => usage.ended(Ended::NotClosed),
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
