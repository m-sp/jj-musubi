//! The daemon's side of [`super::link`]: this machine's node, which the daemon starts the
//! first time something asks for a tailnet hub, and keeps for as long as it runs.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use futures::FutureExt as _;
use interprocess::local_socket::tokio::Stream;
use tokio::sync::watch;

use super::address::Address;
use super::gate::DialError;
use super::gate::Dialer;
use super::gate::Served;
use super::link::Reply;
use super::node::Node;
use super::node::StartError;
use super::settings::Role;
use super::supervise::Over;
use super::supervise::Usage;
use crate::socket::Socket;

/// How long a request may take to arrive.
const REQUEST: Duration = Duration::from_secs(5);

/// How long, from a connection to the socket, the node may take to be ready and to open the link it
/// asks for, all told: less than a command waits for the answer (`ANSWER` in
/// [`super::link`]), so that it hears why rather than timing out.
const OPEN: Duration = Duration::from_secs(11);

/// How the node is.
#[derive(Clone)]
enum Status {
    Starting,
    Login(String),
    Failed { why: String, settings: bool },
    Ready(Ready),
}

#[derive(Clone)]
struct Ready {
    node: Arc<Node>,
    dialer: Arc<Dialer<Node>>,
    runtime: tokio::runtime::Handle,
    usage: Arc<Usage>,
}

/// The daemon's socket for links to tailnet hubs, until dropped.
pub struct Bridge {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Bridge {
    /// Listens for links on this machine's socket for them, and listens there again whenever
    /// the socket goes, as the daemon does on its own socket. A daemon that can't still syncs
    /// copies of hubs it reaches otherwise, so a failure is only logged, and tried again.
    pub fn listen() -> Self {
        super::supervise::prepare();
        Self {
            task: tokio::spawn(keep_listening()),
        }
    }
}

/// How often to look for the socket having gone, and how long to leave between listening
/// again and the next time, as the daemon's own socket does.
const LOOK: Duration = Duration::from_secs(5);
const RELISTEN_GAP: Duration = Duration::from_secs(1);

fn socket() -> anyhow::Result<(Socket, std::path::PathBuf)> {
    let path = super::link::socket_path()?;
    let socket = Socket::Path(path.clone());
    if let Some(over) = socket.too_long() {
        anyhow::bail!("{socket} is {over} bytes longer than this system allows");
    }
    // The directory it is in, made private whatever the umask.
    crate::config::create_state_dir()?;
    super::settings::private_dirs(&crate::config::state_dir()?, None)?;
    Ok((socket, path))
}

async fn keep_listening() {
    let mut said = None;
    loop {
        let listening = socket().and_then(|(socket, path)| Ok((socket.listen()?, socket, path)));
        let (listener, socket, path) = match listening {
            Ok(listening) => listening,
            Err(err) => {
                let why = format!("{err:#}");
                if said.as_ref() != Some(&why) {
                    tracing::warn!("not reaching tailnet hubs, until this changes: {why}");
                    said = Some(why);
                }
                tokio::time::sleep(LOOK).await;
                continue;
            }
        };
        said = None;
        let bound = socket.file();
        let mut gone = crate::watch::Watcher::removal(&path).ok();
        let mut look = tokio::time::interval(LOOK);
        loop {
            tokio::select! {
                stream = crate::socket::accept(&listener) => {
                    tokio::spawn(serve(stream));
                }
                _ = look.tick() => {}
                () = crate::watch::changed(gone.as_mut()) => {}
            }
            if socket.file() != bound {
                break;
            }
        }
        match socket.file() {
            None => tracing::warn!("{socket} is gone; listening there again"),
            // Another process's now: it can have it.
            Some(_) => {
                tracing::warn!("{socket} is another process's now; not reaching tailnet hubs");
                return;
            }
        }
        tokio::time::sleep(RELISTEN_GAP).await;
    }
}

/// The node, started the first time it is asked for.
fn node() -> watch::Receiver<Status> {
    static NODE: OnceLock<watch::Receiver<Status>> = OnceLock::new();
    NODE.get_or_init(|| {
        let (status, watching) = watch::channel(Status::Starting);
        let status = Arc::new(status);
        let ended = status.clone();
        super::supervise::spawn(
            "musubi-tailnet",
            move |generation| {
                let status = status.clone();
                async move {
                    status.send_replace(Status::Starting);
                    let login = |url| {
                        status.send_replace(Status::Login(url));
                    };
                    let node = match Node::start(Role::Daemon, generation.trust, login).await {
                        Ok(node) => Arc::new(node),
                        Err(StartError::Settings(why)) => {
                            status.send_replace(Status::Failed {
                                why: why.clone(),
                                settings: true,
                            });
                            return Over::Failed(why);
                        }
                        Err(StartError::Other(why)) => {
                            status.send_replace(Status::Failed {
                                why: why.clone(),
                                settings: false,
                            });
                            return Over::Failed(why);
                        }
                    };
                    tracing::info!("this machine is tailnet node {}, at {}", node.id, node.ip);
                    let ready = Ready {
                        dialer: Arc::new(Dialer::new(node.clone())),
                        node: node.clone(),
                        runtime: tokio::runtime::Handle::current(),
                        usage: generation.usage,
                    };
                    status.send_replace(Status::Ready(ready));
                    Over::Replace(node.unhealthy().await)
                }
                .boxed()
            },
            move |over| {
                if let Over::Replace(_) = over {
                    ended.send_replace(Status::Starting);
                }
            },
        );
        watching
    })
    .clone()
}

/// Serves one request: a link to the hub it names, carried from then on, or why not.
async fn serve(mut stream: Stream) {
    let deadline = tokio::time::Instant::now() + OPEN;
    let asked = tokio::time::timeout(REQUEST, super::link::read_request(&mut stream)).await;
    let Ok(Ok(asked)) = asked else {
        // Nothing asked, as `check` does.
        return;
    };
    let hub = match Address::parse(&asked) {
        Some(Ok(hub)) => hub,
        Some(Err(err)) => return reply(stream, Reply::Refused, &format!("{err:#}")).await,
        None => return reply(stream, Reply::Refused, "not a tailnet address").await,
    };
    let mut status = node();
    let ready = tokio::time::timeout_at(deadline, async {
        loop {
            let now = status.borrow_and_update().clone();
            match now {
                Status::Ready(ready) => return Ok(ready),
                Status::Login(url) => return Err((Reply::Login, url)),
                Status::Failed { why, settings } => {
                    let reply = if settings {
                        Reply::Refused
                    } else {
                        Reply::Failed
                    };
                    return Err((reply, format!("this machine's tailnet node: {why}")));
                }
                Status::Starting => {}
            }
            if status.changed().await.is_err() {
                return Err((
                    Reply::Failed,
                    "this machine's tailnet node stopped".to_owned(),
                ));
            }
        }
    })
    .await;
    let ready = match ready {
        Ok(Ok(ready)) => ready,
        Ok(Err((answer, why))) => return reply(stream, answer, &why).await,
        Err(_) => {
            let why = "this machine's tailnet node is still starting";
            return reply(stream, Reply::Failed, why).await;
        }
    };
    // On the node's runtime, which drops it, and the connection, if the node is replaced.
    let runtime = ready.runtime.clone();
    runtime.spawn(link(ready, hub, stream, deadline));
}

async fn reply(mut stream: Stream, answer: Reply, text: &str) {
    super::link::write_reply(&mut stream, answer, text)
        .await
        .ok();
}

async fn link(ready: Ready, hub: Address, mut stream: Stream, deadline: tokio::time::Instant) {
    let _in_use = ready.usage.in_use();
    let opened = tokio::time::timeout_at(deadline, ready.dialer.open(&hub)).await;
    let link = match opened {
        Ok(Ok(link)) => link,
        Ok(Err(err)) => {
            let answer = match &err {
                DialError::OtherNode { .. } => Reply::Refused,
                DialError::NoAnswer { .. } => {
                    ready.usage.unanswered();
                    Reply::Failed
                }
                _ => Reply::Failed,
            };
            return reply(stream, answer, &err.to_string()).await;
        }
        Err(_) => {
            ready.usage.unanswered();
            let why = format!("{} didn't answer over the tailnet", hub.ip);
            return reply(stream, Reply::Failed, &why).await;
        }
    };
    ready.usage.reached();
    // Carried even if whoever asked has gone, so that the link closes as it should.
    super::link::write_reply(&mut stream, Reply::Open, "")
        .await
        .ok();
    let carried = super::gate::carry(ready.node.as_ref(), hub.ip, &hub.node, link, stream).await;
    match carried {
        Served::Ended(ended) => {
            // The hub went silent: if nothing else answers either, the node may be what fails.
            if ended == musubi_transport::heartbeat::Ended::Silent {
                ready.usage.unanswered();
            }
            ready.usage.ended(ended);
        }
        // Dropped without ending: its socket may never close.
        _ => ready
            .usage
            .ended(musubi_transport::heartbeat::Ended::NotClosed),
    }
}
