//! Reaching a tailnet hub through this machine's daemon, which holds the node.
//!
//! The daemon listens on a socket of its own for this, beside its state: a command, or the
//! daemon's own copies, send [`BRIDGE`] and the hub's address, and the daemon answers with a
//! [`Reply`] and, if it opened a link, carries the connection over it from then on. A local
//! socket ends a connection by closing, so nothing else is framed here.

use std::io;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::time::Duration;

use async_trait::async_trait;
use musubi_transport::stream::Connector;
use musubi_transport::stream::Reader;
use musubi_transport::stream::Writer;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt as _;

use super::address::Address;
use crate::config;
use crate::socket::Socket;
use crate::ui::Ui;

/// What a request to the daemon starts with: its protocol and version.
pub const BRIDGE: &[u8] = b"musubi-tailnet-bridge-1\n";

/// How long a command waits for the daemon to answer: longer than the daemon takes, all told,
/// to be ready and open a link (`OPEN` in `bridge`), so that it hears why one wasn't.
const ANSWER: Duration = Duration::from_secs(14);

/// How long joining waits for a hub that isn't there yet.
const PREPARE: Duration = Duration::from_secs(60);

/// What the daemon answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    /// The link is open, and carries the connection from here on.
    Open,
    /// It isn't, for now, as the text says.
    Failed,
    /// It isn't, as the text says, and trying again won't change that.
    Refused,
    /// The hub doesn't admit this machine's node, whose ID the text is.
    NotAllowed,
    /// The node waits for a login at the URL the text is.
    Login,
}

impl Reply {
    const ALL: [Self; 5] = [
        Self::Open,
        Self::Failed,
        Self::Refused,
        Self::NotAllowed,
        Self::Login,
    ];
}

/// The socket the daemon listens on for links to tailnet hubs.
pub fn socket_path() -> anyhow::Result<PathBuf> {
    Ok(config::state_dir()?.join("tailnet").join("daemon.sock"))
}

pub async fn write_request(to: &mut (impl AsyncWrite + Unpin), hub: &Address) -> io::Result<()> {
    let hub = hub.to_string();
    let len = u16::try_from(hub.len()).map_err(|_| io::Error::other("address too long"))?;
    let mut message = BRIDGE.to_vec();
    message.extend(len.to_be_bytes());
    message.extend(hub.as_bytes());
    to.write_all(&message).await?;
    to.flush().await
}

/// The address a request names, as written: it is the caller's to parse.
pub async fn read_request(from: &mut (impl AsyncRead + Unpin)) -> io::Result<String> {
    let mut bridge = [0; BRIDGE.len()];
    from.read_exact(&mut bridge).await?;
    if bridge != BRIDGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a request of this build",
        ));
    }
    read_text(from).await
}

pub async fn write_reply(
    to: &mut (impl AsyncWrite + Unpin),
    reply: Reply,
    text: &str,
) -> io::Result<()> {
    let text = &text[..text.floor_char_boundary(usize::from(u16::MAX))];
    let mut message = vec![reply as u8];
    // Cut to fit just above.
    message.extend((text.len() as u16).to_be_bytes());
    message.extend(text.as_bytes());
    to.write_all(&message).await?;
    to.flush().await
}

pub async fn read_reply(from: &mut (impl AsyncRead + Unpin)) -> io::Result<(Reply, String)> {
    let said = from.read_u8().await?;
    let reply = Reply::ALL
        .into_iter()
        .find(|&reply| reply as u8 == said)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the daemon is of another build; `musubi daemon restart` restarts it",
            )
        })?;
    Ok((reply, read_text(from).await?))
}

async fn read_text(from: &mut (impl AsyncRead + Unpin)) -> io::Result<String> {
    let len = from.read_u16().await?;
    let mut text = vec![0; usize::from(len)];
    from.read_exact(&mut text).await?;
    String::from_utf8(text).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))
}

/// That tailnet hubs can't be reached, as the daemon that reaches them isn't running.
fn daemon_stopped() -> anyhow::Error {
    crate::ui::with_hint(
        anyhow::anyhow!("the daemon isn't running"),
        "`musubi daemon start` starts it",
    )
}

/// Why asking the daemon for a link failed, as the transport takes it: only an answer from
/// another build means trying again won't help.
#[derive(Debug)]
enum AskError {
    /// What can be put right, and tried again: no daemon, or one that didn't answer.
    Unavailable(anyhow::Error),
    /// The daemon is of another build.
    OtherBuild(io::Error),
}

/// A connection to the daemon's socket for links at `path`, or why there is none.
async fn bridge(path: &Path) -> anyhow::Result<interprocess::local_socket::tokio::Stream> {
    anyhow::ensure!(
        super::SUPPORTED,
        "tailnet hubs can only be reached from Linux and macOS"
    );
    let socket = Socket::Path(path.to_owned());
    if let Some(over) = socket.too_long() {
        anyhow::bail!(
            "the daemon's socket for tailnet hubs, {socket}, would be {over} bytes longer than \
             this system allows; give MUSUBI_STATE_DIR a shorter path"
        );
    }
    if let Some(stream) = socket.connect_stream().await? {
        return Ok(stream);
    }
    if crate::daemon::Running::find()?.is_some() {
        let err = anyhow::anyhow!("the daemon isn't listening for tailnet hubs on {socket}");
        return Err(crate::ui::with_hint(
            err,
            "Its log says why. `musubi daemon restart` restarts it.",
        ));
    }
    Err(daemon_stopped())
}

/// Fails now if nothing would answer a link to a tailnet hub, saying what to do, rather
/// than after a connection's timeout.
pub async fn check() -> anyhow::Result<()> {
    drop(bridge(&socket_path()?).await?);
    Ok(())
}

/// Asks the daemon, on its socket at `path`, for a link to `hub`.
async fn ask(
    path: &Path,
    hub: &Address,
) -> Result<(Reply, String, interprocess::local_socket::tokio::Stream), AskError> {
    let mut stream = bridge(path).await.map_err(AskError::Unavailable)?;
    let answered = async {
        write_request(&mut stream, hub).await?;
        read_reply(&mut stream).await
    };
    match tokio::time::timeout(ANSWER, answered).await {
        Ok(Ok((reply, text))) => Ok((reply, text, stream)),
        Ok(Err(err)) if err.kind() == io::ErrorKind::InvalidData => Err(AskError::OtherBuild(err)),
        Ok(Err(err)) => Err(AskError::Unavailable(
            anyhow::Error::new(err).context("the daemon stopped answering"),
        )),
        Err(_) => Err(AskError::Unavailable(anyhow::anyhow!(
            "the daemon didn't answer in time"
        ))),
    }
}

/// What keeps a tailnet hub from being reached, while something does.
#[derive(Clone, Default)]
pub struct Health(Arc<Mutex<Option<String>>>);

impl Health {
    pub fn problem(&self) -> Option<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set(&self, problem: Option<String>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = problem;
    }
}

/// Opens connections to a tailnet hub, each a link through the daemon.
pub struct Link {
    hub: Address,
    /// The daemon's socket for links: [`socket_path`], unless a test gives another.
    socket: Option<PathBuf>,
    health: Health,
}

impl Link {
    pub fn new(hub: Address) -> Self {
        Self {
            hub,
            socket: None,
            health: Health::default(),
        }
    }

    pub fn health(&self) -> Health {
        self.health.clone()
    }
}

#[async_trait]
impl Connector for Link {
    async fn connect(&self) -> io::Result<(Reader, Writer)> {
        let failed = |problem: String, kind| {
            self.health.set(Some(problem.clone()));
            io::Error::new(kind, problem)
        };
        let path = match &self.socket {
            Some(path) => path.clone(),
            None => {
                socket_path().map_err(|err| failed(format!("{err:#}"), io::ErrorKind::Other))?
            }
        };
        // Where trying again soon won't help, the transport takes `InvalidData`: for a first
        // connection it gives up at once, saying why, and later it waits a minute. That is a
        // daemon of another build, and a refusal: the hub not admitting this machine, or an
        // address that isn't the hub's. Anything else, a daemon that's busy or restarting, or
        // a login, it tries again soon, and the daemon says why each time.
        let (reply, text, stream) = ask(&path, &self.hub).await.map_err(|err| match err {
            AskError::Unavailable(err) => failed(format!("{err:#}"), io::ErrorKind::Other),
            AskError::OtherBuild(err) => failed(err.to_string(), io::ErrorKind::InvalidData),
        })?;
        match reply {
            Reply::Open => {
                self.health.set(None);
                let (reader, writer) = tokio::io::split(stream);
                Ok((Box::new(reader), Box::new(writer)))
            }
            Reply::Failed => Err(failed(text, io::ErrorKind::Other)),
            Reply::Refused => Err(failed(text, io::ErrorKind::InvalidData)),
            Reply::NotAllowed => Err(failed(not_allowed(&text), io::ErrorKind::InvalidData)),
            Reply::Login => Err(failed(
                format!("this machine's tailnet node waits for a login at {text}"),
                io::ErrorKind::Other,
            )),
        }
    }

    fn not_hub(&self, why: &io::Error) {
        self.health.set(Some(format!(
            "reached {} over the tailnet, but {why}",
            self.hub.ip
        )));
    }
}

/// That the hub doesn't admit this machine's node, `own`, and what to do about it.
fn not_allowed(own: &str) -> String {
    format!(
        "the hub refused this machine's tailnet node, {own}; add it to musubi.tailnet.allow on \
         the hub's machine"
    )
}

/// Makes sure the hub at `hub` can be reached before a join asks it anything: logging this
/// machine's node in to the tailnet if it asks, and waiting a while for a hub not there yet.
pub async fn prepare(ui: &Ui, hub: &Address) -> anyhow::Result<()> {
    let mut deadline = tokio::time::Instant::now() + PREPARE;
    let mut said = None;
    loop {
        let (reply, text, _stream) = match ask(&socket_path()?, hub).await {
            Ok(asked) => asked,
            Err(AskError::Unavailable(err)) => return Err(err),
            Err(AskError::OtherBuild(err)) => {
                return Err(crate::ui::with_hint(
                    anyhow::Error::new(err),
                    "`musubi daemon restart` restarts it.",
                ));
            }
        };
        match reply {
            Reply::Open => return Ok(()),
            Reply::Refused => anyhow::bail!("{text}"),
            Reply::NotAllowed => {
                return Err(crate::ui::with_hint(
                    anyhow::anyhow!("the hub refused this machine's tailnet node, {text}"),
                    format!(
                        "Add {text} to `musubi.tailnet.allow` on the hub's machine, then run \
                         this again."
                    ),
                ));
            }
            Reply::Login => {
                if said.as_ref() != Some(&text) {
                    writeln!(
                        ui.stderr(),
                        "To add this machine to the tailnet, log in at {text}"
                    )?;
                    said = Some(text);
                }
                // However long logging in takes.
                deadline = tokio::time::Instant::now() + PREPARE;
            }
            Reply::Failed if tokio::time::Instant::now() >= deadline => {
                anyhow::bail!("the hub at {hub} is out of reach: {text}");
            }
            Reply::Failed => {}
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request and each reply read back as written, and nothing of another build is taken
    /// for one.
    #[tokio::test]
    async fn requests_and_replies_read_back() {
        let hub = Address::parse("tailnet:nExample1CNTRL@100.64.0.1")
            .unwrap()
            .unwrap();
        let mut request = vec![];
        write_request(&mut request, &hub).await.unwrap();
        assert_eq!(
            read_request(&mut request.as_slice()).await.unwrap(),
            hub.to_string()
        );
        request[BRIDGE.len() - 2] = b'2';
        assert!(read_request(&mut request.as_slice()).await.is_err());

        for reply in Reply::ALL {
            let mut written = vec![];
            write_reply(&mut written, reply, "é".repeat(40_000).as_str())
                .await
                .unwrap();
            let (read, text) = read_reply(&mut written.as_slice()).await.unwrap();
            assert_eq!(read, reply);
            assert_eq!(text, "é".repeat(32_767));
        }
        assert!(read_reply(&mut &[9, 0, 0][..]).await.is_err());
    }
}

#[cfg(all(test, unix))]
mod bridge_tests {
    use musubi_transport::MemoryNetwork;
    use musubi_transport::StreamTransport;
    use musubi_transport::stream::WhileDisconnected;

    use super::*;

    /// A daemon that drops a connection before answering, as one restarting does, is tried
    /// again: taken for another build, the first connection would fail for good.
    #[tokio::test]
    async fn a_daemon_that_drops_a_request_is_tried_again() {
        let dir = musubi_testutil::tempdir();
        let path = dir.path().join("daemon.sock");
        let listener = Socket::Path(path.clone()).listen().unwrap();
        let network = MemoryNetwork::new(0, 1 << 20);
        let hub = Arc::new(network.connect());
        let daemon = tokio::spawn(async move {
            // The first, dropped unanswered.
            drop(crate::socket::accept(&listener).await);
            // The next, answered, and carried to a hub.
            let mut stream = crate::socket::accept(&listener).await;
            read_request(&mut stream).await.unwrap();
            write_reply(&mut stream, Reply::Open, "").await.unwrap();
            let (read, write) = tokio::io::split(stream);
            musubi_transport::stream::serve(hub, read, write).await.ok();
        });
        let link = Link {
            hub: Address::parse("tailnet:nExample1CNTRL@100.64.0.1")
                .unwrap()
                .unwrap(),
            socket: Some(path),
            health: Health::default(),
        };
        let connecting = StreamTransport::connect_with(Arc::new(link), WhileDisconnected::Wait);
        tokio::time::timeout(Duration::from_secs(10), connecting)
            .await
            .expect("connecting again")
            .expect("a dropped request taken for another build");
        daemon.abort();
    }

    /// A refusal ends a first connection at once, saying why, as `musubi list` shows it: tried
    /// again, it would wait out the command's whole limit. What may clear soon is tried again.
    #[tokio::test]
    async fn a_refusal_is_final_and_the_rest_is_tried_again() {
        for (reply, text, final_) in [
            (Reply::NotAllowed, "nExample2CNTRL", true),
            (Reply::Refused, "that address isn't the hub's", true),
            (Reply::Failed, "the node is starting", false),
            (Reply::Login, "https://login.example/a", false),
        ] {
            let dir = musubi_testutil::tempdir();
            let path = dir.path().join("daemon.sock");
            let listener = Socket::Path(path.clone()).listen().unwrap();
            let daemon = tokio::spawn(async move {
                loop {
                    let mut stream = crate::socket::accept(&listener).await;
                    read_request(&mut stream).await.unwrap();
                    write_reply(&mut stream, reply, text).await.unwrap();
                }
            });
            let link = Link {
                hub: Address::parse("tailnet:nExample1CNTRL@100.64.0.1")
                    .unwrap()
                    .unwrap(),
                socket: Some(path),
                health: Health::default(),
            };
            let connecting = StreamTransport::connect_with(Arc::new(link), WhileDisconnected::Wait);
            // Long enough for a few retries, and far short of any command's limit.
            let connected = tokio::time::timeout(Duration::from_secs(2), connecting).await;
            if final_ {
                let err = connected.expect("given up on at once").err().unwrap();
                assert!(err.to_string().contains(text), "{reply:?}: {err}");
            } else {
                assert!(connected.is_err(), "{reply:?} given up on");
            }
            daemon.abort();
        }
    }

    /// Only an answer of another build is taken for one.
    #[tokio::test]
    async fn only_another_build_is_given_up_on() {
        let dir = musubi_testutil::tempdir();
        let path = dir.path().join("daemon.sock");
        let listener = Socket::Path(path.clone()).listen().unwrap();
        let daemon = tokio::spawn(async move {
            let mut stream = crate::socket::accept(&listener).await;
            read_request(&mut stream).await.unwrap();
            stream.write_all(&[200, 0, 0]).await.unwrap();
            std::future::pending::<()>().await;
        });
        let link = Link {
            hub: Address::parse("tailnet:nExample1CNTRL@100.64.0.1")
                .unwrap()
                .unwrap(),
            socket: Some(path),
            health: Health::default(),
        };
        let err = link.connect().await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        daemon.abort();
    }
}
