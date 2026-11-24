//! A tailscale-rs device: starting one, and what it tells the gate.

use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

use super::address::NodeId;
use super::gate::Peer;
use super::gate::Tailnet;
use super::settings::Role;
use super::settings::Settings;
use super::supervise::Trust;

/// The port hubs listen on, in their node's own network stack.
pub const PORT: u16 = 7575;

/// How long to wait for the device to answer a question. Asked before it has registered, or
/// with a key the tailnet refused, it can wait for ever.
const ANSWER: Duration = Duration::from_secs(5);

/// How long registering may take, once a login, if one was needed, is done.
const REGISTER: Duration = Duration::from_secs(30);

/// How often to look at the device's health, and how long it may fail to answer before it is
/// replaced.
const HEALTH: Duration = Duration::from_secs(15);
const UNHEALTHY: Duration = Duration::from_secs(300);

/// What the client for tailnet hubs is called, which the tailnet's admin console shows.
const CLIENT_NAME: &str = "jj-musubi";

async fn answered<T>(asking: impl Future<Output = Result<T, tailscale::Error>>) -> io::Result<T> {
    tokio::time::timeout(ANSWER, asking)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "this machine's tailnet node didn't answer",
            )
        })?
        .map_err(io::Error::other)
}

/// A device, while it can be trusted.
pub struct Node {
    device: tailscale::Device,
    trust: Trust,
    pub id: NodeId,
    pub ip: Ipv4Addr,
}

/// What went wrong starting a node: whether trying again could help.
pub enum StartError {
    /// A setting or the auth key is wrong: until it is changed, trying again won't help.
    Settings(String),
    Other(String),
}

impl Node {
    /// Starts `role`'s node, from its keys if it has any. `login` hears a URL to log in at,
    /// if there is one, and it waits for that login.
    pub async fn start(
        role: Role,
        trust: Trust,
        login: impl Fn(String),
    ) -> Result<Self, StartError> {
        let settings = Settings::load().map_err(|err| StartError::Settings(format!("{err:#}")))?;
        // Before anything contacts the tailnet: a key that is set but can't be read stops it.
        let auth_key = settings
            .auth_key()
            .map_err(|err| StartError::Settings(format!("{err:#}")))?;
        let dir = role
            .state_dir()
            .map_err(|err| StartError::Other(format!("{err:#}")))?;
        let keys = dir.join("keys.json");
        let key_state = tailscale::config::load_key_file(&keys, Default::default())
            .await
            .map_err(|err| {
                StartError::Settings(format!(
                    "{}: {err}; delete it to make this machine a new node",
                    keys.display()
                ))
            })?;
        restrict(&keys);
        let mut config = tailscale::Config::from(key_state);
        config.requested_hostname = Some(settings.name(role));
        config.client_name = Some(CLIENT_NAME.to_owned());
        let device = tokio::time::timeout(REGISTER, tailscale::Device::new(&config, auth_key))
            .await
            .map_err(|_| unreachable_control())?
            .map_err(|err| StartError::Other(err.to_string()))?;
        // Asked once a login is done, it answers that it is authorized.
        let mut said = None;
        loop {
            match tokio::time::timeout(REGISTER, device.is_authorized()).await {
                Err(_) => return Err(unreachable_control()),
                Ok(Err(tailscale::Error::AuthKeyRejected)) => {
                    return Err(StartError::Settings(
                        "the tailnet refused the key in musubi.tailnet.auth-key-file".to_owned(),
                    ));
                }
                Ok(Err(err)) => return Err(StartError::Other(err.to_string())),
                Ok(Ok(tailscale::AuthState::Authorized)) => break,
                Ok(Ok(tailscale::AuthState::NotAuthorized(url))) => {
                    let url = url.to_string();
                    if said.as_ref() != Some(&url) {
                        login(url.clone());
                        said = Some(url);
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
        let own = tokio::time::timeout(REGISTER, device.self_node())
            .await
            .map_err(|_| unreachable_control())?
            .map_err(|err| StartError::Other(err.to_string()))?;
        let id = own.stable_id.0.parse().map_err(|err: anyhow::Error| {
            StartError::Other(format!("this machine's node ID: {err}"))
        })?;
        Ok(Self {
            device,
            trust,
            id,
            ip: own.tailnet_address.ipv4.addr(),
        })
    }

    /// Returns once the device has failed to answer, or has changed its address, for long
    /// enough that it should be replaced, saying why.
    pub async fn unhealthy(&self) -> String {
        let mut since = None;
        loop {
            tokio::time::sleep(HEALTH).await;
            match answered(self.device.ipv4_addr()).await {
                Ok(ip) if ip == self.ip => since = None,
                Ok(ip) => return format!("its address changed from {} to {ip}", self.ip),
                Err(err) => {
                    let since = *since.get_or_insert_with(tokio::time::Instant::now);
                    if since.elapsed() >= UNHEALTHY {
                        return format!("it hasn't answered for minutes: {err}");
                    }
                }
            }
        }
    }

    /// Listens on the hub's port.
    pub async fn listen(&self) -> io::Result<tailscale::netstack::TcpListener> {
        answered(self.device.tcp_listen(SocketAddr::from((self.ip, PORT)))).await
    }

    /// Waits for the next connection to `listener`.
    pub async fn accept(
        &self,
        listener: &tailscale::netstack::TcpListener,
    ) -> io::Result<(Trusted<tailscale::netstack::TcpStream>, IpAddr)> {
        let stream = listener.accept().await.map_err(io::Error::other)?;
        self.trust.check()?;
        let from = stream.remote_addr().ip();
        Ok((self.trusted(stream), from))
    }

    /// Sends a datagram to `ip`, which has the node start a WireGuard handshake with it if it
    /// has no session, or only one from before it started, which the peer would keep sending
    /// on for minutes. A datagram, unlike a connect, leaves nothing behind.
    pub async fn wave(&self, ip: Ipv4Addr) -> io::Result<()> {
        let socket = answered(self.device.udp_bind(SocketAddr::from((self.ip, PORT)))).await?;
        answered(async {
            socket
                .send_to(SocketAddr::from((ip, PORT)), b"musubi")
                .await
                .map_err(Into::into)
        })
        .await
    }

    fn trusted<S>(&self, stream: S) -> Trusted<S> {
        Trusted {
            stream,
            trust: self.trust.clone(),
        }
    }
}

fn unreachable_control() -> StartError {
    StartError::Other(format!(
        "the tailnet's control server didn't register this machine within {}s; check the \
         network, and if it is set, musubi.tailnet.auth-key-file",
        REGISTER.as_secs()
    ))
}

/// Makes the node's key file readable by this user alone: it is created by tailscale-rs, as
/// the umask says, though in a directory only this user can enter.
fn restrict(keys: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(keys, std::fs::Permissions::from_mode(0o600)).ok();
    }
}

fn peer(node: &tailscale::NodeInfo) -> Peer {
    Peer {
        id: node.stable_id.0.clone(),
        key_expires: node.node_key_expiry.map(|at| at.timestamp()),
        relayed: node.derp_region.is_some(),
        tags: node.tags.clone(),
    }
}

#[async_trait]
impl Tailnet for Node {
    type Stream = Trusted<tailscale::netstack::TcpStream>;

    async fn owner(&self, ip: Ipv4Addr) -> io::Result<Option<Peer>> {
        self.trust.check()?;
        let node = answered(self.device.peer_by_tailnet_ip(IpAddr::V4(ip))).await?;
        self.trust.check()?;
        Ok(node.as_ref().map(peer))
    }

    async fn routed(&self, ip: Ipv4Addr) -> io::Result<Vec<Peer>> {
        self.trust.check()?;
        let nodes = answered(self.device.peers_with_route(IpAddr::V4(ip))).await?;
        self.trust.check()?;
        Ok(nodes.iter().map(peer).collect())
    }

    async fn connect(&self, ip: Ipv4Addr) -> io::Result<Self::Stream> {
        self.trust.check()?;
        let stream = self
            .device
            .tcp_connect(SocketAddr::from((ip, PORT)))
            .await
            .map_err(io::Error::other)?;
        Ok(self.trusted(stream))
    }
}

/// A stream from the node, which reads nothing once the node can't be trusted, even what it
/// had read as the trust was lost.
pub struct Trusted<S> {
    stream: S,
    trust: Trust,
}

impl<S: AsyncRead + Unpin> AsyncRead for Trusted<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.trust.check()?;
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.stream).poll_read(cx, buf);
        if poll.is_ready()
            && let Err(err) = this.trust.check()
        {
            buf.set_filled(before);
            return Poll::Ready(Err(err));
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Trusted<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.trust.check()?;
        Pin::new(&mut this.stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
