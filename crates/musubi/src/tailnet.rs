//! Reaching a hub over a tailnet, with tailscale-rs, as an alternative to ssh.
//!
//! A hub's address on a tailnet is `tailnet:<node ID>@<IPv4 address>`. The tailnet's access
//! controls, which a node enforces on every packet it receives, are a hub's whole access
//! control over it, as ssh's restricted key is over ssh: a hub admits whatever they let reach
//! it, or only the node IDs `musubi.tailnet.allow` lists, if it is set, and a machine talks
//! only to the node its hub's address names (`gate`).
//! `musubi_transport::heartbeat` tells a dead link, which tailscale-rs doesn't.
//!
//! Upstream's processes hold the nodes, and no other: on a machine, the daemon (`bridge`),
//! which commands and its own copies reach through a socket (`link`); on the hub's machine,
//! the hub (`host`). Each runs its node so that it can be thrown away whole (`supervise`).

#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(
        dead_code,
        reason = "only the client side is built where tailscale-rs doesn't run"
    )
)]
mod address;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod bridge;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod gate;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod host;
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(
        dead_code,
        reason = "only the client side is built where tailscale-rs doesn't run"
    )
)]
mod link;
mod logging;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod node;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod settings;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supervise;

pub use address::Address;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use bridge::Bridge;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use host::host;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use host::listens;
pub use link::Health;
pub use link::Link;
pub use link::check;
pub use link::prepare;
pub use logging::without_secrets;

use crate::socket::Socket;

/// Whether tailscale-rs runs here.
const SUPPORTED: bool = cfg!(any(target_os = "linux", target_os = "macos"));

/// Starts this machine's daemon, if `hub` is on a tailnet: it reaches tailnet hubs, for
/// commands too.
pub fn start_daemon(hub: &str, socket: &Socket) -> anyhow::Result<()> {
    if Address::parse(hub).is_some() {
        crate::block_on(crate::daemon::ensure(socket))?;
    }
    Ok(())
}

/// No daemon reaches tailnet hubs here.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct Bridge;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Bridge {
    pub fn listen() -> Self {
        Self
    }
}

/// No hub listens on a tailnet here.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn host(_: &crate::ui::Ui, _: std::sync::Arc<dyn musubi_transport::Transport>, _: bool) {
    std::future::pending().await
}

/// No hub listens on a tailnet here.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn listens() -> bool {
    false
}
