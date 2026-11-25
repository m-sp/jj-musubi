//! What the user sets for tailnets, in jj's config, and where nodes keep their keys.

use std::path::Path;
use std::path::PathBuf;

use jj_lib::config::ConfigGetResultExt as _;

use super::address::Allowed;
use crate::config;

/// The two nodes a machine may have: its daemon's, to reach hubs, and its hub's, which other
/// machines reach. Each is a device of its own on the tailnet, with keys of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Daemon,
    Hub,
}

impl Role {
    fn dir(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Hub => "hub",
        }
    }

    /// Where the node keeps its keys, and a hub the peers it has served, made if need be,
    /// readable by this user alone, as is each directory above it that musubi makes.
    pub fn state_dir(self) -> anyhow::Result<PathBuf> {
        config::create_state_dir()?;
        private_dirs(&config::state_dir()?, Some(self))
    }
}

/// `<state>/tailnet` and, for `role`, the directory beneath it, made one at a time, each
/// private whatever the umask: `create_private_dir` makes only the last component so, and
/// the socket beside them can be trusted only in a private directory.
pub fn private_dirs(state: &Path, role: Option<Role>) -> anyhow::Result<PathBuf> {
    let mut dir = state.join("tailnet");
    crate::socket::create_private_dir(&dir)?;
    if let Some(role) = role {
        dir.push(role.dir());
        crate::socket::create_private_dir(&dir)?;
    }
    Ok(dir)
}

/// `musubi.tailnet.*`, as a node starting reads them.
pub struct Settings {
    /// `musubi.tailnet.auth-key-file`: a file holding the key that adds the node to the
    /// tailnet, the first time. Without it, the node asks for a login in a browser.
    pub auth_key_file: Option<PathBuf>,
    /// `musubi.tailnet.name`: the name the node asks for, which isn't trusted for anything.
    pub name: Option<String>,
}

impl Settings {
    pub fn load() -> anyhow::Result<Self> {
        let config = crate::settings::user_config()?;
        let auth_key_file = config
            .get::<String>("musubi.tailnet.auth-key-file")
            .optional()?
            .map(|path| PathBuf::from(config::expand_home(&path)));
        if let Some(path) = &auth_key_file {
            anyhow::ensure!(
                path.is_absolute(),
                "musubi.tailnet.auth-key-file must be an absolute path or start with ~/"
            );
        }
        Ok(Self {
            auth_key_file,
            name: config.get::<String>("musubi.tailnet.name").optional()?,
        })
    }

    /// The auth key, if one is set. A key that is set but can't be read is an error, rather
    /// than a login in a browser that nobody may see.
    pub fn auth_key(&self) -> anyhow::Result<Option<String>> {
        let Some(path) = &self.auth_key_file else {
            return Ok(None);
        };
        let key = std::fs::read_to_string(path).map_err(|err| {
            anyhow::anyhow!(
                "can't read musubi.tailnet.auth-key-file, {}: {err}",
                path.display()
            )
        })?;
        let key = key.trim();
        anyhow::ensure!(
            !key.is_empty(),
            "musubi.tailnet.auth-key-file, {}, is empty",
            path.display()
        );
        Ok(Some(key.to_owned()))
    }

    /// The name the node asks for.
    pub fn name(&self, role: Role) -> String {
        if let Some(name) = &self.name {
            return name.clone();
        }
        let host = whoami::hostname().unwrap_or_else(|_| "machine".to_owned());
        let host: String = host
            .split('.')
            .next()
            .unwrap_or_default()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        match role {
            Role::Daemon => format!("musubi-{host}"),
            Role::Hub => format!("musubi-hub-{host}"),
        }
    }
}

/// What `musubi.tailnet.hub` says, which puts the hub on the tailnet.
#[derive(Debug, PartialEq, Eq)]
pub enum Switch {
    /// It is unset, or false: no node.
    Off,
    /// Whether it is on can't be told: jj's config couldn't be read, or the value isn't a
    /// boolean.
    Unknown(String),
    On,
}

impl Switch {
    pub fn read() -> Self {
        match crate::settings::user_config() {
            Ok(config) => Self::of(&config),
            Err(err) => Self::Unknown(format!("{err:#}")),
        }
    }

    fn of(config: &jj_lib::config::StackedConfig) -> Self {
        match config.get::<bool>("musubi.tailnet.hub").optional() {
            Ok(None | Some(false)) => Self::Off,
            Ok(Some(true)) => Self::On,
            Err(err) => Self::Unknown(format!("musubi.tailnet.hub: {err}")),
        }
    }
}

/// What `musubi.tailnet.allow` says: which of the nodes the tailnet's access controls let
/// through the hub admits.
#[derive(Debug)]
pub enum Allow {
    /// It isn't set: every node they let through.
    Unset,
    /// Whether it is set can't be told: jj's config couldn't be read.
    Unknown(String),
    /// It is set, to what it admits. An entry that isn't a node ID, or a value that isn't a
    /// list of strings, admits nobody, and says why.
    Set(Result<Allowed, String>),
}

impl Allow {
    pub fn read() -> Self {
        match crate::settings::user_config() {
            Ok(config) => Self::of(&config),
            Err(err) => Self::Unknown(format!("{err:#}")),
        }
    }

    fn of(config: &jj_lib::config::StackedConfig) -> Self {
        match config.get::<Vec<String>>("musubi.tailnet.allow").optional() {
            Ok(None) => Self::Unset,
            Ok(Some(entries)) => {
                Self::Set(Allowed::parse(&entries).map_err(|err| format!("{err:#}")))
            }
            Err(err) => Self::Set(Err(format!("musubi.tailnet.allow: {err}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A umask that lets others read new directories doesn't reach the ones under the state
    /// directory, whose socket couldn't be trusted otherwise.
    #[cfg(unix)]
    #[test]
    fn tailnet_directories_are_private_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt as _;
        let state = musubi_testutil::tempdir();
        let before = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o002));
        let made = private_dirs(state.path(), Some(Role::Hub));
        rustix::process::umask(before);
        let made = made.unwrap();
        for dir in [made.parent().unwrap(), &made] {
            let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
    }

    #[test]
    fn only_true_puts_the_hub_on_the_tailnet() {
        let config = |text: &str| {
            let mut config = jj_lib::config::StackedConfig::empty();
            config.add_layer(
                jj_lib::config::ConfigLayer::parse(jj_lib::config::ConfigSource::User, text)
                    .unwrap(),
            );
            Switch::of(&config)
        };
        assert_eq!(config(""), Switch::Off);
        assert_eq!(config("musubi.tailnet.hub = false"), Switch::Off);
        assert_eq!(config("musubi.tailnet.hub = true"), Switch::On);
        assert!(matches!(
            config("musubi.tailnet.hub = 'yes'"),
            Switch::Unknown(_)
        ));
    }

    #[test]
    fn a_list_that_is_set_but_unreadable_admits_nobody() {
        let config = |text: &str| {
            let mut config = jj_lib::config::StackedConfig::empty();
            config.add_layer(
                jj_lib::config::ConfigLayer::parse(jj_lib::config::ConfigSource::User, text)
                    .unwrap(),
            );
            Allow::of(&config)
        };
        assert!(matches!(config(""), Allow::Unset));
        assert!(matches!(
            config("musubi.tailnet.allow = []"),
            Allow::Set(Ok(_))
        ));
        assert!(matches!(
            config("musubi.tailnet.allow = 'nExample1CNTRL'"),
            Allow::Set(Err(_))
        ));
        assert!(matches!(
            config("musubi.tailnet.allow = ['laptop']"),
            Allow::Set(Err(_))
        ));
    }
}
