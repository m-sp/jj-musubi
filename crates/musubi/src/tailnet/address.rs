//! Node IDs, and a hub's address on a tailnet, `tailnet:<node ID>@<IPv4 address>`.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// What a hub's address on a tailnet starts with.
const SCHEME: &str = "tailnet:";

/// A node's stable ID, which the tailnet's control server gives it and no node chooses, as
/// each does its name. It outlasts the node's keys and addresses.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeId(String);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NodeId {
    type Err = anyhow::Error;

    /// Refuses what can't be one, as a name with a `-` or a `.`, an address or a tag, so
    /// that a list of those admits nobody and says why.
    fn from_str(id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            id.len() > 1 && id.starts_with('n') && id.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{id:?} isn't a tailnet node ID, like nExample1CNTRL; names, addresses and tags \
             can't be used"
        );
        Ok(Self(id.to_owned()))
    }
}

/// A hub's address: where it is and, as ssh's host key does, which node must be there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub node: NodeId,
    pub ip: Ipv4Addr,
}

impl Address {
    /// `hub`, as given to `--hub`, if it is on a tailnet.
    pub fn parse(hub: &str) -> Option<anyhow::Result<Self>> {
        let rest = hub.strip_prefix(SCHEME)?;
        Some(Self::parse_rest(rest).ok_or_else(|| {
            anyhow::anyhow!(
                "{hub:?} isn't a hub's tailnet address, which is like \
                 tailnet:nExample1CNTRL@100.64.0.1"
            )
        }))
    }

    fn parse_rest(rest: &str) -> Option<Self> {
        let (node, ip) = rest.split_once('@')?;
        Some(Self {
            node: node.parse().ok()?,
            ip: ip.parse().ok()?,
        })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}@{}", self.node, self.ip)
    }
}

/// The nodes that may use a hub: none, unless listed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowed(BTreeSet<NodeId>);

impl Allowed {
    /// The nodes `musubi.tailnet.allow` lists. One entry that isn't a node ID fails it all,
    /// rather than being passed over.
    pub fn parse(entries: &[String]) -> anyhow::Result<Self> {
        entries
            .iter()
            .map(|entry| entry.parse())
            .collect::<anyhow::Result<_>>()
            .map(Self)
            .map_err(|err: anyhow::Error| err.context("bad entry in musubi.tailnet.allow"))
    }

    pub fn admits(&self, node: &NodeId) -> bool {
        self.0.contains(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_names_the_node_as_well_as_where_it_is() {
        let hub = "tailnet:nExample1CNTRL@100.64.0.1";
        let address = Address::parse(hub).unwrap().unwrap();
        assert_eq!(address.node.to_string(), "nExample1CNTRL");
        assert_eq!(address.ip, Ipv4Addr::new(100, 64, 0, 1));
        assert_eq!(address.to_string(), hub);

        // ssh's destinations stay ssh's.
        for hub in ["devbox", "you@devbox", "/srv/hub", "ssh://devbox"] {
            assert!(Address::parse(hub).is_none(), "{hub}");
        }
        // Nothing that would leave the node unpinned.
        for hub in [
            "tailnet:100.64.0.1",
            "tailnet:@100.64.0.1",
            "tailnet:devbox@100.64.0.1",
            "tailnet:nExample1CNTRL@devbox",
            "tailnet:nExample1CNTRL@100.64.0.1:22",
            "tailnet:nExample1CNTRL@::ffff:100.64.0.1",
        ] {
            assert!(Address::parse(hub).unwrap().is_err(), "{hub}");
        }
    }

    #[test]
    fn only_node_ids_can_be_allowed() {
        for entry in [
            "",
            "n",
            "*",
            "laptop",
            "nas.example.ts.net",
            "tag:musubi",
            "100.64.0.2",
            "nExample1CNTRL ",
        ] {
            assert!(Allowed::parse(&[entry.to_owned()]).is_err(), "{entry:?}");
        }
        let allowed = Allowed::parse(&["nExample1CNTRL".to_owned()]).unwrap();
        assert!(allowed.admits(&"nExample1CNTRL".parse().unwrap()));
        assert!(!allowed.admits(&"nExample2CNTRL".parse().unwrap()));
        assert!(!Allowed::default().admits(&"nExample1CNTRL".parse().unwrap()));
    }
}
