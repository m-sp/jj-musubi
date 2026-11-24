//! Node IDs and tags, and a hub's address on a tailnet, `tailnet:<node ID>@<IPv4 address>`.

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

    /// Refuses what can't be one, as a name with a `-` or a `.`, or an address, so that a
    /// hub's address with one is refused, and a list with one admits nobody.
    fn from_str(id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            id.len() > 1 && id.starts_with('n') && id.bytes().all(|b| b.is_ascii_alphanumeric()),
            "{id:?} isn't a tailnet node ID, like nExample1CNTRL; names and addresses can't \
             be used"
        );
        Ok(Self(id.to_owned()))
    }
}

/// What a tag starts with.
const TAG: &str = "tag:";

/// A tag the tailnet's control server gives a node, `tag:<name>`. No node chooses its own:
/// the tailnet policy's `tagOwners` say who may give one, as with an auth key that carries
/// it. A tag stands for every node it is given, so admitting one admits nodes not yet made,
/// as ephemeral ones are each time they start.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tag(String);

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Tag {
    type Err = anyhow::Error;

    /// Takes only what Tailscale does: letters, digits and dashes after `tag:`.
    fn from_str(tag: &str) -> anyhow::Result<Self> {
        let name = tag.strip_prefix(TAG).unwrap_or_default();
        anyhow::ensure!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "{tag:?} isn't a tailnet tag, like tag:musubi"
        );
        Ok(Self(tag.to_owned()))
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

/// The nodes that may use a hub: none, unless listed, by node ID or by a tag they have.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Allowed {
    nodes: BTreeSet<NodeId>,
    tags: BTreeSet<Tag>,
}

impl Allowed {
    /// The nodes and tags `musubi.tailnet.allow` lists. One entry that is neither a node ID
    /// nor a tag fails it all, rather than being passed over.
    pub fn parse(entries: &[String]) -> anyhow::Result<Self> {
        let mut allowed = Self::default();
        for entry in entries {
            let added = if entry.starts_with(TAG) {
                entry.parse().map(|tag| allowed.tags.insert(tag))
            } else {
                entry.parse().map(|node| allowed.nodes.insert(node))
            };
            added.map_err(|err| err.context("bad entry in musubi.tailnet.allow"))?;
        }
        Ok(allowed)
    }

    /// Whether `node`, which has `tags`, may use the hub.
    pub fn admits(&self, node: &NodeId, tags: &[Tag]) -> bool {
        self.nodes.contains(node) || tags.iter().any(|tag| self.tags.contains(tag))
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
    fn only_node_ids_and_tags_can_be_allowed() {
        for entry in [
            "",
            "n",
            "*",
            "laptop",
            "nas.example.ts.net",
            "100.64.0.2",
            "nExample1CNTRL ",
            "tag:",
            "tag:*",
            "tag:a b",
            "tag:sandbox.example",
            "Tag:musubi",
            "musubi",
        ] {
            assert!(Allowed::parse(&[entry.to_owned()]).is_err(), "{entry:?}");
        }
        let node = |id: &str| id.parse::<NodeId>().unwrap();
        let tags =
            |tags: &[&str]| -> Vec<Tag> { tags.iter().map(|t| t.parse().unwrap()).collect() };

        let allowed = Allowed::parse(&["nExample1CNTRL".to_owned()]).unwrap();
        assert!(allowed.admits(&node("nExample1CNTRL"), &[]));
        assert!(!allowed.admits(&node("nExample2CNTRL"), &[]));
        assert!(!allowed.admits(&node("nExample2CNTRL"), &tags(&["tag:musubi"])));
        assert!(!Allowed::default().admits(&node("nExample1CNTRL"), &tags(&["tag:musubi"])));

        // A tag admits whichever node has it, and only it.
        let allowed =
            Allowed::parse(&["nExample1CNTRL".to_owned(), "tag:sandbox-1".to_owned()]).unwrap();
        assert!(allowed.admits(&node("nExample2CNTRL"), &tags(&["tag:ci", "tag:sandbox-1"])));
        assert!(!allowed.admits(&node("nExample2CNTRL"), &tags(&["tag:sandbox"])));
        assert!(allowed.admits(&node("nExample1CNTRL"), &[]));
    }
}
