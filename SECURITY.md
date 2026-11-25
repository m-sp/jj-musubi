# Security

Report a vulnerability privately, through
[GitHub](https://github.com/bos/jj-musubi/security/advisories/new), not in a public issue.
Only the latest release gets fixes.

## What jj-musubi protects

Anyone who can reach a hub can read and write every hive on it. So a hub listens only on a
local socket that only its own user can reach, and other machines come in over ssh, as that
user, with a key allowed only to run `musubi hub connect`.

A hub can also be put on a Tailscale tailnet, with `musubi.tailnet.hub`
([setup](docs/guides/setup.md#or-connect-over-a-tailnet)). Then the tailnet's access controls
are the hub's whole access control over it: every device they let reach the hub's device on
TCP port 7575 gets the same full access to every hive as an ssh key would. Tailscale's default
policy lets every device on the tailnet reach every other, so until it is changed, that is
every device on the tailnet. A device stands for the keys in `tailnet/daemon/keys.json` in
its machine's state directory: whoever has them is that machine. To shut out a lost or
compromised machine, remove its device in the tailnet's admin console, or change the access
controls so that it no longer reaches the hub's. The hub's device enforces them on every
packet it receives, so a change applies once the tailnet sends it there. `musubi.tailnet.allow`
narrows that further, to the device IDs it lists, which the hub rereads every few seconds:
taking an ID out ends that machine's connections within seconds. The tailnet link is carried
by tailscale-rs, which runs inside jj-musubi and hasn't had an independent security audit.
