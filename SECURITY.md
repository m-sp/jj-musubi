# Security

Report a vulnerability privately, through
[GitHub](https://github.com/bos/jj-musubi/security/advisories/new), not in a public issue.
Only the latest release gets fixes.

## What jj-musubi protects

Anyone who can reach a hub can read and write every hive on it. So a hub listens only on a
local socket that only its own user can reach, and other machines come in over ssh, as that
user, with a key allowed only to run `musubi hub connect`.

A hub can also be put on a Tailscale tailnet, with `musubi.tailnet.allow`
([setup](docs/guides/setup.md#or-connect-over-a-tailnet)). Then a machine whose tailnet device
ID the list names gets the same full access to every hive as an ssh key would. That ID stands
for the keys in `tailnet/daemon/keys.json` in the machine's state directory: whoever has them
is that machine. To shut out a lost or compromised machine, take its ID out of
`musubi.tailnet.allow` on the hub's machine, which ends its connections within seconds;
removing the device in the tailnet's admin console alone may not reach the hub. The tailnet's
access controls are a second fence: let only the machines that need it reach the hub's
device on TCP port 7575. The tailnet link is carried by tailscale-rs, which runs inside
jj-musubi and hasn't had an independent security audit.
