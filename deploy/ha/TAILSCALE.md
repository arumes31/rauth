# Dedicated Tailscale service

These files provision the private node identity. They do not deploy a complete
RAuth worker or satisfy HA acceptance on their own.

Use a unique RAUTH_NODE_NAME (for example rauth-node-a or rauth-node-c).
RAUTH_STATE_ROOT must be an absolute, explicitly checked host directory;
pi3 must use /mnt/usb1/rauth. Verify that /mnt/usb1 is actually mounted before
creating any directories. Persist all cluster data with explicit host bind
mounts; do not introduce Docker named/anonymous volumes.

1. Pin RAUTH_TAILSCALE_IMAGE to the digest of the official Tailscale image
   validated for the target CPU architecture.
2. Create RAUTH_STATE_ROOT/tailscale on the intended filesystem.
3. Put the supplied enrollment key in a root-only external file and set
   RAUTH_TS_AUTHKEY_FILE to its path. Never put its value in an env file or Git.
4. Enroll with both compose files:
   docker compose -p rauth-ha -f compose.tailscale.yml -f compose.tailscale-bootstrap.yml up -d
5. Verify BackendState=Running and record the node's distinct tailnet address.
6. Before cleanup, record node-key expiry from status and the tailnet device
   policy. Require expiry disabled for the service identity, or an owned renewal
   procedure and expiry alert. An absent expiry field alone is not proof.
7. Recreate using only compose.tailscale.yml, verify the same identity/address,
   and remove the bootstrap key file from that host.
8. Test required peer connectivity and restrict ingress before attaching
   authentication/state services. Keep application TLS and node authorization.

The image is runtime read-only except the explicit state bind mount and tmpfs.
Do not copy a tailscale state directory between nodes. Never enable Funnel,
subnet routes or exit-node operation as an enrollment shortcut.

Set RAUTH_DOCKER_SUBNET only after checking host routes and Docker IPAM for overlap. Use this dedicated bridge; do not attach the Tailscale service to NPM’s shared network. Any later NPM-to-worker ingress must be separately scoped and validated.

## Node-key lifetime and renewal

Auth-key expiry and node-key expiry are different: expiration of the enrollment
key does not itself remove an enrolled node. Tagged devices normally enroll
with node-key expiry disabled; verify the device policy rather than assuming it.
If ordinary status omits the field, inspect the live control-map SelfNode with an
in-memory parser and verify its representation against the pinned client schema.
For the validated client, [Node.KeyExpiry](https://github.com/tailscale/tailscale/blob/27047635f237d1f3e0b08c0f487674757f30d2f7/tailcfg/tailcfg.go#L389)
is a zero-omitted time whose zero value explicitly means no expiry. Require the
matching stable node ID, an authorized non-cached control map, and the expected
tags. Record only filtered expiry evidence; never persist the complete netmap,
node keys or peer profiles. This is stronger evidence than an absent field in
the optional status PeerStatus object. Revalidate schema/serialization when
changing the image digest.
See [Tailscale key expiry](https://tailscale.com/docs/features/access-control/key-expiry)
and [auth keys](https://tailscale.com/docs/features/access-control/auth-keys).

If expiry remains enabled, monitor it, alert at 30 days remaining and renew one
node at a time. First drain that worker and, for a state node, verify healthy
quorum/replication and fencing. Establish independent host/console access: forced
reauthentication can interrupt the very tailnet connection used to administer it.
Obtain a currently authorized enrollment key in a root-only host file, mount it
only for the bootstrap operation, and use the official forced-reauthentication
flow. Never log its value or assume the old enrollment key remains valid.
Preserve that node's state directory; do not clone or delete its identity.
Verify Running, the expected identity/addresses, expiry policy, ACL/TLS peer
connectivity and the dependent shared-network-namespace services before returning
traffic. Recreate key-free, verify again, then remove the transient secret file.

## Application topology gate

The bootstrap files provision identity only. The worker overlay must use
network_mode: service:tailscale so cluster egress uses this service's identity.
State services on that node share the same namespace and bind their private
listeners to the node's tailnet address. Cluster APIs still require TLS and
per-node authorization; Tailscale membership alone does not grant API access.

Keep the Tailscale service on its isolated bridge. Scope local NPM ingress with
a published auth port bound only to the NPM bridge's host gateway, plus firewall
rules permitting the NPM container source and that one port. Do not publish it
on all host interfaces or attach the Tailscale service to NPM's shared network.
The worker exposes only auth routes there and rejects admin mutations. Private
cluster/state ports have no host publication. Verify every listener, route,
source restriction, peer ACL, shared-namespace restart and health path before
using the service addresses; a bridge by itself creates no forwarding path.


## Firewall backend compatibility

Keep netfilter enabled. A kernel that supports only nftables can report a
legacy-iptables initialization warning even while the tailnet identity is
Running. Set `RAUTH_TAILSCALE_FIREWALL_MODE=nftables` for that node, recreate the
key-free service, verify the same identity, empty health warnings and actual
peer connectivity. The default remains iptables for existing compatible nodes.
This selects the backend inside the dedicated container namespace; it does not
change Docker's or the host's firewall configuration.

The official [Tailscale firewall-mode documentation](https://tailscale.com/docs/features/firewall-mode)
identifies `TS_DEBUG_FIREWALL_MODE` as a temporary interface. Keep the image pinned
and revalidate the setting, rules and health before changing the image digest.
Do not silence this warning by disabling netfilter or granting host-network or
host-module privileges to the service.
