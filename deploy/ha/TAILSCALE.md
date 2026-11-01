# Dedicated Tailscale service

These files provision the private node identity. They do not deploy a complete
RAuth worker or satisfy HA acceptance on their own.

Use a unique RAUTH_NODE_NAME (for example rauth-hodus or rauth-pi3).
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
6. Recreate using only compose.tailscale.yml, verify the same identity/address,
   and remove the bootstrap key file from that host.
7. Test required peer connectivity and restrict ingress before attaching
   authentication/state services. Keep application TLS and node authorization.

The image is runtime read-only except the explicit state bind mount and tmpfs.
Do not copy a tailscale state directory between nodes. Never enable Funnel,
subnet routes or exit-node operation as an enrollment shortcut.

Set RAUTH_DOCKER_SUBNET only after checking host routes and Docker IPAM for overlap. Use this dedicated bridge; do not attach the Tailscale service to NPM’s shared network. Any later NPM-to-worker ingress must be separately scoped and validated.
