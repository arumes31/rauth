# Private node transport primitives

`internal/clustertransport` is source infrastructure, not an enrolled/deployed
worker API. It does not load private keys, issue certificates, implement the
node registry, start listeners, wire application routes or change the tailnet.
Those remain deployment/integration gates.

## Identity and permissions

Use a dedicated private node-API CA. Keep its signing key outside application
containers; use separate browser/public and database/DCS certificate identities.
Every node has its own persistent private key and leaf certificate with exactly
one URI SAN:

```
spiffe://rauth/<cluster-uuid>/node/<node-uuid>
```

UUIDs are canonical lowercase. CommonName, DNS SAN, request headers, submitted
node_id fields and browser RAuth cookies never substitute for this identity.
Certificates must cover their actual service Tailscale IPs as IP SANs too.
Local key/certificate matching, private CA trust, identity and validity are
checked before TLS configuration is returned. Runtime provisioning must first
validate host-file ownership/modes, use host bind mounts and mount-guard the USB
node's /mnt/usb1/rauth tree. No keys belong in policy/feed payloads or logs.

Server TLS requires TLS 1.3 plus a verified client certificate. Client TLS checks
the private CA, hostname, exact expected server node and 1-2 enrolled SPKI pins.
Pins and CA pools are copied. Two pins support a deliberate rotation overlap;
remove old pins only after the fleet has acknowledged replacement configuration.

Gate chooses a fixed server-side scope: policy:read, events:write, admin:relay
or status:read. There is no wildcard permission. Its Authorizer is called for
every HTTP request, including requests reusing a TLS connection. That callback
must check current enrollment/revocation, public-key pin, assigned service IP
and permission against the authoritative registry; a handshake's positive result
must not become a permanent permission cache. Honor the supplied three-second
context deadline. Denied peers get 403; backend failures get a generic 503.

Certificate-chain dates are rechecked for each request. Operation context also
expires at the peer certificate's deadline. Long streams must additionally
revalidate permissions or finish within a bounded request lifetime. Endpoint
handlers obtain PeerForScope(request.Context(), expectedScope) and use that
verified node ID, never a client-supplied node ID. The context proof is valid
only for the exact scope authorized by the gate.

## Dedicated service addresses

Private endpoints/listeners accept only canonical literal IPv4 100.64.0.0/10 or
IPv6 fd7a:115c:a1e0::/48 addresses and an explicit port. Wildcard, loopback, public
IP, DNS, credentials, path/query/fragment and mapped-address ambiguity are rejected.
The deployment must use the node's actual dedicated Tailscale service address,
not the host daemon's address, and still enforce peer/port ACLs and local firewall
boundaries. Range membership alone does not enroll a peer.

Always use NewClient for outgoing private RPCs. Its socket binds LocalServiceIP,
which must be a certificate-covered service Tailscale address. A missing address
fails dialing; it does not fall back to the host's default interface. The client
pins a single enrolled HTTPS destination, overwrites HTTP Host, disables environment
proxies/compression and installs no browser cookie jar. Alternate destinations,
query credentials, ambiguous paths and redirects cannot move traffic elsewhere.
A redirect response is returned without following Location so admin forwarding
can preserve normal browser redirects while policy fetchers reject non-200 data.
Timeouts are bounded; the default is 60 seconds and the maximum 120 seconds.

ClientTLS alone provides cryptographic settings; it does not provide endpoint,
source-binding or HTTP redirect/proxy safeguards. Private RPC implementations must
use the complete client and server gate, with body/header limits and timeouts.
Private routes belong on their own service-IP TLS listener, not the public auth
listener or a host-published wildcard port. Workers must not gain Docker sockets.

## Verification and remaining gates

Real mutual-TLS loopback tests cover valid identity/scope, spoofed headers/cookies,
revocation on an existing connection, expired credentials, no CommonName fallback,
wrong CA/hostname/node/key, TLS 1.2 rejection, endpoint/source constraints, alternate
URL and redirect rejection, and private diagnostic response handling.

These are local protocol tests. Enroll real host-mounted certificates, implement
authoritative registry authorization and private API handlers, validate Tailscale
source addresses on the wire, test key/revocation rotation, and exercise namespace
owner/dependent-service restart before worker rollout. The current application
still has no worker-role/control transport activation from this package.

Local credential checks include the intermediate certificates supplied in the
TLS pair (up to eight certificates total). Intermediates never substitute for
the configured root trust. An actual mutual-TLS test covers root -> intermediate
-> node leaf on both ends, plus missing/malformed/untrusted chain rejection.

The socket dialer independently rejects any address other than the configured
literal endpoint. Do also rebuilds the outgoing URL from the owned enrollment
and validated RPC path. Gosec G704 treats the caller-controlled path as a complete
URL taint and cannot model these constraints; its narrow call-site annotation
records the endpoint, socket, proxy and redirect controls. Tests cover rejection
both before Do dials and directly at the actual socket dialer. No project-wide
rule or security check is disabled.
