# Consistent controller policy publication

This source adds an explicit node-security profile and a controller publisher
from the existing rule/feed database to the shared signed policy authority.
It does not enable main startup, issue private credentials, deploy workers or
change production authentication/DNS.

## Frozen node settings

NodeSecurityFingerprint hashes an explicit reviewed projection of security
settings; operational and secret fields are excluded. Every Config field must be
classified, so adding a field requires review before profile creation works.
The projection covers proxy trust, origins/RP, CSRF, country/session/password/
rate-limit settings, telemetry trust and SMTP delivery settings. It never hashes
cookie/database/SMTP passwords, keyfile locations or bootstrap credentials.
Common cookie secret and auth keyring compatibility need their separate existing
fleet guards and cross-node acceptance; profile hashes do not distribute secrets.

WorkerPolicyOptionsForConfig requires the SQL authority, exact canonical SSO,
individual trusted proxy IPs, target headers and disabled out-of-band Cloudflare
config updates. Measure actual Docker SNAT and firewall peers before selecting
addresses. The controller owns copies of config slices, desired profiles and its
signing key, so later caller mutations cannot alter an in-flight publication.

## Source and transaction ordering

Capture reads rule metadata and active feed versions together in a repeatable-read
primary transaction. Read-only former-primary/standby sources are rejected even
when the separate head connection is writable. It never reads process-global
rule/feed caches. Rule/feed credentials, URLs, notes and audit identities are
omitted. Environment deny ties retain their existing precedence; public environment
rules inherit the managed Eworx feed. UI public rules must complete managed-default
bootstrap first; explicit opt-outs remain encoded. The default feed must be ready.
Existing active empty versions encode their prior explicit AcceptEmpty approval,
as guaranteed by the refresh transaction; database writers must preserve that rule.

GeoIP uses the trusted host-file opener after releasing the SQL snapshot, with
bounds and cancellation. Required country data cannot be omitted. Desired profiles
carry each node's GeoIP requirement so capture includes the aggregate requirement.
The complete document/blob list is deterministic and has a source digest separate
from signed revision/time.

Reconcile permits one local publication, reads its current authoritative base,
then captures fresh source data. It signs the next revision and calls transactional
publication with that exact expected base. A conflict returns; the next attempt
recaptures source and base instead of re-signing an older edit under a new revision.
New database edits during an upload remain pending for the next reconciliation.
Unchanged dependency identities plus active signing key preserve the current head,
including after restart. Key rotation publishes a new signed head for unchanged
content. Source writes must not be reported as fully applied before this head and
worker acknowledgments agree.

Every dependency independently passes exact size/hash and parsing checks. The last
validation callback performs complete rule/feed/profile/GeoIP cross-validation
inside the publication transaction, before head commit. Its private finalizer uses
the verified signed-head metadata and the fully validated map; outer bundle
verification confirms the same signed dependencies again. No runtime globals are
published while compiling. This avoids a second full GeoIP/feed compilation.

Use four independent verified-TLS source/head/payload/write pools, separate from
auth request budgets. Only the controller receives publisher grants/signing keys.
HA strict synchronization, fencing and leader routing are prerequisites, not
properties established by these local primary checks. No Docker socket/volume is
introduced; signing-key loading and physical host mount/secret guards remain
startup integration requirements.

## Validation and remaining integration

Real verified-TLS PostgreSQL tests cover deterministic private-data-free source,
source snapshot consistency during concurrent rule/feed changes, first/unchanged/
updated publication, cross-reference rejection before commit, caller ownership,
key rotation, read-only reused source connections, and default/country prerequisites.
Pure profile tests cover secret/location exclusion, security-setting changes and
explicit cluster configuration requirements. Vet/lint pass.

Next wire the role-aware startup, private mounted signer/profile files and a
bounded controller reconciliation loop; expose desired/applied state. Add enrolled
private API identities/registry, admin relay and durable events, then HA/fencing,
actual worker/frontend/browser/passkey and outage acceptance. Source publication
alone is not a live worker deployment.

Included CodeRabbit review raised a conditional concern about comment-only empty
feeds. The refresh path stores normalized bytes, so every accepted zero-prefix
version has zero payload bytes. A real refresh regression now submits upstream
comments with explicit AcceptEmpty, confirms persisted empty normalization and
successful approved-empty publication. No second full feed parse is needed.
Compiler finalization also receives and checks the staging/publication context.
