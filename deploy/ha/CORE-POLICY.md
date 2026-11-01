# Concrete immutable policy and request admission

This source integration compiles signed worker policy data into RAuth's actual
rule matcher, prefix indexes and owned GeoIP reader. Context-aware validation,
session binding, password/passkey session issuance, policy preview and request
feed country enrichment use the same pinned generation when admission is enabled.
Production/main startup does not enable it yet; no workers are deployed here.

## Signed policy document

WorkerPolicyDocument schema 1 uses exact canonical JSON with no unknown/duplicate
fields or trailing documents. It declares the complete rule set, feed versions,
explicit empty-feed approvals, managed-default state, GeoIP requirement and
per-node security fingerprints. Every declared dependency must exist in the
verified complete manifest, and every validated blob must match its metadata.
Rules retain existing specificity, deny precedence and opaque WebDAV path behavior.

Feeds reuse existing byte, per-feed and combined prefix limits; missing references,
missing metadata, invalid versions and unapproved empty updates fail compilation.
The managed default cannot disappear from a document declaring it configured.
Selected-country rules or the caller's global-country requirement need a valid
Country/City GeoIP dependency. Each snapshot owns its own country cache and reader.
A returned rule copies its slices, preventing callers from mutating active policy.

The expected local node UUID/security fingerprint is frozen compiler input.
Startup still needs to derive that fingerprint from a reviewed explicit security
configuration projection, and the publisher must enumerate desired node profiles.
These opaque hashes are not secret/configuration distribution. Reject mismatches;
coordinate restarts for proxy/origin/security configuration changes instead of
mutating live config outside a policy generation. No automatic Cloudflare range
updater may bypass that coordination once cluster mode is activated.

GeoIP loading uses the library's FromBytes constructor over an exactly bounded
allocation (maximum 256 MiB); it does not create a Docker volume or temporary tree.
Budget for previous/pinned/staging generations, compiled feeds and database/HA
services. Validate actual Pi3 memory/latency under configured maximums before
rollout. Positive GeoIP tests currently use a country-reader stub; malformed real
MMDB rejection is tested. Actual valid Country/City file and resource benchmarks
remain acceptance gates.

## Request integration and resource lifetime

WorkerPolicyAdmission structurally accepts the coordinator's WithPolicy method.
It runs the downstream handler only with a fresh complete immutable snapshot,
adds it to request context for that callback and restores the original request
before releasing the pin. Unavailable admission clears identity headers and
returns a generic 503 with Retry-After; it never enters a handler or public bypass.
Original handler errors keep their status/body. Main startup must install it on
all public auth/UI routes once cluster mode is explicitly configured; liveness
and private control endpoints need their own defined routing.

RequestFeed stays outside admission so denied requests are also recorded. Admission
captures the telemetry source/country as plain values while its snapshot is pinned.
The feed never dereferences a retired reader after the callback returns or falls
back to another generation for captured metadata. Source mismatch gives unknown
country. Query/body/cookie material is still excluded and no NPM log reader exists.

Legacy requests without an installed worker admission path retain existing global
cache behavior. Enabling cluster mode must require the middleware, matching frozen
configuration, signed initial state and all existing shared-SQL/SSO/HA gates. These
helpers alone do not constitute a production activation or a safety fallback.

## Verification and remaining work

Pure compiler checks cover completeness/profile mismatches, canonical JSON,
explicit empty feeds, rule/metadata errors, missing country data, global-cache
isolation, copied rule slices and owned reader cleanup. HTTP checks exercise real
forward-auth handling with pinned feeds, anonymous opaque WebDAV paths, valid
session denial, protected paths, unavailable admission, inner errors and country
telemetry after release. Existing rule/semicolon and request-feed checks pass.

Finish the security fingerprint projection and policy publisher from a consistent
source snapshot, explicit runtime configuration/startup, worker role/admin relay,
private identity registry/APIs and host secret/mount guards. Then complete shared
HA/fencing, durable events, actual worker/NPM/browser/passkey and outage acceptance.

Included CodeRabbit review raised two conditional concerns. Legacy feed snapshots
are initialized in package init and worker feed snapshots are embedded non-nil
values. The managed Eworx ID is already a canonical UUID. An additional positive
regression compiles a configured managed-default bundle and verifies both listed
IP denial and an unlisted control. No compatibility relaxation is required.
