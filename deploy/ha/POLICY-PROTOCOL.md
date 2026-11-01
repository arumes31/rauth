# Worker policy verification and freshness primitives

This package is a source foundation. It is not wired into request handling and
is not a deployed worker. Host-file persistence/anti-rollback, HA head storage,
private mTLS transport, semantic compilers and atomic runtime publication remain
integration requirements. Do not enable workers based on these unit checks alone.

## Signed envelope v1

`internal/clusterpolicy` signs exact JSON bytes with Ed25519 using the domain
`rauth-worker-policy-v1`, key ID, cluster UUID and a positive int64 revision.
The envelope contains key ID, base64 payload and signature. The producer's exact
JSON encoding is required: unknown/duplicate fields, trailing documents, alternate
encodings, wrong cluster/key/domain or altered bytes fail closed. A bundle's
identity is revision plus SHA256 of the exact signed envelope. Never decode and
re-encode a stored envelope in a transport proxy.

Public verifier keys are copied and scoped to one cluster; at most three IDs
support controlled overlap during rotation. Signing keys must stay private on the
control service, separately from cookie/session keys. Loading/distributing those
keys and mTLS node identity/revocation are separate integration work.

The manifest names every dependency by kind, logical ID, SHA256 and byte length.
It contains exactly one policy/config object, up to 32 UUID-addressed normalized
feeds and optionally one GeoIP database. Logical IDs are not filesystem paths.
The policy compiler must check country/GeoIP requirements and every feed reference;
an omitted required dependency is an error. Trusted proxy configuration and exact
SSO application enrollment are policy/config inputs and must be versioned too.
No feed credentials, session keys or private node keys belong in these payloads.

Engineering bounds: policy <=1 MiB, each feed <=10 MiB, GeoIP <=256 MiB,
complete bundle <=512 MiB, manifest <=64 KiB and envelope <=96 KiB. Existing feed
prefix/count limits still apply during semantic compilation. A zero-byte feed is
only acceptable if the signed policy/version records an explicitly approved
empty update. Hash verification alone does not approve an empty denylist.

`VerifyBundle` requires every dependency plus a semantic validation callback.
It streams bounded content, verifies exact size and checksum, closes resources
on error, and returns a complete bundle only after all checks pass. Validators
stage parsed objects; they must reject invalid/trailing input and must never
publish global policy during staging. A valid partial prefix cannot bypass the
hash of the full content.

## Lease and activation contract

The HA write leader stores the current signed envelope/head. Read it through
verified TLS independently of the control service every 10 seconds. A control
notification or cached HTTP response is not proof of the current authoritative
head. Verify its signature before observing it.

`NewFreshness` takes the durable high-water revision/hash and starts unready.
`Restore` accepts a complete verified cache but cannot restore a prior wall-clock
lease. Persist a verified newer head before publishing its observation; an
indeterminate persistence failure is an operational error, never permission to
serve an older public rule. The monotonic in-process deadline is 120 seconds by
default, configurable from 10 through 300 seconds.

A matching authoritative head renews the lease even when the control host is down.
A newer head withdraws readiness immediately until the matching complete bundle
is activated. Lower revisions, same-revision/different-hash heads, and invalid
head evidence withdraw readiness. A failed SQL/head read does not renew anything;
a running worker can use only the remaining lease. Expiry is checked for each
request, including equality at the deadline, without depending on a timer tick.

Stage all files and parsed objects privately. Durably commit a verified current
bundle, atomically publish its immutable runtime pointer, then `Activate` it.
A head may change while staging or publishing. Admission must pin that exact
runtime bundle once and call `Status(bundle).Ready` before evaluating its rules.
The check binds the lease to the actual content, so a delayed/failed activation
cannot borrow the previous bundle's readiness. Use the same pinned immutable
objects for the ensuing request decision. A stale complete cache remains useful
for recovery; it cannot authorize traffic until it matches a fresh HA head.

After lease expiry or a new-head mismatch, affected public/identity validation
must return an operational 503. Never turn a missing or stale restriction into a
broader Public Access match. Private/session operations already fail closed on
SQL authority errors. Collector health is independent of policy/auth readiness.

## Durable-store integration still required

Use a mount-checked, pre-existing absolute host bind root (Pi3 below
/mnt/usb1/rauth). Create immutable content-addressed blobs and signed envelopes,
fsync before atomic state-pointer publication, and retain active/previous plus
one bounded staging generation. Persist high-water identity and current/previous
pointers with an exclusive writer lock. Reject symlink/traversal paths and corrupt
state. Handle disk-full, interrupted writes and ambiguous fsync/rename outcomes
without publishing unverified content or resetting the watermark. On restart,
verify signatures, all blob hashes and semantic compilation again, then require
a fresh authoritative head. Never trust a persisted deadline for readiness.

Make current manifests/dependencies durably available after control-host loss;
commit the HA head only after its payload availability is established. A newly
signed higher revision is the rollback mechanism. Do not overwrite a revision
or let an old signature remove a newer restriction. Implement and test this
store/control-plane contract before wiring these primitives into workers.
