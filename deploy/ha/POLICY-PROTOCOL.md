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

`NewFreshness` takes the configured verifier plus the durable high-water
revision/hash and starts unready. Verified evidence is bound to that exact trust
key set as well as the cluster; a keyring change requires re-verifying the cache
and current head through the replacement verifier.
`Restore` accepts a complete verified cache but cannot restore a prior wall-clock
lease. Withdraw readiness immediately upon a verified new head before waiting for
disk I/O. Durably record its watermark before activating a replacement; an
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

## Durable Linux host cache

The Linux `Store` now implements the local persistence primitive. It requires a
pre-existing private absolute bind root; it never creates an absent configured
root that could conceal a missing USB mount. Deployment still has to check the
expected mounted filesystem and use create_host_path:false on Docker binds.
Pi3 paths stay below /mnt/usb1/rauth. The store rejects symlink roots/directories
and acquires an exclusive lifetime writer lock. Its os.Root-relative operations
address blobs/manifests by validated hashes and never traverse supplied paths.

Content files are streamed to private temporaries, checked, fsynced and renamed
before the atomic state journal can reference them. One journal retains high-water
identity, active, previous and at most one staged generation. Staging needs every
hash and semantic compiler to succeed. A failed/cancelled/invalid download cannot
replace active data or accumulate its newly written orphan blobs. Old unused
artifacts are reclaimed before another staging generation is downloaded.

Head observations do not wait for network staging. A newer head arriving during
staging prevents its older result from committing. Artifact cleanup never removes
an in-progress head journal temporary. Root journal temporaries are reclaimed at
startup or during locked post-commit cleanup. Only exact generated hash/temporary
names are removed; unrelated operator files and directories are left alone.

An ambiguous state-rename/directory-fsync result requires reopening; the caller
must not infer the old pointer still won. Recovery verifies the journal and signed
manifests, loads and revalidates every active blob/semantic object, then requires
a fresh HA head. Missing journals beside artifacts are corrupt state, not a reason
to reset the watermark. No persisted deadline can restore readiness.

After a successful activation commit, reclamation failures are reported through
CleanupError, independently of commit success. Activation retry is idempotent;
a cleanup fault cannot falsely make a committed generation look uncommitted.
The next staging operation reclaims before allowing more downloads, bounding
retention even when cleanup is failing. Runtime health must expose this signal.

This component remains unwired. Make current manifests/dependencies durably
available after control-host loss and commit the HA head only after its payload
availability is established. Integrate Store and Freshness with the private mTLS
control plane and an atomic immutable runtime bundle pointer. Readiness must use
Status on the exact pinned bundle. A newly signed higher revision is the rollback
mechanism. Re-verification after trust-key rotation is mandatory; keep public
keys needed by retained active/previous/staged generations until those generations
have been safely retired. Never delete a required verifier key as a shortcut.

Native Linux tests cover writer exclusion, missing/private root checks, restart,
active/previous/staged bounds, failed staging, concurrent heads, symlink/corrupt
state, interrupted commit recovery, disk-full rename failure, journal-temporary
races and idempotent commit/cleanup separation. They also reject evidence verified
under a different key set even when its cluster or envelope identity matches.
These checks do not certify the physical disk's power-loss behavior, HA fencing,
transport identity, production filesystem mounts, or worker request admission.

An identical durable staged generation is re-verified and reused after restart;
it is not cleared/reclaimed before activation. Successful complete pre-stage
cleanup clears the previous cleanup health signal. Root temporary reclamation
holds the journal lock; network staging does not. A second writer reports the
explicit ErrStoreLocked sentinel. Changing the cluster UUID intentionally changes
the trust scope and invalidates cached policies; re-registration into a different
cluster requires its own verified state rather than reusing the old cache.
