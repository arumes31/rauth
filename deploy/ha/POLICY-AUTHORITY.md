# Durable shared policy authority

`internal/clusterstate` and migration 0009 add PostgreSQL storage for complete
signed policy generations. They do not activate worker routes or provide HA by
themselves. Production is still Redis-authoritative for authentication; no SQL
cutover or worker deployment is implied by these source tests.

## Publication and availability

The control role compiles and signs a candidate with the existing scoped
`clusterpolicy` verifier. `Publisher.Publish` requires the exact expected base
revision/hash and the next contiguous revision. A per-cluster nonblocking
transaction advisory lock permits only one publication; a competing publisher
gets Busy, while a changed base gets Conflict. A retry after a lost commit ACK
returns success if the exact candidate is already current. Re-read Current after
any other ambiguous commit error; never issue a conflicting revision blindly.

One bounded transaction streams all dependencies in at most 1 MiB chunks,
checks their exact signed sizes/hashes and runs mandatory semantic validation.
It inserts the immutable manifest/dependency references, then changes the head.
Nothing is visible until that transaction commits. Failure of a source, parser,
checksum, close, cancellation, database write or commit never exposes a partial
head. Shared content is deduplicated per cluster and revalidated before reuse.
No external payload server is needed to survive loss of the control host.

Readers receive the exact stored signed bytes and verify the signature plus
revision/hash on each manifest read. OpenBlob first checks requested metadata
against that signed generation; reading to EOF checks chunk ordering, bounds,
length and checksum. Always close a stream. Its repeatable-read snapshot survives
retirement during a download, but a new fetch of a retired generation returns
NotFound: reconcile from Current and restart staging rather than serving stale
rules. Corrupt stored content is an operational failure.

Retention is active plus previous manifest and their shared content. Publication
atomically retires older references and unreferenced chunks. The largest allowed
bundle is 512 MiB; budget for two retained generations, an in-flight publication,
WAL/replication, bounded reader snapshots and backups. This is not a database disk
quota. Provision storage and WAL limits before activation; a USB mount check and
host bind mounts remain deployment requirements. Transfers/publication are bounded
at 120 seconds; callbacks must honor the supplied operation context and readers.
No parser/source callback may publish application globals while staging.

## Independent pools and authority checks

NewReader requires distinct verified-TLS head and payload pools. Head checks
have a three-second deadline; slow payload streams cannot occupy those reserved
connections. Use separate publisher write credentials/pool and do not share these
budgets with the authentication hot path. Workers receive SELECT-only roles for
these tables, no signing key or publisher write credentials. The Go read/write
capabilities supplement database grants; they do not replace them.

Every operation, including a reused connection, checks pg_is_in_recovery and
transaction_read_only. Verified hostname TLS is required on the primary and all
fallback connection configurations. A read-only replica cannot renew freshness.
Current is the only fresh-head read; Manifest and payload fetches are not lease
renewals. Integrate it with Freshness.ObserveHead/Store.RecordHead and pin the exact
complete runtime bundle for each request. SQL failures never renew a lease.

These checks cannot distinguish a writable isolated former leader. Strict
synchronous replication, quorum, safe promotion, effective fencing and verified
leader-aware routing that drops withdrawn connections remain mandatory. A single
PostgreSQL test fixture proves transaction behavior, not failover safety or RPO0.
Configure endpoint discovery and target_session_attrs=read-write independently of
the control host; validate TLS identities across actual leader changes.

## Remaining runtime work

Connect the publisher to atomic rule/feed/GeoIP compilation, make private APIs
use the enrolled mTLS gate, and give workers their mount-guarded cache plus
independent current-head reconciliation. Compile immutable request bundles before
activation; keep admin writes on the controller. No listener, credentials, grants,
HA services, DNS records or production source rules are changed by this module.

Actual verified-TLS PostgreSQL tests cover independent readers, multichunk
streaming/deduplication, head reads while staging or payload pools are occupied,
partial/corrupt/failed publication rollback, competing writers, lost-ACK retry,
retirement during an open stream, zero-byte signed feeds, cluster/revision
rejection and read-only reused connections. Empty-feed approval and all semantic
policy/feed limits remain the compiler's responsibility.

Validation evidence: all ten top-level PostgreSQL tests (21 including subtests)
pass natively on Linux against the disposable verified-TLS database. Windows
passes the full storage suite plus pure verifier/freshness checks; vet/lint pass
for both platform loads. Included CodeRabbit CLI review completed with no findings.
A test-only identity collision between two concurrent platform binaries was fixed
by assigning each process its own synthetic cluster UUID; production lock
semantics remain unchanged. No actual HA or worker admission is certified here.
