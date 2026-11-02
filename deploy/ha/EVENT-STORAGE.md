# Durable local buffers and HA PostgreSQL history

The selected topology is synced bbolt on every RAuth node, forwarding to a central collector backed by a separate event database on the planned Dockerized HA PostgreSQL cluster. SQLite is not used. Extra PostgreSQL servers on workers are not required.

This component provides the local store/queue, bounded event schema and central ledger. Runtime configuration, mTLS HTTP delivery, persistent management SSE and node status integration are subsequent work; this component alone does not enable production event forwarding.

## Local bbolt

An existing private host directory is required. Every path component is opened without following symlinks; files must be regular, private, singly linked and on the directory's device. Runtime mount checks must precede opening it. Missing directories are not created. bbolt holds an exclusive file lock, uses synced commits, and enforces a hard MaxSize on the file. A 24-hour retention limit and conservative accounted-payload budget reserve space for indexes, free pages and copy-on-write commits within the default 2 GiB file cap.

A 1,024-entry queue never waits for disk/network I/O. The background writer assigns stable UUIDs before persistence and retries the same content. Exact-ID acknowledgments delete only delivered records. Queue overflow and permanent batch rejection produce counted gap markers. Evicting a marker carries its represented count and unknown-loss flag forward. Cumulative per-node loss/restart totals let readers recognize rolled-over history without summing it twice; rolling a marker does not increment those totals again. Unclean restart reports possible loss of the unpersisted queue without claiming an exact crash-loss count. Indexed time ranges separate recent live events from catch-up.

## Central PostgreSQL

The collector uses its own credentials and pool, with at least three connections: one actor lock and bounded read/write capacity. It never borrows the authentication pool. Mutations require a writable primary with fsync and full_page_writes enabled and force synchronous_commit=on. HA promotion, synchronous replication and fencing remain deployment responsibilities.

An operator runs Migrate and Provision. The operator owns the tables and needs no superuser/BYPASSRLS privilege. The runtime role is a non-owner, with schema USAGE, SELECT on event_schema_version, SELECT/UPDATE on event_ledgers and SELECT/INSERT/DELETE on request_events. Enabled row security and a role-bound foreign key prevent access to another collector ledger. Runtime credentials have no CREATE, migration or provisioning privilege. Workers need no event-database credentials; mTLS ingestion attributes records to enrolled node identities.

An advisory actor lock and durable owner token fence replaced collectors. Per-ledger cursor allocation commits with content; rollback does not create a false cursor gap. Identical retries are deduplicated and conflicting identity reuse is rejected. An ingestion acknowledgment is returned only after commit. Central retention defaults to seven days and 8 GiB of accounted payload, configurable within bounds. Retention deletes only the necessary oldest records in small transactions and preserves a pruning watermark.

Accounted payload is not physical PostgreSQL disk usage. Tables/indexes, dead tuples, temporary files, WAL, logs and backups need separate capacity protection. Sharing the HA instance also shares WAL/CPU/I/O with authentication. Rate/connection budgets and saturation testing are required; a separate database alone does not provide physical isolation.

All persistence uses explicit host bind mounts, with Pi3 files under /mnt/usb1/rauth and the expected host filesystem UUID checked before creation/start. A missing USB mount must never redirect writes to the system disk. GeoIP lookup remains independent and uses only the master's local database and verified worker copies.

Tests cover privacy, duplicate/lost ACK, conflict/identity rejection, restart cursors, native local filesystem guards and actual process termination, overflow/permanent-error recovery, retention, actor fencing and ordinary PostgreSQL runtime/operator roles. A trigger-injected SQLSTATE 53100 checks rollback/no ACK; actual disk exhaustion, host-loss and resource acceptance remain integration gates. These are RAuth decisions only; no NPM log ingestion or security-audit retention changes.
