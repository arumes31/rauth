# Active-active implementation checkpoint

The complete approved goal remains active. Live host identities, addresses,
operational paths and detailed evidence remain in a private deployment inventory.
No secrets belong in Git.

- Country and IP-feed implementation merged in PR #778 after functional, Linux
  race, build and security checks passed. The advisory scan runs separately.
  This includes the managed Eworx default, rule inheritance/explicit opt-out,
  pre-session blocking, bounded last-good snapshots, admin menu and URL/IP preview.
- Real-source integration denied a listed IP. The production snapshot has 4,827
  entries. The exact reviewed release is deployed and healthy after backup; a
  listed IP receives 403 and an unlisted control receives anonymous 200. All 73
  before/after root/admin/WebDAV probes match.
- Original-client-IP proxy migration is applied to the existing integrations,
  including the RAuth login/admin/profile paths. All 73 before/after root/admin/
  WebDAV probes matched. Syntax/render tests and RAuth application-log probes
  verify spoof rejection through LAN, Tailscale and actual public Cloudflare
  routes. A forged Cloudflare visitor header was rejected at the edge.
- Dedicated persistent Tailscale identities are enrolled on five hosts and passed
  key-free restart. All 20 directed IPv4 kernel/discovery checks and two state-node
  IPv6 checks passed. Expiry-disabled policy was verified from each authorized
  live control map against the pinned client schema. Identity bootstrap alone is
  not a complete worker deployment.
- SQL sessions, encrypted one-use proofs, atomic enrollment/invitation flows and
  global security counters/replay markers are implemented separately in draft
  PR #780. Real PostgreSQL and no-Redis adapter tests pass; callback cancellation
  and browser-bound registration regressions pass; lint and vet report no issues.
  SQL family listing/revocation/IP queries and atomic step-up grants now also pass
  their real-database tests. Stable keyed aliases preserve logout across token
  replacement and grace cleanup. Primary authorization/logout/binding/grant adapters now pass the full local
  suite with SQL/no-Redis tests. Admin/profile now use the selected authority
  for paginated metadata and owned revocation, with non-bearer handles in both
  modes. Backend errors are visible. Committed credential changes keep their
  audit/notification even if retaining the caller fails. A real-database
  regression also prevents credential restamp from reviving retired siblings.
  Runtime migration remains pending; SQL authority is not enabled in production.
- CodeRabbit's included milestone reviews were used and their verified findings
  fixed. No paid reviews were started; honor quota/cooldown reports.

- The third state candidate passed a mount-guarded USB fsync/throughput probe.
  Its test tree, containers and image were removed. This is performance evidence,
  not a quorum, fencing, durability or failover acceptance claim.

Remaining work: finish the session/grant adapters and all call sites, runtime
selection and readiness, cross-node and cross-domain flows, HA quorum and
storage/fencing gates, dedicated networking and node lifecycle checks, signed
persistent policy synchronization with bounded freshness, durable RAuth-only
event forwarding, worker/public-rule rollout, and controlled outage tests.

Preserve existing login requirements and application-native challenges. All
persistence uses host bind mounts. The third state host's application data must
remain below /mnt/usb1/rauth after verifying that filesystem is mounted. No HA
routing or DNS activation is implied by source or identity-only milestones.
