# Active implementation checkpoint

Updated: 2026-11-01, Europe/Vienna.
Goal remains active: implement the complete approved plan, deploy workers on the other NPM hosts, configure current public pages, and verify all acceptance/failover requirements. This checkpoint is not a completion claim.

## Authoritative source

- Worktree: C:/DR/worktrees/rauth-ha-design
- Branch: feat/public-access-policies-ha
- Country-policy milestone: 272179ed9ba57dd24a2646d57cc5ee9b579ec6fc
- Approved design/plan remain under docs/superpowers/specs and plans.
- User additions: dedicated per-node Tailscale services; pi3 is the third HA-node candidate; all pi3 RAuth data below /mnt/usb1/rauth; all RAuth persistent files must use explicit host bind mounts, no named/anonymous Docker volumes.
- Keep Go. The user asked whether Rust would be better; the recommendation was to continue Go, not a language-rewrite authorization.

## Implemented and tested

Country policy engine, persistence, checkbox/search admin controls, pre-session enforcement, private-network option and legacy defaults are implemented. The IP feed registry, bounded HTTPS fetch/parser, immutable last-good snapshots, rule attachments, separate admin menu and effective URL/IP preview are now implemented in source. Production still runs the prior release.

A full go test ./... -count=1 -timeout 10m run passed with disposable PostgreSQL. CodeRabbit then found two scope regressions and encoding issues; these were fixed, and the relevant policy/bypass/handler/template tests plus go vet passed afterward. The major regression tests prove restricted rules do not lock out unrelated applications. Country/feed desktop and mobile visual QA has passed; remote CI for the combined milestone is the next publishing gate.

CodeRabbit completed one included review (4 findings); no paid credits were used. Do not repeatedly review this unchanged milestone.

## Live infrastructure progress

Hodus dedicated Tailscale service:
- /opt/rauth/compose.tailscale.yml, project rauth-ha, container rauth-tailscale.
- Official image pinned to tailscale/tailscale@sha256:ed6480b33c6eb67c9cbd203ed42b9fb57e361986725b6856def71b7a3d9e276c.
- Identity rauth-hodus, IPv4 100.72.210.48, IPv6 fd7a:115c:a1e0::e62a:d231.
- Running, no Tailscale health warnings, same identity after a key-free restart.
- Persistent state bind-mounted at /opt/rauth/tailscale; no Docker volumes and no published ports.
- Dedicated bridge rauth-ha_rauth-local, verified non-overlapping 10.253.42.0/28. Not attached to NPM shared network.
- The bootstrap key is no longer mounted and its hodus file has been removed. The user-provided key remains only in the ACL-protected local external secret file; do not print it.
- Runtime /tmp and /run use tmpfs; /run was required for iptables lock files.
- /opt/rauth/tailscale-enrollment-verification.json is the server-side evidence.

Automatic approval review rejected attaching this new service to NPM's existing network due to broadened container access. That action was not performed. A separate non-overlapping bridge was used successfully instead; this is no longer a blocker. Later NPM-to-worker ingress still needs a narrowly scoped design and verification.

Production RAuth is still the prior 52cd1a2 release. No new worker applications, public rules, HA database nodes or DNS changes have been deployed for this goal yet.

## Inventory evidence and access

Authenticated Portainer agent access is available via hodus's existing service identity. Helper /root/rauth-portainer-inventory.py reads existing keys locally and honors saved TLS settings. Never print/copy the private keys or signature headers.

- oracle-ubnt-1 (endpoint 19): about 1 GB RAM; 3 enabled public NPM proxy entries, no RAuth/Basic Auth/IP ACL in inspected routes.
- massivgrid-alpine-1 (endpoint 27): about 1 GB RAM; no proxy entries loaded by successful nginx -T.
- nl-bluehost-ubnt-1 (endpoint 41; SSH alias orderotto-dev): about 8 GB total RAM but only ~0.9 GB available in current sample; 9 public NPM entries / 10 hostnames.
- hodus: ~20 GB total RAM, ~9 GB available, ~22 GB free on Docker root in the sampled preflight.
- pi3 (endpoint 20): ARM64, 4 cores, 4,246,601,728 bytes RAM, 2,693,070,848 bytes available in sample. Live probe confirmed /mnt/usb1 is an ext4 USB mount on /dev/sda1 with 147,653,619,712 bytes available. TUN exists. Its fstab also declares /mnt/usb1 ext4.
- The read-only temporary pi3 probe container and image were removed. No probe data was written to pi3 USB.

Local evidence:
- C:/DR/rauth-deployment/pi3-storage-preflight.json
- C:/DR/rauth-deployment/npm-inventory-oracle-massivgrid.json
Server evidence:
- /root/rauth-pi3-storage-preflight.json
- /root/rauth-ha-npm-inventory.json

Pi3 fsync/latency, final resource budgets, fencing and location/failure-domain checks remain incomplete. The current design targets loss of one host; do not claim three independent sites.

## Test resources currently left running for continued implementation

- Hodus container rauth-ha-policy-test-pg, label codex.task=rauth-ha, postgres:18-alpine.
- It now uses an explicit bind /root/rauth-ha-tests/postgres -> /var/lib/postgresql. The initial anonymous test volume was verified removed.
- Bound only at 127.0.0.1:32769 on hodus.
- Local hidden SSH tunnel PID 19028, localhost 55435 -> hodus localhost 32769; PID record C:/DR/rauth-deployment/ha-policy-test-tunnel.pid. Verify PID/command line before stopping/reusing.
- RAUTH_TEST_DATABASE_URL for tests uses this isolated disposable database. See current test launch history; no production data is used.
- Full regression process and CodeRabbit review have completed; do not treat those old handles as running.
- Current test tunnel/container are useful for next implementation stages, but verify their live state before reuse.

## Next work

1. Publish the reviewed country/feed milestone and verify remote CI; bootstrap the default feed and verify original-client-IP authorization before production activation.
2. Implement transactional SQL auth state, cross-node flows and cross-domain SSO per approved plan.
3. Provision dedicated Tailscale services on the remaining RAuth/state nodes with unique persistent state. Check the supplied key's reuse/expiry during enrollment; never clone state directories.
4. Build/test HA PostgreSQL+quorum and required worker roles/control/event collection with host bind mounts.
5. Deploy worker applications, preserve existing login requirements, add current public host aliases, and test all routing/auth/failover acceptance.
6. Only after all gates pass, merge/publish/deploy exact reviewed releases and apply health-aware routing.


## Default-feed milestone and NL enrollment

The user requested https://blocklist.eworx.at/api/v1/raw as the default blocked feed for Public Access and as a real integration-test source. Source now installs a deterministic managed default, backfills existing public rules once, attaches new public rules by default, preserves explicit opt-outs and leaves login-required rules unchanged. Pending referenced data fails closed. The included rauth-feed-bootstrap command must seed the feed before cutover because the feed-serving route may itself pass through RAuth. The current request-feed observed-IP header is telemetry only; deployment must verify the authorization IP chain separately.

Feed bounds: HTTPS public destinations only, validated DNS/dial and redirects, no ambient proxy, 20-second request deadline, 10 MiB payload/canonical limit, 500,000 prefixes per feed, 32 feeds and 2,000,000 combined prefixes. SQL refresh leases and revision checks prevent duplicate/stale publishers; malformed/empty/large-drop updates preserve last-good data unless explicitly accepted. In-use feeds cannot be disabled/deleted. The built-in default cannot be removed, disabled or repointed. Query credentials stay out of rendered HTML/JSON/audit metadata.

Verification:
- Full go test ./... -count=1 -timeout 10m passed against disposable PostgreSQL (core 167.515s, handlers 247.161s, middleware 10.078s).
- CodeRabbit included review completed with three minor findings. Fixed cold first-download retry (60 seconds rather than a full refresh interval), alternate UUID spelling in default deletion guard, and preview JSON error negotiation. Targeted review-fix tests and go vet passed.
- Default catalog-cap rollback regression passed after manual review.
- Explicit real-source integration test passed: 4,771 entries, 82,452 normalized bytes, ready version 1; a real listed IP was denied by an inherited public rule. Counts change with provider updates.
- Desktop and 390px mobile QA passed for IP Feeds, country search, edit round-trips, feed checkbox retention, and actual allowed/blocked preview responses. Fixed deprecated duplicate country aliases found during QA. The temporary preview process, file and browser tab were removed.
- No new policies, worker applications or HA state services are live in production yet.

NL dedicated Tailscale service is now also live and verified:
- Host orderotto-dev / nl-bluehost-ubnt-1; /opt/rauth, project rauth-ha, isolated bridge 10.253.43.0/28.
- Identity rauth-nl-bluehost: 100.124.226.67, fd7a:115c:a1e0::402a:e244.
- Same official pinned image as hodus; Running with no health warnings after a key-free restart.
- Only persistent mount is host bind /opt/rauth/tailscale; no Docker volumes or published ports. Enrollment key removed from mount and host.
- Server evidence: /opt/rauth/tailscale-enrollment-verification.json.

The full active-active goal remains active. SQL auth authority, cross-node/cross-domain authentication, remaining node enrollment, HA database/quorum, durable event forwarding, workers, NPM rollout and outage tests are still required.
