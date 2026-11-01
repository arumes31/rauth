# Active-active implementation checkpoint

The complete approved goal remains active. This public checkpoint contains
technical progress only; live host identities, addresses, bridge subnets,
operational paths and detailed evidence remain in a private deployment inventory.
No secrets belong in Git.

- Country and IP-feed implementation: PR #778. Includes the requested managed
  Eworx default, rule inheritance/explicit opt-out, pre-session blocking, bounded
  fetch/parse, last-good data, admin menu and URL/IP preview.
- Real-source integration test loaded 4,771 entries and blocked a listed IP.
  Deterministic tests and desktop/mobile visual checks also passed.
- Linux Go/race, static/security/dependency checks passed before the latest PR
  review fixes; final current-head CI remains the merge gate.
- Latest review fixes preserve required default-feed references after a failed
  initial reload and promptly schedule refresh after a source change. Targeted
  core policy/feed/bypass tests, template rendering and lint passed.
- Dedicated persistent Tailscale identities are enrolled on two hosts and passed
  key-free restart. The identity bootstrap is not a complete worker deployment.
- SQL session foundation is separate in draft PR #780. Full local regression,
  lint and vet passed. Its runtime selector and the remaining security-state
  adapters are deliberately not enabled yet.
- A complete source-IP migration for 68 existing integrations is privately
  prepared. Isolated spoof/proxy tests and the full nginx syntax preview passed;
  non-IP directives matched. It has not been applied to production.
- Production still uses the prior release. No new country/feed policies, worker
  applications, HA databases or DNS routing changes have been activated.

Remaining work: finish SQL authority and all call sites, shared challenges,
replay/grants/invites/counters, cross-node and cross-domain flows, HA quorum and
storage/fencing gates, dedicated networking and node lifecycle checks, signed
persistent policy synchronization with bounded freshness, durable RAuth-only
event forwarding, worker/public-rule rollout, and controlled outage tests.

Before deployment, bootstrap the default feed and verify the authorization IP
chain; preserve existing login requirements and application-native challenges.
All persistence uses host bind mounts. The third state host's application data
must remain below /mnt/usb1/rauth after verifying that filesystem is mounted.

CodeRabbit's free hourly quota was exhausted at the SQL milestone; no paid
review was started. Continue useful local review/testing and respect cooldowns.
