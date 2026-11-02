# Reduce authenticated validation SQL round trips

Implements the approved HA plan's query optimization and latency gate. The native remote worker measured p95 476.557 ms at concurrency eight with an explicit four-connection pool. Each valid request currently performs authoritative session Get, redundant user/generation lookup, counter reset, and bounded refresh in four separate SQL dispatches.

Use a typed core read helper that retains the legacy account/generation check and relies on the selected SQL session store's existing live user/generation/family/expiry joins in SQL mode. Every request still queries current authority; no positive authorization cache is added.

Batch the post-binding validate-counter reset and existing conditional refresh into one pgx batch, draining all results including commit errors. Reuse the exact refresh SQL and bounds. Preserve global login/2FA counters, token/audience/IP/UA/country enforcement, retired-token handling, rotation, absolute expiry, and authority-unavailable responses. Retain the existing counter-reset effects on binding failure, grace-token, rotation-loss and roaming paths; only ordinary valid-path cleanup is batched.

First add a real SQL handler regression that counts dispatches, fails old behavior (four vs two), verifies counter cleanup, refresh throttling and acknowledged revocation. Add batch atomicity/late-error, generation/revocation/retirement/expiry/bound tests using independent native SQL pools. Run native authstate, core and handler regressions plus local Go/vet; review within included quota. Build exact Linux artifacts, upgrade isolated canaries preserving HA authority and mounts, repeat fresh login/2FA/SSO and the same host-local timed workload. Keep production performance acceptance pending until measured.
