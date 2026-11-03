# Approved collector WAN recovery implementation plan

User approved the short design in this chat on 2026-11-03. The writing-plans companion skill was searched in all installed roots and is unavailable; this concrete plan records the implementation without claiming that skill was invoked.

1. Scope the PostgreSQL idle timeout to the reserved advisory-lock session and heartbeat it from existing Status checks; serialize heartbeat/disposal and always destroy that connection on close.
2. Add native PostgreSQL regressions for bounded orphan expiry/takeover, live heartbeat renewal, stale-writer no-ACK fencing, and repeated close without returning reserved sessions to the pool.
3. Prove relevant failures on unchanged main; run patched native regressions plus existing collector/stats tests in the network-isolated database copy; compile/vet affected packages. Review the diff. CodeRabbit CLI included-usage lookup was already unavailable; do not retry quotas or use credits.
4. Open PR, resolve valid review findings, wait for latest CI, merge expected head under existing authorization. Stage immutable runtime then replica-only guarded canary rollout with closed full backups.
5. One scoped SQL interruption with independent rollback; prove automatic collector and original-cookie UI recovery without manual backend termination/app restart, delayed event IDs and no duplicates. Preserve original failed evidence. Production cutover remains gated separately.
