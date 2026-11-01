# Admin live-feed implementation plan

- Add a bounded request-event ring with reconnect cursors, restart IDs, URL redaction and concurrent-access tests.
- Record forward-auth outcomes around the existing request/security chain using the trusted original IP and country.
- Add an admin-only SSE endpoint with heartbeats, repeat session/admin checks, stream limits and write deadlines; test authorization, revocation, delivery and cancellation.
- Add the Live Feed management tab with safe text rendering, action colors, filtering, pause/resume, reconnect state and responsive cards/table layout.
- Run focused local tests and Go vet, CodeRabbit within its quota, then the PostgreSQL/race suite and all CI gates. Verify live delivery and desktop/mobile rendering before merging and deploying.
