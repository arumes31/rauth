# Admin live request feed

## Intent
Give administrators a live view of forward-auth decisions so they can spot blocked or redirected requests without reading server logs.

## Design
Add a Live Feed panel to the existing management GUI. Show time, protected URL (host and path), original client IP, country, and a colored action label. Actions distinguish authenticated access, anonymous bypass, login required, rate limited, blocked, and errors. Keep the existing audit log for account/admin changes.

Use an instant server-sent-event stream, as selected by the user. Reuse the existing admin/session middleware on connection, then recheck session validity, account generation and live admin status every five seconds. Send heartbeat comments, honor reconnect cursors, expose stream resets/history gaps, cap concurrent streams, and bound each socket write. A stalled viewer must never block authentication processing.

Capture recent forward-auth outcomes in a bounded, thread-safe in-memory ring of 1,000 events per instance. Send at most 100 events per batch and keep at most 300 rows in the browser. Expose history gaps and restart/reset state rather than silently losing position. Restart clears this operational feed; the durable audit log is unchanged.

Render colored labels with text, provide search/action filters, pause/resume, connection state, and a responsive layout with wrapping URLs. Close streams in hidden tabs/panels and reconnect with the last event cursor. Build rows with text APIs, never request-supplied HTML.

Only accept protected URL metadata from trusted reverse proxies. Use the application's existing original-IP and country lookup. Drop URL query strings/fragments, redact URL userinfo, limit field sizes, and never capture credentials, cookies, request bodies or authentication tokens. Send the API response with no-store caching.

## Verification
Test buffer ordering, retention, cursor/reset handling and concurrent access; verify decision classification, admin-only access and revocation, trusted-proxy metadata, and hostile URL rendering. Run the PostgreSQL-backed suite and race checks in CI, review with CodeRabbit within its free quota, then verify desktop/mobile layouts and live updates before merging and deploying.
