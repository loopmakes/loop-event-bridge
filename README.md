# loop-event-bridge (experimental)

A small Go service that turns changes in an allowlisted author's GitHub pull requests into MCP Events. Run one container behind your existing Traefik HTTPS endpoint. GitHub polling is deterministic: unchanged snapshots produce no callbacks and invoke no model. This service has no model API integration.

**The MCP event implementation is experimental.** Local mocked tests do not prove your ChatGPT account can discover events, subscribe, or start a dot run. Treat the first real test event received in your chat as the integration acceptance gate. A successful webhook HTTP response acknowledges receipt, not model execution.

## What it does

- Implements MCP 2.0 (2026-07-28) event discovery, subscribe, refresh and unsubscribe
- Verifies callbacks before delivering application events; signs using Standard Webhooks
- Persists subscriptions, initial baseline, observed fingerprints and delivery queue atomically
- Emits `bridge.test` only when the operator invokes the local container command
- Emits `github.pull_request.changed` for observed PR state/head changes, published reviews (pending drafts are ignored), conversation comments and inline review comments
- Defaults to repository `colthreepv/symmetro`, PR author `loopmakes`; both are configurable, exact allowlist filters
- Exposes only a read-only `bridge_status` MCP tool; it does not duplicate the GitHub plugin's editing tools
- Never pushes commits, comments on GitHub, executes remote commands, or calls a model

## Run behind your existing Traefik

No separate identity provider is needed. OAuth is embedded in this process using the Fosite library: one predefined public client, authorization code + S256 PKCE, local owner approval, short-lived access tokens, refresh and revocation. This is a single-owner experimental service, not a general identity platform. GitHub access is separate and read-only; public repositories can be polled without a token.

1. Copy `.env.example` to `.env`. Set your HTTPS domain, existing Traefik network, HTTPS entrypoint and certificate resolver. The template does not install or change Traefik.
2. In the ChatGPT custom MCP/plugin setup, use `https://YOUR_DOMAIN/mcp` and OAuth with a predefined public client. Configure one client ID and copy the exact redirect URI from that management page into `.env`. The token endpoint authentication method is `none`; there is no client secret. Do not guess the redirect URI. Availability and UI differ by account; if predefined public-client setup is not offered, stop and resolve that integration mismatch rather than disabling authentication.
3. Create a private `secrets` directory and put a strong, unique 32–72-character ASCII owner password in `secrets/owner_password`. It is the password you enter on the bridge's approval page, not your GitHub password. Keep this directory owner-only. Docker Compose mounts the file into the non-root container, so the mounted file must be readable by UID 65532. Do not commit it or put it in `.env`.
4. Build and start the container yourself:

```sh
docker compose config
docker compose up -d --build
docker compose logs --tail=50 bridge
```

For optional GitHub read-only authentication, put your existing token in `secrets/github_token` and use the override consistently:

```sh
docker compose -f compose.yaml -f compose.github-token.yaml up -d --build
```

5. Connect/rescan the MCP server in ChatGPT. Its authorization page is on your own HTTPS domain. Confirm the client and scope and enter the bridge owner password there. Never paste that password into chat. `bridge_status` should be available after connection.
6. Ask ChatGPT to subscribe to `bridge.test` with repository `colthreepv/symmetro` and author `loopmakes`, and to acknowledge the event. With `CALLBACK_HOSTS` empty, the request fails closed and reports `requestedHost`. Verify this is the client's expected callback host, put that exact hostname in `CALLBACK_HOSTS` and recreate the container with the same Compose command. Retry the subscription. No wildcard domains are accepted.
7. Once callback verification and subscription creation succeed, trigger the harmless test locally:

```sh
docker compose exec bridge /loop-event-bridge emit-test
```

8. Confirm the event actually arrives in your chat and starts the expected response. A queued message or HTTP 2xx alone is insufficient. Then ask ChatGPT to subscribe to `github.pull_request.changed` with the same filters and your desired reporting instructions. Do not assume discovery alone proves subscriptions are available on your account.
9. Ask ChatGPT to stop monitoring; verify unsubscribe removes the subscription. Also restart the container and verify an unchanged GitHub snapshot causes no duplicate notification.

The container needs outbound HTTPS to GitHub and the configured callback hosts. It publishes no host port. Its healthcheck confirms process responsiveness, not GitHub or ChatGPT delivery health; use `bridge_status` for polling/queue health. The existing Traefik HTTPS termination must be correct, and the domain must resolve to it.

### Persistence and revocation

Keep the `bridge-data` volume across upgrades. It holds both event state and OAuth grants/keys. The service initializes its own internal OAuth signing material only on your first deployment. Protect volume backups as credentials; do not share the files. Use one replica only. Deleting the volume loses grants, subscriptions, and deduplication state.

To revoke all access, stop the service. Changing the owner password (or client/domain configuration) and restarting invalidates existing grants; old event subscriptions are then pruned. Ordinary disconnect should revoke through the client when supported. Never leave a publicly reachable no-auth variant running.

## Delivery and polling semantics

The first complete GitHub scan establishes a silent baseline. Later complete scans compare stable record fingerprints. Partial scans and rate-limit failures never advance the baseline. All collection endpoints are paginated, capped at 100 pages each; a cap is an error, never silently truncated history. A poll has a two-minute overall timeout and a 64 MiB aggregate response-body budget. This conservative full-history scanner is intended for small repositories, not thousands of PRs.

A normal poll defaults to every 300 seconds, with a 60-second minimum. GitHub API calls still happen when nothing changes. Public unauthenticated GitHub access has a small rate limit; an optional read-only token can raise it. Read access to the allowlisted repository's pull requests/issues is sufficient; no write permissions are needed. Reviews/comments by any actor are included only when the PR itself is authored by the configured author.

State and queue are saved together before delivery. Event IDs remain stable across retries and restart. A crash after the receiver accepts an event but before acknowledgment is persisted can produce a duplicate. Delivery is at-least-once within bounded retries, not exactly once. Transient failures back off, stopping after eight attempts; permanent 4xx (except 408/429), 410 and 413 are not retried. Up to 100 terminal failures are retained for seven days for operator inspection; expired/revoked subscriptions and their queue are removed. The read-only status exposes a dead-letter count. Queue capacity is 10,000 entries; hitting it stops snapshot advancement.

`cursor` is null: protocol replay is not implemented. After an outage, the next complete scan detects records still present and state differences from the saved snapshot; intermediate transitions, deleted comments and events during expired subscriptions may be missed. Multiple rapid edits may coalesce. Review edits/dismissals retain GitHub’s submitted_at timestamp because that endpoint supplies no updated_at. This is an explicit limitation, not a lossless GitHub event log. No unsupported `gap`, `terminated`, stream, or polling delivery modes are advertised.

Subscriptions have a finite maximum lifetime of one hour. The client must refresh them. Callback secrets rotate with a five-minute overlap. Successful verification is cached for five minutes by owner, callback and secret. Unsubscribe clears queued items; a request already in flight may finish.

## Safety boundaries

Callback hosts must be explicitly configured. HTTPS on port 443 is required. Every connection resolves and rejects non-public addresses, dials only the validated address and preserves TLS hostname verification. Redirects and environment proxy settings are disabled for callbacks. Do not copy a guessed callback hostname: get the real destination from the client setup/request and allow only the required host.

Callbacks, signing secrets and queue state are sensitive. The state file is mode 0600; protect and encrypt volume backups. Logs/status omit tokens, callback URLs, signing secrets and comment text. Comment bodies are fingerprinted to detect edits but are not forwarded. The operator-only `/test` endpoint binds to loopback inside the container; do not publish it or change that binding.

The process is non-root and the container has no shell. Use a single replica per state volume. Disk corruption or invalid persisted state fails startup rather than resetting deduplication silently. Stop the service to revoke all subscriptions immediately. Never expose an unauthenticated deployment.

## Protocol references

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events)
- [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth)
- [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks)
- [GitHub REST pull requests](https://docs.github.com/en/rest/pulls/pulls)

## Development

Use Go 1.26 or newer:

```sh
go test ./...
go test -race ./...
go vet ./...
go build .
```

Tests use synthetic local/mock HTTP endpoints and temporary test keys only. No production secrets or GitHub data are bundled.

## Integration limits and operating notes

- This is intentionally single-owner and single-process. It has not received an independent security audit
- Fosite handles OAuth mechanics, but browser consent and file persistence are application code. A crash between protocol storage steps can require reconnecting; operations fail closed
- Preserve the public `Host` header through Traefik. The embedded OAuth endpoints reject requests for another host
- Access tokens last 15 minutes; rotating refresh tokens last up to 30 days. Password/config rotation invalidates existing grants on restart
- Source read permissions must remain available. Removed GitHub access pauses polling without advancing the baseline; callback access follows the owner's live OAuth grant
- The service exposes no remote write tools. A future automation that acts on events needs its own explicit permissions in the client
- Modern clients must send the 2026-07-28 request metadata and mirrored HTTP headers. Older MCP clients are not supported
- Scope is a small-repository polling bridge. A large repository may exceed API quotas or the two-minute scan deadline; choose a webhook-based source adapter for that scale
