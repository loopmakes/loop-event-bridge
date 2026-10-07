# Verification record

## Event-delivery correlation and opt-in payload diagnostics (2026-10-07)

Base: `428f5de9e7fb95d0a0b6b8ae120d1d437de35796` (v0.2.3). Added durable enqueue/start/result correlation, bounded event-discovery reporting, subscription lifecycle traces, and content-free callback diagnostics. `EVENT_DEBUG_LOG=true` additionally logs bounded, sanitized event JSON with actual allowlisted source metadata. Default logging remains content-free. Neither the event wire format nor acknowledgment, retry, persistence or source behavior was changed.

Passed locally with Go 1.27.1: full unit/mocked integration tests, full race suite, `go vet ./...`, static Linux/amd64 build, `go mod verify`, formatting, `git diff --check`, environment-file shell syntax, and Swarm YAML structure/interpolation checks. The built binary rejects an invalid debug-mode setting before OAuth/network startup without echoing its value. Independent review found no remaining actionable correctness or logging-safety issue.

Synthetic regressions cover correlation across retries/restarts and multiple subscribers/sources, success-only persisted enqueue/subscription logs, concurrent discovery coalescing, local/transport/body failures, bounded response observations, preserved 2xx acknowledgment of invalid bodies, malicious IDs/field names/headers, default-off content logging, all current adapter metadata, primitive-only allowlisting, URL sanitization, Unicode control escaping, bounded valid JSON excerpts and sanitized-only hashes, and unchanged delivered event bytes. The [operations guide](docs/OPERATIONS.md#temporarily-inspect-event-metadata) describes the debugging mode's deliberate content exposure and its limits.

Not performed locally: Docker/Swarm validation (Docker CLI unavailable), the opt-in native-browser suite, deployment, live source event generation, or receiver-side trace inspection. YAML parsing is not Docker stack validation. Publication checks must be verified for the exact commit/tag in CI. A transport HTTP 2xx and a passing synthetic suite do not establish that a receiver exposed an event payload to an automation or produced a chat response; the missing-payload cause remains unconfirmed without correlated receiver evidence. No previously acknowledged notification was replayed.

## Manual Proton browser CAPTCHA handoff (2026-10-07)

Base: `4149138885d0ae46f9a430fd09daac765da514d6` (v0.2.2). The interactive CLI now supports an exact advertised `captcha` at the authentication step, using the official external-browser challenge URL, manual Enter confirmation, and one SDK continuation with the original challenge token. Email remains preferred when both are offered. No CAPTCHA solving, browser-cookie import, callback server, app-identity change, or unattended verification was added.

Protocol evidence is pinned in [the operator guide](docs/proton.md#verification-and-sources). Proton's external-browser redeemable-proof implementation was added on [2026-08-11](https://github.com/ProtonMail/WebClients/commit/df2f2b0545ed0b3785b7b83927d13457a510df65), after the February report of standalone verification failing. This source evidence establishes the intended flow, not deployment or account acceptance for this integration.

Passed locally with Go 1.27.1: full unit/mocked integration suite, full race suite, `go vet ./...`, static Linux/amd64 build, formatting, and `git diff --check`. Independent review found no blocking code or privacy issue and also passed tests/race/vet. New real Linux PTY tests passed for redirected-output rejection before session access and empty Enter handling; credential prompts still reject empty input. A final focused race check also passed for the unattended CAPTCHA no-URL/no-retry regression added after the full-race run began.

Synthetic tests cover original-token SDK headers only on the single `auth` continuation, normal SRP proof generation, CAPTCHA-only and mixed-method handling, optional TOTP, account checks, encoded fixed-origin URLs, unsafe/missing tokens, unsupported authentication stages, cancellation, output failure, rejected/expired/repeated challenges, and unchanged existing ciphertext on failure. The private challenge URL is an explicit terminal-only display exception; returned errors, background status/logs, and persisted sessions remain token-free.

Not performed: live Proton login/CAPTCHA, browser challenge completion, real-account/free-plan acceptance, actual event delivery, or deployment. Docker is unavailable locally; tagged CI performs container, browser, multiarchitecture build, and anonymous image-pull checks. Publication status must be established from the exact commit/tag's GitHub Actions results.

Prepared on 2026-10-04 using the official Go 1.27.1 Linux/amd64 toolchain.

## Local checks

- Unit and mocked integration tests: passed
- Race detector suite: passed
- `go vet`: passed
- Static Linux/amd64 build with `CGO_ENABLED=0`: passed
- Go formatting: clean
- Swarm stack YAML: parses successfully; CLI interpolation/schema validation runs in CI
- `govulncheck`: no reachable vulnerabilities and no vulnerabilities in imported packages after dependency upgrades

The vulnerability scan still reports the unmaintained `golang.org/x/crypto/openpgp` package at module level. The application does not import or call OpenPGP; it uses `x/crypto/bcrypt`. The advisory has no fixed module version. This is not a clean bill of health for all code, and scanning should be repeated before deployment.

Covered behavior includes callback verification/signatures, modern MCP metadata and header validation, subscription ownership/idempotency/refresh/unsubscribe, initial-history suppression, restart deduplication, precise persisted IDs, pagination and body limits, account-wide Notifications identity checks, all-type pagination, source polling/rate-limit headers, terminal delivery responses, OAuth code/PKCE/consent/token flow, restart persistence, refresh rotation/reuse revocation, owner rotation, CSRF and input bounds.

An additional source review identified and corrected expiry cleanup, acknowledgement handling, transport validation and OAuth refresh/permission-ordering bugs before this package was finalized.

## Not run / not established

- Local Docker was unavailable. The [CI workflow](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml) now builds the Docker image and tests non-root startup/health with networking disabled, without publishing it; consult the run for the exact commit and result
- Live Docker Swarm deployment: not run
- Deployment behind a real Traefik instance: not run
- Live authenticated GitHub Notifications polling by this service: not run
- A real ChatGPT subscription, callback and resulting chat/dot response: not tested
- Independent security audit: not performed

A locally passing suite is not evidence that a particular ChatGPT account exposes custom event subscription controls. Follow the README's harmless `bridge.test` flow before relying on live monitoring.

## Optional-source expansion: local verification (2026-10-06)

Base: `b66f74f987f17f4d1d5ff9106626117eb3f6d5f9`. This section records the pre-publication local validation snapshot. Subsequent publication/CI results are recorded in GitHub Actions. All provider/authentication fixtures are synthetic; no live GitLab or Proton account was accessed.

Passed with official Go 1.27.1 on Linux:

- `go test -count=1 ./...`
- `go test -race -count=1 ./...`
- `go vet ./...`
- `CGO_ENABLED=0 go build -trimpath ...` (static Linux amd64 executable)
- `go mod verify`, `gofmt`, and `git diff --check`
- Final standalone-binary startup/health/shutdown with optional sources disabled and invalid credential paths; repeated with optional sources enabled but misconfigured to verify isolated failures
- Environment-file shell syntax, YAML structural checks (including optional/bootstrap secret examples), and local documentation links

There are 64 new top-level source test groups, including account/source separation, legacy state preservation, outbox/cursor rollback, baseline/restart/reconciliation, incoming-mail filtering, credential precedence, once-only bootstrap, revoked-auth latching, session encryption/locking, storage-path aliases, and nonblocking FIFO rejection.

`govulncheck v1.8.0` reported no reachable-symbol or imported-package vulnerabilities. It identified unused-module advisory [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) for deprecated `golang.org/x/crypto/openpgp`; this service does not import that package, and no fixed upstream version is listed. A scan is not a security audit.

Not completed in this environment:

- Native browser regression: attempted with installed Chromium 154, but startup fails before assertions because its local socket is forbidden (`Operation not permitted`), including the approved execution retry. The Playwright download also returned invalid/truncated archives. Existing browser CI is retained; `LOOP_CHROMIUM_EXECUTABLE` optionally selects an installed Chromium for local testing
- Docker/Swarm/container validation: Docker CLI unavailable; YAML parsing is not equivalent to `docker stack config` or a container smoke test
- Real GitLab/Proton login, Proton free-account access/application-version acceptance, real mail events, and Swarm/Traefik/ChatGPT end-to-end acceptance

At this validation stage, no branch, PR, image, release, or deployment had been published. Prior unpublished work outside this isolated checkout was not included.

## Proton identity and diagnostic fix (2026-10-07)

Credential-free GET checks with `x-pm-appversion: Other` returned HTTP 200 / API code 1000 at both `https://mail.proton.me/api/auth/v4/modulus` and `https://mail-api.proton.me/auth/v4/modulus` during 04:47–04:48 UTC. No cookies, account credentials, authenticated login, or deployment were used. This establishes public-endpoint compatibility only; see the [operator guide](docs/proton.md#application-identity-and-compatibility-configuration) for the limits and pinned third-party consumer evidence. Human/email verification was unsupported in that patch; the subsequent interactive change is recorded below.

The patch adds eleven synthetic regression groups for conservative identity validation, application-version error classification, wrapped SDK errors, allowlisted authentication stages, malformed responses, concurrent trace isolation, per-request status reset, safe status/log persistence, once-only bootstrap, and refresh failure/retry behavior without session replacement.

Local pre-publication checks passed: `git diff --check`, `.env.example` shell syntax, stack YAML parsing, and local documentation paths/anchors. At that validation stage, the execution environment had no Go compiler or `gofmt`, so Go tests, race detection, vet, formatting, and builds depended on the exact published commit's [CI](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml) and [container workflow](https://github.com/loopmakes/loop-event-bridge/actions/workflows/publish-image.yml). YAML parsing alone is not Swarm CLI validation. No release tag is to be published before those checks pass.

## Interactive Proton email human verification (2026-10-07)

The implementation uses the pinned SDK’s `GetHVDetails`, `SendVerificationCode`, and `NewClientWithLoginWithHVToken`, with the plain-email proof contract cross-checked against official Proton WebClients source. Only an exact advertised `email` method at the SDK’s `auth` step enables a hidden destination/code prompt. No live account authentication, verification email, CAPTCHA, browser-session reuse, or deployment was performed while developing this change. Real-account login and event delivery are still unverified.

New synthetic tests cover allowlisted method reporting (including unknown/malformed/null details), separate ownership-email handling, a single email request and login continuation, fresh network deadlines outside prompts, code rejection, cancellation, no automatic retries, TOTP after human verification, account mismatch, encrypted success-only persistence, and unchanged existing ciphertext on failed authentication. Mock HTTP tests exercise the actual SDK email request, normal SRP proof generation from public synthetic test vectors, and human-verification headers on the one login continuation. The original challenge token is not reused as an email proof, headers do not leak onto auth-info or email-send requests, and rejected verification ends without further requests.

After explicit operator approval, official Go 1.27.1 Linux/amd64 was installed in an isolated workspace toolchain directory. Its archive SHA-256 was verified against `go.dev` release metadata before extraction; no global executable was replaced.

Local pre-publication checks passed:

- `go test -count=1 ./...`, including all new synthetic challenge/session tests
- `go test -race -count=1 ./...`
- `go vet ./...`
- `CGO_ENABLED=0 go build -trimpath ...`
- `go mod verify`, clean `gofmt`, and `git diff --check`
- Static-binary `proton-auth` smoke check: piped/non-terminal input is rejected before session access

The existing browser-specific suite (requires `LOOP_BROWSER_TEST=1`), Docker/Swarm smoke tests, live account authentication, deployment, and release publication are not established by these checks. Exact-commit browser/container CI must still pass before a release tag is published.
