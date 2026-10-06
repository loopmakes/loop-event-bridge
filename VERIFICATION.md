# Verification record

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
