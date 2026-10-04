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
