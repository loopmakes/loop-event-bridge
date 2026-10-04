# Verification record

Prepared on 2026-10-04 using the official Go 1.27.1 Linux/amd64 toolchain.

## Local checks

- Unit and mocked integration tests: passed
- Race detector suite: passed
- `go vet`: passed
- Static Linux/amd64 build with `CGO_ENABLED=0`: passed
- Go formatting: clean
- Compose YAML files: parse successfully
- `govulncheck`: no reachable vulnerabilities and no vulnerabilities in imported packages after dependency upgrades

The vulnerability scan still reports the unmaintained `golang.org/x/crypto/openpgp` package at module level. The application does not import or call OpenPGP; it uses `x/crypto/bcrypt`. The advisory has no fixed module version. This is not a clean bill of health for all code, and scanning should be repeated before deployment.

Covered behavior includes callback verification/signatures, modern MCP metadata and header validation, subscription ownership/idempotency/refresh/unsubscribe, initial-history suppression, restart deduplication, precise persisted IDs, pagination and body limits, source rate limits, terminal delivery responses, OAuth code/PKCE/consent/token flow, restart persistence, refresh rotation/reuse revocation, owner rotation, CSRF and input bounds.

An additional source review identified and corrected expiry cleanup, acknowledgement handling, transport validation and OAuth refresh/permission-ordering bugs before this package was finalized.

## Not run / not established

- Docker image build and Docker Compose runtime: not run because Docker was unavailable in the build environment
- Deployment behind a real Traefik instance: not run
- Live GitHub polling by this service with an operator token: not run
- A real ChatGPT subscription, callback and resulting chat/dot response: not tested
- Independent security audit: not performed

A locally passing suite is not evidence that a particular ChatGPT account exposes custom event subscription controls. Follow the README's harmless `bridge.test` flow before relying on live monitoring.
