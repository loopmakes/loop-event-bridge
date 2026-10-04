# Development

Use the Go version declared in `go.mod` or newer. The Dockerfile and CI pin the build toolchain.

```sh
go test ./...
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build -trimpath -o /tmp/loop-event-bridge .
test -z "$(gofmt -l *.go)"
```

Tests use synthetic/mock endpoints and temporary test credentials. Never add real tokens, inbox fixtures with private information, or OAuth state to this repository.

## Validate the Swarm template without deploying

With a current Docker CLI installed, this uses only placeholder settings and does not create secrets, pull an image, or deploy a service:

```sh
BRIDGE_IMAGE=example.invalid/bridge:ci \
BRIDGE_DOMAIN=bridge.example \
TRAEFIK_NETWORK=traefik-public \
TRAEFIK_ENTRYPOINT=websecure \
TRAEFIK_CERT_RESOLVER=letsencrypt \
BRIDGE_NODE_LABEL=primary \
BRIDGE_DATA_VOLUME=bridge-ci-data \
OWNER_PASSWORD_SECRET=bridge-ci-owner \
GITHUB_TOKEN_SECRET=bridge-ci-github \
GITHUB_ACCOUNT=ci-example \
OAUTH_CLIENT_ID=ci-public \
OAUTH_REDIRECT_URI=https://client.example/callback \
docker stack config --compose-file stack.yaml > /dev/null
```

Use `docker stack config`, not only `docker compose config`: stack deployment uses the legacy v3 format and has different feature support. Check its stderr as well as the exit code; ignored-option warnings should be investigated. [Docker command reference](https://docs.docker.com/reference/cli/docker/stack/config/)

## What does CI establish?

CI runs source tests, race detection, vet, and a static build. It validates the stack configuration, builds the container without publishing it, and runs a non-root startup/healthcheck with networking disabled. The offline smoke test has no production GitHub token, so it cannot validate source polling.

A green run does not establish real Swarm scheduling, secret mounts, volume initialization, Traefik routing, OAuth linking in your account, or a ChatGPT response to a webhook. Use the exact commit's [CI run](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml), the [verification record](../VERIFICATION.md), and the README's live acceptance steps together.

## Protocol references

- [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events)
- [OpenAI MCP authentication](https://developers.openai.com/plugins/build/auth)
- [MCP 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks)
- [GitHub Notifications API](https://docs.github.com/en/rest/activity/notifications)

The server implements the `2026-07-28` request metadata and mirrored HTTP headers. Older MCP clients are not supported. See tests for malformed requests, callback verification, OAuth consent/PKCE, token refresh, revocation, queue handling, and restart behavior.
