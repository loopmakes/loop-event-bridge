# Docker Swarm setup

The supplied `stack.yaml` targets Traefik v3. Check your installed version first; see the [v2 adjustment](#using-traefik-v2) below. It joins your existing proxy network. It does not install Traefik, publish host ports, create credentials, or publish a container image for you.

## Prepare the Swarm once

### 1. Fill in non-secret settings

Copy `.env.example` to `.env`, replace the placeholders, then load it in your shell:

```sh
cp .env.example .env
# Edit .env first, then:
set -a
. ./.env
set +a
```

Only source a file you wrote or reviewed: sourcing runs shell syntax. Keep its single-quoted assignments and never put credentials or commands in it. Run the export block again after changes. [Swarm does not automatically load `.env`](https://docs.docker.com/compose/how-tos/environment-variables/variable-interpolation/).

`BRIDGE_DOMAIN` is a hostname with no scheme or path. The stack turns it into `PUBLIC_URL=https://...`. The exact HTTPS origin is also the OAuth issuer; avoid changing it after connection.

The OAuth defaults avoid needing an already-connected client to deploy: choose a public `OAUTH_CLIENT_ID` now, and initially use `https://chatgpt.com/connector_platform_oauth_redirect`. OpenAI documents this stable redirect for issuer-aware servers; this bridge advertises that support and returns the matching `iss` parameter. After deployment, register the reachable `/mcp` endpoint with that client ID and authentication method `none`. **Before approving OAuth, verify the exact management-page redirect**; if it differs, copy it to `.env` and redeploy. No unauthenticated deployment stage is needed. [Official redirect documentation](https://developers.openai.com/plugins/build/auth#redirect-url)

### 2. Check your existing Traefik network

From a manager:

```sh
docker network inspect "$TRAEFIK_NETWORK" --format '{{.Driver}} {{.Scope}}'
```

Expect `overlay swarm`. Traefik and the bridge must both join this exact network. In Traefik v3, enable the **Swarm provider**, not the standalone Docker provider. Match your existing HTTPS entrypoint and certificate resolver. If Traefik selects services with extra constraint labels, add its required label under `deploy.labels`.

The template assumes an existing certificate resolver. If you use certificates from Traefik's file provider instead, remove only the `tls.certresolver` label and keep `tls=true`. Preserve the public Host header. Allow outbound HTTPS from the bridge to `api.github.com` when GitHub is enabled and to your verified client callback hosts. Optional sources also need their configured GitLab origin or `mail.proton.me` for the Proton API; see [source setup](SOURCES.md).

The service labels use `traefik.swarm.network` and explicitly route to port 8080. [Traefik Swarm provider](https://doc.traefik.io/traefik/providers/swarm/) · [Swarm routing labels](https://doc.traefik.io/traefik/reference/routing-configuration/other-providers/swarm/)

### Using Traefik v2

For an existing Traefik v2 installation, its Docker provider must have `swarmMode: true`. In `stack.yaml`, replace `traefik.swarm.network=...` with `traefik.docker.network=...`, keeping the same network value. Keep the routing labels under `deploy.labels` and the explicit port 8080. Do not change a working proxy installation solely to match this template. [Official v2 Swarm configuration](https://doc.traefik.io/traefik/v2.11/providers/docker/#docker-swarm-mode) · [v2 network label](https://doc.traefik.io/traefik/v2.11/routing/providers/docker/#traefikdockernetwork)

### 3. Choose the node that keeps the state

The default volume is local to one node. From a manager, pick a reliable Linux node and give **only that node** this label:

```sh
docker node ls
docker node update --label-add "loop-event-bridge=$BRIDGE_NODE_LABEL" YOUR_CHOSEN_NODE
```

On that chosen node, create the volume. Use the name from `BRIDGE_DATA_VOLUME` if you changed the example:

```sh
docker volume create loop-event-bridge-data
```

The image supplies `/data` owned by UID/GID 65532 when Docker initializes a fresh empty volume. An existing/restored volume must retain that ownership and let this UID write. Don't use a root-owned bind directory instead without preparing its permissions.

Keep the label on one node, one replica, and the same volume. If the node is unavailable, leaving this service pending is safer than silently starting with empty state elsewhere. For migration, stop the old task and restore the state files (and the encrypted Proton session if used) on the replacement node before moving the label. Never run two copies against one volume. [Docker service volumes and constraints](https://docs.docker.com/reference/cli/docker/service/create/)

### 4. Supply your default secrets manually

The unchanged stack enables GitHub only. [Optional GitLab and Proton setup](SOURCES.md) explains their additional secrets, Proton session bootstrap, and how to disable GitHub without a dummy token.

In your own secure workflow, obtain:

- A GitHub **classic personal access token** for `GITHUB_ACCOUNT`, with the `notifications` scope. Do not use a fine-grained token or GitHub App token
- A strong, unique **32–72-character ASCII owner password** for the bridge approval page

Create the Swarm secrets yourself with your management UI or from private local files. These example commands run on a manager; replace the file paths:

```sh
docker secret create "$OWNER_PASSWORD_SECRET" /secure/path/owner-password
docker secret create "$GITHUB_TOKEN_SECRET" /secure/path/github-token
```

Keep source files outside the repository, readable only by you; manage their removal through your normal secret-handling process. Never paste secret values into commands, `.env`, issues, logs, or chat. The stack references existing secret **names**, mounts them only in this service, and makes the files readable by UID 65532 with mode `0400`. [Docker Swarm secrets](https://docs.docker.com/engine/swarm/secrets/)

### 5. Add optional sources only when needed

The same image contains all adapters. `.env.example` leaves `GITLAB_ENABLED=false` and `PROTON_ENABLED=false`. The optional service mounts and top-level secret definitions in `stack.yaml` are comments; enabling a flag does not mount a secret automatically.

Follow [Sources](SOURCES.md) to enable the appropriate pair of secret blocks. GitLab needs its user token. Proton needs a separate raw 32-byte session-encryption key and an encrypted refresh session on the writable `/data` volume. On first use, username/password secrets can bootstrap that session in the persistent service. After success, remove the bootstrap variables and mounts and redeploy; keep the session key. Interactive `proton-auth` is an optional fallback for supported challenges, not a required setup step. Do not store provider credentials in `.env` or image layers. No sidecar or new Traefik router is needed.

## Build and deploy

From the source directory, with `.env` exported:

```sh
docker build --tag "$BRIDGE_IMAGE" .
docker push "$BRIDGE_IMAGE"
```

Choose a new version tag per release; an image digest is best for the deployment setting. Build for the chosen node's architecture. No registry image is bundled, and `docker stack deploy` ignores `build:`. [Docker stack deployment](https://docs.docker.com/engine/swarm/stack-deploy/)

<details>
<summary>Building on a different architecture?</summary>

The image must match the chosen state node, not necessarily your laptop. With a configured Buildx builder, this example builds and pushes for an amd64 Linux node:

```sh
docker buildx build --platform linux/amd64 --tag "$BRIDGE_IMAGE" --push .
```

Use `linux/arm64` instead for an arm64 node. This replaces the two build/push commands above. Publishing remains a manual action to your chosen registry.

</details>

Then, on a manager with the same configuration exported:

```sh
docker stack config --compose-file stack.yaml > /dev/null
docker stack deploy --compose-file stack.yaml loop-event-bridge
docker service ps --no-trunc loop-event-bridge_bridge
docker service logs --tail 50 loop-event-bridge_bridge
```

For a private registry, sign in yourself using your usual secure flow. If your nodes need those registry credentials, deploy with `--with-registry-auth`; that passes your registry authentication to the Swarm agents. Use only the access your registry requires. Do not put registry credentials in the image or `.env`.

`stack config` validates interpolation and the stack schema; it does not prove the network, secrets, image, or node are available. Docker health checks only process responsiveness. Finish the README's real `bridge.test` check and inspect `bridge_status` for source/delivery health.

## Update or restart

After changing callback hosts, image version, or secret names, reload `.env` and rerun the same stack deployment. Preserve the volume and stack name. The stack uses `stop-first` for updates and rollbacks, avoiding simultaneous writers during a normal update.

For an intentional restart:

```sh
docker service update --force loop-event-bridge_bridge
```

A Swarm secret's value cannot be changed in place. Create a new version yourself, change the corresponding secret name in `.env`, and redeploy. Owner-password or OAuth client/domain changes invalidate existing grants; reconnect and subscribe again. Keep old secrets until no service needs them.

## Container hardening and compatibility

The service runs as UID/GID 65532, with a read-only root filesystem, all Linux capabilities dropped, and a shell-free image. Only the state volume is writable. Use a supported Docker Engine/CLI; capabilities in Swarm require API 1.41 or newer.

`security_opt` is not supported by the stack deploy implementation, so this template deliberately does not claim that `no-new-privileges` is applied. Do not copy Compose-only settings and assume they work. [Docker CLI unsupported properties](https://github.com/docker/cli/blob/master/cli/compose/types/types.go) · [Swarm conversion](https://github.com/docker/cli/blob/master/cli/compose/convert/service.go)

No service ports are published. Traefik can reach port 8080 through the overlay. Port 8081 is bound to container loopback and is only used by the local healthcheck/test command. Never route or publish that operator endpoint.
