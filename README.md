# loop-event-bridge

[![CI](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml)

**Account updates, delivered as MCP Events.** GitHub Notifications work as before. Optionally add GitLab To-Dos and incoming Proton Mail, in the same small Go binary and Docker Swarm container behind your existing Traefik.

```text
GitHub Notifications ─┐
GitLab To-Dos ────────┼─▶ shared subscriptions + durable outbox ─▶ ChatGPT / dot
Proton Mail ──────────┘            OAuth + /mcp                     your instructions
```

GitHub is enabled by default; GitLab and Proton are off until configured. The bridge never calls a model. Quiet checks still use the enabled providers' APIs, but send no events. One source's configuration or polling failure does not stop the others. All sources use the same OAuth server, `/mcp` endpoint, subscriptions, and signed delivery queue.

**Experimental:** automated tests cover code paths and offline container startup, not live provider compatibility. No live GitLab or Proton account has been tested; free Proton account compatibility is unverified. A real Swarm + Traefik + ChatGPT connection still needs testing. A successful `bridge.test` response in your chat is the acceptance test, not merely a healthy container or webhook HTTP 200.

**Proton application identity:** explicitly set `PROTON_APP_VERSION=Other`; a copied frontend version is invalid. This compatibility value passed credential-free public-endpoint checks. Full account authentication remains unverified. Interactive `proton-auth` supports the exact offered `email` method or a manual browser CAPTCHA handoff; other human-verification methods remain explicit unsupported stops. See the [configuration and limits](docs/proton.md#application-identity-and-compatibility-configuration).

## What would I use it for?

For example: someone requests your review on a PR. If GitHub adds or updates a notification in your inbox, the bridge sends `github.notification.changed`. Your instruction to ChatGPT might be:

> Monitor my GitHub notifications. Tell me when something needs my attention, with the repository, title, and reason. Don't change anything on GitHub.

It covers the configured account's **whole Notifications inbox**: all returned repositories, subject types, and reasons, including read notifications. GitHub notification preferences and account access determine what appears there. It cannot see every action across GitHub.

The first complete GitHub scan quietly records a starting point, so you won't receive a flood of old notifications. The bridge only makes GET requests to GitHub; it never marks a notification read or done.

Optional sources:

- **GitLab:** new or changed pending To-Dos. This is a partial view of account activity, not a complete notification inbox. It never marks a To-Do done
- **Proton:** newly received incoming messages through Proton's direct API. The initial payload contains only message ID and receive time, with no subject, sender, body, or attachments. No IMAP or Proton Bridge sidecar

[Source setup, credentials, payloads, and limits](docs/SOURCES.md)

## How do MCP Events fit in?

ChatGPT connects to `/mcp`, discovers the events for enabled sources plus `bridge.test`, then subscribes with a callback destination. Every event takes empty filter arguments: `{}`.

- `github.notification.changed`: a new or changed GitHub inbox notification (default)
- `gitlab.todo.changed`: a new or changed pending GitLab To-Do (optional)
- `proton.mail.received`: a newly received incoming Proton message (optional)
- `bridge.test`: a harmless event you trigger locally to check the connection

The bridge checks the callback and signs deliveries. ChatGPT decides what to do with an event using your instructions. The only regular MCP tool is `bridge_status`, which reports polling and delivery health.

<details>
<summary>Show the protocol steps</summary>

1. `server/discover` advertises MCP protocol `2026-07-28` and event support
2. `events/list` describes enabled events and their payloads
3. `events/subscribe` supplies the event name, `{}`, callback URL, and signing secret
4. Callback verification must pass before the subscription becomes active
5. Changed observations enter a persistent queue and are sent with Standard Webhooks signatures
6. The client refreshes expiring subscriptions with `events/subscribe`, and stops them with `events/unsubscribe`

Subscriptions last at most one hour. The client must keep refreshing them. There is no protocol replay (`cursor` is null). An HTTP 2xx acknowledges webhook receipt; the client processes it asynchronously.

See [OpenAI's MCP Events guide](https://developers.openai.com/plugins/build/mcp-events) and [delivery details](docs/OPERATIONS.md).

</details>

## Why does it need OAuth if it's just for me?

Your sources can contain private repository and mail metadata. OAuth lets ChatGPT access the bridge only after you approve it, and lets that access expire or be revoked.

**No separate login server is needed.** OAuth runs in the same Go process using Fosite. You choose a separate bridge owner password, which you enter only on your own bridge domain. Provider access uses separate credentials. GitHub and GitLab tokens are mounted secrets; Proton stores an encrypted refresh session protected by its own mounted secret. [Source authentication](docs/SOURCES.md)

<details>
<summary>How are provider credentials and bridge OAuth different?</summary>

- **GitHub classic personal access token:** reads your notification inbox. Use the `notifications` scope. This GitHub scope also permits notification changes, but this program uses GET only. Fine-grained and GitHub App tokens do not work for this endpoint. [GitHub documentation](https://docs.github.com/en/rest/activity/notifications)
- **Optional provider credentials:** GitLab uses a token; Proton can bootstrap from username/password secrets, then reuse an encrypted refresh session. Interactive `proton-auth` is available when operator action is needed. These are separate from the bridge owner password
- **Bridge owner password:** a strong, unique, 32–72-character ASCII password you supply. It protects the bridge's approval screen; it is not your GitHub password
- **Public OAuth client ID:** matches the client registered in ChatGPT. It is not a password. This service uses authorization code + S256 PKCE, token endpoint authentication method `none`, and no client secret

The example uses OpenAI's documented stable redirect for issuer-aware servers, so you can deploy before registering the connection. Before approving access, compare it with the exact URI in ChatGPT's management page; update and redeploy if different. The service supports one predefined client, not dynamic registration or CIMD. [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth#redirect-url)

</details>

## What do I need before deploying?

- A Linux Docker Swarm, existing Traefik, HTTPS domain, and shared overlay network. The template targets **Traefik v3**; [v2 needs one label change](docs/SWARM.md#using-traefik-v2)
- A registry where you can push your own image, accessible to the chosen Swarm node
- ChatGPT/plugin management access that supports a **predefined public OAuth client** and MCP Events. Work/web, desktop Work with Cloud, or a dot are the documented event surfaces; workspace controls still apply
- A bridge owner password, plus credentials for each enabled source, supplied through your own secure workflow. The default stack needs a GitHub classic token; [optional source setup](docs/SOURCES.md) explains the additional mounts

You can deploy first and register the reachable endpoint afterward. Choose a non-secret public client ID in `.env`; its initial redirect is the documented ChatGPT default. If your account doesn't offer predefined public-client setup or event subscriptions, resolve that before relying on the bridge; don't turn authentication off.

## How do I run it on my Swarm?

1. Copy `.env.example` to `.env` and fill in the domain, Traefik settings, image name, and expected `GITHUB_ACCOUNT`. Choose a public client ID; keep the documented redirect initially. Keep passwords and tokens out of this file
2. Follow the short [Swarm preparation steps](docs/SWARM.md#prepare-the-swarm-once): create your two default secrets manually (plus any optional source secrets), label exactly one state-owning node, and create its persistent volume
3. Load your reviewed configuration, then build and push **your own** image:

   ```sh
   set -a
   . ./.env
   set +a
   docker build --tag "$BRIDGE_IMAGE" .
   docker push "$BRIDGE_IMAGE"
   ```

4. From a Swarm manager with the same variables exported, validate and deploy:

   ```sh
   docker stack config --compose-file stack.yaml > /dev/null
   docker stack deploy --compose-file stack.yaml loop-event-bridge
   docker service ps loop-event-bridge_bridge
   docker service logs --tail 50 loop-event-bridge_bridge
   ```

Swarm does not build images or automatically load `.env`. Repeat the export step after edits and in new shells. Keep one replica and the same volume. [Full setup, private registry notes, and upgrades](docs/SWARM.md)

## How do I choose sources?

Keep the default GitHub-only settings, or independently set `GITHUB_ENABLED`, `GITLAB_ENABLED`, and `PROTON_ENABLED` in `.env`. Enabling GitLab or Proton also requires the source's credentials and the optional secret mounts described in [Sources](docs/SOURCES.md). Merely setting the flag is not enough.

`bridge_status` reports health for each source. An enabled source with bad credentials remains visible with a safe error; disabling it removes its event from discovery and stops its poller. The existing GitHub event name, payload, token settings, and saved baseline remain compatible.

<details>
<summary>GitHub token configuration and precedence</summary>

The process supports two options:

- `GITHUB_TOKEN_FILE`: path to a mounted token file (recommended; the Swarm template uses `/run/secrets/github_token`)
- `GITHUB_TOKEN`: token supplied directly in the process environment, used only when `GITHUB_TOKEN_FILE` is unset or empty

Leading and trailing whitespace is trimmed in either case. A configured file always takes precedence; an unreadable, empty, or malformed file fails GitHub polling instead of falling back to the environment. Other configured sources and bridge OAuth remain available. Tokens must be single ASCII values without internal whitespace or control characters; GitHub validates the credential and its permissions when polling. If neither option supplies a token, the server can start for offline checks, but GitHub polling cannot succeed.

Token values are excluded from logs, errors, and status responses. Environment variables may be visible through container/service inspection and process tooling, so prefer mounted secrets and never commit token values to `.env`, stack files, or source control. The supplied Swarm template continues to use the file option; an exported host `GITHUB_TOKEN` is not automatically passed into its container.

</details>

## How do I know it actually works?

1. In ChatGPT's MCP management page, add `https://YOUR_DOMAIN/mcp` using OAuth, a predefined public client with your configured ID, and authentication method `none`. **Before approving access**, compare the displayed redirect URI with `.env`; update and redeploy if different. Then connect, enter your bridge owner password on your bridge's HTTPS approval page, and check for `bridge_status`
2. Ask ChatGPT: **“Subscribe to `bridge.test` with arguments `{}` and tell me when the test arrives.”** With `CALLBACK_HOSTS` initially empty, the subscription is refused and reports `requestedHost`. If ChatGPT hides that error detail, note the time of your deliberate test request and check the bridge service logs (for example, `docker service logs --since 5m loop-event-bridge_bridge`) for `events/subscribe callback denied: requestedHost="…"`. This diagnostic logs only the parsed, quoted hostname, never the callback URL or signing secret; an empty hostname means the URL could not provide one. Correlate the log timestamp with your test before using it
3. Verify that hostname belongs to the expected client callback. Put the exact hostname in `CALLBACK_HOSTS`, reload `.env`, redeploy the same stack, and retry the subscription. The diagnostic is untrusted input, not proof of ownership or automatic approval. No wildcard or guessed hosts
4. After subscription and callback verification succeed, run this **on the node hosting the bridge**:

   ```sh
   docker ps --filter label=com.docker.swarm.service.name=loop-event-bridge_bridge
   docker exec YOUR_RUNNING_CONTAINER_ID /loop-event-bridge emit-test
   ```

5. Confirm ChatGPT receives the test and responds. Then ask it to monitor the desired enabled source event (`github.notification.changed`, `gitlab.todo.changed`, or `proton.mail.received`) with `{}` and your instructions
6. Test stopping monitoring, and verify `bridge_status` shows the subscription removed. Restart the service and confirm unchanged notifications are not resent

## What should I keep in mind?

Polling defaults to 300 seconds, with a 60-second minimum; GitHub can require a longer wait. Rapid updates may combine into one observation. There is no lossless event history, and retries can produce duplicates.

Keep `/data/state.json` **and** `/data/oauth.json`: they hold delivery/deduplication state, provider checkpoints, and OAuth credentials. If Proton is enabled, also preserve `/data/proton-session.json` and its separate encryption key securely. Protect backups. This is a single-owner service and has not had an independent security audit.

[Sources and credentials](docs/SOURCES.md) · [Operations and limitations](docs/OPERATIONS.md) · [Development](docs/DEV.md) · [Verification record](VERIFICATION.md)
