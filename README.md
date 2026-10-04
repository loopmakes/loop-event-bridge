# loop-event-bridge

[![CI](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml/badge.svg)](https://github.com/loopmakes/loop-event-bridge/actions/workflows/ci.yml)

**Your GitHub notification inbox, delivered as MCP Events.** A small Go service for Docker Swarm, behind your existing Traefik. One container includes the poller, event delivery, and OAuth login.

```text
GitHub Notifications inbox
          │  check every 5 minutes
          ▼
  loop-event-bridge ── changed notification ──▶ ChatGPT / dot
          │                                    follows your
          └─ no change? stay quiet             instructions
```

The bridge never calls a model. Quiet checks still use GitHub's API, but send no events.

**Experimental:** automated tests cover the code and offline container startup. A real Swarm + Traefik + ChatGPT connection still needs testing. A successful `bridge.test` response in your chat is the acceptance test, not merely a healthy container or webhook HTTP 200.

## What would I use it for?

For example: someone requests your review on a PR. If GitHub adds or updates a notification in your inbox, the bridge sends `github.notification.changed`. Your instruction to ChatGPT might be:

> Monitor my GitHub notifications. Tell me when something needs my attention, with the repository, title, and reason. Don't change anything on GitHub.

It covers the configured account's **whole Notifications inbox**: all returned repositories, subject types, and reasons, including read notifications. GitHub notification preferences and account access determine what appears there. It cannot see every action across GitHub.

The first complete scan quietly records a starting point, so you won't receive a flood of old notifications. The bridge only makes GET requests to GitHub; it never marks a notification read or done.

## How do MCP Events fit in?

ChatGPT connects to `/mcp`, discovers two event types, then subscribes with a callback destination. Both take empty filter arguments: `{}`.

- `github.notification.changed`: a new or changed inbox notification
- `bridge.test`: a harmless event you trigger locally to check the connection

The bridge checks the callback and signs deliveries. ChatGPT decides what to do with an event using your instructions. The only regular MCP tool is `bridge_status`, which reports polling and delivery health.

<details>
<summary>Show the protocol steps</summary>

1. `server/discover` advertises MCP protocol `2026-07-28` and event support
2. `events/list` describes the two events and their payloads
3. `events/subscribe` supplies the event name, `{}`, callback URL, and signing secret
4. Callback verification must pass before the subscription becomes active
5. Changed observations enter a persistent queue and are sent with Standard Webhooks signatures
6. The client refreshes expiring subscriptions with `events/subscribe`, and stops them with `events/unsubscribe`

Subscriptions last at most one hour. The client must keep refreshing them. There is no protocol replay (`cursor` is null). An HTTP 2xx acknowledges webhook receipt; the client processes it asynchronously.

See [OpenAI's MCP Events guide](https://developers.openai.com/plugins/build/mcp-events) and [delivery details](docs/OPERATIONS.md).

</details>

## Why does it need OAuth if it's just for me?

Your inbox can contain private repository information. OAuth lets ChatGPT access the bridge only after you approve it, and lets that access expire or be revoked.

**No separate login server is needed.** OAuth runs in the same Go process using Fosite. You choose a separate bridge owner password, which you enter only on your own bridge domain. GitHub access uses a different credential stored as a Swarm secret.

<details>
<summary>What are the three authentication settings?</summary>

- **GitHub classic personal access token:** reads your notification inbox. Use the `notifications` scope. This GitHub scope also permits notification changes, but this program uses GET only. Fine-grained and GitHub App tokens do not work for this endpoint. [GitHub documentation](https://docs.github.com/en/rest/activity/notifications)
- **Bridge owner password:** a strong, unique, 32–72-character ASCII password you supply. It protects the bridge's approval screen; it is not your GitHub password
- **Public OAuth client ID:** matches the client registered in ChatGPT. It is not a password. This service uses authorization code + S256 PKCE, token endpoint authentication method `none`, and no client secret

The example uses OpenAI's documented stable redirect for issuer-aware servers, so you can deploy before registering the connection. Before approving access, compare it with the exact URI in ChatGPT's management page; update and redeploy if different. The service supports one predefined client, not dynamic registration or CIMD. [OpenAI authentication guide](https://developers.openai.com/plugins/build/auth#redirect-url)

</details>

## What do I need before deploying?

- A Linux Docker Swarm, existing Traefik, HTTPS domain, and shared overlay network. The template targets **Traefik v3**; [v2 needs one label change](docs/SWARM.md#using-traefik-v2)
- A registry where you can push your own image, accessible to the chosen Swarm node
- ChatGPT/plugin management access that supports a **predefined public OAuth client** and MCP Events. Work/web, desktop Work with Cloud, or a dot are the documented event surfaces; workspace controls still apply
- Your own GitHub classic token and bridge owner password, entered manually into Swarm secrets

You can deploy first and register the reachable endpoint afterward. Choose a non-secret public client ID in `.env`; its initial redirect is the documented ChatGPT default. If your account doesn't offer predefined public-client setup or event subscriptions, resolve that before relying on the bridge; don't turn authentication off.

## How do I run it on my Swarm?

1. Copy `.env.example` to `.env` and fill in the domain, Traefik settings, image name, and expected `GITHUB_ACCOUNT`. Choose a public client ID; keep the documented redirect initially. Keep passwords and tokens out of this file
2. Follow the short [Swarm preparation steps](docs/SWARM.md#prepare-the-swarm-once): create your two secrets manually, label exactly one state-owning node, and create its persistent volume
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

## How do I know it actually works?

1. In ChatGPT's MCP management page, add `https://YOUR_DOMAIN/mcp` using OAuth, a predefined public client with your configured ID, and authentication method `none`. **Before approving access**, compare the displayed redirect URI with `.env`; update and redeploy if different. Then connect, enter your bridge owner password on your bridge's HTTPS approval page, and check for `bridge_status`
2. Ask ChatGPT: **“Subscribe to `bridge.test` with arguments `{}` and tell me when the test arrives.”** With `CALLBACK_HOSTS` initially empty, the subscription is refused and reports `requestedHost`
3. Verify that hostname belongs to the expected client callback. Put the exact hostname in `CALLBACK_HOSTS`, reload `.env`, redeploy the same stack, and retry the subscription. No wildcard or guessed hosts
4. After subscription and callback verification succeed, run this **on the node hosting the bridge**:

   ```sh
   docker ps --filter label=com.docker.swarm.service.name=loop-event-bridge_bridge
   docker exec YOUR_RUNNING_CONTAINER_ID /loop-event-bridge emit-test
   ```

5. Confirm ChatGPT receives the test and responds. Then ask it to monitor `github.notification.changed` with `{}` and your desired instructions
6. Test stopping monitoring, and verify `bridge_status` shows the subscription removed. Restart the service and confirm unchanged notifications are not resent

## What should I keep in mind?

Polling defaults to 300 seconds, with a 60-second minimum; GitHub can require a longer wait. Rapid updates may combine into one observation. There is no lossless event history, and retries can produce duplicates.

Keep `/data/state.json` **and** `/data/oauth.json`: they hold delivery/deduplication state and OAuth credentials. Protect backups. This is a single-owner service and has not had an independent security audit.

[Operations and limitations](docs/OPERATIONS.md) · [Development](docs/DEV.md) · [Verification record](VERIFICATION.md)
