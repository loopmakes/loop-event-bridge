# Operations and limits

## What does an event contain?

`github.notification.changed` includes the account login/ID, notification ID, repository, subject type, title, reason, unread flag, update time, and an API URL. Titles and repository names may be private information: subscribe only from a client and conversation where you want to receive them. Notification text is data, never an instruction to execute.

`bridge.test` contains a fixed connectivity-test message. Neither event takes filters; subscribe with `{}`. Use the client instruction to decide which received notifications warrant a response.

## What counts as a change?

The poller verifies the token's user against `GITHUB_ACCOUNT`, then reads the account-wide Notifications endpoint with `all=true` and `participating=false`. It compares stable fingerprints of the returned records. New notifications, changed titles/reasons, and changes to read/unread state can produce events. The bridge itself makes no GitHub writes.

The first **complete** scan establishes a silent baseline, even for an empty inbox. Saved fingerprints survive restart. Failed or incomplete scans leave the last good baseline in place. There are no repository, author, subject-type, or reason allowlists.

<details>
<summary>Polling limits and recovery details</summary>

- Default interval: 300 seconds; configurable range: 60–86,400 seconds
- GitHub's `X-Poll-Interval` and rate-limit/retry signals can delay the next scan further
- Each scan has a two-minute overall deadline and 64 MiB aggregate response budget
- Each response is limited to 10 MiB; pagination is limited to 100 pages of up to 50 notifications
- Hitting a bound is an error, never a silently truncated successful scan
- The implementation fetches full snapshots; it does not currently use conditional ETag/Last-Modified requests

This is an inbox change detector, not a GitHub audit log. Your GitHub notification settings/access limit the source. Deleted/removed notifications and intermediate updates between polls may be missed. Multiple updates can coalesce. After an outage, only changes still visible in the next complete snapshot can be observed. There is no replay for periods when a subscription was expired or absent.

</details>

## Can an event be lost or delivered twice?

Yes. State and queued events are saved together before delivery, and retries keep the same event ID. A crash after the client accepted an event but before the acknowledgment was saved can cause a duplicate.

Delivery uses bounded retries, not a guarantee of eventual delivery. Transient failures retry with backoff up to eight attempts. Permanent 4xx responses, except 408/429, stop retries; 410 also removes the subscription. A full queue stops snapshot advancement.

<details>
<summary>Queue, expiry, and signing details</summary>

- Queue limit: 10,000 entries
- At most 100 terminal failures are retained for seven days; `bridge_status` shows their count
- Expired/revoked subscriptions and their queued events are removed
- A subscription lasts at most one hour and must be refreshed by the client
- A replacement callback signing secret overlaps the old one for five minutes
- Successful callback verification is cached for five minutes by owner, callback, and secret
- Unsubscribe removes the matching subscription and queue; an already in-flight request may finish
- No `gap`, `terminated`, polling-delivery, or streaming-delivery modes are advertised

</details>

## What do I back up?

Keep the entire `/data` volume, especially:

- `state.json`: subscriptions, callback signing secrets, observations, and delivery queue
- `oauth.json`: OAuth keys, clients, grants, and tokens

Stop the service before a consistent backup. Preserve UID/GID 65532 and private file permissions. Encrypt backups and treat them as credentials. Don't share their contents for debugging. Corrupt or invalid persisted state fails startup rather than silently resetting the baseline.

One process owns this volume. Do not scale the service above one or run a replacement at the same time. The pinned local volume has no multi-node high availability.

## How do I stop or revoke access?

To stop one monitor, ask the client to unsubscribe and confirm the subscription count changes. For an immediate full stop, run on a manager:

```sh
docker service scale loop-event-bridge_bridge=0
```

Reapplying the supplied stack starts its one replica again. Changing the owner password or OAuth client/domain configuration and restarting invalidates existing grants; reconnect afterward. Revoke a compromised GitHub token through GitHub and supply a replacement Swarm secret yourself.

Access tokens last 15 minutes; rotating refresh tokens last up to 30 days. The embedded OAuth system is experimental single-owner infrastructure, not an independently audited identity provider. A persistence failure mid-flow can require reconnecting.

## What if setup fails?

- **Service pending:** check the unique node label, its availability, the external volume on that node, image pull access, and the shared overlay network
- **Traefik 404/502:** check its provider/version, `deploy.labels`, network name, port 8080, entrypoint, certificate setup, and any Traefik service-selection constraints
- **OAuth fails:** check HTTPS origin, preserved Host header, exact redirect URI, predefined public client ID, and token endpoint authentication method `none`
- **Subscription returns `requestedHost`:** verify the real client destination, add that exact hostname to `CALLBACK_HOSTS`, and redeploy. Discovery is deliberately available before callback hosts are allowed
- **Polling error:** check the token's expiry, classic-token type, `notifications` scope, and account match; look at `bridge_status` without exposing secrets
- **Test queued but no chat response:** inspect subscription expiry and delivery health. HTTP receipt alone does not prove the client processed the event

Callback connections require HTTPS on port 443 and an exact allowed hostname. They reject non-public addresses, redirects, and environment proxies, while preserving TLS hostname verification. Don't weaken these checks to get a failing destination working.

Logs and `bridge_status` omit secret values, callback URLs, and notification titles. The local healthcheck only means the process responds; it does not prove GitHub polling or callback delivery is healthy.
