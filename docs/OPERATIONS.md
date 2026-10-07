# Operations and limits

## What does an event contain?

`github.notification.changed` includes the account login/ID, notification ID, repository, subject type, title, reason, unread flag, update time, and an API URL. Titles and repository names may be private information: subscribe only from a client and conversation where you want to receive them. Notification text is data, never an instruction to execute.

`gitlab.todo.changed` carries pending To-Do metadata, which can include private project names and text. `proton.mail.received` carries only a message ID and receive time. See [source coverage and payloads](SOURCES.md).

`bridge.test` contains a fixed connectivity-test message. No event takes filters; subscribe with `{}`. Use the client instruction to decide which received notifications warrant a response.

## What counts as a change?

For GitHub, the poller verifies the token's user against `GITHUB_ACCOUNT`, then reads the account-wide Notifications endpoint with `all=true` and `participating=false`. It compares stable fingerprints of the returned records. New notifications, changed titles/reasons, and changes to read/unread state can produce events. The bridge itself makes no GitHub writes.

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

## What should the service logs show?

Every GitHub scan logs `GitHub inbox poll started`, then `poll complete` or `poll failed`. Even an empty or unchanged inbox produces a completion line. The timer waits the logged `next_poll_in` **after** the scan finishes; this is not a wall-clock cron job. The default is five minutes, extended by GitHub polling/rate-limit headers or failure backoff.

Successful scans report `observed`, `changed`, `unchanged`, `baseline`, `enqueued` and `duration`. `baseline` counts initial records saved without emitting history; `changed` counts new/changed records after that baseline. `enqueued` counts delivery entries, so multiple subscriptions can make it larger than `changed`, while no active subscriptions makes it zero. Counts are reported only after the snapshot saves successfully. Failed scans report the failing stage, available HTTP status (`0` when unavailable), rate-limit flag, consecutive failures, duration and next delay; they never claim committed changes.

Optional source scans log `source poll complete` or `source poll failed`, with the source name and safe counters. Use `bridge_status.sources` for each source's configuration and polling status (`needsAction` identifies operator setup or reauthentication problems); raw provider errors and response bodies are not logged. Source failures are isolated, while state persistence and delivery remain shared.

Each newly persisted queue entry logs `event enqueued` with `event_id`, `event_name`, `source`, and `subscription_ref`. These fields also appear on `webhook delivery started` and the result line, so one observation can be followed across multiple subscribers, retries and restarts. Generated `evt_…` IDs match the event body's `eventId` and the `webhook-id` header. Subscription references are `sub_sha256_` plus the first 24 hexadecimal characters of SHA-256 of the subscription ID; they are stable labels, not credentials. Malformed/legacy event IDs are hashed similarly rather than printed. Subscription creation/refresh and unsubscribe logs use the same reference.

The start line records serialized `payload_bytes`, whether encoding succeeded, the fixed envelope field names, schema-defined `data_fields` actually present, and a count of other data keys. It does not print the values. The result reports `outcome=success|retry|failed|discarded`, HTTP status (`0` when no response was received, including local rejection), attempt number, duration, retry delay, `state_saved`, and remaining pending/dead counts. `discarded` means its queue entry disappeared while the request was in flight, for example after unsubscribe. If `state_saved=false`, a delivery can repeat even after HTTP success. Idle delivery ticks do not log every second.

`transport_ack=true` means only HTTP 2xx receipt. Processing happens asynchronously at the receiver: it does **not** prove an automation received its payload or a chat response was produced. Response diagnostics include an allowlisted media type (parameters and unknown types are omitted), `response_bytes` read (at most 8,193), `response_complete`, and a fixed `error_class`. No response body is logged. `response_complete=false` means no complete response body was read: no response arrived, reading failed, or the body exceeded the 8,192-byte limit. An HTTP 2xx still acknowledges the delivery even if its body was invalid, preserving existing protocol behavior. A start line without a result can help identify a request interrupted by a process stop; it does not establish receipt.

Authenticated `events/list` calls log the advertised count and allowlisted event names. Repeated calls with the same set are coalesced to one line per minute, with `suppressed_since_last`; a changed set logs immediately. No discovery line means no logged call in that interval, not proof that the client refreshed its cached metadata.

Startup logs include `version`, `revision` and the configured interval. Local builds default to `dev` and use Go VCS metadata where available; builds without revision metadata honestly show `unknown`. Docker builds can set `--build-arg VERSION=… --build-arg REVISION=…`; use the source commit for the latter.

Default operational lifecycle logs contain counters, event correlation and outcomes, not account identities, notification text, repository names, callback URLs, response bodies or credentials. The separate rejected-subscription diagnostic described in the README logs only the requested hostname.

### Temporarily inspect event metadata

Set `EVENT_DEBUG_LOG=true` in the service environment (or `.env` with the supplied stack), reload the configuration and redeploy through your normal workflow. Startup must report `event_debug_log=true`; editing a local `.env` alone does not change a running container. The default is `false`. Only exact `true`, `false`, `1`, or `0` are accepted; empty/unset means off. Invalid values fail startup without printing the value.

Before each delivery attempt, the opt-in mode adds one `event debug` line followed by a JSON object. Its `event` contains the event ID, name, timestamp and allowlisted primitive metadata: for example, GitHub repository/title/reason/notification ID, current GitLab To-Do metadata, or Proton message ID/received time. Normal null cursors are shown; non-null cursor contents are never logged. Unknown keys and values of the wrong type are omitted and counted in `omitted_data_fields`. The mode does not print OAuth/authentication data, callback URLs, signing secrets, signatures, request headers or callback response bodies.

Metadata URL fields have user information, query and fragment removed; unsafe or malformed URLs are omitted. Common URL-like spans inside free-text fields are replaced with `[URL omitted]`. Text is JSON encoded, so control characters cannot create forged log lines. This is **not a general secret scrubber**: actual titles, identifiers and retained metadata URL paths can still contain private or sensitive material. The mode intentionally exposes source content to whoever can read your service logs. Keep access restricted, do not send unreviewed debug logs to external log collectors/support, and turn it off again after diagnosis. Existing retained logs do not disappear when it is disabled.

Each debug message is bounded to 8 KiB excluding the logger's timestamp/prefix. `sanitized_bytes` is the length of the allowlisted sanitized event, not the wire payload. If it will not fit, `truncated=true` replaces `event` with a JSON-encoded `sanitized_excerpt` and adds `sanitized_sha256` for the full sanitized event. The excerpt may cut off a field; it is not a replayable event. The hash excludes omitted raw fields and cannot verify the original webhook signature. Delivery start logs retain the actual serialized `payload_bytes`. Debugging does not change the transmitted event, persisted state, acknowledgment or retries.

### Correlate a connectivity test and a real event

1. Check the running version/revision and `bridge_status`. If event discovery differs between the bridge and client, request `events/list` and compare the server's advertised names before changing subscriptions.
2. Subscribe to `bridge.test` and run `emit-test` once as described in the README. Capture the narrow UTC time window and the `event_id` / `subscription_ref` across enqueue, start and result. A `bridge.test` result proves only that test subscription's path; it does not validate a source subscription.
3. After the source baseline is complete, observe one **new** source update that the provider actually returns in its inbox. For GitHub, wait for the logged poll completion and look for `changed` and `enqueued`; then follow the `github.notification.changed` event's own correlation fields. Several updates between polls can coalesce.
4. Compare the receiver's invocation time and event ID with the bridge's trace. If it wakes without accessible event data despite `transport_ack=true`, retain the IDs, timestamps, running revision and receiver run identifier for receiver-side investigation. The bridge cannot inspect the receiver's internal queue or model/tool handoff. If those traces are unavailable, the cause remains unconfirmed.
5. Keep the test and source evidence separate. Do not replay acknowledged notifications, reset a baseline, edit queue state, or change the envelope solely because the chat response is missing; these actions can duplicate notifications or destroy useful evidence. A read-only provider lookup can recover useful content, but it does not prove what the webhook receiver saw.

## What do I back up?

Keep the entire `/data` volume, especially:

- `state.json`: subscriptions, callback signing secrets, observations, and delivery queue
- `oauth.json`: OAuth keys, clients, grants, and tokens
- `proton-session.json`, if Proton is enabled: the encrypted refresh session. Preserve its separate session-encryption secret securely as well; it is not stored in this volume by the supplied stack

Stop the service before a consistent backup. Preserve UID/GID 65532 and private file permissions. Encrypt backups and treat them as credentials. Don't share their contents for debugging. Corrupt or invalid shared bridge state fails startup rather than silently resetting the baseline. An invalid Proton session fails that source; it is not silently replaced by automatic password login.

One process owns this volume. Do not scale the service above one or run a replacement at the same time. The pinned local volume has no multi-node high availability.

## How do I stop or revoke access?

To stop one monitor, ask the client to unsubscribe and confirm the subscription count changes. For an immediate full stop, run on a manager:

```sh
docker service scale loop-event-bridge_bridge=0
```

Reapplying the supplied stack starts its one replica again. Changing the owner password or OAuth client/domain configuration and restarting invalidates existing grants; reconnect afterward. Revoke a compromised GitHub or GitLab token through its provider and supply a replacement Swarm secret yourself. For Proton session revocation and reauthentication, follow the [operator guide](proton.md). Disabling a source stops its poller; it does not revoke the upstream credential or replace unsubscribing from its events.

Access tokens last 15 minutes; rotating refresh tokens last up to 30 days. The embedded OAuth system is experimental single-owner infrastructure, not an independently audited identity provider. A persistence failure mid-flow can require reconnecting.

## What if setup fails?

- **Service pending:** check the unique node label, its availability, the external volume on that node, image pull access, and the shared overlay network
- **Traefik 404/502:** check its provider/version, `deploy.labels`, network name, port 8080, entrypoint, certificate setup, and any Traefik service-selection constraints
- **OAuth fails:** check HTTPS origin, preserved Host header, exact redirect URI, predefined public client ID, and token endpoint authentication method `none`
- **Subscription returns `requestedHost`:** verify the real client destination, add that exact hostname to `CALLBACK_HOSTS`, and redeploy. Discovery is deliberately available before callback hosts are allowed
- **GitHub polling error:** check the token's expiry, classic-token type, `notifications` scope, and account match; look at `bridge_status` without exposing secrets
- **GitLab polling error:** check `sources.gitlab`, the token mount/expiry/permissions, the expected account, and the HTTPS instance origin
- **Proton polling error:** check `sources.proton`, session/key permissions, expected account ID, client version, and whether manual reauthentication is needed; do not remove shared state
- **Test queued but no chat response:** inspect subscription expiry and delivery health. HTTP receipt alone does not prove the client processed the event

Callback connections require HTTPS on port 443 and an exact allowed hostname. They reject non-public addresses, redirects, and environment proxies, while preserving TLS hostname verification. Don't weaken these checks to get a failing destination working.

Logs and `bridge_status` omit secret values, callback URLs, and notification titles. The local healthcheck only means the process responds; it does not prove any provider polling or callback delivery is healthy.
