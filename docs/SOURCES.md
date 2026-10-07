# Sources and credentials

One process hosts every enabled source, the shared durable outbox, subscriptions, bridge OAuth, and `/mcp`. There is no second service to register in ChatGPT. GitHub stays enabled by default; GitLab and Proton are independent opt-ins.

## Pick the sources you need

| Source | Enable flag and default | Event | What it observes |
| --- | --- | --- | --- |
| GitHub | `GITHUB_ENABLED=true` | `github.notification.changed` | Account-wide Notifications inbox, including read items |
| GitLab | `GITLAB_ENABLED=false` | `gitlab.todo.changed` | Pending To-Dos, a partial view of account activity |
| Proton | `PROTON_ENABLED=false` | `proton.mail.received` | Newly received incoming messages, identifier and receive time only |

Use `true` or `false` for flags. Disabled sources need no usable provider credentials in the process. `events/list` advertises only enabled sources, plus `bridge.test`; every event takes `{}`. An enabled but misconfigured source stays visible with an error in `bridge_status`. A provider configuration or polling error does not stop the other sources, OAuth, or webhook delivery. Shared state, OAuth, HTTP-server, and global configuration failures can still prevent startup.

The default `stack.yaml` mounts GitHub and owner-password secrets only. Optional mounts and top-level secret declarations are commented out, so an unchanged deployment does not require GitLab or Proton credentials. To run without GitHub, set `GITHUB_ENABLED=false`, remove the GitHub entry from the service's `secrets` list and the top-level `github_token` definition, and remove `GITHUB_TOKEN_FILE`. Keep the owner-password secret for bridge OAuth. Do not create a dummy provider token.

Disabling a source stops polling and new subscriptions for it; it does not revoke its upstream credential. Unsubscribe existing monitors before disabling when you also want to stop pending delivery. Keep the persistent volume when changing enabled sources.

## GitHub: existing setup remains compatible

Keep `GITHUB_ACCOUNT` set to the expected login. `GITHUB_TOKEN_FILE` takes precedence over `GITHUB_TOKEN`; the supplied stack mounts `/run/secrets/github_token`. File errors fail the source without silently selecting the environment token. Use a classic personal access token with the `notifications` scope. The implementation only makes GET requests, even though that scope permits notification writes. [GitHub Notifications API](https://docs.github.com/en/rest/activity/notifications)

The event name, payload, existing token variables, and saved version-1 GitHub baseline remain compatible. No migration or deleting `state.json` is needed. The first complete snapshot is silent; later snapshots can report new notifications and changed titles, reasons, or read state. [Full GitHub polling limits](OPERATIONS.md#what-counts-as-a-change)

## GitLab: pending To-Dos

### Configure

- `GITLAB_ENABLED`: `false` by default; set `true` after supplying the token
- `GITLAB_ACCOUNT`: expected account username, checked with `GET /api/v4/user` before reading To-Dos
- `GITLAB_URL`: defaults to `https://gitlab.com`; use an HTTPS instance origin only, such as `https://gitlab.example.com`. Do not include `/api/v4`, an installation subpath, credentials, query, or fragment
- `GITLAB_TOKEN_FILE`: mounted token path, recommended; the example stack uses `/run/secrets/gitlab_token`
- `GITLAB_TOKEN`: direct-process fallback only when the file setting is unset or empty. The supplied stack does not forward an exported host token

Use a personal access token for the expected user with permission to read the user and To-Do endpoints. Choose the least privilege supported by your GitLab installation; `read_api` is GitLab's read-only API scope. Token capability on a live account has not been verified by this change. [GitLab token scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/)

A configured token file always wins. Unreadable, empty, or malformed files fail this source; they do not fall back to `GITLAB_TOKEN`. Outer whitespace is trimmed; tokens must be one ASCII value without internal whitespace or control characters. Token values, provider response bodies, and raw provider errors are excluded from source health and operational logs.

For Swarm:

1. Set the non-secret GitLab settings and `GITLAB_TOKEN_SECRET` in `.env`
2. Create that secret yourself from a private file, using your secure workflow:

   ```sh
   docker secret create "$GITLAB_TOKEN_SECRET" /secure/path/gitlab-token
   ```

3. Uncomment both the `gitlab_token` service mount and its top-level secret declaration in `stack.yaml`. Keep UID/GID `65532` and mode `0400`
4. Reload the reviewed `.env`, validate with `docker stack config`, and redeploy the same stack and volume
5. Check `bridge_status.sources.gitlab`, then subscribe to `gitlab.todo.changed` with `{}`

### Coverage and payload

The adapter reads `GET /api/v4/todos?state=pending`. GitLab exposes To-Dos such as mentions, assignments, and approval requests here; this is **not a full notification inbox**. All returned action and target types are retained. The bridge never marks items read or done. [GitLab To-Do API](https://docs.gitlab.com/api/todos/)

The first complete snapshot is saved silently. Later new or changed pending items produce events. Done, deleted, or inaccessible items disappear from the endpoint; disappearance does not emit an event or prove completion. Intermediate changes between scans may be missed.

Payload fields are `kind` (`todo`), `todo_id`, `account_id`, `account_username`, `instance_url`, `project`, `target_type`, `title`, `action`, `state`, `created_at`, and `updated_at`. The optional `url` is included only when it is a safe same-origin target URL. The title falls back to the To-Do body when no target title is present; this can contain private text. Arbitrary target objects are not forwarded. Subscribe only where that metadata belongs.

Each scan is bounded by 100 pages of up to 100 items, 10 MiB per response, 64 MiB total response bytes, and the shared two-minute source deadline. Hitting a bound or failing partway through leaves the previous snapshot intact. Pagination requests are constructed on the configured origin; redirects and server-provided next-page URLs are not followed. Rate-limit/retry headers and failures can lengthen the next delay. Saved observations are separated by source, instance, and stable account identity.

## Proton: direct API, encrypted session

The optional adapter uses the official [ProtonMail/go-proton-api](https://github.com/ProtonMail/go-proton-api) library directly, confined to HTTPS requests under `https://mail.proton.me/api/`. It does not use IMAP, run Proton Bridge, add a sidecar, or depend on a paid Bridge setup. This does **not** establish free-account compatibility: no live Proton login, mailbox, or free-account test was performed. Proton can reject a client version or require an unsupported challenge.

### Configure

- `PROTON_ENABLED`: `false` by default
- `PROTON_ACCOUNT_ID`: optional extra stable-account-ID pin. Persisted session identity is checked to prevent accidental account switches; one Proton account is supported per instance
- `PROTON_SESSION_FILE`: defaults to `/data/proton-session.json` on the writable persistent volume
- `PROTON_SESSION_KEY_FILE`: path to a separate mounted encryption-key file containing exactly **32 raw random bytes**, not hex or base64 text. Use private `0400`/`0600` file permissions
- `PROTON_APP_VERSION`: explicitly set `Other`, a compatibility identity tested on credential-free public endpoints; not a copied frontend version. There is no automatic runtime default. Public-endpoint acceptance does not establish login, email verification, or account-level access; see [identity details and limits](proton.md#application-identity-and-compatibility-configuration)
- `PROTON_USERNAME_FILE` and `PROTON_PASSWORD_FILE`: optional first-login bootstrap credentials from mounted private files, preferred over environment values
- `PROTON_USERNAME` and `PROTON_PASSWORD`: fallback bootstrap values only when each corresponding file variable is unset or empty. A configured file takes precedence and a broken file does not silently fall back. Do not put values in `.env`, image layers, logs, or source control

### First login and later restarts

With no saved session, the persistent service can authenticate from the configured username/password and save an AES-256-GCM-encrypted refresh session. It attempts automatic password login at most once per process, avoiding retry loops. Later starts use the saved refresh session. Missing credentials, rejected credentials, or a challenge leave Proton unhealthy while other sources keep running. An existing unusable session must be recovered deliberately rather than silently replaced by a new login. No real credentials or authentication were used to develop this source.

For Swarm:

1. Create your private 32-byte key secret and username/password bootstrap secrets through your secure operator workflow. Set their **names** in `.env`, never their values
2. Uncomment the `proton_session_key`, `proton_username`, and `proton_password` service mounts and matching top-level secret declarations in `stack.yaml`. Uncomment `PROTON_USERNAME_FILE` and `PROTON_PASSWORD_FILE` in the service environment too
3. Explicitly configure `PROTON_APP_VERSION=Other`, keep `PROTON_SESSION_FILE` on `/data`, and enable `PROTON_ENABLED=true`. `PROTON_ACCOUNT_ID` is an optional additional pin
4. Reload configuration, validate the stack, redeploy, and inspect `bridge_status.sources.proton`
5. After the encrypted session is saved successfully, remove the username/password environment variables and bootstrap secret mounts/declarations, then redeploy. Keep the session file and encryption key. Remove both inputs: a still-configured username file remains subject to identity checks. This removes the login password from the running service's configuration; Swarm secrets themselves remain until you retire them through your normal workflow

The bridge never writes the password or a TOTP code into the session or shared state. Configured environment values and mounted secrets still exist in the deployment until you remove them. Direct environment variables are supported, but can be exposed through service/process inspection; mounted secrets are preferred.

### When operator authentication is needed

2FA, CAPTCHA/human verification (including email verification), or FIDO2 challenges require operator action; the persistent service does not try to bypass them or repeatedly retry password login. Do not use an automatic restart loop to keep attempting rejected credentials. Safe authentication diagnostics report an allowlisted stage, HTTP status, and numeric API code; codes 2064/5001/5002/5003 identify application-version configuration failures. See [diagnostic details](proton.md#safe-authentication-diagnostics).

`/loop-event-bridge proton-auth` is an optional interactive fallback. It has no credential flags and reads its own username, password, and supported TOTP challenge from a no-echo terminal. It can save the same encrypted refresh session without retaining the password, TOTP, mailbox password, or decryption keys. It cannot complete CAPTCHA/human verification or FIDO2-only authentication. Stop Proton polling before running it against the same session; one process must own session refresh at a time. Other sources can stay enabled while Proton is disabled for this operation.

Follow the complete [Proton operator walkthrough](proton.md) for first-login setup, supported challenges, session recovery, and secret removal.

### Coverage, privacy, and recovery

`proton.mail.received` contains only `message_id` and `received_at` (RFC3339 time). The timestamp is Proton's message metadata `Time` converted to UTC, not an independent delivery-time measurement. It does not include a subject, sender, address, body, attachment, mailbox key, access token, or refresh token. The API can return more metadata internally; the event payload deliberately omits it. Incoming-message creation is observed; outgoing mail, drafts, imports, and label/read-state changes do not produce mail-received events.

On first use, the adapter captures an event cursor and takes a complete bounded incoming-message metadata baseline silently. It does not emit mailbox history. The cursor and deduplication checkpoint are saved with queued deliveries, so a failed save does not advance past undelivered work.

When Proton expires a cursor or requests a mail refresh, the adapter reconciles a bounded incoming-message metadata snapshot against saved message identities. Newly observed IDs can produce catch-up events; old IDs are not deliberately replayed. This is best-effort recovery, not an audit log: mail no longer present in the metadata snapshot, activity outside the provider's retained event history, and incomplete scans can leave gaps. A reconciliation failure does not advance the checkpoint. See [Proton limits and recovery](proton.md).

Keep the encrypted session and its encryption key in separate protected backups. Losing the key makes the session unusable; exposing both compromises it. Reauthentication may be needed after session revocation or refresh failure. A Proton authentication error is isolated to Proton, and is not a reason to delete shared bridge state or reset other sources.

## Shared health and delivery limits

`bridge_status` keeps the existing top-level GitHub status fields and adds `sources.github`, `sources.gitlab`, and `sources.proton`. Each source reports whether it is enabled, its last successful poll, a safe error, a consecutive failure count, and `needsAction`. That flag is true for a configuration problem or a Proton login/reauthentication condition that needs the operator; ordinary transient polling failures leave it false. A successful poll clears the flag. Disabled sources are reported as disabled. A responding healthcheck establishes process liveness only; inspect source and delivery status separately.

`POLL_INTERVAL_SECONDS` applies to the source loops: default 300, accepted range 60–86,400 seconds. Provider limits and failure backoff may lengthen the delay. Pollers are independent, while subscription and outbox storage are shared. A full queue or unwritable shared state can therefore affect every source. Existing bounds include 10,000 queue entries and a 64 MiB persisted-state file.

Subscriptions still expire after at most one hour. There is no downstream event replay cursor, no replay for periods without a live subscription, and no exactly-once guarantee. Keep `state.json` and `oauth.json`; Proton also needs its encrypted session and separate key. [Delivery, backup, and revocation details](OPERATIONS.md)

## Upgrade and rollback

Upgrading preserves existing GitHub subscriptions, baseline keys, queued deliveries, and version-1 state. New per-source checkpoints are additive. Back up the state volume before changing versions. Once optional sources are enabled, do not run an older GitHub-only binary against that active state: its maintenance/save code does not understand the new subscriptions/checkpoints and can discard them. Use a separately reviewed matching backup for a deliberate rollback.

Startup rejects Proton session/key/lock paths that alias shared state, OAuth state, or the owner-password file, including existing hard links and resolved parent-directory aliases. Private/token files must be regular files; FIFOs/devices fail without hanging other sources.
