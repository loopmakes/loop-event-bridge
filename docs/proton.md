# Proton direct events (experimental)

The optional Proton source uses Proton's own [`go-proton-api`](https://github.com/ProtonMail/go-proton-api/tree/390fd389be646b9ac79bc848f57a198e0573c517), pinned to `v0.0.0-20261002101729-390fd389be64`. It polls the direct event API. It does not use IMAP, Proton Mail Bridge, Hydroxide, mailbox key decryption, or a paid-plan workaround.

Only synthetic tests have been run. Successful real-account login, free-account access, event delivery, and Proton acceptance of this application's version are **not established**. The API/client can change, refuse an application, request human verification, or restrict an account. This integration must fail closed in those cases; do not misrepresent another official application's identity to evade restrictions.

## Persistent-service setup

The normal unattended path can bootstrap from username/password, then reuse an encrypted refresh session across restarts. All settings are operator/server-side only; none is an MCP argument or public HTTP parameter.

| Setting | Purpose |
| --- | --- |
| `PROTON_ENABLED=true` | Explicit opt-in; default is false |
| `PROTON_USERNAME`, `PROTON_PASSWORD` | Initial bootstrap credentials, only when the session file is absent |
| `PROTON_USERNAME_FILE`, `PROTON_PASSWORD_FILE` | Private mounted files; each takes strict precedence over its environment value |
| `PROTON_SESSION_FILE` | Encrypted persistent session; default `/data/proton-session.json` |
| `PROTON_SESSION_KEY_FILE` | Separate private file containing exactly 32 **raw bytes** |
| `PROTON_APP_VERSION` | Required application/version value accepted by Proton; no default or impersonated identifier |
| `PROTON_ACCOUNT_ID` | Optional immutable account-ID pin, learned from operator login or authenticated session |

Docker secrets are preferable to environment passwords because environment variables can be inspected by container administrators and may appear in diagnostic output. Secret files must be regular files, private to the service UID (`0400` or `0600`), and cannot be final-component symlinks. A configured missing/unreadable/empty file fails; it never silently falls back to an environment value. Secret-file trailing CR/LF is stripped; other password whitespace is preserved. Use directories controlled by the operator.

Generate the encryption key on the server, not in chat or a shell argument:

```sh
umask 077
openssl rand -out /secure/proton-session.key 32
```

Keep this key outside the session's data volume and backups, and mount it read-only. The image runs as UID/GID `65532`; Swarm secret mounts should specify that ownership and `mode: 0400`. A key is still required when username/password bootstrap is used. Losing or replacing it makes the old session unreadable and requires deliberate recovery. Do not point the session file at `state.json`, OAuth storage, or the key file.

For Swarm, use the commented optional mounts in [`../stack.yaml`](../stack.yaml). Supply an application/version value accepted by Proton, mount both bootstrap secrets plus the session-encryption key, and enable the source. No actual account bootstrap or deployment was performed while developing this change.

On the first poll, the adapter makes at most **one password-login attempt per process**, verifies the immutable user ID, saves only the encrypted refresh session, and starts a no-notification metadata baseline. If login needs TOTP, FIDO2, human verification, or any other intervention, it stops attempting password login for that process and reports operator action required. A deliberate service restart can retry after the operator resolves the problem. It does not repeatedly try passwords every polling interval. Confirmed revoked/invalid-refresh authentication discovered later also marks `needsAction` and stops further authenticated polling for that process; ordinary network errors remain retryable.

After a session is established, the source refreshes that session across restarts and does not read the password or password file. Remove bootstrap password configuration/secrets from the service when practical. Username configuration may also be removed: the encrypted session retains the account binding. If a username remains configured, its normalized hash must match the saved session; a configured username file must remain readable. The password is never serialized into the session, bridge state, payload, or logs. Environment secrets remain visible to privileged administrators until removed from deployment configuration.

A missing session permits bootstrap. A corrupt, unreadable, wrong-key, or mismatched existing session does **not** permit automatic password login or replacement. Restore the correct key/session or preserve the bad file and deliberately move it aside after checking the cause. Existing bridge checkpoints continue to pin the immutable account, even when the optional `PROTON_ACCOUNT_ID` is omitted.

## Optional interactive authentication

`proton-auth` is a fallback for TOTP accounts or operators who do not want to configure bootstrap credentials. It requires an actual Unix terminal, uses no-echo username/password/TOTP prompts, and rejects piped credentials. It never asks for a separate mailbox password. TOTP is supported; FIDO2-only and human-verification challenges are not automated.

1. Keep the source disabled while retaining the mounted encryption key and writable persistent data volume. Other sources may keep running. If it was already enabled, disable/restart it first so its lifetime session lock is released
2. Set `PROTON_SESSION_FILE`, `PROTON_SESSION_KEY_FILE`, and the accepted `PROTON_APP_VERSION`; optionally set `PROTON_ACCOUNT_ID`
3. Run on the server with a terminal:

```sh
docker exec -it <bridge-container> /loop-event-bridge proton-auth
```

4. Enter credentials directly in that terminal. On success the CLI prints the immutable account ID for optional `PROTON_ACCOUNT_ID` pinning, and writes only encrypted session state
5. Enable/restart the source. Initial metadata establishes the baseline without historical notifications

For a standalone Unix installation, run `./loop-event-bridge proton-auth` with those variables set and appropriate private paths. The command takes no credential flags. Existing session ciphertext must be valid and decryptable before the CLI can replace it, and reauthentication must remain on its saved account. Changing accounts intentionally requires distinct bridge state and session files.

The session uses AES-256-GCM with random nonces and authenticated version context. Writes are atomic, `0600`, and fsynced along with the containing directory. Refresh-token rotations are synchronously persisted before further authenticated requests; a persistence error stops that session for the process. The session lock prevents simultaneous service/CLI writers and releases automatically when a process exits. A crash between Proton rotating a token and local persistence can still require manual reauthentication; no client-side file transaction can make the remote and local operations atomic.

## Events, restart, and reconciliation

`proton.mail.received` contains only:

```json
{"message_id":"opaque-proton-id","received_at":"2026-10-06T00:00:00Z"}
```

Normal polling accepts received-message create events. Drafts, sent mail, outgoing mail, imports, update/delete events, and label/read-flag changes do not produce received events. The fingerprint is the immutable message ID, so subsequent metadata changes do not create another received observation for that ID. Webhook retries can still duplicate delivery. `received_at` is Proton's message metadata `Time` value, converted to UTC; it is not an independent delivery-time measurement.

The first run captures the latest event ID **before** a complete metadata-only snapshot. That snapshot records existing incoming IDs without emitting historical events. The checkpoint, deduplication state, and outbox entries commit together in the bridge state transaction. After restart, the saved cursor resumes polling.

A Proton mail-refresh flag or an expired-event HTTP 404/410 triggers the same metadata reconciliation against the saved IDs, preserving the previous baseline. Pagination uses inclusive `EndID` anchors rather than shifting offsets. The next event poll replays activity after the pre-snapshot cursor, and persistent ID deduplication removes overlap. No message bodies or attachments are requested. The API can return additional metadata such as subject/sender during this read; the adapter drops it and does not save or deliver it.

Bounds: at most 1,000 metadata pages of 100 records (with inclusive boundary overlap), 8 MiB per response, 64 MiB cumulative response data per poll, and a two-minute poll deadline. There is no guarantee that a mailbox of any particular size fits: response size and latency may bind first. Exceeding a bound, partial pagination, malformed data, or failed persistence produces no new checkpoint. Event polling commits bounded complete prefixes of at most 20 SDK fetches; the SDK itself caps each fetch at 50 event responses. `Retry-After` is respected, including long and HTTP-date values. Only the Proton source backs off/fails; other sources and delivery workers continue.

The shared state size limit is 64 MiB. Deduplication IDs are retained, so large or long-lived accounts can reach that limit and require operator planning. Reconciliation can recover only messages still present in the mailbox; an incoming message permanently removed before recovery is unavailable through a later metadata scan. Whole-mailbox recovery can also exceed outbox capacity if too many new messages accumulated; the checkpoint then stays unchanged. This is not an exactly-once guarantee across every external failure or message lifecycle.

## Verification and sources

Tests use mock SDK HTTP responses, fake mailbox events, temporary synthetic credentials, and local session files. They cover baseline/restart behavior, incoming filters, inclusive pagination, recovery, duplicate suppression, account binding, session encryption/tamper detection, permissions, locks, refresh rotation, file precedence, once-only bootstrap, unsupported authentication, bounded responses, and secret-free errors. Real Proton login and downstream account delivery remain unverified.

Primary API references at the pin:

- [`manager_auth.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/manager_auth.go): SRP login and refresh
- [`event.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/event.go) and [`event_types.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/event_types.go): direct events and refresh flags
- [`message.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/message.go) and [`server/server_test.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/server/server_test.go): metadata-only and inclusive `EndID` pagination
- [`LICENSE`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/LICENSE): MIT
