# Proton direct events (experimental)

The optional Proton source uses Proton's own [`go-proton-api`](https://github.com/ProtonMail/go-proton-api/tree/390fd389be646b9ac79bc848f57a198e0573c517), pinned to `v0.0.0-20261002101729-390fd389be64`. It polls the direct event API. It does not use IMAP, Proton Mail Bridge, Hydroxide, mailbox key decryption, or a paid-plan workaround.

Account/authentication tests use synthetic data. Successful real-account login, free-account access, and event delivery are **not established**. The explicit compatibility identity below passed credential-free public-endpoint checks; those checks do not establish authenticated access or Proton endorsement. The API/client can change, refuse an application, request human verification, or restrict an account. This integration must fail closed in those cases; do not misrepresent another official application's identity to evade restrictions.

## Application identity and compatibility configuration

Set the complete application identity explicitly:

```sh
PROTON_APP_VERSION='Other'
```

`Other` is the current recommended compatibility value. On **2026-10-07, 04:47–04:48 UTC**, credential-free GET requests with `x-pm-appversion: Other` returned **HTTP 200 / API code 1000** at both `https://mail.proton.me/api/auth/v4/modulus` (this integration's endpoint) and `https://mail-api.proton.me/auth/v4/modulus`. Existing third-party clients also use this value. It does not claim to be Proton's web client or official Bridge. This is evidence of acceptance at those public endpoints, **not** vendor endorsement, an integration registration, or proof of successful login, account eligibility, free-plan access, human/email verification, or event delivery. Proton can change this compatibility behavior.

The binary deliberately keeps this setting explicit: there is no automatic identity discovery or runtime default. The SDK's default `go-proton-api` is explicitly unsuitable for production, and `WithAppVersion` sends the supplied value unchanged. Operators no longer need to find or copy a frontend release number. Existing v0.2.0 already accepts the explicit `Other` value; this patch adds earlier invalid-value detection and safe diagnostics.

A bare frontend version such as `5.0.134.11` is not an application identity: Proton rejects it with API code **2064**, before account credentials can be checked. A common first-party convention is `platform-product@version`, but it is not a universal grammar. Local validation therefore rejects only bare numeric frontend versions, whitespace/control characters, non-ASCII header values, and oversized values. Other explicit identifiers, including `Other`, are passed to Proton for validation. It does not enforce three-component semantic versions or block identifiers merely for omitting a dash or `@`.

Two invented product identities were rejected in credential-free checks on the same date: `linux-loop_event_bridge@0.1.0` returned HTTP **400** / API **2064**, and `external-mail-loop_event_bridge@0.1.0-stable` returned HTTP **400** / API **5002**. These are rejected research candidates, not configuration examples. Their rejection does not show that all third-party identities fail. Proton's Drive-specific external-client naming policy does not establish a Mail naming policy. Do not substitute `web-mail`, `linux-bridge`, or another first-party identity to evade an access restriction.

If `Other` is rejected, preserve the safe diagnostics below and stop. If a human-verification challenge appears, inspect `offered_methods` and use the bounded interactive flow below when `email` or `captcha` is offered. Do not repeatedly restart password login, bypass verification, or assume that a public modulus check or successful browser login validates this API client’s account access.

## Persistent-service setup

The normal unattended path can bootstrap from username/password, then reuse an encrypted refresh session across restarts. All settings are operator/server-side only; none is an MCP argument or public HTTP parameter.

| Setting | Purpose |
| --- | --- |
| `PROTON_ENABLED=true` | Explicit opt-in; default is false |
| `PROTON_USERNAME`, `PROTON_PASSWORD` | Initial bootstrap credentials, only when the session file is absent |
| `PROTON_USERNAME_FILE`, `PROTON_PASSWORD_FILE` | Private mounted files; each takes strict precedence over its environment value |
| `PROTON_SESSION_FILE` | Encrypted persistent session; default `/data/proton-session.json` |
| `PROTON_SESSION_KEY_FILE` | Separate private file containing exactly 32 **raw bytes** |
| `PROTON_APP_VERSION` | Explicit application identity; recommended compatibility value `Other`, public-endpoint tested as described above |
| `PROTON_ACCOUNT_ID` | Optional immutable account-ID pin, learned from operator login or authenticated session |

Docker secrets are preferable to environment passwords because environment variables can be inspected by container administrators and may appear in diagnostic output. Secret files must be regular files, private to the service UID (`0400` or `0600`), and cannot be final-component symlinks. A configured missing/unreadable/empty file fails; it never silently falls back to an environment value. Secret-file trailing CR/LF is stripped; other password whitespace is preserved. Use directories controlled by the operator.

Generate the encryption key on the server, not in chat or a shell argument:

```sh
umask 077
openssl rand -out /secure/proton-session.key 32
```

Keep this key outside the session's data volume and backups, and mount it read-only. The image runs as UID/GID `65532`; Swarm secret mounts should specify that ownership and `mode: 0400`. A key is still required when username/password bootstrap is used. Losing or replacing it makes the old session unreadable and requires deliberate recovery. Do not point the session file at `state.json`, OAuth storage, or the key file.

Use the commented optional mounts in [`../stack.yaml`](../stack.yaml) for Swarm. Explicitly configure `PROTON_APP_VERSION=Other`, mount both bootstrap secrets plus the session-encryption key, and enable the source only when ready for an authorized authentication attempt. No actual account bootstrap or deployment was performed while developing this change.

On the first poll, the adapter makes at most **one password-login attempt per process**, verifies the immutable user ID, saves only the encrypted refresh session, and starts a no-notification metadata baseline. If login needs TOTP, FIDO2, human verification, or any other intervention, it stops attempting password login for that process and reports operator action required. A deliberate service restart can retry after the operator resolves the problem. It does not repeatedly try passwords every polling interval. Confirmed revoked/invalid-refresh authentication discovered later also marks `needsAction` and stops further authenticated polling for that process; ordinary network errors remain retryable.

After a session is established, the source refreshes that session across restarts and does not read the password or password file. Remove bootstrap password configuration/secrets from the service when practical. Username configuration may also be removed: the encrypted session retains the account binding. If a username remains configured, its normalized hash must match the saved session; a configured username file must remain readable. The password is never serialized into the session, bridge state, payload, or logs. Environment secrets remain visible to privileged administrators until removed from deployment configuration.

A missing session permits bootstrap. A corrupt, unreadable, wrong-key, or mismatched existing session does **not** permit automatic password login or replacement. Restore the correct key/session or preserve the bad file and deliberately move it aside after checking the cause. Existing bridge checkpoints continue to pin the immutable account, even when the optional `PROTON_ACCOUNT_ID` is omitted.

## Optional interactive authentication

`proton-auth` is a fallback for TOTP accounts, human verification, or operators who do not want to configure bootstrap credentials. It requires an actual Unix terminal for both input and output, uses no-echo input, and rejects piped credentials and redirected output. It never asks for a separate mailbox password. TOTP and the exact advertised `email` or `captcha` human-verification methods are supported. Human verification is separate from account TOTP: it can be requested even when no authenticator is configured, and does not skip TOTP when TOTP is configured.

1. Keep the source disabled while retaining the mounted encryption key and writable persistent data volume. Other sources may keep running. If it was already enabled, disable/restart it first so its lifetime session lock is released
2. Set `PROTON_SESSION_FILE`, `PROTON_SESSION_KEY_FILE`, and `PROTON_APP_VERSION=Other`; optionally set `PROTON_ACCOUNT_ID`
3. Run on the server with a terminal:

```sh
docker exec -it <bridge-container> /loop-event-bridge proton-auth
```

4. Enter credentials directly in that terminal. If Proton returns code `9001`, the CLI reports the offered methods using safe allowlisted names. At the `auth` step:
   - If `email` is offered, enter an email address you can receive at to explicitly request one verification email from Proton, then enter the six-digit code. The address is never inferred from your login or printed. Blank input or Ctrl-C cancels
   - Otherwise, if `captcha` is offered, the CLI displays a private challenge-specific `https://verify.proton.me/` link. Open it directly in your own browser, complete the CAPTCHA yourself, and press Enter in the waiting terminal only after Proton confirms verification. Ctrl-C cancels. Do not restart the command between opening the link and pressing Enter
   - If TOTP is configured, its separate prompt follows
5. Only after login, any configured TOTP, and the immutable account check succeed, the CLI prints the account ID for optional `PROTON_ACCOUNT_ID` pinning and saves encrypted session state
6. Enable/restart the source. Initial metadata establishes the baseline without historical notifications

The email flow uses the pinned SDK’s `SendVerificationCode` with the operator-provided destination, then `NewClientWithLoginWithHVToken` with an email proof. Each invocation permits one initial login, one email request, and one explicit code submission. Automatic password-login, email-send, and email-code retries remain disabled. The SDK’s existing authenticated-session refresh behavior is unchanged. A wrong/expired code, resend failure, repeated challenge, or network failure ends that attempt; there is no resend loop or automatic second attempt. Each network operation has its own one-minute timeout; time spent reading the email or typing is outside that timeout. The password is kept only for the bounded interactive login and cleared from its input buffer afterward.

The browser CAPTCHA path follows Proton Bridge's external-browser flow: Proton's verification page associates the completed challenge with its original token, and the waiting CLI uses `NewClientWithLoginWithHVToken` once with that token and the exact `captcha` method. The CLI does not solve or automatically open the challenge, embed the page, run a callback server, import cookies, or extract tokens from your browser. Keep the displayed private link out of recordings, screenshots, logs, and chat; opening it can leave it in your browser history. The integration does not persist the link or challenge token. A wrong/expired challenge, a repeated challenge, or a network failure stops the invocation without another attempt. Waiting for you is outside the one-minute network timeouts.

`sms`, `payment`, `invite`, `coupon`, `ownership-email`, `ownership-sms`, and unknown methods are explicitly unsupported. In particular, `ownership-email` is a different token-bound flow and is never treated as `email`. The SDK attaches these verification headers only at `auth`, so a challenge at `auth-info` or another step stops without a verification prompt. Missing/malformed method details report `offered_methods=unavailable`; the CLI never assumes a method is offered. If multiple methods include exact `email`, the existing email path is used; otherwise exact `captcha` permits only the CAPTCHA path, even if other methods are also advertised. Missing, oversized, or unsafe challenge tokens stop without displaying a URL. The API identity is unchanged. Real-account success with this compatibility identity remains unverified.

Successful authentication saves the SDK's encrypted account ID, session UID, and refresh token through the existing session store. A normal web-login cookie is not a drop-in input to that store. This handoff completes the CLI's own pending verification and then saves its own authenticated refresh session; there is no browser-session import feature.

On cancellation or authentication failure, no new session file is created and existing session ciphertext is left unchanged. A new remote login that later fails TOTP or account checks is cleaned up on a best-effort basis. Success remains subject to Proton accepting the destination, code, account, and SDK flow; mocked tests do not establish real-account acceptance.

For a standalone Unix installation, run `./loop-event-bridge proton-auth` with those variables set and appropriate private paths. The command takes no credential flags. Existing session ciphertext must be valid and decryptable before the CLI can replace it, and reauthentication must remain on its saved account. Changing accounts intentionally requires distinct bridge state and session files.

The session uses AES-256-GCM with random nonces and authenticated version context. Writes are atomic, `0600`, and fsynced along with the containing directory. Refresh-token rotations are synchronously persisted before further authenticated requests; a persistence error stops that session for the process. The session lock prevents simultaneous service/CLI writers and releases automatically when a process exits. A crash between Proton rotating a token and local persistence can still require manual reauthentication; no client-side file transaction can make the remote and local operations atomic.

## Safe authentication diagnostics

Authentication errors retain only locally selected wording and these safe fields:

- `stage`: an allowlisted authentication step (`configuration`, `login`, `auth-info`, `auth`, `totp`, `user`, `refresh`, `modulus`, `verification-email`, or `unknown`). `configuration` means local validation failed before authentication. For an SDK operation involving several requests, this identifies its last observed request, not a claim that a later local SRP/proof calculation succeeded
- `http_status`: numeric HTTP status, or `0` if unavailable
- `api_code`: numeric Proton API error code, or `0` if unavailable/unparseable
- `offered_methods`: for API code `9001` only, deduplicated local allowlisted names; unknown provider strings become `unknown`, and missing/malformed method details become `unavailable`. These are advertised options, not a claim that an option has succeeded

Example of a rejected identity: `invalid Proton application-version configuration ... (stage=auth-info http_status=400 api_code=2064)`. Code **2064** covers invalid platform/product identity, not just a missing dash; **5002** also identifies invalid version configuration. Codes **5001** and **5003** remain application-version failures. Code **9001** identifies human verification. For example, `stage=auth http_status=422 api_code=9001 offered_methods=email,captcha` permits the interactive email path, whereas `offered_methods=ownership-email` does not. Code **12087** can indicate a rejected verification proof; the CLI stops rather than repeatedly submitting it. An unknown provider error remains a generic authentication failure with the same safe numeric fields.

Diagnostics never print SDK error chains, response bodies, headers, request URLs, usernames, passwords, TOTP/email codes, email destinations, access/refresh tokens, raw human-verification details, or challenge tokens. The deliberate exception is the browser handoff link displayed once to the operator's terminal, where its validated, URL-encoded challenge token is necessary to complete verification. The origin is fixed to `https://verify.proton.me/`; arbitrary provider URLs and method strings are never forwarded. The link does not appear in returned errors, service logs/status, or saved sessions. A malformed non-JSON error response still preserves an available HTTP status. The service keeps sanitized authentication diagnostics in source status and logs; a latched failure retains them without attempting login again. Failed bootstrap does not create a session, and a rejected refresh does not replace the existing encrypted session. Ordinary network/temporary refresh failures remain retryable; confirmed authentication/configuration rejections require operator action.

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

Tests use mock SDK HTTP responses, fake mailbox events, temporary synthetic credentials, and local session files. They cover baseline/restart behavior, incoming filters, inclusive pagination, recovery, duplicate suppression, account binding, session encryption/tamper detection, permissions, locks, refresh rotation, file precedence, once-only bootstrap, unsupported authentication, bounded responses, and secret-free errors. Interactive synthetic coverage includes offered-method redaction, email request/proof construction, distinct ownership challenges, manual CAPTCHA handoff and original-token SDK headers, fixed-origin query encoding, invalid challenge tokens, mixed methods, unsupported stages, rejected verification, cancellation, one-attempt limits, optional TOTP, account matching, and unchanged session ciphertext on failure. Real Proton login and downstream account delivery remain unverified.

Primary API references at the pin:

- [`manager_builder.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/manager_builder.go): verbatim `x-pm-appversion` header and explicit production-default warning
- [`proton-cal` application identity and SDK configuration](https://github.com/cheeseandcereal/proton-cal/blob/5ff2791a0823ffbd592c3c95808819d40d4e639a/pkg/papi/papi.go#L32-L62): third-party consumer of the official library using `Other`
- [`simplelogin-proton-contacts` session setup](https://github.com/nimser/simplelogin-proton-contacts/blob/0bc66498c14c20c595467c70b09f320ddc59ed3d/internal/protonx/session.go#L27): another direct official-library consumer using `Other`; neither consumer is a Proton endorsement of this integration
- [Official Bridge identity construction](https://github.com/ProtonMail/proton-bridge/blob/b9c5dac1651437100c40896dacd778a0518a26f2/internal/constants/version_default.go) and [platform/product constants](https://github.com/ProtonMail/proton-bridge/blob/b9c5dac1651437100c40896dacd778a0518a26f2/internal/constants/constants.go): first-party format evidence, not permission to reuse its identity
- [Proton Drive SDK personal-project guidelines](https://github.com/ProtonDriveApps/sdk#usage-guidelines-for-personal-projects): Drive-specific external-client naming; does not establish a Mail identity
- [Mail API application-registration question](https://github.com/ProtonMail/go-proton-api/issues/227): an open question, not an accepted registration procedure or identity
- [`manager_auth.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/manager_auth.go): SRP login, refresh, and `NewClientWithLoginWithHVToken`
- [`hv.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/hv.go) and [`manager_user.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/manager_user.go): challenge parsing, SDK headers, and verification-email request
- [Official WebClients human-verification helper](https://github.com/ProtonMail/WebClients/blob/dae7e8b5556622c83e17ab132dce703717ca7091/packages/components/containers/api/humanVerification/helper.ts) and [user API request definitions](https://github.com/ProtonMail/WebClients/blob/dae7e8b5556622c83e17ab132dce703717ca7091/packages/shared/lib/api/user.ts): plain email destination/code proof format and the separate ownership-verification flow
- [Official WebClients verification form](https://github.com/ProtonMail/WebClients/blob/dae7e8b5556622c83e17ab132dce703717ca7091/packages/components/containers/api/humanVerification/VerifyCodeForm.tsx): six-digit numeric email-code validation
- [Official Proton Bridge CLI](https://github.com/ProtonMail/proton-bridge/blob/b9c5dac1651437100c40896dacd778a0518a26f2/internal/frontend/cli/accounts.go), [verification URL construction](https://github.com/ProtonMail/proton-bridge/blob/b9c5dac1651437100c40896dacd778a0518a26f2/internal/hv/hv_default.go), and [SDK continuation](https://github.com/ProtonMail/proton-bridge/blob/b9c5dac1651437100c40896dacd778a0518a26f2/internal/bridge/user.go): manual external-browser link, Enter, and reuse of original challenge details. This integration independently implements that protocol and deliberately does not reproduce upstream's challenge-token logging
- [Official external verification app](https://github.com/ProtonMail/WebClients/blob/dae7e8b5556622c83e17ab132dce703717ca7091/applications/verify/src/app/Verify.tsx) and [verification API definitions](https://github.com/ProtonMail/WebClients/blob/dae7e8b5556622c83e17ab132dce703717ca7091/packages/shared/lib/api/verification.ts): a non-embedded, manually solved CAPTCHA grants a redeemable proof on the original challenge token
- [`event.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/event.go) and [`event_types.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/event_types.go): direct events and refresh flags
- [`message.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/message.go) and [`server/server_test.go`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/server/server_test.go): metadata-only and inclusive `EndID` pagination
- [`LICENSE`](https://github.com/ProtonMail/go-proton-api/blob/390fd389be646b9ac79bc848f57a198e0573c517/LICENSE): MIT
