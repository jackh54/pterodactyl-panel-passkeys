# End-to-end tests (local only)

`run.sh` packs and installs the extension on a **local** Pterodactyl v2 development panel, then
`test_passkeys.py` drives passkey registration, sign-in and management over real HTTP with a software
authenticator (`softauthn.py`): real ES256 credentials, CBOR attestation objects (`none` and `packed`
self attestation) and real assertions. Each negative case tampers with exactly one thing: origin, flags,
signature, challenge, user handle, counter, session, malformed fields. 85 checks; about a minute.

> [!CAUTION]
> Never run it against a real panel. It deletes the passkeys of the test accounts, changes the
> extension's settings, turns TOTP on and off for the `staff` account, creates and deletes a client API
> key and clears the panel's cache (rate limiters). `run.sh` refuses any `PANEL_URL` that is not
> `localhost` or `127.0.0.1`.

## What you need

| Thing | Notes |
|---|---|
| A Pterodactyl v2 dev panel | `2.0-develop`, with `composer install` and `npm run build` done. Its `.env`: `APP_URL` equal to the URL you test (WebAuthn needs `localhost` or HTTPS), `MAIL_MAILER=log`, `TRUSTED_PROXIES=127.0.0.1,::1` (each case uses its own `X-Forwarded-For` address, so one case's lockout doesn't hit the next), no cached config |
| Two accounts without TOTP | `devadmin` / `DevPass-12345!` (root admin, email `dev@passkeys.test`) and `staff` / `StaffPass-12345!` (not admin, email `staff@passkeys.test`), e.g. with `php artisan p:user:make` |
| The panel served locally | e.g. `PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:8210 -t public` from the panel directory |
| A `mariadb` client command for the panel database | `MYSQL_ROOT`, default `docker --context orbstack exec -i v2dev-mariadb mariadb -uroot -pdevroot` |
| Python 3 with `requests` and `cryptography` | |

Build the extension first: `composer install --no-dev && npm run build`.

## Run it

```sh
PANEL_DIR=~/dev/panel PANEL_URL=http://localhost:8210 PANEL_DB=panel \
MYSQL_ROOT='mariadb -h127.0.0.1 -P3306 -uroot -psecret' tests/e2e/run.sh
```

| Variable | Default | |
|---|---|---|
| `PANEL_DIR` | (required) | the dev panel checkout |
| `PANEL_URL` | `http://localhost:8210` | must be local |
| `PANEL_DB` | `panel` | the panel's database |
| `MYSQL_ROOT` | see above | command that runs the `mariadb` client with rights on `PANEL_DB` |
| `PANEL_PASSKEYS_TABLE_PREFIX` | `ext_passkeys_user_` | to test a custom prefix (set it in the panel `.env` too) |
| `SKIP_INSTALL` | `0` | `1` = don't pack and install the extension |

`run.sh` also re-runs the extension's migration over the existing tables (must be a no-op).

## What it covers

- The guest surface: sign-in options (RP id, user verification, no `allowCredentials`), CSRF, and that
  management endpoints need a session.
- Adding passkeys: password confirmation, the opaque user handle, attestation `none` and `packed`,
  duplicates, the per-account limit, names, and everything that must make a registration fail.
- Signing in: the full ceremony, the TOTP checkpoint being skipped, activity log entries, and every
  tampered field (origin, RP id hash, UP/UV flags, signature, challenge, user handle, credential id).
- Counters and replays: clones, counters going backwards, parallel sign-ins with one counter value,
  replay with the pre-login session or in another session, concurrent replays.
- Abuse: one generic error for every failure, failed-login events, the shared login lockout (also
  blocking password sign-in), the per-address request limit, password confirmation limits, other
  users' passkeys, client API keys.
- Admin settings (limit, dashboard notice, emails; validation; guests and non-admins refused) and the
  `panel-passkeys:clear` command (including all-digit usernames), and default ports in `APP_URL`.
