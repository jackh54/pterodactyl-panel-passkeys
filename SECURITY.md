# Security policy

Panel Passkeys is a sign-in method, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through
[GitHub's private vulnerability reporting](https://github.com/jackh54/pterodactyl-panel-passkeys/security/advisories/new)
with:

- what an attacker can do, and what they need first (an account? a stolen cookie? a device? nothing?),
- steps to reproduce on a local panel,
- the panel commit (`2.0-develop`) and extension version.

You'll get an answer within a few days. Fixes are released as a new version with an advisory that
credits you, unless you prefer otherwise.

## Scope

In scope: passkey sign-in (`/extensions/panel-passkeys/passkey/*`), passkey management
(`/api/client/extensions/panel-passkeys/passkeys/*`), challenge handling, credential and counter
storage, the account card, the dashboard notice and the `panel-passkeys:clear` command.

Out of scope: vulnerabilities in Pterodactyl itself (report those to the Pterodactyl project), in a
browser, operating system or passkey provider, in the bundled `lbuchs/webauthn` library (report those
upstream, though a heads-up here is welcome), or that need a root administrator account to exploit
against itself.

## Operator checklist

- Serve the panel over HTTPS only, at exactly the address in `APP_URL`.
- Set `TRUSTED_PROXIES` when the panel is behind a proxy or Cloudflare, so the login lockout and the
  activity log see real client addresses.
- Keep panel mail working, so users hear about passkeys added to their account.
- Keep "require two-factor authentication" on for at least administrators; a passkey sign-in satisfies it.
