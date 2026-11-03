# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-02

First public release.

### Added
- "Sign in with a passkey" under the panel's sign-in form: discoverable credentials, no username needed, user
  verification required, so a passkey sign-in completes two-step on its own.
- Account → Passkeys card: add (current password, a suggested device name), list with "synced" badge, added date
  and last use, and remove (current password).
- One-time dashboard notice inviting accounts without a passkey to add one; dismissal is stored on the account.
- Admin settings: passkeys per account (default 10, up to 25), the dashboard notice, and the change emails.
- `panel-passkeys:clear <user>` to list and remove an account's passkeys.
- Email to the account owner when a passkey is added or removed; activity log entries for sign-ins, additions
  and removals.
- Strict origin check against `APP_URL`, single-use 5-minute challenges bound to the session, signature counter
  clone detection, random user handles, attestation `none`, the panel's login lockout shared with password
  sign-in, and session-only management (no API keys).
- `PANEL_PASSKEYS_TABLE_PREFIX` to reuse the tables of an earlier install.
- End-to-end suite (85 checks) with a software authenticator against a local panel.

[1.0.0]: https://github.com/jackh54/pterodactyl-panel-passkeys/releases/tag/v1.0.0
