#!/usr/bin/env bash
# Packs and installs this extension on a LOCAL Pterodactyl 2.0 dev panel, then runs the passkey suite.
# Never run it against a real panel: it creates and deletes passkeys, changes the extension's settings,
# turns TOTP on and off for the staff account and clears the panel's cache. See README.md here.
#
#   PANEL_DIR=~/dev/panel PANEL_URL=http://localhost:8210 PANEL_DB=panel tests/e2e/run.sh
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
: "${PANEL_DIR:?set PANEL_DIR to the dev panel checkout}"
PANEL_URL=${PANEL_URL:-http://localhost:8210}
PANEL_DB=${PANEL_DB:-panel}
PHP=${PHP:-php}
export PANEL_DIR PANEL_URL PANEL_DB

host=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.urlparse(sys.argv[1]).hostname or "")' "$PANEL_URL")
case "$host" in
    localhost | 127.0.0.1) ;;
    *) echo "refusing PANEL_URL=$PANEL_URL: only localhost or 127.0.0.1" >&2; exit 2 ;;
esac

art() { (cd "$PANEL_DIR" && $PHP -d error_reporting=0 artisan "$@"); }

if [ "${SKIP_INSTALL:-0}" != 1 ]; then
    [ -f "$repo/dist/client.js" ] || { echo "build the extension first (npm run build)" >&2; exit 2; }
    [ -f "$repo/vendor/autoload.php" ] || { echo "install its PHP dependency first (composer install --no-dev)" >&2; exit 2; }
    pack=$(mktemp -d)
    art p:extension:pack "$repo" --output="$pack/panel-passkeys.pteroext" --force >/dev/null
    art p:extension:install "$pack/panel-passkeys.pteroext" --enable --no-interaction --replace >/dev/null
    rm -rf "$pack"
fi

# Running the migration again over the existing tables must change nothing.
art migrate --force --path="extensions/panel-passkeys/database/migrations" >/dev/null

python3 "$here/test_passkeys.py" --base "$PANEL_URL" --instance "$PANEL_DIR" --db "$PANEL_DB"
