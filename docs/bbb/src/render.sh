#!/usr/bin/env bash
# Renders docs/assets/*.svg and docs/bbb/src/*.html to PNG with headless Chrome.
# Fonts (Inter, JetBrains Mono) load from Google Fonts at render time, so you need a network connection.
# Usage: docs/bbb/src/render.sh            (all)
#        docs/bbb/src/render.sh logo hero  (only the named files)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ASSETS="$(cd "$HERE/../../assets" && pwd)"
BBB="$(cd "$HERE/.." && pwd)"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
FONTS='<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=block">'

WANT=" $* "
want() { [ "$WANT" = "  " ] || [[ "$WANT" == *" $1 "* ]]; }

shoot() { # url out w h scale transparent
  local bg=--hide-scrollbars; [ "$6" = 1 ] && bg=--default-background-color=00000000
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --no-first-run --no-default-browser-check \
    --user-data-dir="$TMP/profile" --force-device-scale-factor="$5" --window-size="$3,$4" \
    --virtual-time-budget=8000 "$bg" --screenshot="$2" "$1" >/dev/null 2>&1
  echo "$(sips -g pixelWidth -g pixelHeight "$2" | awk '/pixel/{printf "%s ",$2}') $2"
}

# name  css-width css-height scale transparent
for spec in "logo 256 256 1 1" "banner 1280 420 2 0" "social-preview 1280 640 1 0" "how-it-works 1200 520 2 1"; do
  set -- $spec
  want "$1" || continue
  html="$TMP/$1.html"
  { echo "<!doctype html><meta charset=utf-8>$FONTS<style>html,body{margin:0;background:transparent}svg{display:block}</style>"; cat "$ASSETS/$1.svg"; } > "$html"
  shoot "file://$html" "$ASSETS/$1.png" "$2" "$3" "$4" "$5"
done

for spec in "icon 512 512" "hero 1600 800" "features 1600 900" "security 1600 900" "shot-signin 1600 900" "shot-account 1600 900" "shot-prompt 1600 900"; do
  set -- $spec
  want "$1" || continue
  shoot "file://$HERE/$1.html" "$BBB/$1.png" "$2" "$3" 1 0
done
