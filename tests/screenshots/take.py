#!/usr/bin/env python3
"""
README / listing screenshots from a LOCAL dev panel with the extension installed (never a real panel:
it writes demo passkey rows for `devadmin` and removes them again).

  python3 tests/screenshots/take.py [--base http://localhost:8210] [--db panel_passkeys] [--scheme dark|light]

Needs Python Playwright and Google Chrome, the dev accounts from tests/e2e/README.md and the same
MYSQL_ROOT command. Writes docs/assets/screenshot-{signin,account,card,add,prompt}.png.
"""
import argparse
import os
import subprocess

from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument('--base', default=os.environ.get('PANEL_URL', 'http://localhost:8210'))
ap.add_argument('--db', default=os.environ.get('PANEL_DB', 'panel_passkeys'))
ap.add_argument('--scheme', default='dark', choices=['dark', 'light'])
args = ap.parse_args()

BASE = args.base.rstrip('/')
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'docs', 'assets')
PREFIX = os.environ.get('PANEL_PASSKEYS_TABLE_PREFIX', 'ext_passkeys_user_')
MYSQL = os.environ.get('MYSQL_ROOT', 'docker --context orbstack exec -i v2dev-mariadb mariadb -uroot -pdevroot').split()


def sql(query):
    subprocess.run(MYSQL + ['-N', args.db, '-e', query], check=True, capture_output=True)


def seed():
    sql(f"""
DELETE FROM {PREFIX}passkeys WHERE user_id IN (SELECT id FROM users WHERE username IN ('devadmin', 'staff'));
DELETE FROM {PREFIX}prefs WHERE user_id IN (SELECT id FROM users WHERE username IN ('devadmin', 'staff'));
INSERT INTO {PREFIX}passkeys (user_id, name, credential_id, public_key, sign_count, backup_eligible, last_used_at, created_at, updated_at)
SELECT id, 'iPhone', 'demo-iphone', 'demo', 0, 1, NOW() - INTERVAL 2 HOUR, NOW() - INTERVAL 40 DAY, NOW() FROM users WHERE username = 'devadmin';
INSERT INTO {PREFIX}passkeys (user_id, name, credential_id, public_key, sign_count, backup_eligible, last_used_at, created_at, updated_at)
SELECT id, 'MacBook Pro', 'demo-mac', 'demo', 0, 1, NOW() - INTERVAL 3 DAY, NOW() - INTERVAL 21 DAY, NOW() FROM users WHERE username = 'devadmin';
INSERT INTO {PREFIX}passkeys (user_id, name, credential_id, public_key, sign_count, backup_eligible, last_used_at, created_at, updated_at)
SELECT id, 'YubiKey 5C', 'demo-yubikey', 'demo', 37, 0, NULL, NOW() - INTERVAL 5 DAY, NOW() FROM users WHERE username = 'devadmin';
""")


def unseed():
    sql(f"DELETE FROM {PREFIX}passkeys WHERE credential_id LIKE 'demo-%'")


def sign_in(page, user, password):
    page.goto(BASE + '/auth/login')
    page.fill('input[name="user"], #user, input[autocomplete="username"]', user)
    page.fill('input[type="password"]', password)
    page.keyboard.press('Enter')
    page.wait_for_url(lambda url: '/auth/' not in url, timeout=15000)


def main():
    seed()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel='chrome')
            ctx = lambda: browser.new_context(viewport={'width': 1400, 'height': 1000}, device_scale_factor=2, color_scheme=args.scheme)

            # Guest sign-in page.
            c = ctx()
            page = c.new_page()
            page.goto(BASE + '/auth/login')
            page.get_by_text('Sign in with a passkey').wait_for()
            page.wait_for_timeout(600)
            page.screenshot(path=os.path.join(OUT, 'screenshot-signin.png'), clip={'x': 330, 'y': 160, 'width': 740, 'height': 640})
            c.close()

            # Account page with three passkeys.
            c = ctx()
            page = c.new_page()
            sign_in(page, 'devadmin', 'DevPass-12345!')
            page.goto(BASE + '/account')
            box = page.locator('#passkeys')
            box.get_by_text('YubiKey 5C').wait_for()
            box.scroll_into_view_if_needed()
            page.wait_for_timeout(600)
            page.screenshot(path=os.path.join(OUT, 'screenshot-account.png'), full_page=True)
            box.screenshot(path=os.path.join(OUT, 'screenshot-card.png'))
            page.get_by_role('button', name='Add a passkey').click()
            page.get_by_role('dialog').wait_for()
            page.wait_for_timeout(600)
            page.screenshot(path=os.path.join(OUT, 'screenshot-add.png'))
            c.close()

            # Dashboard notice for an account without passkeys.
            c = ctx()
            page = c.new_page()
            sign_in(page, 'staff', 'StaffPass-12345!')
            page.goto(BASE + '/')
            page.get_by_text('You can now sign in with a passkey').wait_for()
            page.wait_for_timeout(600)
            page.screenshot(path=os.path.join(OUT, 'screenshot-prompt.png'), clip={'x': 0, 'y': 0, 'width': 1400, 'height': 460})
            c.close()
            browser.close()
    finally:
        unseed()


main()
