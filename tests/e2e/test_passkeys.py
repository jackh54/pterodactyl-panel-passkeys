#!/usr/bin/env python3
"""
Passkey (WebAuthn) end-to-end for the `panel-passkeys` extension against a LOCAL dev
panel, with a software authenticator. Never run against production.

Requirements on that instance:
  - APP_URL=http://localhost:8210      (WebAuthn needs "localhost" or https for the RP id)
  - TRUSTED_PROXIES=127.0.0.1,::1      (each test case uses its own X-Forwarded-For address, so the
                                        login lockout and limiters of one case don't hit the next)
  - users devadmin / DevPass-12345! and staff / StaffPass-12345! without TOTP (case 29b turns TOTP on
    for staff for one sign-in and back off)
  - MAIL_MAILER=log, Turnstile off
  - pip: cryptography, requests

  python3 tests/e2e/test_passkeys.py [--base http://localhost:8210] [--instance ~/Documents/GitHub/_v2eval/inst-passkeys] [--db panel_passkeys]

The software authenticator builds real ES256 credentials (COSE key, CBOR attestation object
with fmt "none" or "packed" self attestation) and real assertions, then the cases tamper with
exactly one thing each: origin, flags, signature, challenge, user handle, counter, ...
"""
import argparse
import hashlib
import json
import glob
import os
import random
import re
import struct
import subprocess
import sys
import time
import urllib.parse

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ap = argparse.ArgumentParser()
ap.add_argument('--base', default=os.environ.get('PANEL_URL', 'http://localhost:8210'))
ap.add_argument('--instance', default=os.path.expanduser(os.environ.get('PANEL_DIR', '~/Documents/GitHub/_v2eval/inst-passkeys')))
ap.add_argument('--db', default=os.environ.get('PANEL_DB', 'panel_passkeys'))
args = ap.parse_args()

BASE = args.base.rstrip('/')
PREFIX = os.environ.get('PANEL_PASSKEYS_TABLE_PREFIX', 'ext_passkeys_user_')
PASSKEYS, PREFS = PREFIX + 'passkeys', PREFIX + 'prefs'
MYSQL = os.environ.get('MYSQL_ROOT', 'docker --context orbstack exec -i v2dev-mariadb mariadb -uroot -pdevroot').split()
ORIGIN = BASE
RP_ID = urllib.parse.urlparse(BASE).hostname
GENERIC = 'That passkey could not be used to sign in.'
USERS = {'devadmin': 'DevPass-12345!', 'staff': 'StaffPass-12345!'}

# ---------------------------------------------------------------- helpers

from softauthn import AT, BE, BS, UP, UV, SoftAuthenticator, b64u, cbor, configure, unb64u  # noqa: E402,F401

configure(BASE)


class Client:
    """A browser: its own cookie jar and its own client IP (X-Forwarded-For)."""

    def __init__(self):
        self.s = requests.Session()
        self.ip = '10.%d.%d.%d' % (random.randint(0, 255), random.randint(0, 255), random.randint(1, 254))

    def headers(self, xsrf=True):
        h = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest', 'X-Forwarded-For': self.ip,
             'Origin': ORIGIN, 'Referer': ORIGIN + '/auth/login'}
        token = self.s.cookies.get('XSRF-TOKEN')
        if xsrf and token:
            h['X-XSRF-TOKEN'] = urllib.parse.unquote(token)
        return h

    def csrf(self):
        r = self.s.get(BASE + '/sanctum/csrf-cookie', headers=self.headers(False))
        assert r.status_code == 204, r.status_code
        return self

    def req(self, method, path, body=None, xsrf=True, allow_redirects=False):
        return self.s.request(method, BASE + path, json=body, headers=self.headers(xsrf), allow_redirects=allow_redirects)

    def login(self, user):
        self.csrf()
        r = self.req('POST', '/auth/login', {'user': user, 'password': USERS[user], 'cf-turnstile-response': 'XXXX.DUMMY.TOKEN.XXXX'})
        assert r.status_code == 200 and r.json()['data']['complete'], (r.status_code, r.text[:300])
        self.csrf()
        return self

    def passkey_options(self):
        r = self.req('POST', '/extensions/panel-passkeys/passkey/options')
        assert r.status_code == 200, (r.status_code, r.text[:300])
        return r.json()

    def passkey_login(self, body):
        return self.req('POST', '/extensions/panel-passkeys/passkey/login', body)

    def add_options(self, password):
        return self.req('POST', '/api/client/extensions/panel-passkeys/passkeys/options', {'password': password})

    def register(self, user, auth, name='Test key', **kw):
        r = self.add_options(USERS[user])
        assert r.status_code == 200, (r.status_code, r.text[:300])
        body = auth.create(r.json(), **kw)
        body['name'] = name
        return self.req('POST', '/api/client/extensions/panel-passkeys/passkeys', body)

    def list(self):
        r = self.req('GET', '/api/client/extensions/panel-passkeys/passkeys')
        assert r.status_code == 200, (r.status_code, r.text[:300])
        return r.json()


def detail(r):
    try:
        return r.json()['errors'][0]['detail']
    except Exception:
        return r.text[:200]


def sql(query):
    out = subprocess.run(MYSQL + ['-N', args.db, '-e', query],
                         capture_output=True, text=True)
    return out.stdout.strip()


def user_id(name):
    return int(sql(f"SELECT id FROM users WHERE username = '{name}'"))


# ---------------------------------------------------------------- runner

results = []


def check(name, cond, info=''):
    results.append((name, bool(cond)))
    print(('PASS ' if cond else 'FAIL ') + name + ('' if cond or not info else f'  [{info}]'))


def failed_generic(r):
    return r.status_code == 400 and detail(r) == GENERIC


def clear_limiters():
    # Rate limiter state (lockouts, per-user password tries) lives in the instance's cache.
    subprocess.run(['php', '-d', 'error_reporting=0', 'artisan', 'cache:clear'], cwd=args.instance, capture_output=True)


# Clean slate for the two dev accounts.
clear_limiters()
for u in USERS:
    sql(f'DELETE FROM {PASSKEYS} WHERE user_id = {user_id(u)}; DELETE FROM {PREFS} WHERE user_id = {user_id(u)}')
sql("DELETE FROM api_keys WHERE memo = 'passkey-e2e'")

# --- guest surface -----------------------------------------------------------
g = Client().csrf()
r = g.req('POST', '/extensions/panel-passkeys/passkey/options')
opts = r.json() if r.status_code == 200 else {}
pk = opts.get('publicKey', {})
check('01 guest sign-in options: 200, rpId = APP_URL host, UV required, no allowCredentials',
      r.status_code == 200 and pk.get('rpId') == RP_ID and pk.get('userVerification') == 'required' and 'allowCredentials' not in pk,
      r.text[:200])
check('02 sign-in challenge is 32 random bytes', len(unb64u(pk.get('challenge', ''))) == 32)
r = g.req('GET', '/api/client/extensions/panel-passkeys/passkeys')
check('03 account passkey endpoints refuse guests (401)', r.status_code == 401, r.status_code)
r = Client().csrf().req('POST', '/extensions/panel-passkeys/passkey/options', xsrf=False)
check('04 sign-in options without the CSRF token are refused (419)', r.status_code == 419, r.status_code)

# --- registration ------------------------------------------------------------
admin = Client().login('devadmin')
listing = admin.list()
check('05 new account: no passkeys, prompt not dismissed, max 10',
      listing['passkeys'] == [] and listing['prompt_dismissed'] is False and listing['max'] == 10, listing)

r = admin.req('POST', '/api/client/extensions/panel-passkeys/passkeys/options', {})
r2 = admin.add_options('wrong-password')
check('06 creation options need the account password (400 without / wrong)',
      r.status_code == 400 and r2.status_code == 400 and detail(r2) == 'The password provided was not valid.', (r.status_code, r2.status_code))

r = admin.add_options(USERS['devadmin'])
copts = r.json()['publicKey'] if r.status_code == 200 else {}
handle = unb64u(copts.get('user', {}).get('id', ''))
sel = copts.get('authenticatorSelection', {})
check('07 creation options: rp id, resident key + UV required, attestation none',
      r.status_code == 200 and copts['rp']['id'] == RP_ID and sel.get('residentKey') == 'required'
      and sel.get('userVerification') == 'required' and copts.get('attestation') == 'none', copts)
# The user's own identifiers must not be in the handle. A single byte such as b'@' is not checked: 32 random
# bytes contain 0x40 in about 12% of runs.
me = sql("SELECT CONCAT_WS(' ', id, username, email, uuid) FROM users WHERE username = 'devadmin'").split(' ')
idents = [me[1].encode(), me[2].encode(), me[3].encode(), bytes.fromhex(me[3].replace('-', '')), me[3].replace('-', '').encode()]
check('08 user.id is an opaque 32-byte handle (not the id, username, email or uuid)',
      len(handle) == 32 and len(set(handle)) > 8 and not any(i in handle for i in idents)
      and handle not in (me[0].encode(), int(me[0]).to_bytes(8, 'big'), int(me[0]).to_bytes(8, 'little')), (handle.hex(), me))
check('09 user.name is the email, challenge 32 bytes',
      copts.get('user', {}).get('name') == 'dev@passkeys.test' and len(unb64u(copts.get('challenge', ''))) == 32)

key1 = SoftAuthenticator()
body = key1.create({'publicKey': copts}, origin=ORIGIN + '.evil.test')
body['name'] = 'evil'
r = admin.req('POST', '/api/client/extensions/panel-passkeys/passkeys', body)
check('10 registration from a look-alike origin is refused', r.status_code == 400, r.status_code)
body = key1.create({'publicKey': copts})
body['name'] = 'replay'
r = admin.req('POST', '/api/client/extensions/panel-passkeys/passkeys', body)
check('11 registration challenge is single use (consumed by the failed attempt)',
      r.status_code == 400 and 'expired' in detail(r), detail(r))

for label, kw in [('12 registration without user verification is refused', {'uv': False}),
                  ('13 registration without user presence is refused', {'up': False}),
                  ('14 registration with another challenge is refused', {'challenge': b64u(os.urandom(32))}),
                  ('15 registration with clientData type webauthn.get is refused', {'ctype': 'webauthn.get'}),
                  ('16 registration for another RP id is refused', {'rp_id': 'evil.test'}),
                  ('17 registration from https (other scheme) is refused', {'origin': ORIGIN.replace('http://', 'https://')})]:
    r = admin.register('devadmin', SoftAuthenticator(), **kw)
    check(label, r.status_code == 400, (r.status_code, detail(r)))

r = admin.register('devadmin', key1, name='  <b>My</b> <script>x</script>Mac\x07 ')
check('18 valid registration is stored (201) and the name is cleaned',
      r.status_code == 201 and r.json()['name'] == 'My xMac', (r.status_code, r.text[:200]))
listing = admin.list()
check('19 listing shows it with the synced tag and ISO dates',
      len(listing['passkeys']) == 1 and listing['passkeys'][0]['synced'] is True
      and re.match(r'^\d{4}-\d\d-\d\dT', listing['passkeys'][0]['created_at']) is not None
      and listing['passkeys'][0]['last_used_at'] is None, listing)

r = admin.register('devadmin', key1, name='again')
check('20 registering the same credential twice is refused', r.status_code == 400 and 'already registered' in detail(r), detail(r))
r = admin.add_options(USERS['devadmin'])
excl = [c['id'] for c in r.json()['publicKey'].get('excludeCredentials', [])]
check('21 creation options exclude credentials already registered', excl == [b64u(key1.credential_id)], excl)
handle2 = unb64u(r.json()['publicKey']['user']['id'])
check('22 the user handle is stable across ceremonies', handle2 == handle)

key_packed = SoftAuthenticator(sign_count=5, backup_eligible=False)
r = admin.register('devadmin', key_packed, name='Security key', fmt='packed')
check('23 packed self-attestation is accepted', r.status_code == 201, (r.status_code, detail(r)))

# --- sign-in -----------------------------------------------------------------
c = Client().csrf()
r = c.passkey_login(key1.get(c.passkey_options()))
ok = r.status_code == 200 and r.json().get('data', {}).get('complete') is True
check('24 passkey sign-in completes the login (complete, intended "/", user)',
      ok and r.json()['data']['intended'] == '/' and r.json()['data']['user']['username'] == 'devadmin', (r.status_code, r.text[:300]))
c.csrf()
r = c.req('GET', '/api/client/account')
check('25 the session is signed in afterwards', r.status_code == 200 and r.json()['attributes']['username'] == 'devadmin', r.status_code)
row = sql(f"SELECT sign_count, last_used_at IS NOT NULL, last_used_ip FROM {PASSKEYS} WHERE credential_id = '{b64u(key1.credential_id)}'").split('\t')
check('26 last use (time, IP) recorded', row[1] == '1' and row[2] == c.ip, row)
r = c.req('POST', '/extensions/panel-passkeys/passkey/options')
check('27 signed-in users cannot start another passkey sign-in (guest only)', r.status_code in (302, 303), r.status_code)
act = sql("SELECT event FROM activity_logs WHERE event IN ('auth:passkey','auth:success') ORDER BY id DESC LIMIT 2")
check('28 activity log: auth:passkey and auth:success', 'auth:passkey' in act and 'auth:success' in act, act)

# Each negative case below uses a fresh browser (fresh IP, fresh challenge).
failures = []


def neg(label, make_body, expect_generic=True, options=True):
    cl = Client().csrf()
    o = cl.passkey_options() if options else {'publicKey': {'challenge': b64u(os.urandom(32))}}
    r = cl.passkey_login(make_body(o))
    failures.append(r)
    good = failed_generic(r) if expect_generic else r.status_code >= 400
    check(label, good, (r.status_code, detail(r)))
    return cl, r


staff = Client().login('staff')
staff_key = SoftAuthenticator()
r = staff.register('staff', staff_key, name='Staff phone')
check('29 a second account registers its own passkey', r.status_code == 201, (r.status_code, detail(r)))

# Fork behaviour (spec Review Focus): a passkey sign-in is a complete login, so an account with TOTP
# skips the checkpoint. Asserted explicitly so a change is deliberate.
sql(f"UPDATE users SET use_totp = 1 WHERE id = {user_id('staff')}")
try:
    tc = Client().csrf()
    r = tc.req('POST', '/auth/login', {'user': 'staff', 'password': USERS['staff'], 'cf-turnstile-response': 'XXXX.DUMMY.TOKEN.XXXX'})
    pw_checkpoint = r.status_code == 200 and r.json()['data'].get('complete') is False and 'confirmation_token' in r.json()['data']
    tc = Client().csrf()
    r = tc.passkey_login(staff_key.get(tc.passkey_options()))
    data = r.json().get('data', {}) if r.status_code == 200 else {}
    tc.csrf()
    acct = tc.req('GET', '/api/client/account')
    dash = tc.req('GET', '/api/client')
    check('29b TOTP account: password sign-in stops at the checkpoint, but a passkey signs in with no checkpoint and lands on the dashboard',
          pw_checkpoint and data.get('complete') is True and 'confirmation_token' not in data and data.get('intended') == '/'
          and acct.status_code == 200 and acct.json()['attributes']['username'] == 'staff' and dash.status_code == 200,
          (pw_checkpoint, r.status_code, r.text[:200], acct.status_code, dash.status_code))
finally:
    sql(f"UPDATE users SET use_totp = 0 WHERE id = {user_id('staff')}")

neg('30 assertion from a look-alike origin', lambda o: key1.get(o, origin=ORIGIN + '.evil.test'))
neg('31 assertion from another port', lambda o: key1.get(o, origin=ORIGIN + '0'))
neg('32 assertion from https (scheme mismatch)', lambda o: key1.get(o, origin=ORIGIN.replace('http://', 'https://')))
neg('33 assertion without user verification', lambda o: key1.get(o, uv=False))
neg('34 assertion without user presence', lambda o: key1.get(o, up=False))
neg('35 forged signature (another key)', lambda o: key1.get(o, key=ec.generate_private_key(ec.SECP256R1())))
neg('36 assertion over another challenge', lambda o: key1.get(o, challenge=b64u(os.urandom(32))))
neg('37 assertion with clientData type webauthn.create', lambda o: key1.get(o, ctype='webauthn.create'))
neg('38 assertion for another RP id', lambda o: key1.get(o, rp_id='evil.test'))
neg('39 other user\'s handle with this credential', lambda o: key1.get(o, user_handle=staff_key.user_handle))
neg('40 missing user handle', lambda o: key1.get(o, user_handle=None))
neg('41 staff credential presented with admin handle', lambda o: staff_key.get(o, user_handle=key1.user_handle))
neg('42 unknown credential id', lambda o: SoftAuthenticator().get(o))
neg('43 no challenge in the session (login without options)', lambda o: key1.get(o), options=False)
neg('44 malformed base64url fields', lambda o: {'id': '***', 'client_data_json': '!!', 'authenticator_data': 'a', 'signature': '$'})
neg('45 empty body', lambda o: {})

# Counter: the packed key starts at 5. Equal or lower is a cloned authenticator.
neg('46 cloned authenticator: counter not above the stored value', lambda o: key_packed.get(o, counter=5))
cl = Client().csrf()
r = cl.passkey_login(key_packed.get(cl.passkey_options(), counter=9))
check('47 counter above the stored value signs in', r.status_code == 200, (r.status_code, detail(r)))
neg('48 counter going backwards after use is refused', lambda o: key_packed.get(o, counter=7))
stored = sql(f"SELECT sign_count FROM {PASSKEYS} WHERE credential_id = '{b64u(key_packed.credential_id)}'")
check('49 stored counter is the highest seen (9)', stored == '9', stored)
# Two sign-ins with the same counter value at the same time (a cloned counting authenticator):
# whichever way they interleave, only one may succeed (library check or the counter swap).
import threading as _t
pair = [Client().csrf(), Client().csrf()]
bodies = [key_packed.get(c.passkey_options(), counter=20) for c in pair]
codes = []
threads = [_t.Thread(target=lambda c=c, b=b: codes.append(c.passkey_login(b).status_code)) for c, b in zip(pair, bodies)]
[t.start() for t in threads]
[t.join() for t in threads]
check('49b same counter from two places at once: exactly one sign-in succeeds', sorted(codes) == [200, 400], codes)

cl = Client().csrf()
r = cl.passkey_login(key1.get(cl.passkey_options(), counter=0))
check('50 counter 0 with stored 0 (synced passkey) signs in', r.status_code == 200, (r.status_code, detail(r)))

# Replay. A: the pre-login session cookie is copied (stolen) and the assertion replayed with it
# after the real sign-in. B: the assertion replayed in another session (other challenge).
cl = Client().csrf()
assertion = key1.get(cl.passkey_options(), counter=0)
thief = Client()
thief.s.cookies.update(cl.s.cookies)
r1 = cl.passkey_login(assertion)
thief.csrf()
r2 = thief.passkey_login(assertion)
failures.append(r2)
check('51 replay with the pre-login session after sign-in is refused (challenge gone with the old session)',
      r1.status_code == 200 and failed_generic(r2), (r1.status_code, r2.status_code, detail(r2)))
other_session = Client().csrf()
other_session.passkey_options()
r3 = other_session.passkey_login(assertion)
failures.append(r3)
check('51b replay in another session (other challenge) is refused', failed_generic(r3), (r3.status_code, detail(r3)))

# Race: the same assertion posted 4 times at once in one session. Session writes are not locked,
# so without the atomic single-use marker more than one could read the challenge and sign in.
import threading
race = Client().csrf()
assertion = key1.get(race.passkey_options(), counter=0)
codes = []


def fire():
    s = requests.Session()
    s.cookies.update(race.s.cookies)
    r = s.post(BASE + '/extensions/panel-passkeys/passkey/login', json=assertion, headers=race.headers())
    codes.append(r.status_code)


threads = [threading.Thread(target=fire) for _ in range(4)]
[t.start() for t in threads]
[t.join() for t in threads]
check('51c concurrent replays in one session: at most one sign-in succeeds', codes.count(200) == 1, codes)

msgs = {detail(r) for r in failures}
check('52 every failure answers with the same generic 400 message', msgs == {GENERIC} and all(r.status_code == 400 for r in failures), msgs)

fails = sql("SELECT COUNT(*) FROM activity_logs WHERE event = 'auth:fail' AND properties LIKE '%\"method\":\"passkey\"%'")
check('53 failures fire the failed-login event (auth:fail, method passkey)', int(fails or 0) >= len(failures), fails)

# Lockout: 3 failures from one address lock out passkey AND password sign-in from it.
lk = Client().csrf()
for _ in range(3):
    lk.passkey_login(key1.get(lk.passkey_options(), uv=False))
r = lk.req('POST', '/extensions/panel-passkeys/passkey/options')
r2 = lk.passkey_login(key1.get({'publicKey': {'challenge': b64u(os.urandom(32))}}, counter=0))
r3 = lk.req('POST', '/auth/login', {'user': 'devadmin', 'password': USERS['devadmin'], 'cf-turnstile-response': 'XXXX.DUMMY.TOKEN.XXXX'})
check('54 three failures lock the address out of passkey sign-in (429)', r.status_code == 429 and r2.status_code == 429, (r.status_code, r2.status_code))
check('55 ... and out of password sign-in too (shared core lockout)', r3.status_code == 429, r3.status_code)
other = Client().csrf()
r = other.passkey_login(key1.get(other.passkey_options(), counter=0))
check('56 the lockout is per address: another address still signs in', r.status_code == 200, (r.status_code, detail(r)))

# Brute force on the route limiter (10/min/IP, shared with core login).
bf = Client().csrf()
codes = [bf.req('POST', '/extensions/panel-passkeys/passkey/options').status_code for _ in range(11)]
check('57 throttle:authentication caps sign-in requests at 10 a minute per address', codes[:10] == [200] * 10 and codes[10] == 429, codes)

# --- account management ------------------------------------------------------
key_admin_id = [p['id'] for p in admin.list()['passkeys'] if p['name'] == 'My xMac'][0]
r = staff.req('DELETE', f'/api/client/extensions/panel-passkeys/passkeys/{key_admin_id}', {'password': USERS['staff']})
check('58 another user cannot remove my passkey (404)', r.status_code == 404, r.status_code)

pw = Client().login('staff')
codes = [pw.add_options('nope').status_code for _ in range(5)] + [pw.add_options(USERS['staff']).status_code]
check('59 password confirmation: 5 wrong tries a minute, then 429 even with the right one', codes == [400] * 5 + [429], codes)

# API keys cannot touch passkeys (session only).
r = admin.req('POST', '/api/client/account/api-keys', {'description': 'passkey-e2e', 'allowed_ips': []})
token = None
if r.status_code in (200, 201):
    data = r.json()
    # The bearer token is the identifier followed by the secret.
    token = data['attributes']['identifier'] + data['meta']['secret_token']
if token:
    rr = requests.get(BASE + '/api/client/extensions/panel-passkeys/passkeys', headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
    check('60 a client API key cannot list or manage passkeys (403)', rr.status_code == 403, (rr.status_code, rr.text[:200]))
else:
    check('60 a client API key cannot list or manage passkeys (403)', False, ('could not create API key', r.status_code, r.text[:200]))

r = admin.req('DELETE', f'/api/client/extensions/panel-passkeys/passkeys/{key_admin_id}', {'password': 'wrong'})
check('61 removing needs the password', r.status_code == 400, r.status_code)
r = admin.req('DELETE', f'/api/client/extensions/panel-passkeys/passkeys/{key_admin_id}', {'password': USERS['devadmin']})
check('62 removing with the password works (204)', r.status_code == 204, r.status_code)
neg('63 a removed passkey can no longer sign in', lambda o: key1.get(o, counter=0))
acts = sql("SELECT event FROM activity_logs WHERE event LIKE 'user:passkey.%' ORDER BY id")
check('64 activity log: user:passkey.create and user:passkey.delete', 'user:passkey.create' in acts and 'user:passkey.delete' in acts, acts)

time.sleep(1)
# The newest log: "single" writes laravel.log, "daily" laravel-<date>.log in the app's timezone (UTC), not ours.
logs = sorted(glob.glob(os.path.join(args.instance, 'storage/logs/laravel*.log')), key=os.path.getmtime)
log = open(logs[-1], errors='replace').read() if logs else ''
check('65 owner is emailed on add and remove', 'passkey change on your account' in log and 'was removed from your account' in log)

# Max 10 per account.
n = len(admin.list()['passkeys'])
for i in range(10 - n):
    admin.register('devadmin', SoftAuthenticator(), name=f'k{i}')
r = admin.add_options(USERS['devadmin'])
check('66 at most 10 passkeys per account', len(admin.list()['passkeys']) == 10 and r.status_code == 400 and 'maximum' in detail(r), (r.status_code, detail(r)))

r = admin.req('POST', '/api/client/extensions/panel-passkeys/passkeys/dismiss-prompt')
check('67 dismissing the notice is stored on the account', r.status_code == 204 and admin.list()['prompt_dismissed'] is True, r.status_code)

# --- admin settings (Admin -> Extensions -> Panel Passkeys) ---------------------
SETTINGS = '/api/admin/extensions/panel-passkeys/settings'


def set_settings(**values):
    return admin.req('PATCH', SETTINGS, {'settings': values})


def mail_count():
    logs = sorted(glob.glob(os.path.join(args.instance, 'storage/logs/laravel*.log')), key=os.path.getmtime)
    return open(logs[-1], errors='replace').read().count('passkey change on your account') if logs else 0


r = set_settings(max_per_user=3)
listing = admin.list()
check('68 admin can lower the per-account limit (existing passkeys stay)',
      r.status_code == 200 and listing['max'] == 3 and len(listing['passkeys']) == 10, (r.status_code, r.text[:200]))
r = set_settings(max_per_user=0)
check('69 the limit is validated (0 refused)', r.status_code == 422, r.status_code)
set_settings(max_per_user=None)
check('70 clearing the limit restores the default of 10', admin.list()['max'] == 10)

check('71 staff sees the dashboard notice (not dismissed)', staff.list()['prompt_dismissed'] is False)
set_settings(dashboard_prompt=False)
check('72 turning the notice off hides it for everyone', staff.list()['prompt_dismissed'] is True)
set_settings(dashboard_prompt=True)
check('73 turning it back on shows it again to accounts that never dismissed it', staff.list()['prompt_dismissed'] is False)

set_settings(notify_email=False)
before = mail_count()
victim = admin.list()['passkeys'][-1]
clear_limiters()
r = admin.req('DELETE', f"/api/client/extensions/panel-passkeys/passkeys/{victim['id']}", {'password': USERS['devadmin']})
check('74 with emails off, removing a passkey sends no email', r.status_code == 204 and mail_count() == before, (r.status_code, before, mail_count()))
set_settings(notify_email=None)

r = Client().csrf().req('PATCH', SETTINGS, {'settings': {'max_per_user': 1}})
check('75 a guest cannot change the settings', r.status_code in (401, 403), r.status_code)
r = staff.req('PATCH', SETTINGS, {'settings': {'max_per_user': 1}})
check('76 a non-admin cannot change the settings', r.status_code in (403, 404), r.status_code)

# --- panel-passkeys:clear -------------------------------------------------------
out = subprocess.run(['php', '-d', 'error_reporting=0', 'artisan', 'panel-passkeys:clear', 'staff@passkeys.test', '--force'],
                     cwd=args.instance, capture_output=True, text=True)
check('77 panel-passkeys:clear removes every passkey of the account (by email)',
      out.returncode == 0 and 'Removed' in out.stdout and staff.list()['passkeys'] == [], out.stdout[-300:])
out = subprocess.run(['php', '-d', 'error_reporting=0', 'artisan', 'panel-passkeys:clear', 'nobody-here', '--force'],
                     cwd=args.instance, capture_output=True, text=True)
check('78 panel-passkeys:clear refuses an unknown user', out.returncode != 0 and 'No user matches' in out.stdout + out.stderr, out.stdout[-200:])
check('79 admin passkeys untouched by clearing another account', len(admin.list()['passkeys']) == 9)

# An all-digit username is found by name, not only as an id.
art = ['php', '-d', 'error_reporting=0', 'artisan']
subprocess.run(art + ['p:user:make', '--email=digits@passkeys.test', '--username=90210', '--name-first=Digit', '--name-last=User',
                      '--password=DigitPass-12345!', '--admin=0', '--no-interaction'], cwd=args.instance, capture_output=True)
sql(f"INSERT INTO {PASSKEYS} (user_id, name, credential_id, public_key, created_at, updated_at) "
    f"SELECT id, 'Digit key', 'e2e-digit-key', 'x', NOW(), NOW() FROM users WHERE username = '90210'")
out = subprocess.run(art + ['panel-passkeys:clear', '90210', '--force'], cwd=args.instance, capture_output=True, text=True)
left = sql("SELECT COUNT(*) FROM " + PASSKEYS + " WHERE credential_id = 'e2e-digit-key'")
check('80 panel-passkeys:clear finds an all-digit username', out.returncode == 0 and left == '0', (out.stdout[-200:], left))
sql("DELETE FROM users WHERE username = '90210'")

# A default port in APP_URL (https://host:443) is left out of the expected origin, like browsers do.
php = ("$s = app(PanelPasskeys\\Auth\\PasskeyService::class); $o = [];"
       "foreach (['https://Panel.Example.com:443', 'http://panel.example.com:80', 'https://panel.example.com:8443', 'https://panel.example.com/'] as $u)"
       " { config(['app.url' => $u]); $o[] = $s->expectedOrigin(); } echo implode(' ', $o);")
out = subprocess.run(art + ['tinker', '--execute', php], cwd=args.instance, capture_output=True, text=True)
check('81 expected origin drops default ports and keeps others',
      out.stdout.strip().endswith('https://panel.example.com http://panel.example.com https://panel.example.com:8443 https://panel.example.com'), out.stdout[-300:])

# Clean up.
clear_limiters()
for u in USERS:
    sql(f'DELETE FROM {PASSKEYS} WHERE user_id = {user_id(u)}; DELETE FROM {PREFS} WHERE user_id = {user_id(u)}')
sql("DELETE FROM api_keys WHERE memo = 'passkey-e2e'")

passed = sum(1 for _, ok in results if ok)
print(f'\n{passed}/{len(results)} checks passed')
sys.exit(0 if passed == len(results) else 1)
