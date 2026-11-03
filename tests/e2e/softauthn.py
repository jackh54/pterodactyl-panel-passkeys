"""
Software WebAuthn authenticator for the panel-passkeys e2e suite.

Real ES256 credentials (COSE key, CBOR attestation object with fmt "none" or "packed" self
attestation) and real assertions. Call configure(base) once with the instance URL: the origin and
RP id default to it, and every call can override either to tamper with exactly one thing.
"""
import base64
import hashlib
import json
import os
import struct
import urllib.parse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ORIGIN = 'http://localhost:8210'
RP_ID = 'localhost'


def configure(base: str) -> None:
    """Point the defaults at the instance under test (origin = base URL, RP id = its host)."""
    global ORIGIN, RP_ID
    ORIGIN = base.rstrip('/')
    RP_ID = urllib.parse.urlparse(ORIGIN).hostname


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def unb64u(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def cbor(value) -> bytes:
    """Minimal canonical CBOR encoder (ints, bytes, str, list, dict, bool)."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        if n < 256:
            return bytes([major << 5 | 24, n])
        if n < 65536:
            return bytes([major << 5 | 25]) + struct.pack('>H', n)
        return bytes([major << 5 | 26]) + struct.pack('>I', n)

    if isinstance(value, bool):
        return b'\xf5' if value else b'\xf4'
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(cbor(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b''.join(cbor(k) + cbor(v) for k, v in value.items())
    raise TypeError(type(value))


UP, UV, BE, BS, AT = 0x01, 0x04, 0x08, 0x10, 0x40


class SoftAuthenticator:
    """One ES256 discoverable credential, as a platform authenticator would hold it."""

    def __init__(self, sign_count=0, backup_eligible=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = sign_count
        self.backup_eligible = backup_eligible
        self.user_handle = None

    def cose_key(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, 'big'), -3: nums.y.to_bytes(32, 'big')})

    def flags(self, up=True, uv=True, extra=0):
        f = (UP if up else 0) | (UV if uv else 0) | extra
        if self.backup_eligible:
            f |= BE | BS
        return f

    def create(self, options, origin=None, up=True, uv=True, fmt='none', challenge=None, ctype='webauthn.create', rp_id=None):
        pk = options['publicKey']
        self.user_handle = unb64u(pk['user']['id'])
        client_data = json.dumps({
            'type': ctype,
            'challenge': challenge if challenge is not None else pk['challenge'],
            'origin': origin or ORIGIN,
            'crossOrigin': False,
        }, separators=(',', ':')).encode()
        auth_data = (hashlib.sha256((rp_id or RP_ID).encode()).digest()
                     + bytes([self.flags(up, uv, AT)])
                     + struct.pack('>I', self.sign_count)
                     + b'\x00' * 16
                     + struct.pack('>H', len(self.credential_id)) + self.credential_id
                     + self.cose_key())
        att_stmt = {}
        if fmt == 'packed':
            sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
            att_stmt = {'alg': -7, 'sig': sig}
        attestation = cbor({'fmt': fmt, 'attStmt': att_stmt, 'authData': auth_data})
        return {'client_data_json': b64u(client_data), 'attestation_object': b64u(attestation)}

    def get(self, options, origin=None, up=True, uv=True, challenge=None, counter=None, user_handle='own',
            ctype='webauthn.get', key=None, rp_id=None, credential_id=None):
        pk = options['publicKey']
        if counter is None:
            # Synced passkeys keep the counter at 0; others count up on every use.
            if self.sign_count > 0:
                self.sign_count += 1
            counter = self.sign_count
        client_data = json.dumps({
            'type': ctype,
            'challenge': challenge if challenge is not None else pk['challenge'],
            'origin': origin or ORIGIN,
            'crossOrigin': False,
        }, separators=(',', ':')).encode()
        auth_data = (hashlib.sha256((rp_id or RP_ID).encode()).digest()
                     + bytes([self.flags(up, uv)])
                     + struct.pack('>I', counter))
        signature = (key or self.key).sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        handle = self.user_handle if user_handle == 'own' else user_handle
        body = {
            'id': b64u(credential_id or self.credential_id),
            'client_data_json': b64u(client_data),
            'authenticator_data': b64u(auth_data),
            'signature': b64u(signature),
        }
        if handle is not None:
            body['user_handle'] = b64u(handle)
        return body
