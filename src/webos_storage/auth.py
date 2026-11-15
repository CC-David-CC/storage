"""Short-lived issuer confirmations plus client proof and durable one-use nonces.

This validates identity only. Resource ACL/path/body validation must happen
before invoking a broker or UserStore. A browser-supplied account ID is never
an authority. The issuer policy must come from protected operator configuration.
"""
import re
import hashlib
from dataclasses import dataclass
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from webos_accounts import jose
from .policy import Denied, Principal
from .user_store import registered

from webos_runtime.file_protocol import CONFIRMATION_TYPE, USE_TYPE, AUTHORIZE, CHALLENGE, LIFETIME, gateway_context as context
MAX_REQUEST_BYTES = 192 * 1024 * 1024

@dataclass(frozen=True)
class AuthorizedUse:
    principal: Principal
    request_sha256: str

    def decode(self, raw):
        if not isinstance(raw, bytes) or len(raw) > MAX_REQUEST_BYTES:
            raise Denied('Bounded gateway request required')
        if jose.b64(hashlib.sha256(raw).digest()) != self.request_sha256:
            raise Denied('Authorized request bytes changed')
        # json.loads(bytes) also accepts UTF-16/32 and a UTF-8 BOM. This
        # protocol accepts plain UTF-8 JSON only; literal NUL is never valid.
        if b'\x00' in raw or raw.startswith(b'\xef\xbb\xbf'):
            raise Denied('Plain UTF-8 JSON required')
        value = jose.loads(raw)
        if not isinstance(value, dict):
            raise Denied('Object gateway request required')
        return value
TABLES = {
    'gateway_auth_metadata': 'CREATE TABLE gateway_auth_metadata (version INTEGER PRIMARY KEY CHECK(version=1))',
    'gateway_challenges': 'CREATE TABLE gateway_challenges (nonce TEXT PRIMARY KEY, key_thumb TEXT NOT NULL, request_sha TEXT NOT NULL, expires INTEGER NOT NULL)',
    'gateway_used_grants': 'CREATE TABLE gateway_used_grants (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)',
}

def digest(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', value) or len(jose.unb64(value)) != 32:
        raise Denied('Canonical SHA256 digest required')
    return value

def window(claims, now):
    if any(type(claims.get(k)) is not int for k in ['iat', 'exp']) or not (claims['iat'] <= now + 5 and claims['exp'] > now and 0 < claims['exp'] - claims['iat'] <= LIFETIME):
        raise Denied('Expired or invalid gateway proof')

def check_schema(db):
    if db.execute('SELECT version FROM gateway_auth_metadata').fetchall() != [(1,)]:
        raise ValueError('Gateway authorization metadata unavailable')
    for name, statement in TABLES.items():
        if db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?', ('table', name)).fetchone() != (statement,):
            raise ValueError('Gateway authorization schema changed; retain state for recovery')

def initialize_ledger(store):
    """Explicit operator migration; service startup never repairs missing state."""
    with store.lock(), store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        existing = {r[0] for r in db.execute('SELECT name FROM sqlite_master WHERE type=?', ('table',))} & TABLES.keys()
        if not existing:
            for statement in TABLES.values():
                db.execute(statement)
            db.execute('INSERT INTO gateway_auth_metadata VALUES(1)')
        check_schema(db);db.commit()

class Gatekeeper:
    def __init__(self, store, issuer_policy, *, base_path='', clock=time.time, capacity=128):
        if not isinstance(issuer_policy, dict) or issuer_policy.get('mode') != 'server':
            raise ValueError('Pinned server issuer policy required')
        self.origin = issuer_policy['issuer']
        self.audience, self.use_path = context(self.origin, base_path)
        self.clock, self.store = clock, store
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError('Bounded gateway challenge capacity required')
        self.capacity = capacity
        entries = issuer_policy['authorityKeys']
        if not isinstance(entries, list) or not 1 <= len(entries) <= 4:
            raise ValueError('Explicit trusted issuer keys required')
        self.keys = {}
        for item in entries:
            kid = item['kid']
            if not isinstance(kid, str) or not 1 <= len(kid) <= 128 or kid in self.keys:
                raise ValueError('Unique trusted key IDs required')
            self.keys[kid] = jose.public_jwk(jose.load_public(item['jwk']))
        with self.store.lock(), self.store.db() as db:
            check_schema(db)

    def challenge(self, key, request_sha):
        thumb = jose.thumbprint(key);digest(request_sha)
        with self.store.lock(), self.store.db() as db:
            now = int(self.clock());db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM gateway_challenges WHERE expires<=?', (now,))
            db.execute('DELETE FROM gateway_used_grants WHERE expires<=?', (now,))
            if db.execute('SELECT count(*) FROM gateway_challenges').fetchone()[0] >= self.capacity or db.execute('SELECT count(*) FROM gateway_challenges WHERE key_thumb=?', (thumb,)).fetchone()[0] >= 8:
                raise Denied('Gateway challenge capacity reached')
            nonce = secrets.token_urlsafe(32)
            db.execute('INSERT INTO gateway_challenges VALUES(?,?,?,?)', (nonce, thumb, request_sha, now + 60));db.commit()
        return {'nonce': nonce, 'request_sha256': request_sha, 'expires_at': now + 60}

    def _verify(self, confirmation, proof, request_sha=None):
        header, _, _, _ = jose.inspect(confirmation, CONFIRMATION_TYPE, 8192)
        key = self.keys.get(header.get('kid'))
        if key is None:
            raise Denied('Untrusted gateway identity authority')
        c = jose.verify(confirmation, key, CONFIRMATION_TYPE, 8192)
        expected = {'v','iss','aud','sub','sid','kind','cnf','iat','exp','jti','nonce','request_sha256','session_deadline'}
        if set(c) != expected or type(c['v']) is not int or c['v'] != 1 or c['iss'] != self.origin or c['aud'] != self.audience:
            raise Denied('Wrong gateway confirmation context')
        if type(c['session_deadline']) is not int or type(c['exp']) is not int or c['session_deadline'] < c['exp']:
            raise Denied('Gateway confirmation exceeds the session deadline')
        for name in ['jti','nonce']:
            if not isinstance(c[name], str) or not re.fullmatch('[A-Za-z0-9_-]{43}', c[name]) or len(jose.unb64(c[name])) != 32:
                raise Denied('Invalid gateway confirmation identifier')
        if not isinstance(c['sid'], str) or not 1 <= len(c['sid']) <= 80 or not isinstance(c['cnf'], dict) or set(c['cnf']) != {'jwk'}:
            raise Denied('Invalid gateway identity binding')
        public = jose.public_jwk(jose.load_public(c['cnf']['jwk']))
        p = jose.verify(proof, public, USE_TYPE, 8192)
        if set(p) != {'v','iss','aud','nonce','grant_sha256','request_sha256','method','path','iat','exp'} or type(p['v']) is not int or p['v'] != 1:
            raise Denied('Invalid gateway client proof')
        request_sha = digest(request_sha if request_sha is not None else c['request_sha256'])
        if p['iss'] != c['sid'] or p['aud'] != self.audience or p['method'] != 'POST' or p['path'] != self.use_path or p['nonce'] != c['nonce'] or p['grant_sha256'] != jose.digest(confirmation) or p['request_sha256'] != request_sha or c['request_sha256'] != request_sha:
            raise Denied('Gateway request, client or route binding changed')
        principal = Principal(c['sub'], c['sid'], c['kind'], public, c['exp'])
        registered(principal)  # Initial personal-storage gateway is registered-only.
        return principal, c, p

    def _spend(self, principal, c, p):
        with self.store.lock(), self.store.db() as db:
            now = int(self.clock());window(c, now);window(p, now)
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT key_thumb,request_sha,expires FROM gateway_challenges WHERE nonce=?', (c['nonce'],)).fetchone()
            if row is None or row[:2] != (jose.thumbprint(principal.key), c['request_sha256']) or row[2] <= now:
                raise Denied('Missing, changed, expired or already used gateway challenge')
            db.execute('DELETE FROM gateway_used_grants WHERE expires<=?', (now,))
            if db.execute('SELECT count(*) FROM gateway_used_grants').fetchone()[0] >= 4096 or db.execute('SELECT 1 FROM gateway_used_grants WHERE id=?', (c['jti'],)).fetchone():
                raise Denied('Gateway grant already used or capacity reached')
            db.execute('INSERT INTO gateway_used_grants VALUES(?,?)', (c['jti'], c['exp']))
            db.execute('DELETE FROM gateway_challenges WHERE nonce=?', (c['nonce'],));db.commit()
        return now

    def begin(self, confirmation, proof, *, seconds=900):
        """Authenticate before reading an upload, then bound its execution time.

        The 30s grant must be fresh at admission. An admitted exact request may
        finish within its operation deadline, never beyond its session deadline.
        Call decode() before any file operation to verify the transmitted body.
        """
        if type(seconds) is not int or not 1 <= seconds <= 900:
            raise ValueError('Bounded gateway operation lifetime required')
        principal, c, p = self._verify(confirmation, proof)
        started = self._spend(principal, c, p)
        deadline = min(c['session_deadline'], started + seconds)
        return AuthorizedUse(Principal(principal.sub, principal.sid, principal.kind, principal.key, deadline), c['request_sha256'])

    def consume(self, raw_request, confirmation, proof):
        if not isinstance(raw_request, str) or len(raw_request.encode('utf-8')) > MAX_REQUEST_BYTES:
            raise Denied('Bounded gateway request required')
        principal, c, p = self._verify(confirmation, proof, jose.digest(raw_request))
        request = AuthorizedUse(principal, c['request_sha256']).decode(raw_request.encode('utf-8'))
        self._spend(principal, c, p)
        return principal, request
