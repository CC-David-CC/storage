"""Strict operator-owned resource policy. Request data never selects a host root."""
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from urllib.parse import urlsplit
import uuid

class Denied(ValueError):
    pass

def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('Unexpected gateway policy fields')

def integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Gateway policy number out of range')
    return value

def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', value):
        raise ValueError('Invalid resource identifier')
    return value

def parts(value, *, absolute=False):
    if not isinstance(value, str) or len(value.encode('utf-8')) > 2048:
        raise Denied('Invalid resource path')
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in '\\%?#'):
        raise Denied('Invalid resource path')
    if absolute:
        if not value.startswith('/') or value.startswith('//'):
            raise Denied('Absolute path required')
        value = value[1:]
    elif value.startswith('/'):
        raise Denied('Relative path required')
    if not value:
        return ()
    result = tuple(value.split('/'))
    if any(p in ('', '.', '..') or p.startswith('.') for p in result):
        raise Denied('Invalid resource path component')
    return result

@dataclass(frozen=True)
class Limits:
    bytes_per_second: int
    burst_bytes: int
    bytes_per_day: int
    bytes_per_use: int
    seconds_per_use: int
    concurrent_uses: int

    @classmethod
    def parse(cls, value):
        exact(value, ['bytesPerSecond', 'burstBytes', 'bytesPerDay', 'bytesPerUse', 'secondsPerUse', 'concurrentUses'])
        return cls(integer(value['bytesPerSecond'], 1, 16*1024*1024),
                   integer(value['burstBytes'], 1, 65536),
                   integer(value['bytesPerDay'], 1, 1 << 40),
                   integer(value['bytesPerUse'], 1, 1 << 30),
                   integer(value['secondsPerUse'], 1, 600),
                   integer(value['concurrentUses'], 1, 8))

@dataclass(frozen=True)
class Principal:
    sub: str
    sid: str
    kind: str
    key: dict
    deadline: int

    @property
    def budget_key(self):
        # Anonymous certificates do not establish one-person identity. New
        # anonymous sessions share a cohort quota instead of resetting it.
        return self.sub if self.kind == 'registered' else 'anonymous'

@dataclass(frozen=True)
class Resource:
    id: str
    kind: str
    subjects: tuple
    anonymous: bool
    limits: Limits
    shared_limits: Limits
    root: str | None = None
    scheme: str | None = None
    hostname: str | None = None
    port: int | None = None
    addresses: tuple = ()
    path_prefix: tuple = ()
    methods: tuple = ()
    query_keys: tuple = ()

    def authorize(self, principal):
        allowed = (principal.kind == 'anonymous' and self.anonymous or
                   principal.kind == 'registered' and
                   (principal.sub in self.subjects or 'registered:*' in self.subjects))
        if not allowed:
            raise Denied('Resource not permitted')

    def request(self, data):
        if not isinstance(data, dict) or data.get('resource') != self.id:
            raise Denied('Resource not permitted')
        if self.kind == 'files':
            exact(data, ['resource', 'operation', 'path'])
            if data['operation'] not in ('list', 'read'):
                raise Denied('Only listing and reading are permitted')
            path = parts(data['path'])
            if data['operation'] == 'read' and not path:
                raise Denied('File path required')
            return {'resource': self.id, 'operation': data['operation'], 'path': '/'.join(path)}
        exact(data, ['resource', 'operation', 'method', 'path', 'query', 'body'])
        if data['operation'] != 'fetch' or data['method'] not in self.methods:
            raise Denied('Web operation not permitted')
        path = parts(data['path'])
        query = data['query']
        if not isinstance(query, dict) or len(query) > 16 or not set(query) <= set(self.query_keys):
            raise Denied('Query keys not permitted')
        if any(not isinstance(v, str) or len(v.encode('utf-8')) > 512 or any(ord(c) < 32 for c in v) for v in query.values()):
            raise Denied('Invalid query value')
        body = data['body']
        if not isinstance(body, str) or len(body.encode('utf-8')) > 16384 or data['method'] != 'POST' and body:
            raise Denied('Invalid web request body')
        return {'resource': self.id, 'operation': 'fetch', 'method': data['method'],
                'path': '/'.join(path), 'query': query, 'body': body}

class Policy:
    def __init__(self, value, *, forbidden_roots=()):
        exact(value, ['version', 'origin', 'basePath', 'ownIPv4', 'limits', 'resources'])
        if value['version'] != 'codi-gateway-policy/1':
            raise ValueError('Unknown gateway policy')
        origin = urlsplit(value['origin'])
        if (not origin.hostname or origin.username or origin.password or origin.path or origin.query or origin.fragment or
            origin.scheme != 'https' and not (origin.scheme == 'http' and origin.hostname == '127.0.0.1')):
            raise ValueError('HTTPS or an explicit loopback test origin required')
        base = value['basePath']
        if not isinstance(base, str) or len(base) > 128 or base and not re.fullmatch(r'(?:/[A-Za-z0-9_-]+)+', base):
            raise ValueError('Invalid gateway mount')
        self.origin, self.base_path = value['origin'], base
        self.limits = Limits.parse(value['limits'])
        if not isinstance(value['ownIPv4'], list) or not 1 <= len(value['ownIPv4']) <= 16:
            raise ValueError('Explicit own WAN addresses required')
        self.own_ipv4 = frozenset(str(ipaddress.IPv4Address(x)) for x in value['ownIPv4'])
        entries = value['resources']
        if not isinstance(entries, list) or len(entries) > 64:
            raise ValueError('Resource capacity exceeded')
        self.resources = {}
        protected = tuple(Path(p) for p in ['/etc', '/proc', '/sys', '/dev', '/run', '/root', '/var/lib/codi-connected', '/var/lib/caddy', '/srv/codi-connected', *forbidden_roots])
        private_ranges = tuple(ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10'])
        common = ['id', 'kind', 'subjects', 'anonymous', 'limits', 'sharedLimits']
        for entry in entries:
            if not isinstance(entry, dict) or entry.get('kind') not in ('files', 'http'):
                raise ValueError('Unknown resource kind')
            kind = entry['kind']
            exact(entry, common + (['root'] if kind == 'files' else ['scheme', 'hostname', 'port', 'addresses', 'internal', 'pathPrefix', 'methods', 'queryKeys']))
            id = identifier(entry['id'])
            if id in self.resources:
                raise ValueError('Duplicate resource identifier')
            subjects = entry['subjects']
            if not isinstance(subjects, list) or len(subjects) > 128 or len(set(subjects)) != len(subjects) or type(entry['anonymous']) is not bool:
                raise ValueError('Invalid resource subjects')
            for subject in subjects:
                if subject != 'registered:*' and (not isinstance(subject, str) or not subject.startswith('user:') or str(uuid.UUID(subject[5:])) != subject[5:]):
                    raise ValueError('Use stable registered-account subjects')
            kwargs = dict(id=id, kind=kind, subjects=tuple(subjects), anonymous=entry['anonymous'],
                          limits=Limits.parse(entry['limits']), shared_limits=Limits.parse(entry['sharedLimits']))
            if kind == 'files':
                root = Path(entry['root'])
                if not root.is_absolute() or '..' in root.parts or len(root.parts) < 3 or any(root.is_relative_to(p) or p.is_relative_to(root) for p in protected):
                    raise ValueError('Share root must be explicit and disjoint from private/control trees')
                kwargs['root'] = str(root)
            else:
                host = entry['hostname']
                if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host) or '..' in host or any(not label or len(label)>63 or label.startswith('-') or label.endswith('-') for label in host.split('.')):
                    raise ValueError('Canonical ASCII web hostname required')
                if entry['scheme'] not in ('http', 'https') or type(entry['internal']) is not bool:
                    raise ValueError('Invalid web scheme/internal exception')
                addresses = entry['addresses']
                if not isinstance(addresses, list) or not 1 <= len(addresses) <= 4 or len(set(addresses)) != len(addresses):
                    raise ValueError('Pin one to four destination IPv4 addresses')
                for address in addresses:
                    ip = ipaddress.IPv4Address(address)
                    if str(ip) != address or address in self.own_ipv4 or not (ip.is_global and not ip.is_multicast or entry['internal'] and any(ip in n for n in private_ranges)):
                        raise ValueError('Destination is not an approved public or exact internal exception')
                try:
                    literal = str(ipaddress.IPv4Address(host))
                except ipaddress.AddressValueError:
                    literal = None
                if literal is not None and literal not in addresses:
                    raise ValueError('Literal hostname differs from pinned destination')
                methods, queries = entry['methods'], entry['queryKeys']
                if not isinstance(methods, list) or not methods or len(set(methods)) != len(methods) or not set(methods) <= {'GET', 'HEAD', 'POST'}:
                    raise ValueError('Explicit bounded web methods required')
                if not isinstance(queries, list) or len(queries)>16 or len(set(queries))!=len(queries) or any(not isinstance(q,str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,47}',q) for q in queries):
                    raise ValueError('Invalid query allowlist')
                kwargs.update(scheme=entry['scheme'], hostname=host, port=integer(entry['port'], 1, 65535),
                              addresses=tuple(addresses), path_prefix=parts(entry['pathPrefix'], absolute=True),
                              methods=tuple(methods), query_keys=tuple(queries))
            self.resources[id] = Resource(**kwargs)

    def resource(self, id):
        if not isinstance(id, str) or id not in self.resources:
            raise Denied('Resource not permitted')
        return self.resources[id]
