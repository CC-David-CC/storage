"""Bounded canonical snapshots for proposed account-folder operations.

This is an internal server primitive. It does not expose a gateway endpoint.
The manifest excludes its root, sorts UTF-8 paths by Unicode code point, and
represents directories with no digest and files with a SHA-256 digest. A digest
binds names, types, and file contents; it is not a filesystem transaction.
"""
import hashlib
import json
import os
import stat
from .policy import Denied, parts

MAX_ENTRIES = 4096
MAX_BYTES = 128 * 1024 * 1024  # Per file, matching the gateway limit.
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024  # Bound lock-held hashing work.
MAX_DEPTH = 16


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Denied('Private owned folder required')


def folder_manifest(root_fd):
    """Return ``(entries, digest)`` for one open, private directory.

    File and directory metadata are checked around each read. Independent OS
    writers do not obey the gateway lock: this detects many changes, but cannot
    prove an atomic snapshot against arbitrary out-of-band host modifications.
    """
    entries = []
    total = 0
    stack = [(os.dup(root_fd), '')]
    try:
        while stack:
            fd, prefix = stack.pop()
            try:
                start = os.fstat(fd)
                _directory(start)
                for name in sorted(os.listdir(fd)):
                    if parts(name) != (name,):
                        raise Denied('Invalid folder entry')
                    relative = prefix + '/' + name if prefix else name
                    if len(parts(relative)) > MAX_DEPTH or len(entries) >= MAX_ENTRIES:
                        raise Denied('Folder manifest entry or depth limit exceeded')
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            _directory(os.fstat(child))
                            if _identity(info) != _identity(os.fstat(child)):
                                raise Denied('Folder changed while scanning')
                            stack.append((child, relative)); child = None
                        finally:
                            if child is not None: os.close(child)
                        entries.append({'path': relative, 'directory': True})
                    elif stat.S_ISREG(info.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            before = os.fstat(child)
                            if _identity(info) != _identity(before) or before.st_uid != os.geteuid() or before.st_nlink != 1:
                                raise Denied('Folder file changed or is not private')
                            if stat.S_IMODE(before.st_mode) != 0o600:
                                raise Denied('Private owned file required')
                            if before.st_size > MAX_BYTES:
                                raise Denied('Folder file size limit exceeded')
                            total += before.st_size
                            if total > MAX_TOTAL_BYTES:
                                raise Denied('Folder manifest total byte limit exceeded')
                            digest = hashlib.sha256(); read = 0
                            while chunk := os.read(child, 65536):
                                read += len(chunk)
                                if read > before.st_size or read > MAX_BYTES:
                                    raise Denied('Folder file changed while scanning')
                                digest.update(chunk)
                            if read != before.st_size or _identity(before) != _identity(os.fstat(child)):
                                raise Denied('Folder file changed while scanning')
                            entries.append({'path': relative, 'directory': False, 'sha256': digest.hexdigest()})
                        finally:
                            os.close(child)
                    else:
                        raise Denied('Folder contains a link or special file')
                if _identity(start) != _identity(os.fstat(fd)):
                    raise Denied('Folder changed while scanning')
            finally:
                os.close(fd)
    finally:
        for fd, _ in stack: os.close(fd)
    entries.sort(key=lambda entry: entry['path'])
    canonical = json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return entries, hashlib.sha256(canonical).hexdigest()
