"""Private registered-account folders and a separate permissions database.

The caller must supply a Principal produced by server-side identity verification.
This module never authenticates a browser-supplied username or Linux UID. No
anonymous path can allocate a user row or folder. Files are not a public web tree.
"""
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import sqlite3
import stat
import time
from urllib.parse import quote
import uuid

from .policy import Denied, Principal, integer, parts

OPERATIONS = ('list', 'read', 'create', 'replace', 'mkdir', 'delete', 'rename')
DEFAULT_ACCOUNT_FOLDERS = ('Documents', 'Digital Projects', '3D Objects', 'Games', 'Pictures', 'Audio', 'Video')
class Conflict(Denied):
    """The caller's file version or create precondition no longer holds."""
SCHEMA = [
    'CREATE TABLE metadata (version INTEGER PRIMARY KEY CHECK(version=1))',
    "CREATE TABLE users (subject TEXT PRIMARY KEY, home_id TEXT UNIQUE NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','ready')), enabled INTEGER NOT NULL CHECK(enabled IN (0,1)), created INTEGER NOT NULL)",
    'CREATE TABLE permissions (subject TEXT NOT NULL REFERENCES users(subject), resource TEXT NOT NULL, operation TEXT NOT NULL, allowed INTEGER NOT NULL CHECK(allowed IN (0,1)), PRIMARY KEY(subject,resource,operation))',
]

def registered(principal):
    if not isinstance(principal, Principal) or principal.kind != 'registered' or not isinstance(principal.sub, str) or not principal.sub.startswith('user:'):
        raise Denied('Registered account required for persistent storage')
    try:
        id = uuid.UUID(principal.sub[5:])
    except (ValueError, AttributeError):
        raise Denied('Invalid registered account identifier') from None
    if str(id) != principal.sub[5:]:
        raise Denied('Canonical registered account identifier required')
    return id.hex

def private_directory(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('Explicit private directory required')
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError('Private storage cannot contain symlinks')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Storage directory must be owned and private (0700)')
    return path

class UserStore:
    def __init__(self, state_root, data_root, *, clock=time.time,
                 per_user_bytes=1024*1024*1024, per_user_entries=1024,
                 total_bytes=10*1024*1024*1024, total_entries=100000, maximum_users=1024,
                 initial_folders=()):
        self.state_root = private_directory(state_root)
        self.data_root = private_directory(data_root)
        if self.state_root.is_relative_to(self.data_root) or self.data_root.is_relative_to(self.state_root):
            raise ValueError('Permission database and user files must be disjoint')
        self.clock = clock
        self.per_user_bytes = integer(per_user_bytes, 1, 1 << 40)
        self.per_user_entries = integer(per_user_entries, 1, 100000)
        self.total_bytes = integer(total_bytes, self.per_user_bytes, 1 << 40)
        self.total_entries = integer(total_entries, self.per_user_entries, 1000000)
        self.maximum_users = integer(maximum_users, 1, 100000)
        if not isinstance(initial_folders, tuple) or len(set(initial_folders)) != len(initial_folders):
            raise ValueError('Invalid initial folders')
        for name in initial_folders:
            if not isinstance(name, str) or parts(name) != (name,):raise ValueError('Invalid initial folder name')
        if len(initial_folders) > self.per_user_entries:raise ValueError('Initial folders exceed the account entry limit')
        self.initial_folders = initial_folders
        self.database = self.state_root / 'permissions.sqlite3'
        self.lock_path = self.state_root / '.storage.lock'
        self.users_path = self.data_root / 'users'
        with self.lock():
            new = False
            if not self.database.exists() and not self.database.is_symlink():
                if any(self.data_root.iterdir()) or any(p!=self.lock_path for p in self.state_root.iterdir()):
                    raise ValueError('Retained storage exists without its permission database; recover the database')
            try:
                fd = os.open(self.database, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                os.close(fd);new = True
            except FileExistsError:
                pass
            self._private_file(self.database)
            if new:
                with self.db() as db:
                    db.execute('BEGIN IMMEDIATE')
                    for statement in SCHEMA:
                        db.execute(statement)
                    db.execute('INSERT INTO metadata VALUES(1)');db.commit()
            with self.db() as db:
                if db.execute('SELECT version FROM metadata').fetchall() != [(1,)] or db.execute('PRAGMA integrity_check').fetchall() != [('ok',)] or db.execute('PRAGMA foreign_key_check').fetchall():
                    raise ValueError('Permission database unavailable; retain it for recovery')
            if not self.users_path.exists():
                if not new:
                    raise ValueError('Retained user storage missing; retain state for recovery')
                self.users_path.mkdir(mode=0o700)
                self._sync_directory(self.data_root)
            private_directory(self.users_path)
            # Only transaction staging files are removed. Committed file names
            # are never recreated, replaced or repaired during startup.
            self._usage(clean_staging=True)

    @staticmethod
    def _sync_directory(path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _identity(self, principal):
        home_id = registered(principal)
        if type(principal.deadline) is not int or principal.deadline <= self.clock():
            raise Denied('Fresh registered identity required')
        return home_id

    @staticmethod
    def _publish(parent, source, destination, *, replace):
        if replace:
            os.replace(source, destination, src_dir_fd=parent, dst_dir_fd=parent)
            return
        # Linux renameat2 publishes without either overwriting an existing
        # destination or leaving a two-link intermediate after a process crash.
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(parent, os.fsencode(source), parent, os.fsencode(destination), 1) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))

    @staticmethod
    def _private_file(path):
        info = Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            raise ValueError('Owned private regular storage file required')

    @contextmanager
    def lock(self):
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            self._private_file(self.lock_path)
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    @contextmanager
    def db(self):
        self._private_file(self.database)
        db = sqlite3.connect('file:' + quote(str(self.database), safe='/') + '?mode=rw', uri=True, timeout=2, isolation_level=None)
        db.execute('PRAGMA foreign_keys=ON')
        try:
            yield db
        finally:
            db.close()

    def _home(self, home_id):
        if len(home_id) != 32 or any(c not in '0123456789abcdef' for c in home_id):
            raise ValueError('Invalid retained home identifier')
        return self.users_path / home_id

    def ensure_user(self, principal, *, phase=lambda name: None):
        home_id = self._identity(principal)
        with self.lock(), self.db() as db:
            row = db.execute('SELECT home_id,state,enabled FROM users WHERE subject=?', (principal.sub,)).fetchone()
            if row and row[0] != home_id:
                raise ValueError('Account/folder binding changed; retain state for review')
            if row is None:
                if db.execute('SELECT count(*) FROM users').fetchone()[0] >= self.maximum_users:
                    raise Denied('Registered storage account capacity exceeded')
                db.execute('BEGIN IMMEDIATE')
                db.execute("INSERT INTO users VALUES(?,?,'pending',1,?)", (principal.sub, home_id, int(self.clock())))
                db.commit();row = (home_id, 'pending', 1)
            if row[2] != 1:
                raise Denied('Personal storage disabled')
            folder = self._home(home_id)
            if row[1] == 'pending':
                phase('registered')
                try:
                    folder.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                private_directory(folder)
                self._sync_directory(self.users_path)
                # Pending homes may contain only our empty, private starter
                # directories after an interrupted initialization. Never adopt
                # unexpected data or recreate folders after the account is ready.
                for entry in folder.iterdir():
                    if entry.name not in self.initial_folders:
                        raise ValueError('Uncommitted home contains data; retain for recovery')
                    private_directory(entry)
                    if any(entry.iterdir()):raise ValueError('Uncommitted home contains data; retain for recovery')
                phase('directory-created')
                _, _, entries = self._usage(clean_staging=True)
                missing = [name for name in self.initial_folders if not (folder/name).exists()]
                if entries + len(missing) > self.total_entries:raise Denied('Storage entry quota exceeded')
                for name in missing:
                    (folder/name).mkdir(mode=0o700)
                    self._sync_directory(folder)
                    phase('starter-folder-created')
                db.execute('BEGIN IMMEDIATE')
                for operation in OPERATIONS:
                    db.execute('INSERT INTO permissions VALUES(?,?,?,1)', (principal.sub, 'my-files', operation))
                db.execute("UPDATE users SET state='ready' WHERE subject=? AND state='pending'", (principal.sub,))
                db.commit()
                phase('ready')
            else:
                # A missing existing folder is data loss, never a reason to
                # silently create an empty replacement with the same identity.
                private_directory(folder)
            return {'subject': principal.sub, 'storageId': home_id, 'ready': True}

    def _authorized(self, db, principal, operation):
        home_id = self._identity(principal)
        if operation not in OPERATIONS:
            raise Denied('Storage operation not permitted')
        row = db.execute('SELECT home_id,state,enabled FROM users WHERE subject=?', (principal.sub,)).fetchone()
        permit = db.execute('SELECT allowed FROM permissions WHERE subject=? AND resource=? AND operation=?', (principal.sub, 'my-files', operation)).fetchone()
        if row != (home_id, 'ready', 1) or permit != (1,):
            raise Denied('Storage operation not permitted')
        folder = private_directory(self._home(home_id))
        return os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    @staticmethod
    def _parent(home, path):
        names = parts(path)
        if not names or len(names) > 16:
            raise Denied('Bounded file path required')
        fd = os.dup(home)
        try:
            for name in names[:-1]:
                following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd);fd = following
            return fd, names[-1]
        except BaseException:
            os.close(fd);raise

    @staticmethod
    def _data_stat(fd):
        """Validate an owned single-link data file and tighten common external modes."""
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid():
            raise Denied('Owned regular file required')
        mode = stat.S_IMODE(info.st_mode)
        # Only remove group/other access from owner-readable/writable files.
        # Never broaden deliberately restrictive modes or follow a link.
        if mode != 0o600 and mode & ~0o077 == 0o600:
            os.fchmod(fd, 0o600)
            info = os.fstat(fd)
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise Denied('A private owner-readable/writable file is required')
        return info

    @staticmethod
    def _read(fd, maximum):
        info = UserStore._data_stat(fd)
        if info.st_size > maximum:
            raise Denied('Regular file within the size limit required')
        chunks = [];size = 0
        while chunk := os.read(fd, min(65536, maximum + 1 - size)):
            chunks.append(chunk);size += len(chunk)
            if size > maximum:
                raise Denied('File size limit exceeded')
        return b''.join(chunks)

    def read(self, principal, path, *, maximum_bytes=None):
        maximum = self.per_user_bytes if maximum_bytes is None else integer(maximum_bytes, 1, self.per_user_bytes)
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, 'read')
            parent = fd = None
            try:
                parent, name = self._parent(home, path)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                raw = self._read(fd, maximum)
                return {'bytes': raw, 'sha256': hashlib.sha256(raw).hexdigest()}
            finally:
                for descriptor in [fd, parent, home]:
                    if descriptor is not None:
                        os.close(descriptor)

    def open_read_snapshot(self,principal,path,*,maximum_bytes):
        """Open one private file and hash it in chunks; caller owns the returned fd.

        Normal API writes publish with atomic rename, so an open descriptor
        continues to refer to the selected version even if its path is replaced.
        The client checks the digest if a local operator changes bytes in place.
        """
        maximum=integer(maximum_bytes,1,self.per_user_bytes)
        with self.lock(),self.db() as db:
            home=self._authorized(db,principal,'read');parent=fd=None
            try:
                parent,name=self._parent(home,path)
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                info=self._data_stat(fd)
                if info.st_size>maximum:raise Denied('File size limit exceeded')
                digest=hashlib.sha256();size=0
                while chunk:=os.read(fd,65536):
                    size+=len(chunk)
                    if size>maximum:raise Denied('File size limit exceeded')
                    digest.update(chunk)
                if size!=info.st_size:raise Conflict('File changed while reading')
                os.lseek(fd,0,os.SEEK_SET)
                result=(fd,size,digest.hexdigest());fd=None;return result
            finally:
                for descriptor in [fd,parent,home]:
                    if descriptor is not None:os.close(descriptor)

    def version_batch(self, principal, paths, *, maximum_total_bytes=32*1024*1024):
        """Hash a bounded group of private files, deferring large or missing files.

        Every path is opened beneath the authorized account home with the same
        ownership and no-symlink checks as a normal read. The byte budget bounds
        hashing work; callers use the ordinary version request for deferred files.
        """
        maximum_total_bytes=integer(maximum_total_bytes,1,32*1024*1024)
        if not isinstance(paths,list) or not 1<=len(paths)<=16 or any(not isinstance(path,str) for path in paths):
            raise Denied('A bounded set of unique file paths is required')
        if len(set(paths))!=len(paths) or any(not parts(path) for path in paths):raise Denied('Unique file paths required')
        if sum(len(path.encode('utf-8')) for path in paths)>8192:raise Denied('Batch paths are too large')
        result=[];remaining=maximum_total_bytes
        for path in paths:
            with self.lock(),self.db() as db:
                home=self._authorized(db,principal,'read');parent=fd=None
                try:
                    try:
                        parent,name=self._parent(home,path)
                        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
                    except FileNotFoundError:
                        result.append({'path':path,'deferred':True});continue
                    info=self._data_stat(fd)
                    if info.st_size>min(self.per_user_bytes,128*1024*1024):raise Denied('File size limit exceeded')
                    if info.st_size>remaining:
                        result.append({'path':path,'deferred':True});continue
                    digest=hashlib.sha256();size=0
                    while chunk:=os.read(fd,65536):
                        size+=len(chunk)
                        if size>remaining:raise Conflict('File changed while reading')
                        digest.update(chunk)
                    end=os.fstat(fd)
                    if size!=info.st_size or (end.st_mtime_ns,end.st_ctime_ns)!=(info.st_mtime_ns,info.st_ctime_ns):
                        raise Conflict('File changed while reading')
                    remaining-=size;result.append({'path':path,'bytes':size,'sha256':digest.hexdigest()})
                finally:
                    for descriptor in [fd,parent,home]:
                        if descriptor is not None:os.close(descriptor)
        return result

    def list(self, principal, path=''):
        with self.lock(), self.db() as db:
            fd = self._authorized(db, principal, 'list')
            try:
                for name in parts(path):
                    following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd);fd = following
                names = os.listdir(fd)
                if len(names) > self.per_user_entries:
                    raise Denied('Directory listing limit exceeded')
                result = []
                for name in sorted(names):
                    if name.startswith('.'):
                        continue
                    try:
                        parts(name);info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except (OSError, ValueError):
                        continue
                    if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        result.append({'name': name, 'directory': stat.S_ISDIR(info.st_mode), 'bytes': info.st_size if stat.S_ISREG(info.st_mode) else None})
                return result
            finally:
                os.close(fd)

    def inventory(self, principal, *, max_directories=128, max_entries=2048, max_path_bytes=524288):
        """Return a bounded account tree, or ask the client to use ordinary listings.

        Each directory uses the normal list authorization and no-follow checks.
        Nothing is returned if the tree exceeds a bound; clients must never
        interpret an incomplete tree as evidence that a file was deleted.
        """
        queue=[''];result=[];directories=0;path_bytes=0
        while queue:
            if directories>=max_directories:return {'complete':False,'entries':[]}
            directory=queue.pop(0);directories+=1
            for item in self.list(principal,directory):
                path=(directory+'/' if directory else '')+item['name'];parts(path)
                path_bytes+=len(path.encode('utf-8'))
                if len(result)>=max_entries or path_bytes>max_path_bytes:return {'complete':False,'entries':[]}
                result.append({'path':path,'directory':item['directory']})
                if item['directory']:queue.append(path)
        return {'complete':True,'entries':result}

    def inventory_versions(self, principal, *, maximum_total_bytes=32*1024*1024, maximum_files=64):
        """Bounded tree and file hashes, with ordinary version fallback.

        Never return partial trees. Reuse the normal list and read permissions,
        no-follow descriptor checks and change-during-hash detection. Files
        beyond the count or byte budget remain in the inventory without a hash.
        """
        maximum_total_bytes=integer(maximum_total_bytes,1,32*1024*1024)
        maximum_files=integer(maximum_files,1,64)
        with self.lock(),self.db() as db:
            home=self._authorized(db,principal,'read');os.close(home)
        result=self.inventory(principal)
        if not result['complete']:return result
        files=[entry for entry in result['entries'] if not entry['directory']][:maximum_files]
        remaining=maximum_total_bytes
        for offset in range(0,len(files),16):
            if remaining<=0:break
            group=files[offset:offset+16]
            values=self.version_batch(principal,[entry['path'] for entry in group],maximum_total_bytes=remaining)
            for entry,value in zip(group,values):
                if value.get('deferred'):continue
                entry.update(bytes=value['bytes'],sha256=value['sha256']);remaining-=value['bytes']
        return result

    def _usage(self, *, clean_staging=False):
        total_size = total_entries = 0;users = {}
        for root in self.users_path.iterdir():
            self._home(root.name)
            private_directory(root)
            if len(users) >= self.maximum_users:
                raise Denied('Registered storage account capacity exceeded')
            count = size = 0
            stack = [(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC), 0)]
            try:
                while stack:
                    fd, depth = stack.pop()
                    try:
                        for name in os.listdir(fd):
                            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                            if re.fullmatch(r'\.save-[0-9a-f]{32}', name):
                                self._private_file(Path('/proc/self/fd') / str(fd) / name)
                                if clean_staging:
                                    os.unlink(name, dir_fd=fd);os.fsync(fd)
                                    continue
                            parts(name)
                            count += 1
                            if count > self.per_user_entries or total_entries + count > self.total_entries or depth >= 16:
                                raise Denied('Storage entry/depth quota exceeded')
                            if stat.S_ISDIR(info.st_mode):
                                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                                    raise Denied('Private storage directory required')
                                stack.append((os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd), depth + 1))
                            elif stat.S_ISREG(info.st_mode):
                                data_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                                try:size += self._data_stat(data_fd).st_size
                                finally:os.close(data_fd)
                            else:
                                raise Denied('Unexpected link or special file in user storage')
                    finally:
                        os.close(fd)
                users[root.name] = (size, count)
                total_size += size;total_entries += count
            finally:
                for fd, _ in stack:
                    os.close(fd)
        return users, total_size, total_entries

    def put(self, principal, path, data, *, previous_sha256=None, phase=lambda name: None):
        if not isinstance(data, bytes) or len(data) > self.per_user_bytes:
            raise Denied('Save size limit exceeded')
        operation = 'replace' if previous_sha256 is not None else 'create'
        if previous_sha256 is not None and (not isinstance(previous_sha256, str) or not re.fullmatch('[0-9a-f]{64}', previous_sha256)):
            raise Denied('Exact previous content hash required')
        home_id = registered(principal)
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, operation)
            parent = fd = old = None;temporary = None
            try:
                parent, name = self._parent(home, path)
                existing_size = 0;exists = False
                try:
                    old = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent);exists = True
                except FileNotFoundError:
                    pass
                if operation == 'create' and exists or operation == 'replace' and not exists:
                    raise Conflict('Save precondition failed')
                if old is not None:
                    original = self._read(old, self.per_user_bytes)
                    existing_size = len(original)
                    if hashlib.sha256(original).hexdigest() != previous_sha256:
                        raise Conflict('File changed; reload before replacing it')
                usage, total, entries = self._usage(clean_staging=True);used, count = usage[home_id]
                if used - existing_size + len(data) > self.per_user_bytes or total - existing_size + len(data) > self.total_bytes or count + (not exists) > self.per_user_entries or entries + (not exists) > self.total_entries:
                    raise Denied('Storage quota exceeded')
                temporary = '.save-' + secrets.token_hex(16)
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                with os.fdopen(fd, 'wb', closefd=False) as stream:
                    stream.write(data);stream.flush();os.fsync(fd)
                phase('staged')
                self._publish(parent, temporary, name, replace=operation == 'replace')
                temporary = None;os.fsync(parent)
                phase('committed')
                return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            finally:
                if temporary is not None:
                    os.unlink(temporary, dir_fd=parent)
                for descriptor in [old, fd, parent, home]:
                    if descriptor is not None:
                        os.close(descriptor)

    def put_stream(self, principal, path, stream, size, sha256, *, previous_sha256=None, phase=lambda name: None):
        """Publish a verified, bounded temporary upload without loading it into RAM.

        `stream` is a server-owned binary file object, not a pathname from a
        client. Both size and content hash are rechecked while copying into the
        account's private staging file, before atomic publication.
        """
        integer(size,0,self.per_user_bytes)
        if not isinstance(sha256,str) or not re.fullmatch('[0-9a-f]{64}',sha256) or not callable(getattr(stream,'read',None)):
            raise Denied('Bounded upload and SHA-256 required')
        operation='replace' if previous_sha256 is not None else 'create'
        if previous_sha256 is not None and (not isinstance(previous_sha256,str) or not re.fullmatch('[0-9a-f]{64}',previous_sha256)):
            raise Denied('Exact previous content hash required')
        home_id=registered(principal)
        with self.lock(),self.db() as db:
            home=self._authorized(db,principal,operation)
            parent=fd=old=None;temporary=None
            try:
                parent,name=self._parent(home,path);existing_size=0;exists=False
                try:old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);exists=True
                except FileNotFoundError:pass
                if operation=='create' and exists or operation=='replace' and not exists:raise Conflict('Save precondition failed')
                if old is not None:
                    info=self._data_stat(old);existing_size=info.st_size
                    if existing_size>self.per_user_bytes:raise Denied('File size limit exceeded')
                    digest=hashlib.sha256();seen=0
                    while chunk:=os.read(old,65536):
                        seen+=len(chunk)
                        if seen>self.per_user_bytes:raise Denied('File size limit exceeded')
                        digest.update(chunk)
                    if seen!=existing_size or digest.hexdigest()!=previous_sha256:raise Conflict('File changed; reload before replacing it')
                usage,total,entries=self._usage(clean_staging=True);used,count=usage[home_id]
                if used-existing_size+size>self.per_user_bytes or total-existing_size+size>self.total_bytes or count+(not exists)>self.per_user_entries or entries+(not exists)>self.total_entries:
                    raise Denied('Storage quota exceeded')
                temporary='.save-'+secrets.token_hex(16)
                fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
                digest=hashlib.sha256();seen=0
                with os.fdopen(fd,'wb',closefd=False) as target:
                    while seen<size:
                        chunk=stream.read(min(65536,size-seen))
                        if not isinstance(chunk,bytes) or not chunk or len(chunk)>size-seen:raise Denied('Truncated or invalid upload')
                        target.write(chunk);digest.update(chunk);seen+=len(chunk)
                    if stream.read(1) or digest.hexdigest()!=sha256:raise Denied('Upload size or hash changed')
                    target.flush();os.fsync(fd)
                phase('staged');self._publish(parent,temporary,name,replace=operation=='replace')
                temporary=None;os.fsync(parent);phase('committed')
                return {'bytes':size,'sha256':sha256}
            finally:
                if temporary is not None:os.unlink(temporary,dir_fd=parent)
                for descriptor in [old,fd,parent,home]:
                    if descriptor is not None:os.close(descriptor)

    def mkdir(self, principal, path):
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, 'mkdir');parent = None
            try:
                parent, name = self._parent(home, path)
                usage, _, entries = self._usage(clean_staging=True)
                if usage[registered(principal)][1] >= self.per_user_entries or entries >= self.total_entries:
                    raise Denied('Storage entry quota exceeded')
                os.mkdir(name, mode=0o700, dir_fd=parent);os.fsync(parent)
            finally:
                for fd in [parent, home]:
                    if fd is not None:
                        os.close(fd)

    def delete(self, principal, path, *, previous_sha256=None):
        """Delete a version-matched file or an empty directory; never recursive."""
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, 'delete');parent = fd = None
            try:
                parent, name = self._parent(home, path)
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and previous_sha256 is None:
                    os.rmdir(name, dir_fd=parent)
                else:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                    if hashlib.sha256(self._read(fd, self.per_user_bytes)).hexdigest() != previous_sha256:
                        raise Conflict('File changed; reload before deleting it')
                    os.unlink(name, dir_fd=parent)
                os.fsync(parent)
            finally:
                for descriptor in [fd, parent, home]:
                    if descriptor is not None:
                        os.close(descriptor)

    def rename(self, principal, source, destination, *, previous_sha256=None):
        """Rename a version-matched file; target must not exist."""
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, 'rename');parent = target = fd = None
            try:
                parent, name = self._parent(home, source)
                target, new_name = self._parent(home, destination)
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                if hashlib.sha256(self._read(fd, self.per_user_bytes)).hexdigest() != previous_sha256:
                    raise Conflict('File changed; reload before renaming it')
                libc = ctypes.CDLL(None, use_errno=True)
                rename = libc.renameat2
                rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
                rename.restype = ctypes.c_int
                if rename(parent, os.fsencode(name), target, os.fsencode(new_name), 1) != 0:
                    error = ctypes.get_errno();raise OSError(error, os.strerror(error))
                os.fsync(parent);os.fsync(target)
            finally:
                for descriptor in [fd, parent, target, home]:
                    if descriptor is not None:
                        os.close(descriptor)

    def folder_manifest(self, principal, path):
        """Return a bounded content manifest; no folder-move endpoint is exposed."""
        from .folder_manifest import folder_manifest
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, 'list')
            parent = fd = read_home = None
            try:
                read_home = self._authorized(db, principal, 'read')
                parent, name = self._parent(home, path)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                entries, digest = folder_manifest(fd)
                return {'entries': entries, 'sha256': digest}
            finally:
                for descriptor in (fd, parent, read_home, home):
                    if descriptor is not None: os.close(descriptor)

    def move_folder(self, principal, source, destination, *, manifest_sha256, operation_id, phase=lambda name: None):
        """No-replace folder move with a durable, account-scoped retry receipt.

        Gateway-controlled mutations are serialized by the storage lock. Host
        processes writing directly to the disk do not honor this lock; they must
        be quiesced during this operation. Ambiguous recovery is never repaired
        by deleting or replacing either path. This primitive is not yet routed.
        """
        from .folder_manifest import folder_manifest
        src, dst = parts(source), parts(destination)
        if not src or not dst or len(src) > 16 or len(dst) > 16 or src == dst or dst[:len(src)] == src:
            raise Denied('Choose a different destination outside the folder')
        if not isinstance(manifest_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', manifest_sha256):
            raise Denied('Exact folder manifest hash required')
        try:
            if not isinstance(operation_id, str) or str(uuid.UUID(operation_id)) != operation_id:
                raise ValueError()
        except (ValueError, AttributeError):
            raise Denied('Canonical operation identifier required') from None
        with self.lock(), self.db() as db:
            home = self._authorized(db, principal, 'rename')
            src_parent = dst_parent = read_home = list_home = tree = None
            try:
                read_home = self._authorized(db, principal, 'read')
                list_home = self._authorized(db, principal, 'list')
                db.execute('PRAGMA synchronous=FULL')
                db.execute("CREATE TABLE IF NOT EXISTS folder_move_receipts (subject TEXT NOT NULL, operation_id TEXT NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL, manifest_sha256 TEXT NOT NULL, device TEXT NOT NULL, inode TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','done')), marker TEXT NOT NULL, PRIMARY KEY(subject,operation_id))")
                row = db.execute('SELECT source,destination,manifest_sha256,device,inode,state,marker FROM folder_move_receipts WHERE subject=? AND operation_id=?', (principal.sub, operation_id)).fetchone()
                if row and row[:3] != (source, destination, manifest_sha256):
                    raise Conflict('Operation identifier was used for a different folder move')
                if row and row[5] == 'done':
                    return {'operationId': operation_id, 'state': 'done'}
                src_parent, src_name = self._parent(home, source)
                dst_parent, dst_name = self._parent(home, destination)
                marker_name = 'user.codiserver.folder_move'
                def marker_matches(fd, expected):
                    try: return os.getxattr(fd, marker_name).hex() == expected
                    except OSError: return False
                def clean_marker(fd, expected):
                    try:
                        if marker_matches(fd, expected): os.removexattr(fd, marker_name);os.fsync(fd)
                    except OSError: pass
                def info(parent_fd, name):
                    try: return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError: return None
                def matches_manifest(fd):
                    entries, digest = folder_manifest(fd)
                    for entry in entries:
                        destination_path = '/'.join(dst) + '/' + entry['path']
                        if len(parts(destination_path)) > 16: raise Denied('Moved folder exceeds path depth limit')
                    return digest == manifest_sha256
                src_info, dst_info = info(src_parent, src_name), info(dst_parent, dst_name)
                if row:
                    device, inode = row[3:5]
                    identity = lambda item: item is not None and stat.S_ISDIR(item.st_mode) and str(item.st_dev) == device and str(item.st_ino) == inode
                    if src_info is None and identity(dst_info):
                        tree = os.open(dst_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dst_parent)
                        if not marker_matches(tree,row[6]) or not matches_manifest(tree): raise Conflict('Folder move recovery is ambiguous; retain both paths for review')
                        os.fsync(src_parent);os.fsync(dst_parent)
                        db.execute('BEGIN IMMEDIATE');db.execute("UPDATE folder_move_receipts SET state='done' WHERE subject=? AND operation_id=? AND state='prepared'", (principal.sub,operation_id));db.commit();phase('committed')
                        clean_marker(tree,row[6])
                        return {'operationId': operation_id, 'state': 'done'}
                    if not identity(src_info) or dst_info is not None:
                        raise Conflict('Folder move recovery is ambiguous; retain both paths for review')
                else:
                    if src_info is None or not stat.S_ISDIR(src_info.st_mode): raise Denied('Source folder required')
                    if dst_info is not None: raise Conflict('Destination already exists')
                tree = os.open(src_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src_parent)
                tree_info = os.fstat(tree)
                if not src_info or (tree_info.st_dev,tree_info.st_ino) != (src_info.st_dev,src_info.st_ino): raise Conflict('Source folder changed')
                if not matches_manifest(tree): raise Conflict('Folder changed; refresh its manifest before moving')
                if row and not marker_matches(tree,row[6]): raise Conflict('Folder move recovery is ambiguous; retain both paths for review')
                if not row:
                    # A crash after committing a completed receipt may leave its
                    # marker behind. Remove only a matching, completed receipt.
                    try: old_marker = os.getxattr(tree,marker_name).hex()
                    except OSError: old_marker = None
                    if old_marker is not None:
                        prior = db.execute("SELECT destination,device,inode,state FROM folder_move_receipts WHERE subject=? AND marker=?",(principal.sub,old_marker)).fetchone()
                        if not prior or prior != (source,str(tree_info.st_dev),str(tree_info.st_ino),'done'): raise Conflict('Folder has an unresolved move marker')
                        clean_marker(tree,old_marker)
                    count = db.execute('SELECT count(*) FROM folder_move_receipts WHERE subject=?', (principal.sub,)).fetchone()[0]
                    if count >= 10000: raise Denied('Folder move receipt limit reached')
                    marker = secrets.token_hex(32)
                    os.setxattr(tree,marker_name,bytes.fromhex(marker),flags=os.XATTR_CREATE);os.fsync(tree)
                    phase('marked')
                    try:
                        db.execute('BEGIN IMMEDIATE')
                        db.execute("INSERT INTO folder_move_receipts VALUES(?,?,?,?,?,?,?,'prepared',?)", (principal.sub,operation_id,source,destination,manifest_sha256,str(tree_info.st_dev),str(tree_info.st_ino),marker))
                        db.commit()
                    except BaseException:
                        db.rollback();clean_marker(tree,marker);raise
                    phase('prepared')
                else: marker = row[6]
                # Re-scan after receipt creation; never act on a known stale tree.
                if not matches_manifest(tree): raise Conflict('Folder changed; refresh its manifest before moving')
                current = info(src_parent, src_name)
                if not current or (current.st_dev,current.st_ino)!=(tree_info.st_dev,tree_info.st_ino): raise Conflict('Source folder changed')
                libc = ctypes.CDLL(None, use_errno=True);rename = libc.renameat2
                rename.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];rename.restype = ctypes.c_int
                if rename(src_parent,os.fsencode(src_name),dst_parent,os.fsencode(dst_name),1) != 0:
                    error=ctypes.get_errno();raise OSError(error,os.strerror(error))
                phase('renamed');os.fsync(src_parent);os.fsync(dst_parent)
                landed = info(dst_parent,dst_name)
                if info(src_parent,src_name) is not None or not landed or (landed.st_dev,landed.st_ino)!=(tree_info.st_dev,tree_info.st_ino): raise Conflict('Folder move recovery is ambiguous; retain both paths for review')
                if not marker_matches(tree,marker) or not matches_manifest(tree): raise Conflict('Folder changed during move; operation requires review')
                db.execute('BEGIN IMMEDIATE');db.execute("UPDATE folder_move_receipts SET state='done' WHERE subject=? AND operation_id=? AND state='prepared'", (principal.sub,operation_id));db.commit();phase('committed')
                clean_marker(tree,marker)
                return {'operationId': operation_id, 'state': 'done'}
            finally:
                for descriptor in (tree, src_parent, dst_parent, read_home, list_home, home):
                    if descriptor is not None: os.close(descriptor)

    def set_permission(self, subject, operation, allowed):
        if operation not in OPERATIONS or type(allowed) is not bool:
            raise ValueError('Invalid storage permission')
        with self.lock(), self.db() as db:
            cursor = db.execute('UPDATE permissions SET allowed=? WHERE subject=? AND resource=? AND operation=?', (int(allowed), subject, 'my-files', operation))
            if cursor.rowcount != 1:
                raise ValueError('Unknown registered storage permission')

    def set_enabled(self, subject, enabled):
        if type(enabled) is not bool:
            raise ValueError('Boolean storage policy required')
        with self.lock(), self.db() as db:
            cursor = db.execute('UPDATE users SET enabled=? WHERE subject=? AND state=?', (int(enabled), subject, 'ready'))
            if cursor.rowcount != 1:
                raise ValueError('Unknown ready registered storage account')


    def word_count(self, principal, path, previous_sha256, *, phase=lambda name: None):
        """One bounded, idempotent document operation; the server owns its record.

        Accepted report bytes survive a worker crash or a closed browser. A retry
        completes that exact snapshot rather than recounting a changed source.
        Output publication uses the normal private-folder ACLs and quotas.
        """
        home_id = self._identity(principal)
        names = parts(path)
        if not names or len(names) > 16 or not isinstance(previous_sha256, str) or not re.fullmatch('[0-9a-f]{64}', previous_sha256):
            raise Denied('Exact document path and version required')
        # Require both privileges even for a retry of a previously accepted job.
        with self.lock(), self.db() as acl:
            for operation in ['read', 'create']:
                os.close(self._authorized(acl, principal, operation))
        operation_id = hashlib.sha256(json.dumps(['word-count/1', principal.sub, path, previous_sha256], separators=(',', ':')).encode()).hexdigest()
        # A separate ledger does not change the permission schema or login DB.
        lock_path = self.state_root / '.document-operations.lock'
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            self._private_file(lock_path)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            database = self.state_root / 'document-operations.sqlite3'
            try:
                fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                os.close(fd)
                self._sync_directory(self.state_root)
            except FileExistsError:
                pass
            self._private_file(database)
            with sqlite3.connect('file:' + quote(str(database), safe='/') + '?mode=rw', uri=True, timeout=2) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute("CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, subject TEXT NOT NULL, source TEXT NOT NULL, source_sha256 TEXT NOT NULL, output TEXT NOT NULL, data BLOB NOT NULL, sha256 TEXT NOT NULL, completed INTEGER NOT NULL CHECK(completed IN (0,1)))")
                row = db.execute('SELECT subject,source,source_sha256,output,data,sha256,completed FROM reports WHERE id=?', (operation_id,)).fetchone()
                if row is None:
                    if db.execute('SELECT count(*) FROM reports WHERE subject=?', (principal.sub,)).fetchone()[0] >= 256 or db.execute('SELECT count(*) FROM reports').fetchone()[0] >= 10000:
                        raise Denied('Document operation record capacity reached')
                    source = self.read(principal, path, maximum_bytes=min(1024*1024, self.per_user_bytes))
                    if source['sha256'] != previous_sha256:
                        raise Conflict('Document changed; reload before generating a report')
                    try:
                        text = source['bytes'].decode('utf-8')
                    except UnicodeDecodeError:
                        raise Denied('Word count requires UTF-8 text') from None
                    if '\0' in text:
                        raise Denied('Word count requires text without NUL bytes')
                    basename = names[-1].encode('utf-8')[:80].decode('utf-8', errors='ignore')
                    output = '/'.join([*names[:-1], basename + '.word-count-' + operation_id[:16] + '.txt'])
                    parts(output)
                    report = ('Word-count report — generated by the server\n'
                              + 'Operation: ' + operation_id + '\nSource: ' + path
                              + '\nSource SHA256: ' + previous_sha256
                              + '\n\nWords (whitespace separated): ' + str(len(text.split()))
                              + '\nLines: ' + str(len(text.splitlines()))
                              + '\nCharacters (Unicode code points): ' + str(len(text))
                              + '\nUTF-8 bytes: ' + str(len(source['bytes'])) + '\n').encode('utf-8')
                    report_sha = hashlib.sha256(report).hexdigest()
                    db.execute('INSERT INTO reports VALUES(?,?,?,?,?,?,?,0)', (operation_id, principal.sub, path, previous_sha256, output, report, report_sha))
                    db.commit()
                    phase('accepted')
                    row = (principal.sub, path, previous_sha256, output, report, report_sha, 0)
                if row[:3] != (principal.sub, path, previous_sha256) or hashlib.sha256(row[4]).hexdigest() != row[5]:
                    raise Denied('Document operation record mismatch')
                # Check the current ACL again before returning an old completion.
                with self.lock(), self.db() as acl:
                    for operation in ['read', 'create']:
                        os.close(self._authorized(acl, principal, operation))
                try:
                    existing = self.read(principal, row[3])
                except FileNotFoundError:
                    if row[6]:
                        raise Conflict('The saved report was removed; this operation will not recreate it') from None
                    try:
                        self.put(principal, row[3], row[4])
                    except (Conflict, FileExistsError):
                        if self.read(principal, row[3])['sha256'] != row[5]:
                            raise Conflict('Report destination changed; no file was overwritten') from None
                else:
                    if existing['sha256'] != row[5]:
                        raise Conflict('Report destination changed; no file was overwritten')
                phase('published')
                db.execute('UPDATE reports SET completed=1 WHERE id=?', (operation_id,))
                db.commit()
                phase('completed')
                return {'status': 'completed', 'operation': 'word-count', 'operationId': operation_id,
                        'sourcePath': path, 'sourceSHA256': previous_sha256, 'path': row[3],
                        'sha256': row[5], 'bytes': len(row[4])}
        finally:
            os.close(descriptor)
