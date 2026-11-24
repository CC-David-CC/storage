"""Retire a specific deleted account's Files home for issuer maintenance."""

from contextlib import contextmanager
import os
from pathlib import Path
import shutil
import stat
import uuid

from .user_store import (
    RETIRED_HOMES_SCHEMA,
    permissions_database,
    private_directory,
    storage_lock,
)

DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _home_id(subject):
    if not isinstance(subject, str) or not subject.startswith('user:'):
        raise ValueError('Invalid cleanup account subject')
    identifier = uuid.UUID(subject[5:])
    if subject != f'user:{identifier}':
        raise ValueError('Non-canonical cleanup account subject')
    return identifier.hex


def _mount_id(fd):
    with Path(f'/proc/self/fdinfo/{fd}').open() as info:
        for line in info:
            name, _, value = line.partition(':')
            if name == 'mnt_id':
                return int(value)
    raise ValueError('Storage mount identity unavailable')


def _check_tree(fd, mount, depth=0):
    if _mount_id(fd) != mount:
        raise ValueError('Mount inside the selected Files home')
    info = os.fstat(fd)
    if info.st_uid != os.geteuid():
        raise ValueError('Unexpected owner inside the selected Files home')
    if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
        return
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or depth > 16:
        raise ValueError('Unexpected entry inside the selected Files home')

    directory = os.open('.', DIRECTORY_FLAGS, dir_fd=fd)
    try:
        for name in os.listdir(directory):
            child = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                _check_tree(child, mount, depth + 1)
            finally:
                os.close(child)
    finally:
        os.close(directory)


class AccountHomeCleanup:
    """Use the same permissions database and lock as the Files service."""

    def __init__(self, state_root, data_root):
        state = private_directory(state_root)
        data = private_directory(data_root)
        if state.is_relative_to(data) or data.is_relative_to(state):
            raise ValueError('Permission database and user files must be disjoint')
        self.users = private_directory(data / 'users')
        self.database = state / 'permissions.sqlite3'
        self.lock = state / '.storage.lock'

    @contextmanager
    def _open(self, *, read_only):
        with storage_lock(self.lock), permissions_database(self.database, read_only=read_only) as db:
            if db.execute('SELECT version FROM metadata').fetchall() != [(1,)]:
                raise ValueError('Unexpected Files permissions database version')
            root = os.open(self.users, DIRECTORY_FLAGS)
            try:
                yield db, root
            finally:
                os.close(root)

    @staticmethod
    def _binding(db, subject):
        home = _home_id(subject)
        binding = db.execute('SELECT home_id FROM users WHERE subject=?', (subject,)).fetchone()
        owner = db.execute('SELECT subject FROM users WHERE home_id=?', (home,)).fetchone()
        if binding not in (None, (home,)) or owner not in (None, (subject,)):
            raise ValueError('Files home ownership does not match the deleted account')
        return home, binding is not None

    @staticmethod
    def _check_directory(root, home, bound):
        try:
            directory = os.open(home, DIRECTORY_FLAGS, dir_fd=root)
        except FileNotFoundError:
            return False
        try:
            if not bound:
                raise ValueError('Unregistered Files home requires separate review')
            _check_tree(directory, _mount_id(root))
        finally:
            os.close(directory)
        return True

    def existing_homes(self, subjects):
        if not subjects:
            return set()
        with self._open(read_only=True) as (db, root):
            return {
                subject for subject in subjects
                if self._check_directory(root, *self._binding(db, subject))
            }

    def retire_and_remove(self, subject):
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError('Descriptor-relative directory removal unavailable')
        with self._open(read_only=False) as (db, root):
            home, bound = self._binding(db, subject)
            if not bound:
                self._check_directory(root, home, bound)
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            db.execute(RETIRED_HOMES_SCHEMA)
            # Leave a disabled binding even for a user who never opened Files.
            # This also prevents an older Files worker from provisioning it.
            db.execute(
                "INSERT INTO users VALUES (?, ?, 'pending', 0, 0) ON CONFLICT(subject) DO NOTHING",
                (subject, home),
            )
            db.execute('UPDATE users SET enabled=0 WHERE subject=?', (subject,))
            db.execute('INSERT OR IGNORE INTO retired_homes VALUES (?)', (subject,))
            db.execute('DELETE FROM permissions WHERE subject=?', (subject,))
            db.commit()
            exists = self._check_directory(root, home, bound)
            if exists:
                shutil.rmtree(home, dir_fd=root)
            os.fsync(root)
            return exists
