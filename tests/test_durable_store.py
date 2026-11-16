"""Real temporary filesystem/SQLite domain tests; HTTP authentication is separate."""
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from webos_storage import Conflict, DEFAULT_ACCOUNT_FOLDERS, Denied, Principal, UserStore
from webos_storage.transfers import Quotas, AllowanceExceeded, initialize_transfers


class DurableStoreTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix='webos-storage-test-')
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)
        self.state = self.root / 'state'
        self.data = self.root / 'data'
        self.state.mkdir(mode=0o700)
        self.data.mkdir(mode=0o700)
        # Trusted server-domain fixture. A real HTTP principal must be verified by Gatekeeper.
        self.owner = Principal('user:' + str(uuid.uuid4()), str(uuid.uuid4()), 'registered', {}, int(time.time()) + 3600)
        self.store = self.open_store()
        self.store.ensure_user(self.owner)

    def open_store(self):
        return UserStore(self.state, self.data, initial_folders=DEFAULT_ACCOUNT_FOLDERS)

    def test_saved_bytes_revision_and_ownership_survive_service_restart(self):
        saved = self.store.put(self.owner, 'Documents/restart.txt', b'Durable synthetic document')
        resumed = self.open_store()
        resumed.ensure_user(self.owner)
        loaded = resumed.read(self.owner, 'Documents/restart.txt')
        self.assertEqual(loaded['bytes'], b'Durable synthetic document')
        self.assertEqual(loaded['sha256'], saved['sha256'])
        self.assertTrue((self.data / 'users' / self.owner.sub[5:].replace('-', '') / 'Documents/restart.txt').is_file())

    def test_stale_revision_refuses_overwrite_and_preserves_latest_bytes(self):
        first = self.store.put(self.owner, 'Documents/revision.txt', b'first')
        second = self.store.put(self.owner, 'Documents/revision.txt', b'second', previous_sha256=first['sha256'])
        with self.assertRaises(Conflict):
            self.store.put(self.owner, 'Documents/revision.txt', b'stale', previous_sha256=first['sha256'])
        actual = self.store.read(self.owner, 'Documents/revision.txt')
        self.assertEqual(actual['bytes'], b'second')
        self.assertEqual(actual['sha256'], second['sha256'])

    def test_server_permission_denial_prevents_replacement(self):
        saved = self.store.put(self.owner, 'Documents/permission.txt', b'unchanged')
        self.store.set_permission(self.owner.sub, 'replace', False)
        with self.assertRaises(Denied):
            self.store.put(self.owner, 'Documents/permission.txt', b'denied', previous_sha256=saved['sha256'])
        self.assertEqual(self.store.read(self.owner, 'Documents/permission.txt')['bytes'], b'unchanged')

    def test_anonymous_identity_cannot_create_persistent_home(self):
        anonymous = Principal(str(uuid.uuid4()), str(uuid.uuid4()), 'anonymous', {}, int(time.time()) + 3600)
        with self.assertRaises(Denied):
            self.store.ensure_user(anonymous)

    def test_eight_account_transfers_and_sixteen_shared_preserve_backpressure(self):
        initialize_transfers(self.store)
        quotas = Quotas(self.store, concurrent_uses=8, shared_concurrent_uses=16)
        other = Principal('user:' + str(uuid.uuid4()), str(uuid.uuid4()), 'registered', {}, int(time.time()) + 3600)
        third = Principal('user:' + str(uuid.uuid4()), str(uuid.uuid4()), 'registered', {}, int(time.time()) + 3600)
        active = []
        try:
            active.extend(quotas.begin(self.owner, 512) for _ in range(8))
            with self.assertRaises(AllowanceExceeded):
                quotas.begin(self.owner, 512)
            active.extend(quotas.begin(other, 512) for _ in range(8))
            with self.assertRaises(AllowanceExceeded):
                quotas.begin(third, 512)
            quotas.finish(active.pop(0))
            active.append(quotas.begin(third, 512))
        finally:
            for transfer in active:
                quotas.finish(transfer)


if __name__ == '__main__':
    unittest.main()
