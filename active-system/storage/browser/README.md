# Browser storage

`mirror.mjs` stores each registered account's files in IndexedDB, scoped by
issuer and account ID. It queues changes made offline and synchronizes them
through the signed file gateway. Browser storage can be cleared or evicted; it
is not a substitute for server backups. Linux guest files are separate.

If the gateway reports a rate limit, new local changes remain queued and do
not restart automatic synchronization before its jittered retry. Manual sync
can still be requested. Once access returns, pending changes are retried. For
existing files, gateways with batch version support check up to 16 versions per
request; each write or deletion still checks its own expected server hash.
The current issuer file-authorization limit is shared behind the reverse proxy;
these client changes reduce load but do not establish 100-user capacity.

`stat(path)` reports the local file version, hash, status and size without
materializing its contents; applications may use it to detect changes.

`acquireSnapshot(path, {signal, expected})` returns
`{data, version, sha256, status, release}` for large-file consumers. Always call
the idempotent `release()` in `finally` after consuming the Blob. The lease
protects its backing generation across cooperating tabs. Account closure cannot
revoke bytes already handed to a caller, so it does not release that caller's
lease; tab death does. Existing byte reads remain supported. `readBlob` is a
compatibility call that materializes an independent Blob in a worker and has a
larger memory cost; use a leased snapshot for new large-file consumers.

## Verified-content candidate (not deployed)

`account-context.mjs` creates the one account-bound mirror used by the desktop.
It preserves the existing issuer/account scope and byte-returning app contract.
The default remains IndexedDB content. A release may explicitly select OPFS
with the issuer config:

```json
{"fileStorage":{"version":"codi-browser-file-content/1","backend":"opfs","databaseVersion":2}}
```

For an isolated connected preview this is `--user-files --file-content-store
opfs`. This is an **origin-wide release selection**, not an app or account
preference. OPFS content references raise the shared mirror database to version
2. Older version-1 writers stop on version change and cannot reopen the database.
Removing the config does not undo this migration or make an old client usable.
Unknown storage versions and unavailable OPFS fail explicitly; there is no silent
fallback to an older writer. Qualify the guarded assets and recovery procedure
before enabling this on beta or promoting it to main.

The existing mirror rows remain authoritative for path, local version,
conflicts and attempted writes. Immutable OPFS content references do not replace
that metadata. Migration compares the entire original row before replacing its
content and preserves unresolved state. Large captures and verification use a
module worker; this alone does not guarantee a fixed browser memory ceiling.
Published generations are retained while safe reader-aware reclamation is being
implemented. Browser storage can still be evicted or cleared.

Public assets are staged through `origin_service/public_storage.py`'s closed
allowlist, including worker imports and the hash library's license. Do not copy
the storage tree recursively: its neighboring folders describe private account
state. The complete static builder uses the same staging helper and hashes each
included module into its cache manifest. Staging does not enable the backend.

General preview staging requires a fresh private destination or independent
regular files. It refuses pre-existing hardlinks and symlinks before copying
root/network/app assets. The multi-file stage is not a transaction; discard a
failed stage. Do not let concurrent writers modify it during a build.
