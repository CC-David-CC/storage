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
