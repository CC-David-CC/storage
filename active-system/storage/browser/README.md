# Browser storage

`mirror.mjs` stores each registered account's files in IndexedDB, scoped by
issuer and account ID. It queues changes made offline and synchronizes them
through the signed file gateway. Browser storage can be cleared or evicted; it
is not a substitute for server backups. Linux guest files are separate.
