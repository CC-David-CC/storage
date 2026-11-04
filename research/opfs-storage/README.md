# OPFS storage research prototype

This is isolated research, not connected to the desktop, gateway, accounts or
live beta. It takes an opaque scope supplied by its caller. A future integration
must bind that scope to a stable issuer plus account ID, enforce signed server
permissions separately, and prevent stale account contexts from operating.
Hash-named OPFS directories provide namespace hygiene only: hostile JavaScript
on the same origin can access OPFS and IndexedDB directly.

A dedicated worker reads/writes/hashes no more than 256 KiB per processing
iteration. It writes a uniquely named candidate, closes it, verifies the saved
generation and re-hashes the source, then the main thread uses an IndexedDB
transaction to compare-and-swap a small current/previous metadata record. No
OPFS rename is used or assumed atomic. A reader hashes the named generation in
a worker, compares it to recorded length/hash, and rechecks the metadata version
before returning a File. Failed integrity or a missing generation is reported
as Corrupt; previous recovery is explicit and itself verifies and CAS-checks.
Transient worker startup, worker error, quota, and deadline failures are
StorageUnavailable with separate codes. A total worker deadline is bounded and
close/account invalidation terminates the worker. An IDB transaction that
commits as an account closes reports Uncertain.

Important limits: this does not yet implement general generation collection, repeated
rollback history, quota reservations, automatic server sync,
cross-device conflict UX, robust multiprocess cleanup or production authorization.
Concurrent/conflicting/cancelled saves can leave candidate generations behind.
OPFS close and IndexedDB transaction completion are not proved durable across
machine power loss; independently persisted files and pointers cannot be
claimed one atomic physical transaction. If a newly published generation is
missing after a crash, the previous metadata allows explicit recovery where
its data remains intact. Only explicitly journaled never-published candidates may be cleaned under
cooperative account locks; published and unknown generations are retained. A File
already returned to a caller cannot be revoked. Browser and OS caches, native
Blob backing and concurrent operations mean the 256 KiB processing window is
not a universal browser-RAM bound.

Tests ran on isolated R730 loopback with disposable Chrome profiles. `opfs-test`
passed scoped namespace separation, stale/concurrent CAS, deliberate corruption
and verified explicit previous restoration, and cancellation during a save.
`opfs-errors` passed simulated worker hang (deadline/termination) and worker
startup failure, both reported unavailable rather than corrupt, with existing
bytes preserved. `opfs-large` saved and reopened 128 MiB with an independent
SHA-256 match, 16.1 s save and no main-thread Blob.arrayBuffer calls observed.
A dedicated Chrome profile sampled summed process RSS peak 1,354,063,872 bytes
at 0.25 s intervals; RSS double-counts shared pages. It is not comparable to
the earlier two-session network test and is not a hard memory guarantee.

In a separate persistent disposable Chrome profile, `opfs-crash-start-b` saved
an initial 15-byte generation and started a 128 MiB replacement. The dedicated
Chrome process was SIGKILLed immediately after the replacement started; after
restarting the same profile, `opfs-crash-read` verified the prior generation
and SHA-256. This exercises one browser process crash before publication, not
host failure, power loss or every write/transaction boundary.

Tests require a trustworthy Chromium on loopback and a test-only server serving
this directory as a secure context, e.g. Python HTTP server on 127.0.0.1:19894.
Test Chrome DevTools is loopback 19268 for the small cases and 19278 for large
and crash cases; PUPPETEER_CORE_PATH supplies the external test dependency.
Do not serve or activate this prototype in production.

Database opens now share one pending promise, fail distinctly on blocked/error
or bounded timeout, abort on close/account invalidation, and close a late
connection. Chromium injected hung-open test passes timeout and close; this
does not simulate a real IDB upgrade blocked by another browser process.

## Staging journal and narrowly scoped cleanup

Each participating save holds a shared account-scoped Web Lock and commits a
staging journal entry before starting its worker. A successful publication
updates the file pointer and marks the generation published in one IndexedDB
transaction. Cleanup holds the matching exclusive account lock, immediately
rechecks account-scoped metadata, removes only journaled staging files with no
current/previous reference, then clears the journal entry. Missing files are
idempotent on retry; failures leave the journal for later investigation. All
published generations, unknown files and legacy unjournaled files are retained.
Lock waits are bounded and do not force-release another operation. Cleanup queries only the current account's staging index, processes at most
256 entries per call, and checks current/previous reference indexes individually. This protocol assumes all participating
writers honor the lock and ledger: it is not protection against old or hostile
same-origin code, and does not establish cross-store physical atomicity.

Production account integration does not exist in this prototype. Two real Chromium tabs showed cleanup waited for an in-progress
writer. Tests confirmed stale-CAS orphan deletion, unknown/ever-published
retention, repeated cleanup, scoped-only IDB queries, bounded batches, lock wait
timeout, and a real blocked IDB upgrade: an abandoned open was prevented from
upgrading after the older connection closed. In a dedicated persistent Chrome
profile, SIGKILL after the worker closed and verified a candidate but before
metadata publication retained the prior file; cleanup removed exactly the
staged orphan. A second SIGKILL after publication returned the new verified
file on restart and cleanup removed nothing. These are controlled browser
process crash points, not machine power loss or a proof of OPFS durability.

## Indexed cleanup and experimental signed sync adapter

Schema v3 indexes [scope,status] for staging and scoped current/previous
references. Each cleanup call processes at most 256 staging records and reports
whether more remain; it does not scan ever-growing published history. An
inconsistent staging generation that is still referenced is atomically marked
retained (never deleted) and counted separately, so it does not hide later
orphans. Retained rows require explicit future investigation. The actual
reference check and transition share one readwrite IDB transaction. Chromium
tests pass for 4,097 published rows plus an orphan, 257-orphan pagination,
256 referenced staging rows followed by an orphan, and scope-specific indexes.
The approach still assumes cooperative current-version clients; old or hostile
same-origin code can bypass its locks and schema.

The research-only `sync(path,server)` adapter expects a trusted session-bound
signed file client and an opaque scope constructed by its caller from stable
issuer and account ID. It records the server base and exact attempted hash in
local metadata before dispatch, keeps that attempt across local edits, uses
signed server version checks and CAS writes, and serializes same-account syncs
with a separate lock. Local saves may proceed while network sync is in flight.
A matching server hash establishes byte equality, not which writer produced it
or a unique revision; ABA and host-side concurrent writers remain limitations.
The adapter is not wired into the desktop, provides no automatic pull or user
conflict-resolution UI, does not authenticate its supplied adapter, and is not
ready for deployment or production cleanup. Published generations continue to
accumulate; no general history retention or power-loss durability is claimed.

Isolated real Chromium with an actual dd8/44da signed file gateway passed:
concurrent local edit during committed upload remains pending and then syncs;
injected lost committed reply plus a later local edit reconciles; an invalid
server receipt remains uncertain and reconciles; remote CAS conflict preserves
local bytes; another registered account is denied server read; and a separate
local account scope sees no file. A second test closes the store after the
server commits but while its reply body is deliberately stalled; the SDK aborts,
reports FileCommitUncertain, and reopening reconciles with exactly one upload.
These tests use disposable accounts and local services. They do not demonstrate
real WAN failure, power loss, arbitrary host writer exclusion, multi-device
identity integration, or strict whole-browser RAM limits.

## Experimental verified remote pull

`pull(path,server)` rejects pending local work/attempts, obtains server version
and size, fetches an expected-hash Blob through the trusted SDK, then journals a
candidate and verifies it in 256 KiB worker slices. Before publication it
rechecks remote version and size and atomically compares the prior local
generation and sync metadata in the IDB publication transaction. A racing
local edit or remote version change is rejected without replacing local data.
An interrupted candidate remains eligible for the separately guarded cleanup.
The existing SDK constructs a browser-managed Blob first, so this is bounded
worker processing, not a proven bound on total browser memory or network
buffering. Hash equality provides byte equality, not a unique revision or
protection from ABA or unmanaged host-side writers. A remote change after the
last version check can leave a temporarily stale snapshot; later CAS still
prevents overwriting a changed remote. No automatic pull, user-facing conflict
flow, account authority, production integration or remote deletion is provided.

Signed Chromium test `opfs-pull-signed.mjs` passed initial fetch, corrupted
payload refusal, a local edit immediately before publication (CAS conflict,
local preserved), remote change during fetch, and mirror-validity cancellation
while the SDK adapter remained independently valid. `opfs-validity-return.mjs`
confirmed a server-committed write whose return coincided with account
invalidation reports SyncUncertain; reopening reconciles without re-upload.
A dedicated Chromium process was SIGKILLed after the verified download worker
closed its candidate but before the pointer publication: on same-profile
restart the old file remained and one orphan was cleaned. A second SIGKILL
immediately after confirmed publication preserved the new remote file and
cleanup removed nothing. LocalStorage used for the first test scope was lost
on abrupt termination; the isolated recovery test located the sole test row
by IndexedDB key instead. These are browser-process crash points, not host
power loss, proof of synchronized disk durability or all race conditions.
No live system was used.
