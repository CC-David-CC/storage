# Storage

Owns account file persistence, revision preconditions, permissions, bounded transfers, and the browser mirror implementation. The Python public API is `webos_storage.UserStore`, `FileGateway`, `Gatekeeper`, `Principal`, `Conflict`, `CommitUncertain`, and explicit ledger/transfer initialization. Stateless identity proof primitives come from the public Accounts package; no old-workspace or private cross-repository import is used by the packaged server.

Install alongside the trusted local Accounts checkout using the parent development environment; do not substitute an unrelated public package with the same name. The parent pins both repositories. Third-party dependencies are locked separately by composition.

Run `python -m unittest discover -s tests -v` in that environment. Four real temporary filesystem/SQLite tests cover persisted bytes/revision/account-home binding after restart, rejection of stale revisions, server permission denial, and refusal of anonymous persistent homes. Principals in these domain tests are explicit trusted fixtures. Real HTTP principals must be verified by Gatekeeper; these tests do not establish authentication, browser synchronization or agent authorization.

The browser mirror and client require their public-interface/build port before the desktop can use them. The mirror must never label a browser-local write as a confirmed durable account save. Closing a view must not destroy Storage. Existing identity/file formats and ownership remain requirements; no live account data was copied or migrated.

`research/opfs-storage/` retains a distinct historical research implementation. It is not active code and must not be merged over production OPFS. Do not automatically run cancelled filesystem-race, foreign-account or fault probes. Old native operator source remains preserved separately until its deliberate port and authorization.
