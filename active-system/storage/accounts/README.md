# Account file storage

The application mirrors saved account files between IndexedDB in the user's
browser and a private server data root. A registered account is identified by
its verified account ID, not by a browser-provided folder name. On the server
its files are stored at:

    <configured-data-root>/users/<account-UUID-without-dashes>/

My files presents that account folder as `/`; it is not the server's system
root or the temporary Linux guest filesystem. New accounts receive Documents,
Digital Projects, 3D Objects, Games, Pictures, Audio and Video as ordinary
private folders. Users may rename or delete them; they are seeded only while a
new account's home is initialized and are not recreated on later sign-ins.

For example, the empty `data/` directory beside this note is a possible **local
example**, and `state/` is a separate possible location for the permissions
SQLite database. They are not configured or serving files automatically; the local preview launcher explicitly uses them. Both
are ignored by Git and must be private (owned by the file service and mode
0700). The data and state roots must be separate. On a real server, configure
private directories outside the source checkout and public web tree instead;
back up those directories and the separate login database securely as operational
state. Source-code Git backups do not back up user files or account databases.

The browser copy is a useful second copy, not a guaranteed backup: a user can
clear site data and browsers may evict it. The Linux guest has a separate,
temporary filesystem and is not mirrored yet. The new mirror is under
development and must be tested with the configured server before deployment.

## How isolation works

The service requires the data root, state root, and each account home to be
owned by its service Unix account and private (mode 0700); its database and
file contents also receive restrictive modes. Accounts do **not** each have a
separate Linux user: all folders are owned by the file-service account. The
service verifies the signed request, derives the account ID from the verified
identity, checks its permissions database, and opens only that account's folder.
It rejects unsafe path components and avoids following symlinks. The browser's
Linux guest has no direct host filesystem access. This is application-enforced
account isolation plus Linux isolation from other Unix users; it is not a
separate kernel-enforced Unix UID per website account.

Files created directly on disk must be owned by the file service. The service
automatically tightens common owner-readable/writable file modes such as 0644
and 0664 to 0600 when encountered. It does not broaden a restrictive mode,
follow symlinks, or accept hard-linked files.
