"""Publish the closed set of browser storage modules, never account state."""
import os
from pathlib import Path
import stat
import tempfile


BROWSER_STORAGE_ASSETS = (
    'mirror.mjs',
    'account-context.mjs',
    'verified-content.mjs',
    'opfs/core.mjs',
    'opfs/shared.mjs',
    'opfs/store.mjs',
    'opfs/worker.mjs',
    'opfs/LICENSE.txt',
)
_MAX_ASSET_BYTES = 2 * 1024 * 1024


def require_independent_stage(public_root):
    """Existing preview output must not share writable files with a release.

    Other parts of the general desktop stager copy files in place. Refuse a
    hard-linked or symbolic destination before those copies can mutate another
    release or follow a path outside this disposable output tree.
    """
    public_root = Path(public_root)
    if public_root.is_symlink() or (public_root.exists() and not public_root.is_dir()):
        raise ValueError('Choose an independent public staging directory')
    if not public_root.exists():
        return
    for path in public_root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Public staging must not contain symlinks')
        mode = path.stat()
        if stat.S_ISDIR(mode.st_mode):
            continue
        if not stat.S_ISREG(mode.st_mode) or mode.st_nlink != 1:
            raise ValueError('Public staging must contain independent regular files')


def _regular_tree(path, base):
    """Reject symlinks at every level inside the caller's staging root."""
    if base.is_symlink():
        raise ValueError('Storage asset root must not be a symlink')
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Storage assets must not use symlinks')
        if parent == base:
            return
    raise ValueError('Storage asset is outside its root')


def stage_browser_storage(source_root, public_root):
    """Stage all imports and the worker together; do not walk source folders.

    Validate the complete input and destination before writing. Atomic replacement
    also prevents an existing hard link from modifying another release's assets.
    The output includes modules only; enabling OPFS remains a separate decision.
    """
    source_root, public_root = Path(source_root), Path(public_root)
    source = source_root / 'storage/browser'
    output = public_root / 'storage/browser'
    snapshots = {}
    for relative in BROWSER_STORAGE_ASSETS:
        path = source / relative
        _regular_tree(path, source_root)
        if not path.is_file() or path.stat().st_size > _MAX_ASSET_BYTES:
            raise ValueError('Missing or invalid public storage asset: ' + relative)
        snapshots[relative] = path.read_bytes()
    _regular_tree(output, public_root)
    if output.exists():
        if not output.is_dir():
            raise ValueError('Public storage asset directory is invalid')
        for path in output.rglob('*'):
            _regular_tree(path, public_root)
            relative = path.relative_to(output).as_posix()
            if (path.is_dir() and relative == 'opfs') or (
                path.is_file() and relative in BROWSER_STORAGE_ASSETS
            ):
                continue
            raise ValueError('Unexpected public storage asset: ' + relative)
    for relative, data in snapshots.items():
        path = output / relative
        _regular_tree(path, public_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.storage-asset-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), 0o644)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return tuple(output / relative for relative in BROWSER_STORAGE_ASSETS)
