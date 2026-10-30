"""Read-only, descriptor-relative file shares with no symlink following."""
import os
from pathlib import Path
import stat
from .policy import Denied, parts

class ReadOnlyShare:
    def __init__(self, root):
        self.root = Path(root)
        if not self.root.is_absolute() or '..' in self.root.parts:
            raise ValueError('Explicit share root required')
        # Open each component instead of resolving a user-controlled symlink.
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in self.root.parts[1:]:
                following = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd);fd = following
            self.fd = fd
        except BaseException:
            os.close(fd);raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd);self.fd = None

    def open(self, path, *, directory=False):
        components = parts(path)
        fd = os.dup(self.fd)
        try:
            for index, name in enumerate(components):
                want_directory = directory or index < len(components)-1
                following = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | (os.O_DIRECTORY if want_directory else 0), dir_fd=fd)
                os.close(fd);fd = following
            info = os.fstat(fd)
            if directory:
                if not stat.S_ISDIR(info.st_mode):
                    raise Denied('Not a directory')
            elif not components or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise Denied('Only regular files with one link may be read')
            return fd
        except BaseException:
            os.close(fd);raise

    def list(self, path):
        fd = self.open(path, directory=True)
        try:
            names = os.listdir(fd)
            if len(names) > 512:
                raise Denied('Directory listing limit exceeded')
            result = []
            for name in sorted(names):
                if name.startswith('.'):
                    continue
                try:
                    parts(name)
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except (OSError, ValueError):
                    continue
                if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    result.append({'name': name, 'directory': stat.S_ISDIR(info.st_mode), 'bytes': info.st_size if stat.S_ISREG(info.st_mode) else None})
            return result
        finally:
            os.close(fd)
