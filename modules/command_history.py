"""Local, per-host command logs that also populate interactive readline history."""

import os
import stat
import tempfile
from pathlib import Path

from modules.collection_paths import normalize_hostname


def _readline_module():
    try:
        import readline
    except ImportError:
        return None
    return readline


class CommandHistory:
    def __init__(self, hostname: str, directory: Path = None, readline_module=None):
        if directory is None:
            directory = Path("/tmp") if os.name == "posix" else Path(tempfile.gettempdir())
        self.path = Path(directory) / f"{normalize_hostname(hostname)}_commands.log"
        self._readline = readline_module if readline_module is not None else _readline_module()
        self._load()

    def _open(self, flags: int) -> int:
        fd = os.open(self.path, flags | getattr(os, "O_NOFOLLOW", 0) | os.O_CREAT, 0o600)
        try:
            details = os.fstat(fd)
            if not stat.S_ISREG(details.st_mode):
                raise ValueError(f"command history is not a regular file: {self.path}")
            if os.name == "posix":
                if details.st_uid != os.getuid():
                    raise PermissionError(f"command history belongs to another user: {self.path}")
                if details.st_mode & 0o077:
                    os.fchmod(fd, 0o600)
            return fd
        except Exception:
            os.close(fd)
            raise

    def _load(self) -> None:
        fd = self._open(os.O_RDONLY)
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as history_file:
            if self._readline is not None:
                if hasattr(self._readline, "clear_history"):
                    self._readline.clear_history()
                for line in history_file:
                    line = line.rstrip("\r\n")
                    if line:
                        self._readline.add_history(line)

    def append(self, command: str) -> None:
        if not command.strip() or command == "EOF":
            return
        fd = self._open(os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, (command + "\n").encode("utf-8", errors="replace"))
        finally:
            os.close(fd)
