"""The intentionally small API exposed to command modules."""

import logging
import ntpath
import os
import re
from pathlib import Path
from typing import Optional

from modules.collection_paths import mirrored_path


class CommandUsageError(ValueError):
    """Raised when a command receives invalid arguments."""


class CommandContext:
    """Adapter that keeps command modules independent of the interactive shell."""

    def __init__(self, session, artifact_directory: Optional[Path] = None,
                 collection_directory: Optional[Path] = None):
        self._session = session
        self.artifact_directory = artifact_directory or Path.cwd() / ".wmiexec2-artifacts"
        self.collection_directory = collection_directory or Path.cwd() / "collect"
        self._hostname = None

    @property
    def cwd(self) -> str:
        return self._session.cwd

    @cwd.setter
    def cwd(self, value: str) -> None:
        self._session.cwd = value

    @property
    def shell_type(self) -> str:
        return self._session.shell_type

    @property
    def remote_hostname(self) -> str:
        return self._remote_hostname()

    def run(self, command: str, shell_type: Optional[str] = None) -> str:
        return self._session.execute(command, shell_type)

    def write(self, output: str) -> None:
        if output and output.strip("\r\n"):
            print(output)

    def info(self, message: str, *args) -> None:
        logging.info(message, *args)

    def artifact_path(self, filename: str) -> Path:
        self.artifact_directory.mkdir(parents=True, exist_ok=True)
        return self.artifact_directory / filename

    def download(self, remote_path: str, local_path: Optional[Path] = None) -> Path:
        remote_abs = self._absolute_remote_path(remote_path)
        drive, tail = ntpath.splitdrive(remote_abs)
        if not re.fullmatch(r"[A-Za-z]:", drive):
            raise CommandUsageError(f"remote path must have a drive letter: {remote_path}")

        destination = (
            Path(local_path) if local_path is not None
            else mirrored_path(self.collection_directory, self._remote_hostname(), remote_abs)
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".part")
        share = drive[:-1] + "$"
        path_in_share = tail if tail.startswith("\\") else "\\" + tail

        try:
            with temporary.open("wb") as handle:
                self._session.smb.getFile(share, path_in_share, handle.write)
            os.replace(temporary, destination)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return destination.resolve()

    def _remote_hostname(self) -> str:
        if self._hostname is None:
            output = self.run("hostname", shell_type="cmd")
            self._hostname = next((line.strip() for line in output.splitlines() if line.strip()), "")
            if not self._hostname:
                raise RuntimeError("could not determine the remote hostname for downloads")
        return self._hostname

    def upload(self, local_path: str, remote_path: str = "") -> str:
        source = Path(local_path)
        if not source.is_file():
            raise FileNotFoundError(source)

        destination = remote_path.replace("/", "\\")
        destination_drive, _ = ntpath.splitdrive(destination)
        if destination_drive:
            remote_abs = ntpath.normpath(
                ntpath.join(destination, source.name) if destination.endswith("\\") else destination
            )
        elif destination.startswith("\\"):
            current_drive, _ = ntpath.splitdrive(self.cwd)
            absolute_destination = current_drive + destination
            remote_abs = ntpath.normpath(
                ntpath.join(absolute_destination, source.name)
                if destination.endswith("\\") else absolute_destination
            )
        else:
            base = ntpath.join(self.cwd, destination)
            if destination in ("", ".") or destination.endswith("\\"):
                base = ntpath.join(base, source.name)
            remote_abs = ntpath.normpath(base)

        drive, tail = ntpath.splitdrive(remote_abs)
        if not drive:
            raise CommandUsageError(f"remote path has no drive: {remote_path}")
        share = drive[:-1] + "$"
        path_in_share = tail if tail.startswith("\\") else "\\" + tail
        with source.open("rb") as handle:
            self._session.smb.putFile(share, path_in_share, handle.read)
        return remote_abs

    def _absolute_remote_path(self, path: str) -> str:
        path = _strip_outer_quotes(path)
        drive, _ = ntpath.splitdrive(path)
        if drive:
            return ntpath.normpath(path)
        if path.startswith("\\"):
            current_drive, _ = ntpath.splitdrive(self.cwd)
            return ntpath.normpath(current_drive + path)
        return ntpath.normpath(ntpath.join(self.cwd, path))


def _strip_outer_quotes(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
