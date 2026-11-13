"""Map Windows file paths into a host-scoped local collection tree."""

import ntpath
import re
from pathlib import Path


def mirrored_path(root: Path, hostname: str, remote_path: str) -> Path:
    """Return collect/<host>/<remote path>, omitting the C: drive prefix."""
    name = hostname.strip().rstrip(".").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name):
        raise ValueError(f"invalid remote hostname: {hostname!r}")

    drive, tail = ntpath.splitdrive(ntpath.normpath(remote_path))
    if not re.fullmatch(r"[a-zA-Z]:", drive) or not tail.startswith("\\"):
        raise ValueError(f"remote path must be an absolute drive path: {remote_path!r}")

    components = [part.lower() for part in tail.split("\\") if part]
    if not components or any(part in (".", "..") for part in components):
        raise ValueError(f"remote path must name a file: {remote_path!r}")
    if drive.lower() != "c:":
        components = ["drives", drive[0].lower(), *components]

    collection_root = Path(root).resolve()
    destination = collection_root.joinpath(name, *components)
    if not destination.parent.resolve().is_relative_to(collection_root):
        raise ValueError(f"collection path escapes its root: {remote_path!r}")
    return destination
