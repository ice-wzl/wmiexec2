"""Remote and local filesystem commands."""

import ntpath
import os
import shlex

from modules.command_registry import command
from modules.context import CommandUsageError


def _arguments(value: str):
    lexer = shlex.shlex(value, posix=False)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return [item[1:-1] if len(item) >= 2 and item[0] == item[-1] == '"' else item for item in lexer]


@command("ls", "Filesystem", "List a remote directory", "ls [path]")
def list_directory(context, arguments: str) -> None:
    path = arguments.strip() or "."
    context.write(context.run(f'dir /A /N /O:D "{path}"'))


@command("cat", "Filesystem", "Display a remote file", "cat <path>")
def display_file(context, arguments: str) -> None:
    if not arguments.strip():
        raise CommandUsageError("cat requires a remote path")
    context.write(context.run("type " + arguments))


@command("cd", "Filesystem", "Change the remote working directory", "cd [path]")
def change_remote_directory(context, arguments: str) -> None:
    raw = arguments.strip().strip('"')
    if raw in ("", "."):
        target = context.cwd
    elif raw in ("\\", "/"):
        drive, _ = ntpath.splitdrive(context.cwd)
        target = drive + "\\"
    else:
        drive, _ = ntpath.splitdrive(raw)
        if drive:
            target = ntpath.normpath(raw)
        elif raw.startswith("\\"):
            current_drive, _ = ntpath.splitdrive(context.cwd)
            target = ntpath.normpath(current_drive + raw)
        else:
            target = ntpath.normpath(ntpath.join(context.cwd, raw))

    output = context.run(f'cd /d "{target}"')
    if output.strip():
        context.write(output)
        return
    context.cwd = target
    confirmed = context.run("cd ").strip("\r\n")
    if confirmed:
        context.cwd = confirmed


@command("lcd", "Local", "Change the local working directory", "lcd [path]")
def change_local_directory(context, arguments: str) -> None:
    path = arguments.strip().strip('"')
    if path:
        os.chdir(path)
    print(os.getcwd())


@command("lpwd", "Local", "Display the local working directory", "lpwd")
def local_working_directory(context, arguments: str) -> None:
    print(os.getcwd())


@command("lget", "Local", "Download a remote file", "lget <remote-path>")
def download_file(context, arguments: str) -> None:
    if not arguments.strip():
        raise CommandUsageError("lget requires a remote path")
    destination = context.download(arguments)
    print(f"[+] downloaded to {destination}")


@command("lput", "Local", "Upload a local file", "lput <local-path> [remote-path]")
def upload_file(context, arguments: str) -> None:
    parts = _arguments(arguments)
    if not parts or len(parts) > 2:
        raise CommandUsageError("lput expects a local path and an optional remote path")
    remote = context.upload(parts[0], parts[1] if len(parts) == 2 else "")
    print(f"[+] uploaded {parts[0]} -> {remote}")
