"""Remote and local filesystem commands."""

import ntpath
import os
import shlex

from modules.command_registry import command
from modules.context import CommandUsageError
from modules.powershell import literal


def _arguments(value: str):
    lexer = shlex.shlex(value, posix=False)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return [item[1:-1] if len(item) >= 2 and item[0] == item[-1] == '"' else item for item in lexer]


@command("ls", "Filesystem", "List a remote directory", "ls [-depth N] [path]")
def list_directory(context, arguments: str) -> None:
    parts = _arguments(arguments)
    depth = None
    paths = []
    index = 0
    while index < len(parts):
        if parts[index].lower() == "-depth":
            if depth is not None or index + 1 >= len(parts) or not parts[index + 1].isdigit():
                raise CommandUsageError("-depth requires one non-negative integer")
            depth = int(parts[index + 1])
            index += 2
        else:
            paths.append(parts[index])
            index += 1
    if len(paths) > 1:
        raise CommandUsageError("ls accepts one path")

    path = paths[0] if paths else "."
    recurse = f" -Depth {depth}" if depth is not None else ""
    script = (
        f"Get-ChildItem -LiteralPath {literal(path)} -Force{recurse} -ErrorAction Stop | "
        "Format-Table Mode,LastWriteTime,Length,FullName -AutoSize | Out-String -Width 240"
    )
    context.write(context.run(script, shell_type="powershell"))


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

    output = context.run(f'cd /d "{target}"', shell_type="cmd")
    if output.strip():
        context.write(output)
        return
    context.cwd = target
    confirmed = context.run("cd ", shell_type="cmd").strip("\r\n")
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
