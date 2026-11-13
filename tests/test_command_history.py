"""Persistent command history for an interactive remote shell."""

import os
import stat

from modules.command_history import CommandHistory
from remoteshell import RemoteShell


class Readline:
    def __init__(self):
        self.commands = ["other-host-command"]

    def clear_history(self):
        self.commands.clear()

    def add_history(self, line):
        self.commands.append(line)


def test_history_loads_prior_commands_and_appends_new_ones(tmp_path):
    path = tmp_path / "host-01_commands.log"
    path.write_text("whoami\nhostname\n", encoding="utf-8")
    readline = Readline()

    history = CommandHistory("HOST-01", tmp_path, readline)
    history.append("dir C:\\Windows")
    history.append("")
    history.append("EOF")

    assert readline.commands == ["whoami", "hostname"]
    assert path.read_text(encoding="utf-8") == "whoami\nhostname\ndir C:\\Windows\n"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_shell_uses_remote_hostname_and_records_commands(tmp_path, monkeypatch):
    class Session:
        cwd = "C:\\"
        shell_type = "cmd"
        output_path = r"\temp\output"

        def __init__(self, *args, **kwargs):
            pass

        def execute(self, command, shell_type=None):
            if command == "hostname":
                return "HOST-01\r\n"
            if command == "cd ":
                return self.cwd + "\r\n"
            return ""

    monkeypatch.setattr("remoteshell.RemoteSession", Session)
    shell = RemoteShell("ADMIN$", object(), object(), "cmd", history_directory=tmp_path)

    assert shell.onecmd("exit") is True
    assert (tmp_path / "host-01_commands.log").read_text(encoding="utf-8") == "exit\n"
