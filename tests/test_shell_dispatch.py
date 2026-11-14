"""Interactive command parsing and registry dispatch."""

from remoteshell import RemoteShell


def test_hyphenated_command_is_dispatched_locally(tmp_path, monkeypatch, capsys):
    class Session:
        cwd = "C:\\"
        shell_type = "powershell"
        output_path = r"\temp\output"

        def __init__(self, *args, **kwargs):
            self.calls = []

        def execute(self, command, shell_type=None):
            self.calls.append((command, shell_type))
            if command == "hostname":
                return "HOST-01\r\n"
            if command == "cd ":
                return self.cwd + "\r\n"
            return "task details" if command.startswith("& schtasks.exe") else ""

    monkeypatch.setattr("remoteshell.RemoteSession", Session)
    shell = RemoteShell("ADMIN$", object(), object(), "powershell", history_directory=tmp_path)
    startup_cd_calls = [call for call in shell._session.calls if call[0].startswith("cd")]
    assert all(shell_type == "cmd" for _, shell_type in startup_cd_calls)
    shell._session.calls.clear()

    shell.onecmd('view-task "StartWork"')
    assert len(shell._session.calls) == 1
    command, shell_type = shell._session.calls[0]
    assert command == "& schtasks.exe /query /fo LIST /v /tn '\\StartWork'"
    assert shell_type == "powershell"

    shell._session.calls.clear()
    shell.onecmd("view-task")
    assert shell._session.calls == []
    assert "usage: view-task <task-name>" in capsys.readouterr().out
