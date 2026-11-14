"""Check command construction without requiring a remote Windows host."""

import pytest

from modules.commands.filesystem import change_remote_directory, list_directory
from modules.commands.history import powershell_history
from modules.commands.software import installed_software
from modules.commands.task_details import view_task
from modules.commands.tasks import task_triage
from modules.context import CommandUsageError


class Context:
    def __init__(self):
        self.calls = []
        self.outputs = []

    def run(self, script, shell_type=None):
        self.calls.append((script, shell_type))
        return "result"

    def write(self, output):
        self.outputs.append(output)

    def info(self, message, *args):
        pass


def test_ls_depth_uses_literal_path_and_powershell():
    context = Context()
    list_directory(context, '-depth 2 "C:\\Program Files\\O\'Brien"')

    script, shell_type = context.calls[0]
    assert shell_type == "powershell"
    assert "-Depth 2" in script
    assert "-LiteralPath 'C:\\Program Files\\O''Brien'" in script


def test_cd_uses_cmd_syntax_even_in_a_powershell_session():
    class CwdContext(Context):
        cwd = r"C:\Users\Administrator"
        shell_type = "powershell"

        def run(self, script, shell_type=None):
            self.calls.append((script, shell_type))
            return "C:\\\r\n" if script == "cd " else ""

    context = CwdContext()
    change_remote_directory(context, "\\")

    assert context.calls == [('cd /d "C:\\"', "cmd"), ("cd ", "cmd")]
    assert context.cwd == "C:\\"


@pytest.mark.parametrize("arguments", ["-depth", "-depth -1", "-depth x", "a b"])
def test_ls_rejects_invalid_depth_or_multiple_paths(arguments):
    with pytest.raises(CommandUsageError):
        list_directory(Context(), arguments)


def test_software_queries_both_uninstall_views():
    context = Context()
    installed_software(context, "")

    assert len(context.calls) == 2
    assert all(shell_type == "powershell" for _, shell_type in context.calls)
    assert "Wow6432Node" in context.calls[0][0]
    assert "Wow6432Node" not in context.calls[1][0]
    assert all("DisplayName" in script for script, _ in context.calls)


def test_history_uses_saved_file_and_quotes_custom_path():
    context = Context()
    powershell_history(context, '"C:\\Users\\O\'Brien\\history.txt"')

    script, shell_type = context.calls[0]
    assert shell_type == "powershell"
    assert "Get-Content -LiteralPath $historyPath" in script
    assert "$historyPath = 'C:\\Users\\O''Brien\\history.txt'" in script


def test_history_all_scans_saved_histories_in_user_profiles():
    context = Context()
    powershell_history(context, "-all")

    script, shell_type = context.calls[0]
    assert shell_type == "powershell"
    assert "*_history.txt" in script
    assert "Get-PSReadLineOption" in script
    assert "Get-Content -LiteralPath $historyPath" in script


def test_task_triage_includes_actions_and_events():
    context = Context()
    task_triage(context, "")

    assert len(context.calls) == 2
    assert all(shell_type == "powershell" for _, shell_type in context.calls)
    assert "Get-ScheduledTask" in context.calls[0][0]
    assert "TaskPath + $task.TaskName" in context.calls[0][0]
    assert "Get-WinEvent" in context.calls[1][0]
    assert "-MaxEvents 60" in context.calls[1][0]


def test_view_task_uses_a_literal_root_task_name():
    context = Context()
    view_task(context, '"O\'Brien Task"')

    script, shell_type = context.calls[0]
    assert shell_type == "powershell"
    assert "/tn '\\O''Brien Task'" in script
