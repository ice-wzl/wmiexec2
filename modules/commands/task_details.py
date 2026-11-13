"""Detailed view of one scheduled task."""

from modules.command_registry import command
from modules.context import CommandUsageError
from modules.powershell import literal, strip_outer_quotes


@command("view-task", "System", "Display full details for a scheduled task", "view-task <task-name>")
def view_task(context, arguments: str) -> None:
    name = strip_outer_quotes(arguments)
    if not name:
        raise CommandUsageError("view-task requires a task name")
    if not name.startswith("\\"):
        name = "\\" + name
    script = f"& schtasks.exe /query /fo LIST /v /tn {literal(name)}"
    context.write(context.run(script, shell_type="powershell"))
