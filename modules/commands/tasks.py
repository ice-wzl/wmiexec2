"""Scheduled-task action triage and recent Task Scheduler events."""

from modules.command_registry import command
from modules.context import CommandUsageError


@command(
    "tasktriage", "System", "Review nonstandard task actions and recent task events",
    "tasktriage",
)
def task_triage(context, arguments: str) -> None:
    if arguments.strip():
        raise CommandUsageError("tasktriage takes no arguments")

    context.info("Scheduled tasks with nonstandard actions")
    task_script = r"""
$items = foreach ($task in Get-ScheduledTask -ErrorAction Stop) {
    foreach ($action in $task.Actions) {
        $execute = [string]$action.Execute
        if ($execute -and $execute -notmatch '(?i)(\\Windows\\System32\\|%windir%\\system32\\|COM Handler)') {
            [pscustomobject]@{
                TaskName = $task.TaskPath + $task.TaskName
                Execute = $execute
                Arguments = $action.Arguments
            }
        }
    }
}
if ($items) { $items | Format-List | Out-String -Width 240 }
else { 'No nonstandard task actions found' }
""".strip()
    context.write(context.run(task_script, shell_type="powershell"))

    context.info("Recent Task Scheduler events")
    event_script = (
        "Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' "
        "-MaxEvents 60 -ErrorAction SilentlyContinue | "
        "Select-Object TimeCreated,Id,Message | Format-List | Out-String -Width 240"
    )
    context.write(context.run(event_script, shell_type="powershell") or "No task events available")


