"""Installed software inventory from both Windows uninstall registry views."""

from modules.command_registry import command
from modules.context import CommandUsageError
from modules.powershell import literal


@command("software", "System", "List installed software in both registry views", "software")
def installed_software(context, arguments: str) -> None:
    if arguments.strip():
        raise CommandUsageError("software takes no arguments")

    views = (
        ("32-bit", r"HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"),
        ("64-bit", r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"),
    )
    for label, registry_path in views:
        context.info("%s software", label)
        script = (
            f"Get-ItemProperty -Path {literal(registry_path)} -ErrorAction SilentlyContinue | "
            "Where-Object { $_.DisplayName } | Sort-Object DisplayName | "
            "Select-Object -ExpandProperty DisplayName | Out-String -Width 240"
        )
        context.write(context.run(script, shell_type="powershell") or "No entries found")
