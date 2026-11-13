"""Triage saved PSReadLine command history."""

from modules.command_registry import command
from modules.powershell import literal, strip_outer_quotes


def _read_history(path_expression: str) -> str:
    return (
        f"$historyPath = {path_expression}; "
        "Write-Output \"History path: $historyPath\"; "
        "if (Test-Path -LiteralPath $historyPath -PathType Leaf) { "
        "Get-Content -LiteralPath $historyPath -ErrorAction Stop "
        "} else { Write-Output 'No saved history at this path' }"
    )


@command(
    "pshistory", "Security", "Read saved PowerShell command history",
    "pshistory [path | -all]",
)
def powershell_history(context, arguments: str) -> None:
    value = strip_outer_quotes(arguments)
    if value == "-all":
        script = (
            "$profilesRoot = Split-Path $env:USERPROFILE -Parent; "
            "$paths = @(Get-ChildItem -LiteralPath $profilesRoot -Directory -Force "
            "-ErrorAction SilentlyContinue | ForEach-Object { "
            "$folder = Join-Path $_.FullName 'AppData\\Roaming\\Microsoft\\Windows\\"
            "PowerShell\\PSReadLine'; "
            "Get-ChildItem -LiteralPath $folder -File -Filter '*_history.txt' "
            "-ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } }); "
            "$paths += (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath; "
            "$paths = @($paths | Where-Object { $_ } | Sort-Object -Unique); "
            "if (-not $paths) { 'No saved history files found' }; "
            "$paths | ForEach-Object { " + _read_history("$_") + " }"
        )
    elif value:
        script = _read_history(literal(value))
    else:
        script = (
            "$path = (Get-PSReadLineOption -ErrorAction SilentlyContinue).HistorySavePath; "
            "if (-not $path) { $path = Join-Path $env:APPDATA "
            "'Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt' }; "
            + _read_history("$path")
        )
    context.write(context.run(script, shell_type="powershell"))
