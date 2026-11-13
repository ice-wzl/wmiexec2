"""Verbose, read-only Microsoft Defender status and artifact triage."""

from modules.command_registry import command
from modules.context import CommandUsageError

_DEFENDER = r"HKLM\SOFTWARE\Microsoft\Windows Defender"
_POLICY = r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"


def _show(context, label: str, command: str, shell_type: str) -> None:
    print(f"\n[*] {label}")
    print(f"    > {command}")
    output = context.run(command, shell_type=shell_type)
    if output and output.strip():
        context.write(output)
    else:
        print("    (no output)")


@command("defender", "Security", "Inspect Defender status, settings, logs, and events", "defender")
def defender_configuration(context, arguments: str) -> None:
    if arguments.strip():
        raise CommandUsageError("defender takes no arguments")

    _show(
        context,
        "Effective protection status",
        "Get-MpComputerStatus -ErrorAction Stop | "
        "Select-Object AMRunningMode,AMServiceEnabled,AntivirusEnabled,"
        "RealTimeProtectionEnabled,IsTamperProtected,BehaviorMonitorEnabled,"
        "IoavProtectionEnabled,NISEnabled,AMProductVersion,AntivirusSignatureVersion,"
        "AntivirusSignatureLastUpdated,QuickScanEndTime,FullScanEndTime | "
        "Format-List | Out-String -Width 240",
        "powershell",
    )
    _show(
        context,
        "Cloud-delivered protection and configured preferences",
        "Get-MpPreference -ErrorAction Stop | "
        "Select-Object MAPSReporting,SubmitSamplesConsent,CloudBlockLevel,"
        "DisableBlockAtFirstSeen,DisableRealtimeMonitoring,ExclusionPath,ExclusionProcess,"
        "AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions,"
        "EnableNetworkProtection | "
        "Format-List | Out-String -Width 240",
        "powershell",
    )

    registry_keys = (
        ("Defender base key", _DEFENDER),
        ("Real-time protection", _DEFENDER + r"\Real-Time Protection"),
        ("Cloud protection (SpyNet)", _DEFENDER + r"\Spynet"),
        ("Features and tamper protection", _DEFENDER + r"\Features"),
        ("Path exclusions", _DEFENDER + r"\Exclusions\Paths"),
        ("Process exclusions", _DEFENDER + r"\Exclusions\Processes"),
        ("Exploit Guard", _DEFENDER + r"\Windows Defender Exploit Guard"),
        ("Managed Defender policy", _POLICY),
        ("Managed cloud protection policy", _POLICY + r"\Spynet"),
        ("Managed Exploit Guard policy", _POLICY + r"\Windows Defender Exploit Guard"),
    )
    for label, key in registry_keys:
        recursive = " /s" if "Exploit Guard" in key else ""
        _show(context, label, f'reg query "{key}"{recursive}', "cmd")

    _show(
        context,
        "Defender support logs (newest first)",
        "$folder = 'C:\\ProgramData\\Microsoft\\Windows Defender\\Support'; "
        "if (Test-Path -LiteralPath $folder -PathType Container) { "
        "$files = @(Get-ChildItem -LiteralPath $folder -Filter 'MpLog-*.log' -File "
        "-ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending); "
        "if ($files) { $files | Select-Object LastWriteTime,Length,FullName | "
        "Format-Table -AutoSize | Out-String -Width 240 } "
        "else { 'No MpLog files found' } } else { 'Defender support folder not found' }",
        "powershell",
    )
    _show(
        context,
        "Defender Operational event-log file",
        "$path = 'C:\\Windows\\System32\\winevt\\Logs\\"
        "Microsoft-Windows-Windows Defender%4Operational.evtx'; "
        "if (Test-Path -LiteralPath $path -PathType Leaf) { "
        "Get-Item -LiteralPath $path | Select-Object FullName,Length,LastWriteTime | "
        "Format-List | Out-String -Width 240 } else { 'Defender event-log file not found' }",
        "powershell",
    )
    _show(
        context,
        "Latest 60 Defender Operational events",
        "Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' "
        "-MaxEvents 60 -ErrorAction Stop | "
        "Select-Object TimeCreated,Id,LevelDisplayName,Message | "
        "Format-List | Out-String -Width 240",
        "powershell",
    )
    _show(
        context,
        "Real-time signature data directory",
        "$path = 'C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\RtSigs\\Data'; "
        "if (Test-Path -LiteralPath $path -PathType Container) { "
        "Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop | "
        "Select-Object Mode,LastWriteTime,Length,FullName | "
        "Format-Table -AutoSize | Out-String -Width 240 } "
        "else { 'Real-time signature data directory not found' }",
        "powershell",
    )
