"""Security-product, virtualization, privilege, and credential checks."""

import re

from termcolor import cprint

from modules.av.av_procs import av_procs
from modules.av.opsec_procs import opsec_procs
from modules.av.vm_procs import vm_processes
from modules.command_registry import command
from modules.utils import reg_dword_value


def _process_hits(output, indicators):
    process_names = {match.casefold() for match in re.findall(r"(?im)^\s*([^\s]+\.exe)\b", output)}
    normalized = {name.casefold(): name for name in indicators}
    return [normalized[name] for name in sorted(process_names.intersection(normalized))]


@command("av", "Security", "Find known antivirus processes", "av")
def antivirus_processes(context, arguments: str) -> None:
    for process in _process_hits(context.run("tasklist /svc"), av_procs):
        print(process)


@command("securitytools", "Security", "Find security-research processes", "securitytools")
def security_tool_processes(context, arguments: str) -> None:
    hits = _process_hits(context.run("tasklist /svc"), opsec_procs)
    if hits:
        for process in hits:
            print(process)
    else:
        context.info("No security-research processes found")


@command("vmcheck", "Security", "Check for common virtualization indicators", "vmcheck")
def virtualization_check(context, arguments: str) -> None:
    hits = _process_hits(context.run("tasklist /svc"), vm_processes)
    if hits:
        for process in hits:
            cprint(process, "red")
    else:
        context.info("No known VM processes found")

    vmware = context.run(r'dir /B "C:\Program Files\VMware"')
    if vmware.strip() and "File Not Found" not in vmware:
        cprint(r"C:\Program Files\VMware found", "red")
    context.write(context.run('systeminfo | findstr /i "Manufacturer:"'))

    virtualbox = context.run(
        r'if exist "%SystemRoot%\System32\drivers\VBoxMouse.sys" (echo VBoxMouse.sys) & '
        r'if exist "%SystemRoot%\System32\drivers\VBoxGuest.sys" (echo VBoxGuest.sys)'
    )
    hits = [line for line in virtualbox.replace("\r", "").split("\n") if line]
    if hits:
        print("[!] Found VirtualBox files:")
        for hit in hits:
            cprint(hit, "red")
    else:
        print("[*] No VirtualBox files found")


@command("defender", "Security", "Query Microsoft Defender configuration", "defender")
def defender_configuration(context, arguments: str) -> None:
    context.info("Defender install location")
    context.write(context.run(
        r'reg query "HKLM\Software\Microsoft\Windows Defender" /F InstallLocation '
        r"| findstr /i InstallLocation"
    ))

    checks = (
        (
            "Defender service",
            r'reg query "HKLM\Software\Microsoft\Windows Defender" /F IsServiceRunning',
            {0: "not running", 1: "running"},
        ),
        (
            "Real-time protection",
            r'reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" '
            r"/F DisableRealtimeMonitoring",
            {0: "enabled", 1: "disabled"},
        ),
        (
            "Tamper protection",
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection',
            {0: "disabled", 4: "disabled (managed)", 5: "enabled"},
        ),
    )
    for label, remote_command, states in checks:
        value = reg_dword_value(context.run(remote_command))
        context.info("%s: %s", label, states.get(value, f"unknown ({value!r})"))

    for label, key in (
        ("Process exclusions", r"HKLM\Software\Microsoft\Windows Defender\Exclusions\Processes"),
        ("Path exclusions", r"HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths"),
    ):
        context.info(label)
        output = context.run(f'reg query "{key}"')
        context.write(output if output.strip() else "\tNone")


@command("tokens", "Privilege", "Show enabled privileges and relevant techniques", "tokens")
def token_privileges(context, arguments: str) -> None:
    suggestions = {
        "SeImpersonatePrivilege": ["Juicy-Potato", "RogueWinRM", "SweetPotato", "PrintSpoofer"],
        "SeBackupPrivilege": ["SeBackupPrivilegeCmdLets"],
        "SeTakeOwnershipPrivilege": ["takeown", "icacls"],
        "SeDebugPrivilege": ["Review protected-process access paths"],
    }
    output = context.run(r'whoami /priv | findstr /i "Enabled"')
    for privilege, techniques in suggestions.items():
        if re.search(rf"\b{re.escape(privilege)}\b", output, re.IGNORECASE):
            cprint(f"[*] {privilege}", "green")
            print("\n".join(techniques))


@command("creds", "Security", "Inspect credential-protection settings", "creds")
def credential_protection(context, arguments: str) -> None:
    checks = (
        (
            "WDigest UseLogonCredential",
            r"reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "
            r"/v UseLogonCredential",
        ),
        ("LSA RunAsPPL", r"reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL"),
        (
            "Credential Guard LsaCfgFlags",
            r"reg query HKLM\SYSTEM\CurrentControlSet\Control\LSA /v LsaCfgFlags",
        ),
        (
            "Cached logon count",
            r'reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" '
            r"/v CACHEDLOGONSCOUNT",
        ),
    )
    for label, remote_command in checks:
        value = reg_dword_value(context.run(remote_command))
        context.info("%s: %r", label, value)


@command("unattend", "Security", "Find common unattended-install files", "unattend")
def unattended_files(context, arguments: str) -> None:
    candidates = (
        r"C:\unattend.txt", r"C:\unattend.inf", r"C:\Windows\sysprep.inf",
        r"C:\Windows\sysprep\sysprep.xml", r"C:\Windows\sysprep\sysprep.inf",
        r"C:\Windows\Panther\Unattended.xml", r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\Unattend\Unattend.xml", r"C:\Windows\Panther\Unattend\Unattended.xml",
        r"C:\Windows\System32\Sysprep\unattend.xml", r"C:\Windows\System32\Sysprep\unattended.xml",
    )
    for candidate in candidates:
        output = context.run(f'dir "{candidate}"')
        if output.strip() and "File Not Found" not in output:
            context.write(output)
