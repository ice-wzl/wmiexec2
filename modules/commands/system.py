"""System enumeration and configurable survey commands."""

from datetime import date
from importlib.resources import files

from modules.command_registry import command


@command("sysinfo", "System", "Display basic target information", "sysinfo")
def system_information(context, arguments: str) -> None:
    checks = (
        ("Target", "whoami"),
        ("Hostname", "hostname"),
        ("Architecture", 'SET Processor | findstr /i "PROCESSOR_ARCHITECTURE"'),
        ("IP addresses", 'ipconfig /all | findstr /i "(Preferred)"'),
    )
    for label, remote_command in checks:
        context.info(label)
        context.write(context.run(remote_command))


@command("mounts", "System", "List remote logical disks", "mounts")
def mounted_disks(context, arguments: str) -> None:
    context.write(context.run("wmic logicaldisk get description,name"))


@command("survey", "System", "Run the configured host survey", "survey [save]")
def survey(context, arguments: str) -> None:
    save = arguments.strip().lower() == "save"
    configuration = files("modules.data").joinpath("survey.conf")
    commands = [
        line.strip()
        for line in configuration.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    output_file = context.artifact_path(f"survey_{date.today().isoformat()}.txt") if save else None

    handle = output_file.open("w", encoding="utf-8") if output_file else None
    try:
        for remote_command in commands:
            output = context.run(remote_command)
            if handle:
                handle.write(f"[*] {remote_command}\n{output.rstrip()}\n")
            else:
                print(f"[*] {remote_command}")
                context.write(output)
    finally:
        if handle:
            handle.close()

    if output_file:
        print(f"[+] survey saved to {output_file.resolve()}")
