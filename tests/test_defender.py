"""Coverage for the read-only Defender triage checklist."""

import pytest

from modules.commands.defender import defender_configuration
from modules.context import CommandUsageError


class Context:
    def __init__(self):
        self.calls = []
        self.outputs = []

    def run(self, command, shell_type=None):
        self.calls.append((command, shell_type))
        return "query output"

    def write(self, output):
        self.outputs.append(output)


def test_defender_checks_configuration_and_recent_events(capsys):
    context = Context()
    defender_configuration(context, "")

    commands = [command for command, _ in context.calls]
    registry = [command for command, shell in context.calls if shell == "cmd"]
    assert len(registry) == 10
    for area in (
        r"Real-Time Protection", "Spynet", "Features", r"Exclusions\Paths",
        r"Windows Defender Exploit Guard",
    ):
        assert any(area in command for command in registry)
    assert any("MAPSReporting" in command and "SubmitSamplesConsent" in command for command in commands)
    assert any("MpLog-*.log" in command for command in commands)
    assert any("Defender%4Operational.evtx" in command for command in commands)
    assert any("RtSigs\\Data" in command for command in commands)
    assert any("Get-WinEvent" in command and "-MaxEvents 60" in command for command in commands)
    assert len(context.outputs) == len(context.calls)
    progress = capsys.readouterr().out
    assert "[*] Effective protection status" in progress
    assert '> reg query "HKLM\\SOFTWARE\\Microsoft\\Windows Defender"' in progress


def test_defender_rejects_arguments():
    with pytest.raises(CommandUsageError):
        defender_configuration(Context(), "unexpected")
