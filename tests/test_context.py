from pathlib import Path

import pytest

from modules.context import CommandContext


class FailingSMB:
    def getFile(self, share, path, callback):
        callback(b"partial")
        raise RuntimeError("network failure")


class Session:
    cwd = r"C:\Users\tester"
    shell_type = "cmd"
    smb = FailingSMB()

    def execute(self, command, shell_type=None):
        return "output"


def test_failed_download_does_not_destroy_existing_file(tmp_path):
    destination = tmp_path / "important.txt"
    destination.write_text("keep me", encoding="utf-8")
    context = CommandContext(Session())

    with pytest.raises(RuntimeError):
        context.download(r"C:\Temp\important.txt", destination)

    assert destination.read_text(encoding="utf-8") == "keep me"
    assert not Path(str(destination) + ".part").exists()
