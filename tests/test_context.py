from pathlib import Path

import pytest

from modules.collection_paths import mirrored_path
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


class DownloadSMB:
    def __init__(self):
        self.calls = []

    def getFile(self, share, path, callback):
        self.calls.append((share, path))
        callback(b"downloaded")


class DownloadSession:
    cwd = r"C:\Users\tester"
    shell_type = "cmd"

    def __init__(self):
        self.smb = DownloadSMB()
        self.hostname_calls = 0

    def execute(self, command, shell_type=None):
        assert (command, shell_type) == ("hostname", "cmd")
        self.hostname_calls += 1
        return "HOST-01\r\n"


def test_download_mirrors_remote_paths_under_hostname(tmp_path):
    session = DownloadSession()
    context = CommandContext(session, collection_directory=tmp_path / "collect")

    hosts = context.download(r"C:\Windows\System32\drivers\etc\hosts")
    other_drive = context.download(r"D:\Data\Report.TXT")

    assert hosts == tmp_path / "collect" / "host-01" / "windows" / "system32" / "drivers" / "etc" / "hosts"
    assert hosts.read_bytes() == b"downloaded"
    assert other_drive == tmp_path / "collect" / "host-01" / "drives" / "d" / "data" / "report.txt"
    assert session.smb.calls == [("C$", r"\Windows\System32\drivers\etc\hosts"), ("D$", r"\Data\Report.TXT")]
    assert session.hostname_calls == 1


def test_collection_path_rejects_unsafe_host_or_unc_path(tmp_path):
    with pytest.raises(ValueError):
        mirrored_path(tmp_path, "../elsewhere", r"C:\Windows\hosts")
    with pytest.raises(ValueError):
        mirrored_path(tmp_path, "host-01", r"\\server\share\hosts")


class UploadSMB:
    def __init__(self):
        self.calls = []

    def putFile(self, share, path, reader):
        self.calls.append((share, path, reader()))


def test_upload_dot_and_omitted_destination_use_remote_working_directory(tmp_path):
    source = tmp_path / "test.exe"
    source.write_bytes(b"payload")
    session = Session()
    session.smb = UploadSMB()
    session.cwd = r"C:\Users\Administrator\Desktop"
    context = CommandContext(session)

    expected = r"C:\Users\Administrator\Desktop\test.exe"
    assert context.upload(str(source)) == expected
    assert context.upload(str(source), ".") == expected
    assert context.upload(str(source), r"C:\Users\Administrator\Desktop\renamed.exe") == (
        r"C:\Users\Administrator\Desktop\renamed.exe"
    )
    assert session.smb.calls == [
        ("C$", r"\Users\Administrator\Desktop\test.exe", b"payload"),
        ("C$", r"\Users\Administrator\Desktop\test.exe", b"payload"),
        ("C$", r"\Users\Administrator\Desktop\renamed.exe", b"payload"),
    ]
