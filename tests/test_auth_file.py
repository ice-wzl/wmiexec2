import pytest

from wmiexec2 import AuthFileSyntaxError, load_smbclient_auth_file


def test_auth_file_parser(tmp_path):
    path = tmp_path / "auth"
    path.write_text("domain = LAB\nusername = alice\npassword = secret\n", encoding="utf-8")
    assert load_smbclient_auth_file(path) == ("LAB", "alice", "secret")


def test_auth_file_rejects_unknown_keys(tmp_path):
    path = tmp_path / "auth"
    path.write_text("unknown = value\n", encoding="utf-8")
    with pytest.raises(AuthFileSyntaxError):
        load_smbclient_auth_file(path)
