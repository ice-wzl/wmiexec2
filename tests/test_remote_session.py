from remote_session import RemoteSession


class Process:
    def __init__(self):
        self.created = None

    def Create(self, command, cwd, environment):
        self.created = (command, cwd, environment)


class SMB:
    def setTimeout(self, timeout):
        self.timeout = timeout

    def getFile(self, share, path, callback):
        callback("é".encode("cp437"))

    def deleteFile(self, share, path):
        self.deleted = (share, path)


def test_session_uses_requested_output_codec():
    process = Process()
    smb = SMB()
    session = RemoteSession("ADMIN$", process, smb, codec="cp437")

    assert session.execute("hostname") == "é"
    assert "hostname" in process.created[0]
    assert r"\\localhost\ADMIN$" in process.created[0]
    assert smb.deleted == ("ADMIN$", session.output_path)
