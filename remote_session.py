"""WMI execution and SMB output transport, independent of the command UI."""

import logging
import random
import string
import sys
import time
from base64 import b64encode
from typing import Optional


def _randomized_case(value):
    return "".join(
        character.upper() if random.choice((True, False)) else character.lower()
        for character in value
    )


def _output_filename():
    value = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return "{" + "-".join(value[index:index + 4] for index in range(0, len(value), 4)) + "}"


class RemoteSession:
    def __init__(
        self,
        share,
        win32_process,
        smb_connection,
        shell_type="cmd",
        silent_command=False,
        codec=None,
    ):
        self.share = share
        self.smb = smb_connection
        self.shell_type = shell_type or "cmd"
        self.cwd = "C:\\"
        self._win32_process = win32_process
        self._no_output = smb_connection is None
        self._codec = codec or sys.stdout.encoding or "utf-8"
        self._output = "\\" + _randomized_case("temp") + "\\" + _output_filename()
        self._command_prefix = "" if silent_command else _randomized_case("cmd.exe") + " /Q /c "
        self._powershell_prefix = (
            _randomized_case("powershell.exe") + " -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc "
        )

        if self.smb is not None:
            self.smb.setTimeout(100000)

    @property
    def output_path(self):
        return self._output

    def execute(self, data: str, shell_type: Optional[str] = None) -> str:
        selected_shell = shell_type or self.shell_type
        if selected_shell == "powershell":
            data = '$ProgressPreference="SilentlyContinue";' + data
            data = self._powershell_prefix + b64encode(data.encode("utf-16le")).decode()

        command = self._command_prefix + data
        if not self._no_output:
            command += f" 1> \\\\localhost\\{self.share}{self._output} 2>&1"
        self._win32_process.Create(command, self.cwd, None)
        return self._read_output()

    def _read_output(self) -> str:
        if self._no_output:
            return ""

        chunks = []

        def output_callback(data):
            chunks.append(data.decode(self._codec, errors="replace"))

        try:
            started = time.monotonic()
            while True:
                try:
                    self.smb.getFile(self.share, self._output, output_callback)
                    break
                except Exception as exc:
                    message = str(exc)
                    elapsed = time.monotonic() - started
                    if elapsed > 300:
                        raise TimeoutError("timed out waiting for remote output") from exc
                    if "Broken" in message:
                        logging.debug("Connection broken; reconnecting")
                        self.smb.reconnect()
                        continue
                    if "STATUS_SHARING_VIOLATION" in message:
                        time.sleep(1)
                        continue
                    if (
                        "STATUS_OBJECT_NAME_NOT_FOUND" in message
                        or "STATUS_OBJECT_PATH_NOT_FOUND" in message
                        or "The system cannot find the file specified" in message
                    ):
                        if elapsed > 15:
                            logging.debug(
                                "Output file not found; command may have failed before redirection"
                            )
                            break
                        time.sleep(0.5)
                        continue
                    raise
        finally:
            try:
                self.smb.deleteFile(self.share, self._output)
            except Exception:
                logging.debug("Unable to delete remote output file", exc_info=True)
        return "".join(chunks)
