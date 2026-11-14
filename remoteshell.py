"""Interactive command shell with registry-driven command dispatch."""

import cmd
import logging
import os
from functools import partial

from modules.command_history import CommandHistory
from modules.command_registry import command_named, commands
from modules.context import CommandContext, CommandUsageError
from remote_session import RemoteSession


class RemoteShell(cmd.Cmd):
    intro = "[*] **Launching wmiexec2**\n[*] Enter help for available commands"
    identchars = cmd.Cmd.identchars + "-"

    def __init__(self, share, win32Process, smbConnection, shell_type, silentCommand=False,
                 codec=None, artifact_directory=None, history_directory=None):
        super().__init__()
        self._history = None
        self._session = RemoteSession(
            share, win32Process, smbConnection, shell_type, silentCommand, codec
        )
        self._context = CommandContext(self._session, artifact_directory)
        self._install_commands()
        print(f"[*] Output Filename: {self._session.output_path}")

        if smbConnection is not None:
            self._invoke_registered("cd", "\\")
            self._history = CommandHistory(self._context.remote_hostname, history_directory)
            print(f"[*] Command history: {self._history.path}")
        self._update_prompt()

    def onecmd(self, line):
        if self._history is not None:
            self._history.append(line)
        return super().onecmd(line)

    def _install_commands(self):
        for specification in commands():
            setattr(self, "do_" + specification.name, partial(self._run_command, specification))

    def _run_command(self, specification, arguments):
        try:
            return specification.handler(self._context, arguments)
        except CommandUsageError as exc:
            print(f"[!] {exc}")
            if specification.usage:
                print(f"usage: {specification.usage}")
        except Exception:
            logging.exception("Command %s failed", specification.name)
        finally:
            self._update_prompt()

    def _invoke_registered(self, name, arguments):
        specification = command_named(name)
        if specification is None:
            raise LookupError(name)
        return self._run_command(specification, arguments)

    def _update_prompt(self):
        prefix = "👻 PS " if self._session.shell_type == "powershell" else ""
        self.prompt = f"{prefix}{self._session.cwd}> "

    def do_help(self, argument):
        """Show command help generated from registry metadata."""
        name = argument.strip()
        if name:
            specification = command_named(name)
            if specification:
                print(specification.summary)
                print(f"usage: {specification.usage or specification.name}")
            else:
                print(f"[!] Unknown command: {name}")
            return

        current_category = None
        for specification in commands():
            if specification.category != current_category:
                current_category = specification.category
                print(f"\n{current_category}")
            print(f"  {specification.name:<16} {specification.summary}")
        print("\nShell")
        print("  !<command>       Run a command on the local machine")
        print("  exit             Close the session")

    def do_shell(self, command):
        os.system(command)

    def do_exit(self, argument):
        return True

    def do_EOF(self, argument):
        print()
        return True

    def emptyline(self):
        return False

    def default(self, line):
        if len(line) == 2 and line[1] == ":":
            self._invoke_registered("cd", line + "\\")
            return
        if line:
            try:
                output = self._session.execute(line)
                if output:
                    print(output)
            except Exception:
                logging.exception("Remote command failed")
