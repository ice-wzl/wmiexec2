#!/usr/bin/env python3
"""CLI entry point and WMI connection lifecycle for wmiexec2."""

import argparse
import logging
import sys
from getpass import getpass

from impacket import version
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import COMVERSION, DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.krb5.keytab import Keytab
from impacket.smbconnection import SMB2_DIALECT_002, SMB2_DIALECT_21, SMB_DIALECT, SMBConnection

from remoteshell import RemoteShell


class WMIExecutor:
    def __init__(self, command="", username="", password="", domain="", hashes=None, aes_key=None,
                 share="ADMIN$", no_output=False, kerberos=False, kdc_host=None, shell_type="cmd",
                 codec="utf-8"):
        self.command = command
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.aes_key = aes_key
        self.share = share
        self.no_output = no_output
        self.kerberos = kerberos
        self.kdc_host = kdc_host
        self.shell_type = shell_type
        self.codec = codec
        self.shell = None
        if hashes:
            self.lmhash, self.nthash = hashes.split(":", 1)

    def run(self, address, silent_command=False):
        smb_connection = None
        dcom = None
        try:
            if not self.no_output and not silent_command:
                smb_connection = SMBConnection(address, address)
                if self.kerberos:
                    smb_connection.kerberosLogin(
                        self.username, self.password, self.domain, self.lmhash, self.nthash,
                        self.aes_key, kdcHost=self.kdc_host,
                    )
                else:
                    smb_connection.login(
                        self.username, self.password, self.domain, self.lmhash, self.nthash
                    )
                self._log_dialect(smb_connection.getDialect())

            dcom = DCOMConnection(
                address, self.username, self.password, self.domain, self.lmhash, self.nthash,
                self.aes_key, oxidResolver=True, doKerberos=self.kerberos, kdcHost=self.kdc_host,
            )
            interface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            login = wmi.IWbemLevel1Login(interface)
            services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
            login.RemRelease()
            win32_process, _ = services.GetObject("Win32_Process")

            self.shell = RemoteShell(
                self.share, win32_process, smb_connection, self.shell_type,
                silent_command, codec=self.codec,
            )
            if self.command:
                self.shell.onecmd(self.command)
            else:
                self.shell.cmdloop()
        finally:
            if smb_connection is not None:
                try:
                    smb_connection.logoff()
                except Exception:
                    logging.debug("SMB logoff failed", exc_info=True)
            if dcom is not None:
                try:
                    dcom.disconnect()
                except Exception:
                    logging.debug("DCOM disconnect failed", exc_info=True)

    @staticmethod
    def _log_dialect(dialect):
        if dialect == SMB_DIALECT:
            logging.warning("SMBv1 dialect used; traffic will be unencrypted")
        elif dialect == SMB2_DIALECT_002:
            logging.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            logging.info("SMBv2.1 dialect used")
        else:
            logging.info("SMBv3 dialect used")


# Compatibility for callers that imported the historical name.
WMIEXEC = WMIExecutor


class AuthFileSyntaxError(Exception):
    def __init__(self, path, line_number, reason):
        self.path = path
        self.line_number = line_number
        self.reason = reason

    def __str__(self):
        return f"Syntax error in auth file {self.path} line {self.line_number}: {self.reason}"


def load_smbclient_auth_file(path):
    values = {"domain": None, "username": None, "password": None}
    with open(path, encoding="utf-8") as auth_file:
        for line_number, raw_line in enumerate(auth_file, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise AuthFileSyntaxError(path, line_number, 'No "=" present in line')
            key, value = (part.strip() for part in line.split("=", 1))
            if key not in values:
                raise AuthFileSyntaxError(path, line_number, f"Unknown option {key!r}")
            values[key] = value
    return values["domain"], values["username"], values["password"]


def build_parser(default_codec=None):
    parser = argparse.ArgumentParser(
        description="Execute a command or semi-interactive shell through Windows Management Instrumentation."
    )
    parser.add_argument("target", help="[[domain/]username[:password]@]<targetName or address>")
    parser.add_argument("command", nargs="*", help="command to execute; omit for an interactive shell")
    parser.add_argument("-share", default="ADMIN$", help="share used to retrieve output (default: ADMIN$)")
    parser.add_argument("-nooutput", action="store_true", help="do not create an SMB output connection")
    parser.add_argument("-ts", action="store_true", help="add timestamps to logging output")
    parser.add_argument(
        "-silentcommand",
        action="store_true",
        help="execute without a command-shell prefix or output",
    )
    parser.add_argument("-debug", action="store_true", help="enable debug logging")
    parser.add_argument("-codec", default=default_codec or sys.stdout.encoding or "utf-8",
                        help="codec used to decode target output")
    parser.add_argument("-shell-type", default="cmd", choices=("cmd", "powershell"))
    parser.add_argument("-com-version", metavar="MAJOR.MINOR", help="DCOM version, for example 5.7")

    authentication = parser.add_argument_group("authentication")
    authentication.add_argument("-hashes", metavar="LMHASH:NTHASH")
    authentication.add_argument("-no-pass", action="store_true", help="do not prompt for a password")
    authentication.add_argument("-k", action="store_true", help="use Kerberos authentication")
    authentication.add_argument("-aesKey", metavar="HEX_KEY")
    authentication.add_argument("-dc-ip", metavar="ADDRESS")
    authentication.add_argument("-A", metavar="AUTH_FILE", help="smbclient-style authentication file")
    authentication.add_argument("-keytab", help="read SPN keys from a keytab")
    return parser


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        build_parser().print_help()
        return 1

    print(version.BANNER)
    options = build_parser().parse_args(arguments)
    logger.init(options.ts)
    logging.getLogger().setLevel(logging.DEBUG if options.debug else logging.INFO)
    if options.debug:
        logging.debug(version.getInstallationPath())

    command_text = " ".join(options.command)
    if not command_text and (options.nooutput or options.silentcommand):
        logging.error("-nooutput and -silentcommand require a non-interactive command")
        return 1

    if options.com_version:
        try:
            major, minor = options.com_version.split(".", 1)
            COMVERSION.set_default_version(int(major), int(minor))
        except ValueError:
            logging.error('Wrong COM version format; use dot-separated integers such as "5.7"')
            return 1

    domain, username, password, address = parse_target(options.target)
    try:
        if options.A:
            domain, username, password = load_smbclient_auth_file(options.A)
        domain = domain or ""

        if options.keytab:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True
        if options.aesKey:
            options.k = True
        if password == "" and username and not options.hashes and not options.no_pass and not options.aesKey:
            password = getpass("Password:")

        executor = WMIExecutor(
            command_text, username, password, domain, options.hashes, options.aesKey,
            options.share, options.nooutput, options.k, options.dc_ip, options.shell_type, options.codec,
        )
        executor.run(address, options.silentcommand)
        return 0
    except KeyboardInterrupt:
        logging.error("Interrupted")
        return 130
    except Exception as exc:
        logging.exception("Execution failed") if options.debug else logging.error(str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
