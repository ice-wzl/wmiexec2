#!/usr/bin/env python
#made with <3 by ice-wzl
from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab

from remoteshell import *



class WMIEXEC:
    def __init__(self, command='', username='', password='', domain='', hashes=None, aesKey=None, share=None,
                 noOutput=False, doKerberos=False, kdcHost=None, shell_type=None):
        self.__command = command
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__share = share
        self.__noOutput = noOutput
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__shell_type = shell_type
        self.shell = None
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def run(self, addr, silentCommand=False):
        if self.__noOutput is False and silentCommand is False:
            smbConnection = SMBConnection(addr, addr)
            if self.__doKerberos is False:
                smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                            self.__nthash, self.__aesKey, kdcHost=self.__kdcHost)

            dialect = smbConnection.getDialect()
            if dialect == SMB_DIALECT:
                logging.info("SMBv1 dialect used")
                logging.info("[!!] Warning traffic will be unencrypted")
            elif dialect == SMB2_DIALECT_002:
                logging.info("SMBv2.0 dialect used")
            elif dialect == SMB2_DIALECT_21:
                logging.info("SMBv2.1 dialect used")
            else:
                logging.info("SMBv3.0 dialect used")
        else:
            smbConnection = None

        dcom = DCOMConnection(addr, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)
        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Process, _ = iWbemServices.GetObject('Win32_Process')

            self.shell = RemoteShell(self.__share, win32Process, smbConnection, self.__shell_type, silentCommand)
            if self.__command != ' ':
                self.shell.onecmd(self.__command)
            else:
                self.shell.cmdloop()
        except  (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(str(e))
            if smbConnection is not None:
                smbConnection.logoff()
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        if smbConnection is not None:
            smbConnection.logoff()
        dcom.disconnect()

class AuthFileSyntaxError(Exception):
    '''raised by load_smbclient_auth_file if it encounters a syntax error
    while loading the smbclient-style authentication file.'''

    def __init__(self, path, lineno, reason):
        self.path = path
        self.lineno = lineno
        self.reason = reason

    def __str__(self):
        return 'Syntax error in auth file %s line %d: %s' % (
            self.path, self.lineno, self.reason)


def load_smbclient_auth_file(path):
    '''Load credentials from an smbclient-style authentication file (used by
    smbclient, mount.cifs and others).  returns (domain, username, password)
    or raises AuthFileSyntaxError or any I/O exceptions.'''

    lineno = 0
    domain = None
    username = None
    password = None
    for line in open(path):
        lineno += 1

        line = line.strip()

        if line.startswith('#') or line == '':
            continue

        parts = line.split('=', 1)
        if len(parts) != 2:
            raise AuthFileSyntaxError(path, lineno, 'No "=" present in line')

        (k, v) = (parts[0].strip(), parts[1].strip())

        if k == 'username':
            username = v
        elif k == 'password':
            password = v
        elif k == 'domain':
            domain = v
        else:
            raise AuthFileSyntaxError(path, lineno, 'Unknown option %s' % repr(k))

    return (domain, username, password)


# Process command-line arguments.
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True, description="Executes a semi-interactive shell using Windows "
                                                                "Management Instrumentation.")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-share', action='store', default='ADMIN$', help='share where the output will be grabbed from '
                                                                         '(default ADMIN$)')
    parser.add_argument('-nooutput', action='store_true', default=False, help='whether or not to print the output '
                                                                              '(no SMB connection created)')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-silentcommand', action='store_true', default=False,
                        help='does not execute cmd.exe to run given command (no output)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-codec', action='store', help='Sets encoding used (codec) from the target\'s output (default '
                                                       '"%s"). If errors are detected, run chcp.com at the target, '
                                                       'map the result with '
                                                       'https://docs.python.org/3/library/codecs.html#standard-encodings and then execute wmiexec.py '
                                                       'again with -codec and the corresponding codec ' % CODEC)
    parser.add_argument('-shell-type', action='store', default='cmd', choices=['cmd', 'powershell'],
                        help='choose a command processor for the semi-interactive shell')
    parser.add_argument('-com-version', action='store', metavar="MAJOR_VERSION:MINOR_VERSION",
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')
    parser.add_argument('command', nargs='*', default=' ', help='command to execute at the target. If empty it will '
                                                                'launch a semi-interactive shell')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true",
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                            'ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
    group.add_argument('-dc-ip', action='store', metavar="ip address", help='IP Address of the domain controller. If '
                                                                            'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-A', action="store", metavar="authfile", help="smbclient/mount.cifs-style authentication file. "
                                                                      "See smbclient man page's -A option.")
    group.add_argument('-keytab', action="store", help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    # Init the example's logger theme
    logger.init(options.ts)

    if options.codec is not None:
        CODEC = options.codec
    else:
        if CODEC is None:
            CODEC = 'utf-8'

    if ' '.join(options.command) == ' ' and options.nooutput is True:
        logging.error("-nooutput switch and interactive shell not supported")
        sys.exit(1)
    if options.silentcommand and options.command == ' ':
        logging.error("-silentcommand switch and interactive shell not supported")
        sys.exit(1)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error("Wrong COMVERSION format, use dot separated integers e.g. \"5.7\"")
            sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    try:
        if options.A is not None:
            (domain, username, password) = load_smbclient_auth_file(options.A)
            logging.debug('loaded smbclient auth file: domain=%s, username=%s, password=%s' % (
            repr(domain), repr(username), repr(password)))

        if domain is None:
            domain = ''

        if options.keytab is not None:
            Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
            options.k = True

        if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True

        executer = WMIEXEC(' '.join(options.command), username, password, domain, options.hashes, options.aesKey,
                           options.share, options.nooutput, options.k, options.dc_ip, options.shell_type)
        executer.run(address, options.silentcommand)
    except KeyboardInterrupt as e:
        logging.error(str(e))
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback

            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)