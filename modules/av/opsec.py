#!/usr/bin/python3
import logging

def security_tools(self, s):
    logging.info("Security Researcher Tools: ")
    self.execute_remote(
        'tasklist /svc | findstr /i "pd64.exe ida64.exe ida32.exe x64dbg.exe x32dbg.exe hiew32.exe sysanalyzer.exe petools.exe dnSpy.exe lordpe.exe PE-bear.exe Procmon.exe Procmon64.exe Autoruns.exe Autoruns64.exe Dbgview.exe dbgview64.exe Diskmon.exe Diskmon64.exe portmon.exe procdump.exe procdump64.exe tcpview.exe tcpview64.exe procexp.exe procexp64.exe die.exe ProcessHacker.exe Wireshark.exe dumpcap.exe"')
    if len(self.__outputBuffer.strip('\r\n')) > 0:
        self.format_print_buff()
    else:
        logging.info("No Security Researcher Processes Found")


def vm(self, s):
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

    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", e)