#!/usr/bin/python3
import logging

from modules.utils import reg_dword_value


def defender_checks(self, s):
    try:
        # --- Install location ---
        logging.info('Defender Install Location')
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender" /F InstallLocation | findstr /i InstallLocation')
        self.format_print_buff()

        # --- Service running? ---
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender" /F IsServiceRunning')
        val = reg_dword_value(self.out)
        if val == 1:
            logging.info('Defender Service is Running')
        elif val == 0:
            logging.info('Defender Service is not Running')
        else:
            logging.info('Defender Service state: unknown')
        self.out_clear()

        # --- Process exclusions ---
        logging.info('Defender Process Exclusions')
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Processes"')
        buf = (self.out or '').strip()
        if buf:
            self.format_print_buff()
        else:
            print('\tNo Process Exclusions')
            self.out_clear()

        # --- Path exclusions ---
        logging.info('Defender Path Exclusions')
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender\Exclusions\Paths"')
        buf = (self.out or '').strip()
        if buf:
            self.format_print_buff()
        else:
            print('\tNo Path Exclusions')
            self.out_clear()

        # --- Real-time protection ---
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender\Real-Time Protection" /F DisableRealtimeMonitoring')
        val = reg_dword_value(self.out)
        if val == 0:
            logging.info('Real Time Protection is Enabled')
        elif val == 1:
            logging.info('Real Time Protection is Disabled')
        else:
            logging.info('Real Time Protection state: unknown')
        self.out_clear()

        # --- Tamper Protection ---
        self.execute_remote(r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection')
        val = reg_dword_value(self.out)
        # Common values seen in the wild:
        #   0x5 => Enabled, 0x4 => Disabled (managed), 0x0 => Disabled
        if val in (0, 4):
            logging.info('Tamper Protection is Disabled')
        elif val == 5:
            logging.info('Tamper Protection is Enabled')
        else:
            logging.info(f'Unknown Tamper Protection value: {val!r}')
            self.format_print_buff()
            return
        self.out_clear()

    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
