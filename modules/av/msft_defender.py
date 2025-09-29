#!/usr/bin/python3
import logging 

#!/usr/bin/python3
import logging
import re

def _reg_dword_value(buf: str):
    """
    Parse lines like: '    SomeValue    REG_DWORD    0x00000005 (5)'
    Returns an int, or None if not found.
    """
    if not buf:
        return None
    m = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)|REG_DWORD\s+(\d+)', buf)
    if not m:
        return None
    return int(m.group(1), 16) if m.group(1) else int(m.group(2))

def defender_checks(self, s):
    try:
        # --- Install location ---
        logging.info('Defender Install Location')
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender" /F InstallLocation | findstr /i InstallLocation')
        self.format_print_buff()  # prints + clears

        # --- Service running? ---
        self.execute_remote(r'reg query "HKLM\Software\Microsoft\Windows Defender" /F IsServiceRunning')
        val = _reg_dword_value(self.out)
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
            # show what was returned
            self.format_print_buff()  # prints + clears
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
        val = _reg_dword_value(self.out)
        if val == 0:
            logging.info('Real Time Protection is Enabled')
        elif val == 1:
            logging.info('Real Time Protection is Disabled')
        else:
            logging.info('Real Time Protection state: unknown')
        self.out_clear()

        # --- Tamper Protection ---
        self.execute_remote(r'reg query "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection')
        val = _reg_dword_value(self.out)
        # Common values seen in the wild:
        #   0x5 => Enabled, 0x4 => Disabled (managed), 0x0 => Disabled
        if val in (0, 4):
            logging.info('Tamper Protection is Disabled')
        elif val == 5:
            logging.info('Tamper Protection is Enabled')
        else:
            logging.info(f'Unknown Tamper Protection value: {val!r}')
            self.format_print_buff()  # show raw and clear
            # format_print_buff already cleared; return to avoid double-clear
            return
        self.out_clear()

    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

