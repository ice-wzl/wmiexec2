#!/usr/bin/python3
import logging 

def defender_checks(self, s):
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
