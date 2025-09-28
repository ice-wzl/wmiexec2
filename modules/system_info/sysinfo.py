#!/usr/bin/python3
import logging

def basic_system_info(self, s):
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


def get_mounts(self, s):
    try:
        self.execute_remote("wmic logicaldisk get description,name")
        find_description_start = "Description"
        if len(self.__outputBuffer.strip('\r\n')) > 0:
            new_buff = self.__outputBuffer.split("codec")[0]
            print(new_buff)
            self.__outputBuffer = ''

    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
