#!/usr/bin/python3
import os
import logging
import time
from datetime import datetime

_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
SURVEY_CONF = os.path.join(_MODULE_DIR, "survey.conf")


def survey_save(self, commands_to_run: list):
    logging.info("Saving all output from survey to local pwd")
    local_save_file = open(f"survey_{datetime.now().date()}.txt", "w")
    
    try:
        for item in commands_to_run:
            local_save_file.write("[*] %s \n" % (item))
            self.execute_remote(item.strip('\n'))
            time.sleep(1)
            local_save_file.write((self.out or '').strip('\r\n') + '\n')
            self.out_clear()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

def survey_no_save(self, commands_to_run: list):
    try:
         for item in commands_to_run:
            print("[*] %s" % (item))
            self.execute_remote(item.strip('\n'))
            time.sleep(1)
            self.format_print_buff()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))


def survey(self, s):
    logging.info("Starting Survey")
    save_local_option = s.split(" ")[0]
    with open(SURVEY_CONF, "r") as fp:
        config_file = fp.readlines()
        if save_local_option == "save":
            survey_save(self, config_file)
        else:
            survey_no_save(self, config_file)
    
    logging.info("Survey Completed")
