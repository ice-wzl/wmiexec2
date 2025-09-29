#!/usr/bin/python3
import logging
import time

def survey(self, s):
    save_local_option = s.split(" ")[0]
    if save_local_option == "save":
        try:
            logging.info("Saving all output from survey to survey.txt in your local pwd")
            logging.info("Starting Survey")
            # can have issues here if survey with save option is run on multiple tgts. Should append remote host ip or atleast a timestamp...
            local_save_file = open("survey.txt", "a")

            with open("modules/survey/survey.conf", "r") as fp:
                config_file = fp.readlines()
            for item in config_file:
                local_save_file.write("[*] %s \n" % (item))
                self.execute_remote(item.strip('\n'))
                time.sleep(1)
                local_save_file.write((self.out or '').strip('\r\n') + '\n')
                self.out_clear()
            logging.info("Survey Completed")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
    else:
        try:
            logging.info("Starting Survey")
            with open("modules/survey/survey.conf", "r") as fp:
                config_file = fp.readlines()
            for item in config_file:
                print("[*] %s" % (item))
                self.execute_remote(item.strip('\n'))
                time.sleep(1)
                self.format_print_buff()
            logging.info("Survey Completed")
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
