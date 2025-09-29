#!/usr/bin/python3
import logging

def add_tun(self, s):
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


def show_tun(self, s):
    try:
        self.execute_remote("netsh interface portproxy show v4tov4")
        buf = (self.out or "").strip("\r\n")
        if buf:
            self.format_print_buff()
        else:
            print("[-] No current portproxy tunnels")
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))


def del_tun(self, s):
    lport = s.split(" ")[0]
    try:
        self.execute_remote("netsh interface portproxy delete v4tov4 listenport=%s" % (lport))
        self.format_print_buff()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
