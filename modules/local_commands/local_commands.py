#!/usr/bin/python3
import logging
import os

def local_get(self, src_path):
    try:
        import ntpath
        newPath = ntpath.normpath(ntpath.join(self.__pwd, src_path))
        drive, tail = ntpath.splitdrive(newPath)
        filename = ntpath.basename(tail)
        fh = open(filename, 'wb')
        logging.info("Downloading %s\\%s" % (drive, tail))
        self.__transferClient.getFile(drive[:-1] + '$', tail, fh.write)
        fh.close()

    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

        if os.path.exists(filename):
            os.remove(filename)


def local_put(self, s):
    try:
        params = s.split(' ')
        if len(params) > 1:
            src_path = params[0]
            dst_path = params[1]
        elif len(params) == 1:
            src_path = params[0]
            dst_path = ''

        src_file = os.path.basename(src_path)
        fh = open(src_path, 'rb')
        dst_path = dst_path.replace('/', '\\')
        import ntpath
        pathname = ntpath.join(ntpath.join(self.__pwd, dst_path), src_file)
        drive, tail = ntpath.splitdrive(pathname)
        logging.info("Uploading %s to %s" % (src_file, pathname))
        self.__transferClient.putFile(drive[:-1] + '$', tail, fh.read)
        fh.close()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))


def local_cd(self, s):
    if s == '':
        print(os.getcwd())
    else:
        try:
            os.chdir(s)
        except Exception as e:
            logging.error(str(e))