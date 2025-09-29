#!/usr/bin/python3
# modules/local_commands/local_commands.py
import os, ntpath, logging

def _strip_outer_quotes(s: str) -> str:
    s = (s or "").strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] == '"' else s

def local_get(self, src_path: str):
    filename = None  # avoid UnboundLocalError in except
    try:
        src_path = _strip_outer_quotes(src_path)
        # build absolute remote path
        drv, _ = ntpath.splitdrive(src_path)
        if drv or src_path.startswith("\\"):
            remote_abs = ntpath.normpath(src_path)
        else:
            remote_abs = ntpath.normpath(ntpath.join(self.cwd, src_path))

        # local filename
        filename = ntpath.basename(remote_abs)
        # map C:\… → share/path (e.g., share=C$, path=\Users\…)
        drive, tail = ntpath.splitdrive(remote_abs)          # drive like 'C:'
        share = drive[:-1] + '$'                              # 'C$'
        path_in_share = tail if tail.startswith("\\") else "\\" + tail

        logging.info("Downloading %s\\%s", drive, tail)
        with open(filename, "wb") as fh:
            self.smb.getFile(share, path_in_share, fh.write)
        print(f"[+] downloaded {remote_abs} -> {os.path.abspath(filename)}")
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
        if filename and os.path.exists(filename):
            try: os.remove(filename)
            except Exception: pass

def local_put(self, s: str):
    try:
        parts = s.split()
        if not parts:
            print("usage: lput <local_src> [remote_dst_dir_or_file]")
            return
        src_path = parts[0]
        dst_path = _strip_outer_quotes(parts[1]) if len(parts) > 1 else ""

        src_file = os.path.basename(src_path)
        dst_path = dst_path.replace('/', '\\')

        # remote absolute path
        if dst_path and (dst_path.startswith("\\") or ntpath.splitdrive(dst_path)[0]):
            remote_abs = ntpath.normpath(ntpath.join(dst_path, src_file) if dst_path.endswith("\\") else dst_path)
        else:
            # relative to current remote dir
            base = ntpath.join(self.cwd, dst_path)
            # if dst_path points to a directory, append the filename
            if dst_path.endswith("\\") or dst_path == "" or dst_path.endswith("/"):
                remote_abs = ntpath.normpath(ntpath.join(base, src_file))
            else:
                remote_abs = ntpath.normpath(base)

        drive, tail = ntpath.splitdrive(remote_abs)
        share = drive[:-1] + '$'
        path_in_share = tail if tail.startswith("\\") else "\\" + tail

        logging.info("Uploading %s to %s", src_file, remote_abs)
        with open(src_path, "rb") as fh:
            self.smb.putFile(share, path_in_share, fh.read)
        print(f"[+] uploaded {src_path} -> {remote_abs}")
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