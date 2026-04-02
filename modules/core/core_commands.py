import ntpath

def ls(self, s):
    if len(s) == 0:
        try:
            self.execute_remote('dir /A /N /O:D .')
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))
    else:
        path = s.split(" ")[0]
        try:
            self.execute_remote('dir /A /N /O:D "%s"' % path)
            self.format_print_buff()
        except Exception as e:
            print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

def cat(self, s):
    try:
        self.execute_remote('type ' + s)
        self.format_print_buff()
    except Exception as e:
        print("[!] Something went wrong, see below for error:\n", logging.critical(str(e)))

def cd(shell, s):
    raw = (s or '').strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        raw = raw[1:-1]

    if raw in ('', '.'):
        target = shell.cwd
    elif raw in ('\\', '/'):
        drive, _ = ntpath.splitdrive(shell.cwd)
        target = drive + '\\'
    else:
        drv, _ = ntpath.splitdrive(raw)
        if drv:
            target = ntpath.normpath(raw)
        elif raw.startswith('\\'):
            cur_drive, _ = ntpath.splitdrive(shell.cwd)
            target = ntpath.normpath(cur_drive + raw)
        else:
            target = ntpath.normpath(ntpath.join(shell.cwd, raw))

    shell.execute_remote('cd /d "{}"'.format(target))

    if len(shell.out.strip('\r\n')) > 0:
        shell.format_print_buff()
        return

    shell.cwd = target
    shell.execute_remote('cd ')
    shell.cwd = shell.out.strip('\r\n')
    shell.prompt = (shell.cwd + '> ')
    if shell.shell_type == 'powershell':
        shell.prompt = '\U0001F47B' + ' ' + 'PS ' + shell.prompt + ' '
    shell.out_clear()