def format_print_buff(shell):
    """Print the shell's output buffer if non-empty, then clear it."""
    buf = shell.out
    if len(buf.strip('\r\n')) > 0:
        print(buf)
        shell.out_clear()


def print_buf(shell, buf: str):
    """Print the given string if non-empty, then clear the shell's output buffer."""
    if len(buf.strip('\r\n')) > 0:
        print(buf)
        shell.out_clear()
