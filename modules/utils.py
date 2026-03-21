import re


def clean(buf):
    """Normalize CRLF to LF without stripping interior whitespace."""
    return (buf or "").replace("\r", "")


def reg_dword_value(buf):
    """
    Parse a REG_DWORD value from reg query output.
    Returns an int, or None if not found.
    """
    if not buf:
        return None
    m = re.search(r'REG_DWORD\s+0x([0-9a-fA-F]+)|REG_DWORD\s+(\d+)', buf)
    if not m:
        return None
    return int(m.group(1), 16) if m.group(1) else int(m.group(2))


def has_priv(buf, name):
    """Check whether a privilege name appears in whoami /priv output."""
    return re.search(rf'\b{name}\b', buf, re.IGNORECASE) is not None
