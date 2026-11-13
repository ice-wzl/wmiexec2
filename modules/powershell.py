"""Small helpers for passing literal values to remote PowerShell commands."""


def literal(value: str) -> str:
    """Quote a value as a PowerShell single-quoted string."""
    return "'" + value.replace("'", "''") + "'"


def strip_outer_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value
