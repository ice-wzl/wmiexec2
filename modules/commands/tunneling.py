"""Windows portproxy management commands."""

from modules.command_registry import command
from modules.context import CommandUsageError


def _parts(arguments: str, expected: int, usage: str):
    parts = arguments.split()
    if len(parts) != expected:
        raise CommandUsageError(f"usage: {usage}")
    return parts


@command("addtun", "Tunneling", "Add a v4-to-v4 portproxy", "addtun <local-port> <remote-host> <remote-port>")
def add_tunnel(context, arguments: str) -> None:
    usage = "addtun <local-port> <remote-host> <remote-port>"
    local_port, remote_host, remote_port = _parts(arguments, 3, usage)
    context.write(context.run(
        "netsh interface portproxy add v4tov4 "
        f"listenport={local_port} connectport={remote_port} connectaddress={remote_host}"
    ))


@command("showtun", "Tunneling", "Show v4-to-v4 portproxies", "showtun")
def show_tunnels(context, arguments: str) -> None:
    output = context.run("netsh interface portproxy show v4tov4")
    context.write(output or "[-] No current portproxy tunnels")


@command("deltun", "Tunneling", "Delete a v4-to-v4 portproxy", "deltun <local-port>")
def delete_tunnel(context, arguments: str) -> None:
    (local_port,) = _parts(arguments, 1, "deltun <local-port>")
    context.write(context.run(f"netsh interface portproxy delete v4tov4 listenport={local_port}"))
