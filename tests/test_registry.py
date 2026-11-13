from modules.command_registry import command_named, commands

EXPECTED_COMMANDS = {
    "addtun", "av", "cat", "cd", "creds", "defender", "deltun", "lcd", "lget",
    "loggrab", "lpwd", "lput", "ls", "mounts", "regrip", "securitytools", "showtun",
    "survey", "sysinfo", "tokens", "unattend", "vmcheck", "software",
    "pshistory", "tasktriage", "view-task",
}


def test_all_commands_are_discovered_with_complete_metadata():
    registered = tuple(commands())
    assert {item.name for item in registered} == EXPECTED_COMMANDS
    assert all(item.category and item.summary and item.handler for item in registered)


def test_command_lookup():
    assert command_named("mounts").usage == "mounts"
    assert command_named("does-not-exist") is None
