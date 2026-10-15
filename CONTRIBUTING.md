# Contributing

Use Python 3.9 or newer and install the development environment with:

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

## Adding a command

Add a module beneath `modules/commands/`. Modules in that package are discovered
automatically, so do not edit `remoteshell.py` or a separate help file.

```python
from modules.command_registry import command
from modules.context import CommandUsageError


@command("example", "System", "Explain what the command does", "example <argument>")
def example(context, arguments):
    if not arguments.strip():
        raise CommandUsageError("example requires an argument")
    context.write(context.run("hostname"))
```

Every command must provide a unique name, category, one-line summary, usage
string, and tests. Use only the methods exposed by `CommandContext`; command
modules must not import `RemoteShell` or access transport internals.

Generated output belongs in `.wmiexec2-artifacts/`. Use
`context.artifact_path()` so collected data is not accidentally committed.

## Design boundaries

- `wmiexec2.py` parses CLI options and owns connection cleanup.
- `remote_session.py` executes remote commands and retrieves their output.
- `remoteshell.py` handles interactive dispatch only.
- `modules/command_registry.py` discovers commands and owns their metadata.
- `modules/context.py` is the supported API for command implementations.
- `modules/commands/` contains executable commands.
- `modules/av/` and `modules/data/` contain data, not command dispatch.
