# wmiexec2

An extensible WMI command shell for authorized Windows administration and
security testing. It supports password, NTLM hash, Kerberos, `cmd`, PowerShell,
file transfer, system survey, security configuration checks, and artifact
collection.

Use this project only on systems you own or are explicitly authorized to test.

## Installation

Python 3.9 or newer is required.

```bash
git clone https://github.com/ice-wzl/wmiexec2.git
cd wmiexec2
python -m pip install -r requirements.txt
```

For an editable development installation with the `wmiexec2` console command:

```bash
python -m pip install -e ".[dev]"
```

## Usage

```bash
python wmiexec2.py DOMAIN/USERNAME:PASSWORD@10.0.0.2 -shell-type powershell
wmiexec2 WORKGROUP/Administrator@10.0.0.4
```

Run `python wmiexec2.py -h` for connection options. Inside an interactive
session, run `help` for the complete generated command list or `help <command>`
for command-specific usage. Command help is generated from the same registry
used for dispatch, so it cannot drift from the installed commands.

Frequently used commands include:

| Command | Purpose |
|---|---|
| `ls`, `cat`, `cd` | Navigate the remote filesystem |
| `lput`, `lget` | Transfer files |
| `sysinfo`, `mounts`, `survey` | Enumerate the target |
| `av`, `defender`, `vmcheck`, `securitytools` | Inspect security and virtualization indicators |
| `creds`, `tokens`, `unattend` | Inspect credential and privilege configuration |
| `loggrab`, `regrip` | Collect target artifacts |
| `addtun`, `showtun`, `deltun` | Manage Windows portproxy entries |

Collected files and saved surveys are written to `.wmiexec2-artifacts/`, which
is ignored by Git.

## Architecture

```text
wmiexec2.py                   CLI parsing and connection lifecycle
remote_session.py             WMI execution and SMB output transport
remoteshell.py                Interactive UI and registry dispatch
modules/
  command_registry.py         Command discovery and metadata
  context.py                  Stable API exposed to commands
  commands/                   Self-registering command implementations
  data/                       Packaged command configuration
  av/                         Process-indicator data
tests/                        Unit and integration-boundary tests
```

Command modules do not receive the interactive shell or raw WMI objects. They
operate through `CommandContext`, which keeps execution, presentation, file
transfer, and artifact handling consistent and testable.

## Adding a command

Create a Python file under `modules/commands/` and decorate a handler:

```python
from modules.command_registry import command


@command("hostname", "System", "Display the target hostname", "hostname")
def hostname(context, arguments):
    context.write(context.run("hostname"))
```

No import, shell wrapper, or help-file edit is required. Add tests and run:

```bash
ruff check .
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the command contract and repository
boundaries.

## Survey configuration

The commands executed by `survey` are stored in
`modules/data/survey.conf`. Use `survey save` to write results to the artifact
directory.

## Support

Open an issue for reproducible defects or proposed command APIs. Contributions
should include tests and must preserve the registry/context boundary.
