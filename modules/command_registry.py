"""Command registration and discovery for the interactive shell."""

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import import_module
from pkgutil import iter_modules
from typing import Callable, Optional

CommandHandler = Callable[[object, str], None]


@dataclass(frozen=True)
class Command:
    name: str
    category: str
    summary: str
    handler: CommandHandler
    usage: Optional[str] = None


_commands: dict[str, Command] = {}
_discovered = False


def command(name: str, category: str, summary: str, usage: Optional[str] = None):
    """Register a command handler and its user-facing metadata."""

    def decorator(handler: CommandHandler) -> CommandHandler:
        if name in _commands:
            raise ValueError(f"duplicate command registration: {name}")
        _commands[name] = Command(name, category, summary, handler, usage)
        return handler

    return decorator


def discover_commands() -> None:
    """Import every module in modules.commands exactly once."""
    global _discovered
    if _discovered:
        return

    package = import_module("modules.commands")
    for module in iter_modules(package.__path__, package.__name__ + "."):
        import_module(module.name)
    _discovered = True


def commands() -> Iterable[Command]:
    discover_commands()
    return tuple(sorted(_commands.values(), key=lambda item: (item.category, item.name)))


def command_named(name: str) -> Optional[Command]:
    discover_commands()
    return _commands.get(name)
