"""
CLI Interface Module for RedOPS.

Provides command-line tool with subcommands, interactive mode,
and output formatting for security operations.
"""

import argparse
import json
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Sequence, TextIO, Type


class OutputFormat(Enum):
    """Output format options."""

    TEXT = "text"
    JSON = "json"
    TABLE = "table"
    CSV = "csv"
    QUIET = "quiet"


class Color(Enum):
    """ANSI color codes."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"


def supports_color(stream: TextIO = None) -> bool:
    """Check if the stream supports color output."""
    stream = stream or sys.stdout

    # Check environment variables
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True

    # Check if it's a TTY
    if hasattr(stream, "isatty") and stream.isatty():
        return True

    return False


def colorize(text: str, *colors: Color, enabled: bool = True) -> str:
    """Apply color codes to text."""
    if not enabled:
        return text
    color_codes = "".join(c.value for c in colors)
    return f"{color_codes}{text}{Color.RESET.value}"


class OutputWriter:
    """Handles formatted output to console."""

    def __init__(
        self,
        stream: TextIO = None,
        error_stream: TextIO = None,
        use_color: bool | None = None,
        format: OutputFormat = OutputFormat.TEXT,
    ):
        """Initialize output writer."""
        self._stream = stream or sys.stdout
        self._error_stream = error_stream or sys.stderr
        self._use_color = (
            use_color if use_color is not None else supports_color(self._stream)
        )
        self._format = format

    @property
    def use_color(self) -> bool:
        """Check if color is enabled."""
        return self._use_color

    @property
    def format(self) -> OutputFormat:
        """Get output format."""
        return self._format

    @format.setter
    def format(self, value: OutputFormat) -> None:
        """Set output format."""
        self._format = value

    def write(self, text: str, end: str = "\n") -> None:
        """Write text to output."""
        self._stream.write(text + end)
        self._stream.flush()

    def write_error(self, text: str, end: str = "\n") -> None:
        """Write text to error stream."""
        self._error_stream.write(text + end)
        self._error_stream.flush()

    def color(self, text: str, *colors: Color) -> str:
        """Apply color to text if enabled."""
        return colorize(text, *colors, enabled=self._use_color)

    def success(self, message: str) -> None:
        """Write success message."""
        prefix = self.color("✓", Color.GREEN) if self._use_color else "[OK]"
        self.write(f"{prefix} {message}")

    def error(self, message: str) -> None:
        """Write error message."""
        prefix = self.color("✗", Color.RED) if self._use_color else "[ERROR]"
        self.write_error(f"{prefix} {message}")

    def warning(self, message: str) -> None:
        """Write warning message."""
        prefix = self.color("⚠", Color.YELLOW) if self._use_color else "[WARN]"
        self.write(f"{prefix} {message}")

    def info(self, message: str) -> None:
        """Write info message."""
        prefix = self.color("ℹ", Color.BLUE) if self._use_color else "[INFO]"
        self.write(f"{prefix} {message}")

    def header(self, text: str) -> None:
        """Write header text."""
        if self._use_color:
            self.write(self.color(text, Color.BOLD, Color.CYAN))
        else:
            self.write(f"=== {text} ===")

    def json(self, data: Any, pretty: bool = True) -> None:
        """Write JSON output."""
        if pretty:
            self.write(json.dumps(data, indent=2, default=str))
        else:
            self.write(json.dumps(data, default=str))

    def table(
        self,
        rows: list[list[str]],
        headers: list[str] | None = None,
        align: list[str] | None = None,
    ) -> None:
        """Write table output."""
        if not rows and not headers:
            return

        # Calculate column widths
        all_rows = [headers] + rows if headers else rows
        num_cols = max(len(row) for row in all_rows)

        # Ensure all rows have same number of columns
        all_rows = [row + [""] * (num_cols - len(row)) for row in all_rows]
        col_widths = [
            max(len(str(row[i])) for row in all_rows) for i in range(num_cols)
        ]

        # Default alignment
        if not align:
            align = ["l"] * num_cols

        def format_row(row: list[str]) -> str:
            cells = []
            for i, (cell, width, a) in enumerate(zip(row, col_widths, align)):
                if a == "r":
                    cells.append(str(cell).rjust(width))
                elif a == "c":
                    cells.append(str(cell).center(width))
                else:
                    cells.append(str(cell).ljust(width))
            return " | ".join(cells)

        # Write header
        if headers:
            header_row = format_row(headers)
            self.write(header_row)
            self.write("-" * len(header_row))

        # Write rows
        for row in rows:
            self.write(format_row(row))

    def csv(self, rows: list[list[str]], headers: list[str] | None = None) -> None:
        """Write CSV output."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        if headers:
            writer.writerow(headers)
        writer.writerows(rows)
        self.write(output.getvalue().rstrip())

    def progress(
        self, current: int, total: int, prefix: str = "", width: int = 40
    ) -> None:
        """Write progress bar."""
        if total == 0:
            percent = 100
        else:
            percent = int(current / total * 100)

        filled = int(width * current / total) if total > 0 else width
        bar = "█" * filled + "░" * (width - filled)

        line = f"\r{prefix}[{bar}] {percent}% ({current}/{total})"
        self._stream.write(line)
        self._stream.flush()

        if current >= total:
            self._stream.write("\n")

    def spinner_frames(self) -> list[str]:
        """Get spinner animation frames."""
        return ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


@dataclass
class CommandResult:
    """Result of a command execution."""

    success: bool
    message: str = ""
    data: Any = None
    exit_code: int = 0

    @classmethod
    def ok(cls, message: str = "", data: Any = None) -> "CommandResult":
        """Create successful result."""
        return cls(success=True, message=message, data=data, exit_code=0)

    @classmethod
    def fail(
        cls, message: str, exit_code: int = 1, data: Any = None
    ) -> "CommandResult":
        """Create failure result."""
        return cls(success=False, message=message, data=data, exit_code=exit_code)


class Command(ABC):
    """Base class for CLI commands."""

    name: str = ""
    description: str = ""
    aliases: list[str] = []

    def __init__(self, output: OutputWriter):
        """Initialize command."""
        self._output = output

    @abstractmethod
    def configure(self, parser: argparse.ArgumentParser) -> None:
        """Configure argument parser for this command."""
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace) -> CommandResult:
        """Execute the command."""
        pass

    def validate(self, args: argparse.Namespace) -> str | None:
        """Validate arguments. Return error message or None."""
        return None


class CommandGroup:
    """A group of related commands."""

    def __init__(self, name: str, description: str = ""):
        """Initialize command group."""
        self._name = name
        self._description = description
        self._commands: dict[str, Type[Command]] = {}

    @property
    def name(self) -> str:
        """Get group name."""
        return self._name

    @property
    def description(self) -> str:
        """Get group description."""
        return self._description

    def add(self, command_class: Type[Command]) -> "CommandGroup":
        """Add a command to the group."""
        self._commands[command_class.name] = command_class
        for alias in command_class.aliases:
            self._commands[alias] = command_class
        return self

    def get(self, name: str) -> Type[Command] | None:
        """Get a command by name."""
        return self._commands.get(name)

    def list_commands(self) -> list[Type[Command]]:
        """List unique commands (excluding aliases)."""
        seen = set()
        commands = []
        for cmd_class in self._commands.values():
            if cmd_class.name not in seen:
                seen.add(cmd_class.name)
                commands.append(cmd_class)
        return commands


class CLI:
    """Main CLI application."""

    def __init__(
        self, name: str = "redops", version: str = "1.0.0", description: str = ""
    ):
        """Initialize CLI."""
        self._name = name
        self._version = version
        self._description = description
        self._commands: dict[str, Type[Command]] = {}
        self._groups: dict[str, CommandGroup] = {}
        self._output = OutputWriter()
        self._global_options: list[tuple[list[str], dict]] = []
        self._before_hooks: list[Callable] = []
        self._after_hooks: list[Callable] = []

    @property
    def name(self) -> str:
        """Get CLI name."""
        return self._name

    @property
    def version(self) -> str:
        """Get CLI version."""
        return self._version

    @property
    def output(self) -> OutputWriter:
        """Get output writer."""
        return self._output

    def add_command(self, command_class: Type[Command]) -> "CLI":
        """Add a command."""
        self._commands[command_class.name] = command_class
        for alias in command_class.aliases:
            self._commands[alias] = command_class
        return self

    def add_group(self, group: CommandGroup) -> "CLI":
        """Add a command group."""
        self._groups[group.name] = group
        return self

    def add_global_option(self, *args, **kwargs) -> "CLI":
        """Add a global option."""
        self._global_options.append((list(args), kwargs))
        return self

    def before(self, hook: Callable) -> "CLI":
        """Add a before-execution hook."""
        self._before_hooks.append(hook)
        return self

    def after(self, hook: Callable) -> "CLI":
        """Add an after-execution hook."""
        self._after_hooks.append(hook)
        return self

    def create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser."""
        parser = argparse.ArgumentParser(
            prog=self._name,
            description=self._description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        # Add version
        parser.add_argument(
            "--version",
            "-V",
            action="version",
            version=f"{self._name} {self._version}",
        )

        # Add global options
        parser.add_argument(
            "--format",
            "-f",
            choices=["text", "json", "table", "csv", "quiet"],
            default="text",
            help="Output format",
        )
        parser.add_argument(
            "--no-color",
            action="store_true",
            help="Disable colored output",
        )
        parser.add_argument(
            "--verbose",
            "-v",
            action="count",
            default=0,
            help="Increase verbosity",
        )
        parser.add_argument(
            "--quiet",
            "-q",
            action="store_true",
            help="Suppress non-essential output",
        )

        # Add custom global options
        for args, kwargs in self._global_options:
            parser.add_argument(*args, **kwargs)

        # Add subparsers for commands
        if self._commands or self._groups:
            subparsers = parser.add_subparsers(
                dest="command",
                title="commands",
                metavar="<command>",
            )

            # Add direct commands
            for name, cmd_class in self._commands.items():
                if name == cmd_class.name:  # Skip aliases
                    cmd_parser = subparsers.add_parser(
                        name,
                        help=cmd_class.description,
                        aliases=cmd_class.aliases,
                    )
                    cmd_instance = cmd_class(self._output)
                    cmd_instance.configure(cmd_parser)

            # Add grouped commands
            for group_name, group in self._groups.items():
                group_parser = subparsers.add_parser(
                    group_name,
                    help=group.description,
                )
                group_subparsers = group_parser.add_subparsers(
                    dest="subcommand",
                    title="subcommands",
                    metavar="<subcommand>",
                )
                for cmd_class in group.list_commands():
                    cmd_parser = group_subparsers.add_parser(
                        cmd_class.name,
                        help=cmd_class.description,
                        aliases=cmd_class.aliases,
                    )
                    cmd_instance = cmd_class(self._output)
                    cmd_instance.configure(cmd_parser)

        return parser

    def run(self, args: Sequence[str] | None = None) -> int:
        """Run the CLI."""
        parser = self.create_parser()
        parsed = parser.parse_args(args)

        # Configure output
        self._output = OutputWriter(
            use_color=not parsed.no_color,
            format=OutputFormat(parsed.format),
        )

        # Handle no command
        if not parsed.command:
            parser.print_help()
            return 0

        # Find command
        cmd_class = None
        if parsed.command in self._commands:
            cmd_class = self._commands[parsed.command]
        elif parsed.command in self._groups:
            group = self._groups[parsed.command]
            if hasattr(parsed, "subcommand") and parsed.subcommand:
                cmd_class = group.get(parsed.subcommand)
            else:
                parser.parse_args([parsed.command, "--help"])
                return 0

        if not cmd_class:
            self._output.error(f"Unknown command: {parsed.command}")
            return 1

        # Create and execute command
        command = cmd_class(self._output)

        # Validate
        error = command.validate(parsed)
        if error:
            self._output.error(error)
            return 1

        # Run before hooks
        for hook in self._before_hooks:
            hook(parsed)

        # Execute
        try:
            result = command.execute(parsed)
        except KeyboardInterrupt:
            self._output.write("")  # Newline
            self._output.error("Interrupted")
            return 130
        except (OSError, RuntimeError, TypeError, ValueError) as e:
            self._output.error(f"Error: {e}")
            if parsed.verbose > 0:
                import traceback

                traceback.print_exc()
            return 1

        # Run after hooks
        for hook in self._after_hooks:
            hook(parsed, result)

        # Handle result
        if result.message:
            if result.success:
                if not parsed.quiet:
                    self._output.success(result.message)
            else:
                self._output.error(result.message)

        # Output data based on format
        if result.data is not None and self._output.format != OutputFormat.QUIET:
            self._format_output(result.data)

        return result.exit_code

    def _format_output(self, data: Any) -> None:
        """Format and output data."""
        fmt = self._output.format

        if fmt == OutputFormat.JSON:
            self._output.json(data)
        elif fmt == OutputFormat.TABLE:
            if isinstance(data, list) and data and isinstance(data[0], dict):
                headers = list(data[0].keys())
                rows = [[str(row.get(h, "")) for h in headers] for row in data]
                self._output.table(rows, headers)
            elif isinstance(data, dict):
                rows = [[k, str(v)] for k, v in data.items()]
                self._output.table(rows, ["Key", "Value"])
        elif fmt == OutputFormat.CSV:
            if isinstance(data, list) and data and isinstance(data[0], dict):
                headers = list(data[0].keys())
                rows = [[str(row.get(h, "")) for h in headers] for row in data]
                self._output.csv(rows, headers)
        elif fmt == OutputFormat.TEXT:
            if isinstance(data, (dict, list)):
                self._output.json(data)
            else:
                self._output.write(str(data))


class InteractiveShell:
    """Interactive REPL shell."""

    def __init__(self, cli: CLI, prompt: str = "> ", intro: str = ""):
        """Initialize interactive shell."""
        self._cli = cli
        self._prompt = prompt
        self._intro = intro
        self._output = cli.output
        self._running = False
        self._history: list[str] = []
        self._commands: dict[str, Callable] = {
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "history": self._cmd_history,
            "clear": self._cmd_clear,
        }

    def add_command(self, name: str, func: Callable[[list[str]], None]) -> None:
        """Add a shell command."""
        self._commands[name] = func

    def run(self) -> None:
        """Run the interactive shell."""
        self._running = True

        if self._intro:
            self._output.write(self._intro)

        while self._running:
            try:
                line = input(self._prompt).strip()
                if not line:
                    continue

                self._history.append(line)
                self._execute_line(line)

            except EOFError:
                self._output.write("")
                break
            except KeyboardInterrupt:
                self._output.write("")
                continue

    def _execute_line(self, line: str) -> None:
        """Execute a command line."""
        parts = line.split()
        cmd = parts[0].lower()
        args = parts[1:]

        # Check built-in commands
        if cmd in self._commands:
            self._commands[cmd](args)
            return

        # Try CLI command
        try:
            self._cli.run(parts)
        except SystemExit:
            pass  # Ignore argparse exits

    def _cmd_help(self, args: list[str]) -> None:
        """Show help."""
        self._output.write("Available commands:")
        for name in sorted(self._commands.keys()):
            self._output.write(f"  {name}")
        self._output.write("\nCLI commands are also available.")

    def _cmd_exit(self, args: list[str]) -> None:
        """Exit the shell."""
        self._running = False

    def _cmd_history(self, args: list[str]) -> None:
        """Show command history."""
        for i, cmd in enumerate(self._history, 1):
            self._output.write(f"{i:4d}  {cmd}")

    def _cmd_clear(self, args: list[str]) -> None:
        """Clear the screen."""
        print("\033[2J\033[H", end="", flush=True)


class PromptBuilder:
    """Builds interactive prompts."""

    def __init__(self, output: OutputWriter):
        """Initialize prompt builder."""
        self._output = output

    def confirm(self, message: str, default: bool = False) -> bool:
        """Ask for confirmation."""
        suffix = "[Y/n]" if default else "[y/N]"
        response = input(f"{message} {suffix} ").strip().lower()

        if not response:
            return default
        return response in ("y", "yes")

    def ask(
        self,
        message: str,
        default: str | None = None,
        validator: Callable[[str], bool] | None = None,
    ) -> str:
        """Ask for text input."""
        prompt = message
        if default:
            prompt += f" [{default}]"
        prompt += ": "

        while True:
            response = input(prompt).strip()
            if not response and default:
                return default
            if not response:
                self._output.error("Please enter a value")
                continue
            if validator and not validator(response):
                self._output.error("Invalid input")
                continue
            return response

    def secret(self, message: str) -> str:
        """Ask for secret input (hidden)."""
        import getpass

        return getpass.getpass(f"{message}: ")

    def choice(
        self, message: str, choices: list[str], default: str | None = None
    ) -> str:
        """Ask user to choose from options."""
        self._output.write(message)
        for i, choice in enumerate(choices, 1):
            marker = "*" if choice == default else " "
            self._output.write(f"  {marker} {i}. {choice}")

        while True:
            prompt = "Enter number"
            if default:
                prompt += f" [{choices.index(default) + 1}]"
            response = input(f"{prompt}: ").strip()

            if not response and default:
                return default

            try:
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
            except ValueError:
                if response in choices:
                    return response

            self._output.error("Invalid choice")

    def multi_choice(
        self, message: str, choices: list[str], defaults: list[str] | None = None
    ) -> list[str]:
        """Ask user to choose multiple options."""
        defaults = defaults or []
        self._output.write(message)
        for i, choice in enumerate(choices, 1):
            marker = "x" if choice in defaults else " "
            self._output.write(f"  [{marker}] {i}. {choice}")

        self._output.write("Enter numbers separated by commas:")
        response = input("> ").strip()

        if not response:
            return defaults

        selected = []
        for part in response.split(","):
            try:
                idx = int(part.strip()) - 1
                if 0 <= idx < len(choices):
                    selected.append(choices[idx])
            except ValueError:
                pass  # Invalid number - skip this selection

        return selected if selected else defaults


def create_cli(
    name: str = "redops", version: str = "1.0.0", description: str = ""
) -> CLI:
    """Create a new CLI instance."""
    return CLI(name=name, version=version, description=description)


def command(name: str, description: str = "", aliases: list[str] | None = None):
    """Decorator to create a command from a function."""

    def decorator(func: Callable) -> Type[Command]:
        import inspect

        sig = inspect.signature(func)
        params = list(sig.parameters.values())[1:]  # Skip 'args' parameter

        class FunctionCommand(Command):
            pass

        # Set class attributes
        FunctionCommand.name = name
        FunctionCommand.description = description
        FunctionCommand.aliases = aliases or []

        # Define methods that will be bound to instances
        def _configure(self, parser: argparse.ArgumentParser) -> None:
            for param in params:
                if param.annotation is bool:
                    parser.add_argument(
                        f"--{param.name}",
                        action="store_true",
                        default=param.default
                        if param.default != inspect.Parameter.empty
                        else False,
                    )
                elif param.default != inspect.Parameter.empty:
                    parser.add_argument(
                        f"--{param.name}",
                        default=param.default,
                    )
                else:
                    parser.add_argument(param.name)

        def _execute(self, args: argparse.Namespace) -> CommandResult:
            kwargs = {p.name: getattr(args, p.name, p.default) for p in params}
            result = func(args, **kwargs)
            if isinstance(result, CommandResult):
                return result
            return CommandResult.ok(data=result)

        # Override the abstract methods by setting them on the class
        # This works because we're replacing the abstract method references
        FunctionCommand.configure = _configure
        FunctionCommand.execute = _execute

        # Remove abstract method markers
        if hasattr(FunctionCommand, "__abstractmethods__"):
            FunctionCommand.__abstractmethods__ = frozenset()

        return FunctionCommand

    return decorator
