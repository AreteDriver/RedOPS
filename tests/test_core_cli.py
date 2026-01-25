"""Tests for core CLI framework module."""

import argparse
import io
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from redops.core.cli import (
    CLI,
    Color,
    Command,
    CommandGroup,
    CommandResult,
    InteractiveShell,
    OutputFormat,
    OutputWriter,
    PromptBuilder,
    colorize,
    command,
    create_cli,
    supports_color,
)


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_output_formats_exist(self):
        """Test all output formats are defined."""
        assert OutputFormat.TEXT is not None
        assert OutputFormat.JSON is not None
        assert OutputFormat.TABLE is not None
        assert OutputFormat.CSV is not None
        assert OutputFormat.QUIET is not None

    def test_output_format_values(self):
        """Test output format string values."""
        assert OutputFormat.TEXT.value == "text"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.TABLE.value == "table"
        assert OutputFormat.CSV.value == "csv"
        assert OutputFormat.QUIET.value == "quiet"


class TestColor:
    """Tests for Color enum."""

    def test_colors_exist(self):
        """Test colors are defined."""
        assert Color.RED is not None
        assert Color.GREEN is not None
        assert Color.YELLOW is not None
        assert Color.BLUE is not None
        assert Color.RESET is not None

    def test_color_codes_are_ansi(self):
        """Test color codes are ANSI escape sequences."""
        assert Color.RED.value.startswith("\033[")
        assert Color.RESET.value == "\033[0m"

    def test_all_colors_defined(self):
        """Test all standard colors are defined."""
        assert Color.BLACK is not None
        assert Color.WHITE is not None
        assert Color.MAGENTA is not None
        assert Color.CYAN is not None
        assert Color.BOLD is not None
        assert Color.DIM is not None
        assert Color.UNDERLINE is not None


class TestSupportsColor:
    """Tests for supports_color function."""

    def test_no_color_env(self, monkeypatch):
        """Test NO_COLOR environment variable."""
        monkeypatch.setenv("NO_COLOR", "1")
        assert supports_color() is False

    def test_force_color_env(self, monkeypatch):
        """Test FORCE_COLOR environment variable."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert supports_color() is True

    def test_non_tty(self, monkeypatch):
        """Test non-TTY stream."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        stream = io.StringIO()
        assert supports_color(stream) is False


class TestColorize:
    """Tests for colorize function."""

    def test_colorize_enabled(self):
        """Test colorize with color enabled."""
        result = colorize("hello", Color.RED, enabled=True)
        assert Color.RED.value in result
        assert Color.RESET.value in result
        assert "hello" in result

    def test_colorize_disabled(self):
        """Test colorize with color disabled."""
        result = colorize("hello", Color.RED, enabled=False)
        assert result == "hello"

    def test_colorize_multiple_colors(self):
        """Test colorize with multiple colors."""
        result = colorize("bold red", Color.BOLD, Color.RED, enabled=True)
        assert Color.BOLD.value in result
        assert Color.RED.value in result


class TestOutputWriter:
    """Tests for OutputWriter class."""

    def test_init_defaults(self):
        """Test default initialization."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        assert writer.format == OutputFormat.TEXT

    def test_init_custom_format(self):
        """Test custom format initialization."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream, format=OutputFormat.JSON)
        assert writer.format == OutputFormat.JSON

    def test_write(self):
        """Test write method."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream, use_color=False)
        writer.write("Hello, World!")
        assert stream.getvalue() == "Hello, World!\n"

    def test_write_no_newline(self):
        """Test write without newline."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.write("Hello", end="")
        assert stream.getvalue() == "Hello"

    def test_write_error(self):
        """Test write_error method."""
        error_stream = io.StringIO()
        writer = OutputWriter(error_stream=error_stream)
        writer.write_error("Error message")
        assert "Error message" in error_stream.getvalue()

    def test_color_method(self):
        """Test color method."""
        writer = OutputWriter(use_color=True)
        result = writer.color("text", Color.RED)
        assert Color.RED.value in result

    def test_color_disabled(self):
        """Test color method with color disabled."""
        writer = OutputWriter(use_color=False)
        result = writer.color("text", Color.RED)
        assert result == "text"

    def test_success_message(self):
        """Test success message."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream, use_color=False)
        writer.success("Done")
        assert "[OK]" in stream.getvalue()
        assert "Done" in stream.getvalue()

    def test_error_message(self):
        """Test error message."""
        error_stream = io.StringIO()
        writer = OutputWriter(error_stream=error_stream, use_color=False)
        writer.error("Failed")
        assert "[ERROR]" in error_stream.getvalue()
        assert "Failed" in error_stream.getvalue()

    def test_warning_message(self):
        """Test warning message."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream, use_color=False)
        writer.warning("Caution")
        assert "[WARN]" in stream.getvalue()
        assert "Caution" in stream.getvalue()

    def test_info_message(self):
        """Test info message."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream, use_color=False)
        writer.info("Note")
        assert "[INFO]" in stream.getvalue()
        assert "Note" in stream.getvalue()

    def test_header(self):
        """Test header output."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream, use_color=False)
        writer.header("Section")
        assert "Section" in stream.getvalue()
        assert "===" in stream.getvalue()

    def test_json_output(self):
        """Test JSON output."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        data = {"key": "value", "number": 42}
        writer.json(data)
        output = json.loads(stream.getvalue())
        assert output == data

    def test_json_pretty(self):
        """Test pretty JSON output."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.json({"key": "value"}, pretty=True)
        assert "  " in stream.getvalue()  # Indentation

    def test_json_compact(self):
        """Test compact JSON output."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.json({"key": "value"}, pretty=False)
        assert "  " not in stream.getvalue()

    def test_table_output(self):
        """Test table output."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        headers = ["Name", "Age"]
        rows = [["Alice", "30"], ["Bob", "25"]]
        writer.table(rows, headers)
        output = stream.getvalue()
        assert "Name" in output
        assert "Age" in output
        assert "Alice" in output
        assert "Bob" in output

    def test_table_alignment(self):
        """Test table with alignment."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        rows = [["Left", "Center", "Right"]]
        writer.table(rows, align=["l", "c", "r"])
        # Just verify it doesn't crash
        assert "Left" in stream.getvalue()

    def test_table_empty(self):
        """Test table with no data."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.table([], None)
        assert stream.getvalue() == ""

    def test_csv_output(self):
        """Test CSV output."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        headers = ["Name", "Age"]
        rows = [["Alice", "30"], ["Bob", "25"]]
        writer.csv(rows, headers)
        output = stream.getvalue()
        assert "Name,Age" in output
        assert "Alice,30" in output
        assert "Bob,25" in output

    def test_progress_bar(self):
        """Test progress bar."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.progress(50, 100, prefix="Loading")
        output = stream.getvalue()
        assert "50%" in output

    def test_progress_bar_complete(self):
        """Test progress bar at 100%."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.progress(100, 100)
        output = stream.getvalue()
        assert "100%" in output

    def test_progress_bar_zero_total(self):
        """Test progress bar with zero total."""
        stream = io.StringIO()
        writer = OutputWriter(stream=stream)
        writer.progress(0, 0)  # Should not divide by zero
        assert "100%" in stream.getvalue()

    def test_spinner_frames(self):
        """Test spinner frames exist."""
        writer = OutputWriter()
        frames = writer.spinner_frames()
        assert len(frames) > 0
        assert all(isinstance(f, str) for f in frames)

    def test_format_setter(self):
        """Test format property setter."""
        writer = OutputWriter()
        writer.format = OutputFormat.JSON
        assert writer.format == OutputFormat.JSON


class TestCommandResult:
    """Tests for CommandResult class."""

    def test_create_ok(self):
        """Test creating successful result."""
        result = CommandResult.ok("Done", data={"key": "value"})
        assert result.success is True
        assert result.message == "Done"
        assert result.data == {"key": "value"}
        assert result.exit_code == 0

    def test_create_fail(self):
        """Test creating failure result."""
        result = CommandResult.fail("Error", exit_code=2)
        assert result.success is False
        assert result.message == "Error"
        assert result.exit_code == 2

    def test_default_values(self):
        """Test default values."""
        result = CommandResult(success=True)
        assert result.message == ""
        assert result.data is None
        assert result.exit_code == 0


class TestCommand:
    """Tests for Command base class."""

    def test_command_abstract(self):
        """Test Command is abstract."""
        output = OutputWriter()
        with pytest.raises(TypeError):
            Command(output)  # Can't instantiate abstract class

    def test_command_subclass(self):
        """Test Command subclass."""

        class TestCmd(Command):
            name = "test"
            description = "A test command"

            def configure(self, parser):
                parser.add_argument("--flag", action="store_true")

            def execute(self, args):
                return CommandResult.ok("Executed")

        output = OutputWriter()
        cmd = TestCmd(output)
        assert cmd.name == "test"
        assert cmd.description == "A test command"

    def test_command_validate_default(self):
        """Test default validate returns None."""

        class TestCmd(Command):
            name = "test"
            description = "Test"

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        output = OutputWriter()
        cmd = TestCmd(output)
        assert cmd.validate(argparse.Namespace()) is None


class TestCommandGroup:
    """Tests for CommandGroup class."""

    def test_group_init(self):
        """Test group initialization."""
        group = CommandGroup("db", "Database commands")
        assert group.name == "db"
        assert group.description == "Database commands"

    def test_add_command(self):
        """Test adding command to group."""

        class ListCmd(Command):
            name = "list"
            description = "List items"
            aliases = ["ls"]

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        group = CommandGroup("db", "Database")
        group.add(ListCmd)
        assert group.get("list") is ListCmd
        assert group.get("ls") is ListCmd  # Alias

    def test_get_nonexistent(self):
        """Test getting nonexistent command."""
        group = CommandGroup("db", "Database")
        assert group.get("nonexistent") is None

    def test_list_commands(self):
        """Test listing commands."""

        class Cmd1(Command):
            name = "cmd1"
            description = "Cmd 1"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        class Cmd2(Command):
            name = "cmd2"
            description = "Cmd 2"
            aliases = ["c2"]

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        group = CommandGroup("test", "Test")
        group.add(Cmd1).add(Cmd2)
        commands = group.list_commands()
        assert len(commands) == 2
        assert Cmd1 in commands
        assert Cmd2 in commands


class TestCLI:
    """Tests for CLI class."""

    def test_cli_init(self):
        """Test CLI initialization."""
        cli = CLI(name="myapp", version="1.0.0", description="My app")
        assert cli.name == "myapp"
        assert cli.version == "1.0.0"

    def test_cli_add_command(self):
        """Test adding command."""

        class TestCmd(Command):
            name = "test"
            description = "Test"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        cli = CLI()
        cli.add_command(TestCmd)
        # Command added (verify by creating parser)
        parser = cli.create_parser()
        assert parser is not None

    def test_cli_add_group(self):
        """Test adding command group."""
        cli = CLI()
        group = CommandGroup("db", "Database")
        cli.add_group(group)
        parser = cli.create_parser()
        assert parser is not None

    def test_cli_add_global_option(self):
        """Test adding global option."""
        cli = CLI()
        cli.add_global_option("--config", help="Config file")
        parser = cli.create_parser()
        args = parser.parse_args(["--config", "test.yaml"])
        assert args.config == "test.yaml"

    def test_cli_run_no_command(self, capsys):
        """Test running with no command shows help."""

        class TestCmd(Command):
            name = "test"
            description = "Test"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        cli = CLI()
        cli.add_command(TestCmd)
        result = cli.run([])
        assert result == 0  # Shows help

    def test_cli_run_version(self, capsys):
        """Test --version flag."""
        cli = CLI(name="test", version="2.0.0")
        with pytest.raises(SystemExit) as exc_info:
            cli.run(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "2.0.0" in captured.out

    def test_cli_run_command(self):
        """Test running a command."""
        executed = []

        class EchoCmd(Command):
            name = "echo"
            description = "Echo"
            aliases = []

            def configure(self, parser):
                parser.add_argument("text")

            def execute(self, args):
                executed.append(args.text)
                return CommandResult.ok()

        cli = CLI()
        cli.add_command(EchoCmd)
        result = cli.run(["echo", "hello"])
        assert result == 0
        assert executed == ["hello"]

    def test_cli_run_unknown_command(self):
        """Test running unknown command raises SystemExit."""

        class TestCmd(Command):
            name = "test"
            description = "Test"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        cli = CLI()
        cli.add_command(TestCmd)
        # argparse raises SystemExit for unknown commands
        with pytest.raises(SystemExit) as exc_info:
            cli.run(["unknown"])
        assert exc_info.value.code == 2

    def test_cli_before_hook(self):
        """Test before hook."""
        called = []

        class NoopCmd(Command):
            name = "noop"
            description = "No-op"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok()

        cli = CLI()
        cli.add_command(NoopCmd)
        cli.before(lambda args: called.append("before"))
        cli.run(["noop"])
        assert "before" in called

    def test_cli_after_hook(self):
        """Test after hook."""
        called = []

        class NoopCmd(Command):
            name = "noop"
            description = "No-op"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok("done")

        cli = CLI()
        cli.add_command(NoopCmd)
        cli.after(lambda args, result: called.append(result.message))
        cli.run(["noop"])
        assert "done" in called

    def test_cli_error_handling(self):
        """Test error handling."""

        class FailCmd(Command):
            name = "fail"
            description = "Fail"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                raise ValueError("Test error")

        cli = CLI()
        cli.add_command(FailCmd)
        result = cli.run(["fail"])
        assert result == 1

    def test_cli_validation_error(self):
        """Test validation error."""

        class ValidatedCmd(Command):
            name = "validated"
            description = "Validated"
            aliases = []

            def configure(self, parser):
                pass

            def validate(self, args):
                return "Validation failed"

            def execute(self, args):
                return CommandResult.ok()

        cli = CLI()
        cli.add_command(ValidatedCmd)
        result = cli.run(["validated"])
        assert result == 1

    def test_cli_output_json(self, capsys):
        """Test JSON output format."""

        class DataCmd(Command):
            name = "data"
            description = "Data"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                return CommandResult.ok(data={"key": "value"})

        cli = CLI()
        cli.add_command(DataCmd)
        cli.run(["--format", "json", "data"])
        # Result includes JSON output to stdout
        captured = capsys.readouterr()
        assert "key" in captured.out

    def test_cli_group_command(self):
        """Test running command in group."""
        executed = []

        class MigrateCmd(Command):
            name = "migrate"
            description = "Migrate"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                executed.append("migrate")
                return CommandResult.ok()

        cli = CLI()
        group = CommandGroup("db", "Database")
        group.add(MigrateCmd)
        cli.add_group(group)
        result = cli.run(["db", "migrate"])
        assert result == 0
        assert executed == ["migrate"]


class TestInteractiveShell:
    """Tests for InteractiveShell class."""

    def test_shell_init(self):
        """Test shell initialization."""
        cli = CLI(name="test")
        shell = InteractiveShell(cli, prompt="> ")
        assert shell._prompt == "> "

    def test_shell_add_command(self):
        """Test adding shell command."""
        cli = CLI()
        shell = InteractiveShell(cli)
        called = []
        shell.add_command("custom", lambda args: called.append(args))
        shell._execute_line("custom arg1 arg2")
        assert called == [["arg1", "arg2"]]

    def test_shell_exit_command(self):
        """Test exit command."""
        cli = CLI()
        shell = InteractiveShell(cli)
        shell._running = True
        shell._execute_line("exit")
        assert shell._running is False

    def test_shell_quit_command(self):
        """Test quit command."""
        cli = CLI()
        shell = InteractiveShell(cli)
        shell._running = True
        shell._execute_line("quit")
        assert shell._running is False

    def test_shell_history(self):
        """Test history command."""
        cli = CLI()
        shell = InteractiveShell(cli)
        shell._history = ["cmd1", "cmd2", "cmd3"]
        # Just verify it doesn't crash
        stream = io.StringIO()
        shell._output = OutputWriter(stream=stream)
        shell._cmd_history([])
        assert "cmd1" in stream.getvalue()

    def test_shell_help(self):
        """Test help command."""
        cli = CLI()
        shell = InteractiveShell(cli)
        stream = io.StringIO()
        shell._output = OutputWriter(stream=stream)
        shell._cmd_help([])
        assert "Available commands" in stream.getvalue()


class TestPromptBuilder:
    """Tests for PromptBuilder class."""

    def test_confirm_yes(self):
        """Test confirm with yes."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value="y"):
            result = prompt.confirm("Continue?")
            assert result is True

    def test_confirm_no(self):
        """Test confirm with no."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value="n"):
            result = prompt.confirm("Continue?")
            assert result is False

    def test_confirm_default_yes(self):
        """Test confirm with empty input and default yes."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value=""):
            result = prompt.confirm("Continue?", default=True)
            assert result is True

    def test_confirm_default_no(self):
        """Test confirm with empty input and default no."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value=""):
            result = prompt.confirm("Continue?", default=False)
            assert result is False

    def test_ask_basic(self):
        """Test ask for input."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value="test value"):
            result = prompt.ask("Enter value")
            assert result == "test value"

    def test_ask_with_default(self):
        """Test ask with default value."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value=""):
            result = prompt.ask("Enter value", default="default")
            assert result == "default"

    def test_ask_with_validator(self):
        """Test ask with validator."""
        output = OutputWriter(stream=io.StringIO(), error_stream=io.StringIO())
        prompt = PromptBuilder(output)
        inputs = iter(["bad", "good"])
        with patch("builtins.input", side_effect=lambda _: next(inputs)):
            result = prompt.ask("Enter", validator=lambda x: x == "good")
            assert result == "good"

    def test_secret(self):
        """Test secret input."""
        output = OutputWriter()
        prompt = PromptBuilder(output)
        with patch("getpass.getpass", return_value="secret123"):
            result = prompt.secret("Password")
            assert result == "secret123"

    def test_choice(self):
        """Test choice selection."""
        output = OutputWriter(stream=io.StringIO())
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value="2"):
            result = prompt.choice("Select", ["a", "b", "c"])
            assert result == "b"

    def test_choice_with_default(self):
        """Test choice with default."""
        output = OutputWriter(stream=io.StringIO())
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value=""):
            result = prompt.choice("Select", ["a", "b", "c"], default="b")
            assert result == "b"

    def test_choice_by_name(self):
        """Test choice by entering name."""
        output = OutputWriter(stream=io.StringIO(), error_stream=io.StringIO())
        prompt = PromptBuilder(output)
        inputs = iter(["invalid", "b"])
        with patch("builtins.input", side_effect=lambda _: next(inputs)):
            result = prompt.choice("Select", ["a", "b", "c"])
            assert result == "b"

    def test_multi_choice(self):
        """Test multi-choice selection."""
        output = OutputWriter(stream=io.StringIO())
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value="1,3"):
            result = prompt.multi_choice("Select", ["a", "b", "c"])
            assert result == ["a", "c"]

    def test_multi_choice_default(self):
        """Test multi-choice with defaults."""
        output = OutputWriter(stream=io.StringIO())
        prompt = PromptBuilder(output)
        with patch("builtins.input", return_value=""):
            result = prompt.multi_choice("Select", ["a", "b", "c"], defaults=["b"])
            assert result == ["b"]


class TestCommandDecorator:
    """Tests for @command decorator."""

    def test_command_decorator_basic(self):
        """Test basic command decorator."""

        @command("greet", "Greet someone")
        def greet(args):
            return CommandResult.ok("Hello")

        assert greet.name == "greet"
        assert greet.description == "Greet someone"

    def test_command_decorator_with_aliases(self):
        """Test command decorator with aliases."""

        @command("list", "List items", aliases=["ls", "l"])
        def list_cmd(args):
            return CommandResult.ok()

        assert list_cmd.aliases == ["ls", "l"]

    def test_command_decorator_execute(self, capsys):
        """Test executing decorated command via CLI."""

        @command("add", "Add numbers")
        def add(args, a: str, b: str):
            return CommandResult.ok(data=int(a) + int(b))

        cli = CLI()
        cli.add_command(add)
        result = cli.run(["--format", "json", "add", "5", "3"])
        assert result == 0
        captured = capsys.readouterr()
        assert "8" in captured.out


class TestCreateCLI:
    """Tests for create_cli helper function."""

    def test_create_cli(self):
        """Test create_cli function."""
        cli = create_cli(name="myapp", version="1.0.0", description="My app")
        assert cli.name == "myapp"
        assert cli.version == "1.0.0"


class TestCLIOutputFormatting:
    """Tests for CLI output formatting."""

    def test_format_output_json(self):
        """Test JSON output formatting."""
        stream = io.StringIO()
        cli = CLI()
        cli._output = OutputWriter(stream=stream, format=OutputFormat.JSON)
        cli._format_output({"key": "value"})
        output = json.loads(stream.getvalue())
        assert output == {"key": "value"}

    def test_format_output_table_list(self):
        """Test table output with list of dicts."""
        stream = io.StringIO()
        cli = CLI()
        cli._output = OutputWriter(stream=stream, format=OutputFormat.TABLE)
        cli._format_output([{"name": "Alice", "age": "30"}])
        output = stream.getvalue()
        assert "name" in output
        assert "Alice" in output

    def test_format_output_table_dict(self):
        """Test table output with dict."""
        stream = io.StringIO()
        cli = CLI()
        cli._output = OutputWriter(stream=stream, format=OutputFormat.TABLE)
        cli._format_output({"key": "value"})
        output = stream.getvalue()
        assert "Key" in output
        assert "Value" in output

    def test_format_output_csv(self):
        """Test CSV output formatting."""
        stream = io.StringIO()
        cli = CLI()
        cli._output = OutputWriter(stream=stream, format=OutputFormat.CSV)
        cli._format_output([{"name": "Alice", "age": "30"}])
        output = stream.getvalue()
        assert "name,age" in output
        assert "Alice,30" in output

    def test_format_output_text_dict(self):
        """Test text output with dict shows JSON."""
        stream = io.StringIO()
        cli = CLI()
        cli._output = OutputWriter(stream=stream, format=OutputFormat.TEXT)
        cli._format_output({"key": "value"})
        output = stream.getvalue()
        assert "key" in output
        assert "value" in output


class TestEdgeCases:
    """Tests for edge cases."""

    def test_cli_keyboard_interrupt(self):
        """Test keyboard interrupt handling."""

        class InterruptCmd(Command):
            name = "interrupt"
            description = "Interrupt"
            aliases = []

            def configure(self, parser):
                pass

            def execute(self, args):
                raise KeyboardInterrupt()

        cli = CLI()
        cli._output = OutputWriter(
            stream=io.StringIO(),
            error_stream=io.StringIO()
        )
        cli.add_command(InterruptCmd)
        result = cli.run(["interrupt"])
        assert result == 130  # Standard SIGINT exit code

    def test_command_result_fail_default_code(self):
        """Test CommandResult.fail default exit code."""
        result = CommandResult.fail("Error")
        assert result.exit_code == 1

    def test_command_result_with_data(self):
        """Test CommandResult with data in fail case."""
        result = CommandResult.fail("Error", data={"detail": "info"})
        assert result.data == {"detail": "info"}

    def test_output_writer_use_color_property(self):
        """Test use_color property."""
        writer = OutputWriter(use_color=True)
        assert writer.use_color is True
        writer = OutputWriter(use_color=False)
        assert writer.use_color is False
