"""Unit tests for the CLI interface."""

import json
from unittest.mock import patch
import pytest

from password_generator.cli import build_parser, copy_to_clipboard, main


class TestCLI:
    """Test suite for CLI execution and argument parsing."""

    def test_default_cli_run(self, capsys):
        """Test default CLI run outputs a 16-character password."""
        exit_code = main([])
        assert exit_code == 0
        captured = capsys.readouterr()
        output = captured.out.strip()
        assert len(output) == 16

    def test_cli_custom_length(self, capsys):
        """Test -l / --length flag."""
        exit_code = main(["--length", "24"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert len(captured.out.strip()) == 24

    def test_cli_multiple_passwords(self, capsys):
        """Test -n / --count flag."""
        exit_code = main(["-n", "5", "-l", "10"])
        assert exit_code == 0
        captured = capsys.readouterr()
        lines = captured.out.strip().splitlines()
        assert len(lines) == 5
        for line in lines:
            assert len(line) == 10

    def test_cli_with_strength_flag(self, capsys):
        """Test -s / --strength flag displays entropy and rating."""
        exit_code = main(["-l", "20", "--strength"])
        assert exit_code == 0
        captured = capsys.readouterr()
        output = captured.out.strip()
        assert "Entropy:" in output
        assert "Rating:" in output

    def test_cli_json_output(self, capsys):
        """Test --json flag with --strength."""
        exit_code = main(["-l", "18", "--json", "--strength"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "password" in data
        assert len(data["password"]) == 18
        assert "entropy_bits" in data
        assert "rating" in data
        assert "score" in data

    def test_cli_passphrase_mode(self, capsys):
        """Test -p / --passphrase mode."""
        exit_code = main(["--passphrase", "--words", "3", "--separator", "_"])
        assert exit_code == 0
        captured = capsys.readouterr()
        phrase = captured.out.strip()
        parts = phrase.split("_")
        assert len(parts) == 3

    def test_cli_invalid_constraints_exit_code(self, capsys):
        """Test that invalid configuration returns error exit code 1."""
        exit_code = main(["--length", "3", "--min-digits", "5"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_cli_all_categories_disabled_exit_code(self, capsys):
        """Test error when all character categories are turned off."""
        exit_code = main(["--no-lower", "--no-upper", "--no-digits", "--no-symbols"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err

    def test_cli_copy_to_clipboard_invoked(self, monkeypatch, capsys):
        """Test --copy flag calls copy_to_clipboard."""
        monkeypatch.setattr("password_generator.cli.copy_to_clipboard", lambda text: True)
        exit_code = main(["-l", "12", "--copy"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "[Password copied to clipboard]" in captured.err

    def test_copy_to_clipboard_functionality(self):
        """Test copy_to_clipboard return value (bool)."""
        # Regardless of whether clipboard access succeeds in test environment, it shouldn't crash
        res = copy_to_clipboard("test_pass")
        assert isinstance(res, bool)

    def test_cli_json_multiple_passwords(self, capsys):
        """Test --json flag with count > 1 returns a JSON array."""
        exit_code = main(["-n", "3", "-l", "14", "--json"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 3
        for item in data:
            assert "password" in item
            assert len(item["password"]) == 14

    def test_cli_interactive_password(self, monkeypatch, capsys):
        """Test interactive mode for password generation."""
        # Answers: mode [1], length [12], lower [y], upper [y], digits [y], symbols [y], no_ambig [n], count [2]
        inputs = iter(["1", "12", "y", "y", "y", "y", "n", "2"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        exit_code = main(["--interactive"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Generated Passwords:" in captured.out
        assert "[1]" in captured.out
        assert "[2]" in captured.out

    def test_cli_interactive_passphrase(self, monkeypatch, capsys):
        """Test interactive mode for passphrase generation."""
        # Answers: mode [2], words [3], sep [_]
        inputs = iter(["2", "3", "_"])
        monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))
        exit_code = main(["--interactive"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Generated Passphrase:" in captured.out

    def test_cli_interactive_abort(self, monkeypatch, capsys):
        """Test interactive mode aborts cleanly on KeyboardInterrupt."""
        def mock_input(prompt=""):
            raise KeyboardInterrupt()

        monkeypatch.setattr("builtins.input", mock_input)
        exit_code = main(["-i"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Aborted." in captured.out

