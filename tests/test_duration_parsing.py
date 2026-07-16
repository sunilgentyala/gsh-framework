"""
tests/test_duration_parsing.py
Governed Security Hunting (GSH) Framework - Tests

Unit tests for parse_duration() in scripts/gsh-sentinel-deploy.py.
Establishes the tests/ directory and testing pattern for the codebase.
"""

import sys
from pathlib import Path

import pytest

# Ensure project root is on sys.path so we can import from scripts/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import importlib.util

# Load the module from scripts/ (hyphenated filename can't be imported directly)
_spec = importlib.util.spec_from_file_location(
    "gsh_sentinel_deploy", Path(__file__).resolve().parent.parent / "scripts" / "gsh-sentinel-deploy.py"
)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)
parse_duration = _module.parse_duration


class TestParseDuration:
    """Table-driven tests for parse_duration()."""

    @pytest.mark.parametrize(
        "duration_str,expected_seconds",
        [
            # Base units
            ("7d", 604800),
            ("24h", 86400),
            ("30m", 1800),
            ("60s", 60),
            # Case insensitivity
            ("7D", 604800),
            ("24H", 86400),
            ("30M", 1800),
            ("60S", 60),
            # Mixed case
            ("7d", 604800),
            ("24h", 86400),
            ("30m", 1800),
            ("60s", 60),
            # Whitespace handling
            ("  7d  ", 604800),
            ("\t24h\n", 86400),
        ],
    )
    def test_valid_durations(self, duration_str, expected_seconds):
        """Valid duration strings parse to the correct number of seconds."""
        assert parse_duration(duration_str) == expected_seconds

    @pytest.mark.parametrize(
        "invalid_input",
        [
            # Missing unit suffix
            "7",
            "24",
            "30",
            "60",
            # Invalid unit suffix
            "7x",
            "24z",
            "30q",
            "60w",
            # Non-numeric prefix
            "abc",
            "xyz",
            # Empty / whitespace-only
            "",
            "   ",
            "\t\n",
        ],
    )
    def test_invalid_durations_raise_valueerror(self, invalid_input):
        """Invalid inputs raise ValueError with the expected message format."""
        with pytest.raises(ValueError, match=r"Invalid duration format:"):
            parse_duration(invalid_input)

    def test_empty_string_raises_valueerror_not_indexerror(self):
        """Empty string must raise ValueError, not IndexError (regression test)."""
        with pytest.raises(ValueError, match=r"Invalid duration format:"):
            parse_duration("")

    def test_whitespace_only_raises_valueerror(self):
        """Whitespace-only strings must raise ValueError, not IndexError."""
        with pytest.raises(ValueError, match=r"Invalid duration format:"):
            parse_duration("   ")

    def test_error_message_format(self):
        """Error message matches the documented format exactly."""
        with pytest.raises(ValueError) as exc_info:
            parse_duration("7x")
        assert "Invalid duration format: '7x'" in str(exc_info.value)
        assert "Use formats like 7d, 24h, 30m, 60s." in str(exc_info.value)