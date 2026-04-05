"""
parser_facade.py — Universal entry point. Auto-detects format and routes to the right parser.

Usage:
    from parser.parser_facade import RuleParser

    # Auto-detect by extension / content
    rules = RuleParser().parse("rules.iptables")
    rules = RuleParser().parse("acl_config.txt")
    rules = RuleParser().parse("sg_export.json")
    rules = RuleParser().parse("rules.csv")

    # Explicit format
    rules = RuleParser().parse("config.txt", format="cisco")
"""

from pathlib import Path
from typing import Optional
from .models import FirewallRule
from .iptables_parser import IptablesParser
from .json_csv_parser import JsonCsvParser
from .cisco_acl_parser import CiscoACLParser
from .aws_sg_parser import AWSSGParser


class ParseError(Exception):
    pass


class RuleParser:
    """
    Auto-detecting parser facade.

    Detection order:
      1. Explicit `format` argument
      2. File extension (.iptables, .ipt, .json, .csv, .tsv, .txt)
      3. Content sniffing (JSON brace, iptables -A keyword, Cisco 'access-list')
    """

    _PARSERS = {
        "iptables": IptablesParser,
        "json":     JsonCsvParser,
        "csv":      JsonCsvParser,
        "cisco":    CiscoACLParser,
        "aws":      AWSSGParser,
    }

    _EXT_MAP = {
        ".iptables": "iptables",
        ".ipt":      "iptables",
        ".nft":      "iptables",   # Close enough for MVP
        ".json":     "json",
        ".csv":      "csv",
        ".tsv":      "csv",
    }

    def parse(self, filepath: str, format: Optional[str] = None) -> list[FirewallRule]:
        """
        Parse a rule file into a list of FirewallRule objects.

        Args:
            filepath: Path to the rule file.
            format:   One of 'iptables', 'json', 'csv', 'cisco', 'aws'.
                      Leave None to auto-detect.

        Returns:
            List of FirewallRule objects.

        Raises:
            ParseError: If the format cannot be determined or parsing fails.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {filepath}")

        detected = format or self._detect_format(path)
        if detected not in self._PARSERS:
            raise ParseError(
                f"Unknown format {detected!r}. "
                f"Supported: {list(self._PARSERS.keys())}"
            )

        parser_cls = self._PARSERS[detected]
        try:
            rules = parser_cls().parse_file(filepath)
        except Exception as e:
            raise ParseError(f"Failed to parse {filepath} as {detected!r}: {e}") from e

        return rules

    def parse_text(self, text: str, format: str) -> list[FirewallRule]:
        """Parse a raw text string with an explicit format."""
        if format not in self._PARSERS:
            raise ParseError(f"Unknown format: {format!r}")
        parser = self._PARSERS[format]()
        if hasattr(parser, "parse_text"):
            return parser.parse_text(text)
        raise ParseError(f"Parser {format!r} does not support parse_text()")

    # ------------------------------------------------------------------ helpers

    def _detect_format(self, path: Path) -> str:
        ext = path.suffix.lower()

        # Try extension map first
        if ext in self._EXT_MAP:
            return self._EXT_MAP[ext]

        # Sniff file content for .txt and extension-less files
        try:
            with open(path, "r", errors="replace") as f:
                head = f.read(2048)
        except OSError:
            raise ParseError(f"Cannot read file: {path}")

        stripped = head.lstrip()

        # JSON: starts with { or [
        if stripped.startswith(("{", "[")):
            # Distinguish AWS SG JSON from generic JSON rule list
            if '"SecurityGroups"' in head or '"IpPermissions"' in head:
                return "aws"
            return "json"

        # iptables-save: contains -A chain lines
        if re.search(r"^-A\s+\w+", head, re.MULTILINE):
            return "iptables"

        # Cisco ACL: contains 'access-list' or 'ip access-list'
        if re.search(r"^(ip\s+)?access-list", head, re.MULTILINE | re.IGNORECASE):
            return "cisco"

        # CSV: first line has comma-separated headers
        first_line = head.split("\n")[0]
        if first_line.count(",") >= 3:
            return "csv"

        raise ParseError(
            f"Cannot auto-detect format for {path.name}. "
            "Use the `format` argument to specify one of: "
            f"{list(self._PARSERS.keys())}"
        )


import re  # noqa: E402  (needs to be available for _detect_format)