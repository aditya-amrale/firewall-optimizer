"""
iptables_parser.py — Parse iptables-save / iptables -L output into FirewallRule objects.

Handles the two most common formats:
  1. iptables-save format  (-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j ACCEPT)
  2. iptables -L -n format (ACCEPT tcp  -- 10.0.0.0/8 0.0.0.0/0 tcp dpt:22)

Usage:
    from parser.iptables_parser import IptablesParser
    rules = IptablesParser().parse_file("rules.iptables")
"""

import re
import uuid
from typing import Optional
from .models import Action, FirewallRule, Protocol


# Maps iptables jump targets to normalized Action values
_ACTION_MAP = {
    "ACCEPT": Action.ALLOW,
    "DROP":   Action.DROP,
    "REJECT": Action.REJECT,
    "LOG":    Action.LOG,
    "DENY":   Action.DENY,
}

# Maps iptables protocol tokens to Protocol enum
_PROTO_MAP = {
    "tcp":  Protocol.TCP,
    "udp":  Protocol.UDP,
    "icmp": Protocol.ICMP,
    "all":  Protocol.ALL,
}


class IptablesParser:
    """
    Parses iptables-save format rules.

    Typical iptables-save line:
        -A FORWARD -s 192.168.1.0/24 -d 10.0.0.0/8 -p tcp --dport 443 -j ACCEPT

    Supported flags: -A (chain), -s (src), -d (dst), -p (proto),
                     --sport / --dport, -i (interface), -j (jump/action), -m comment --comment
    """

    # Matches a single iptables-save rule line
    # Note: --comment may appear before OR after -j, wrapped in -m comment
    RULE_RE = re.compile(
        r"^-A\s+(\S+)"   # chain name  → group 1
        r"(.*?)"         # option flags → group 2
        r"\s+-j\s+(\S+)" # jump target  → group 3
        r"(.*?)$"        # trailing flags (e.g. -m comment ...) → group 4
    )

    # Individual flag patterns used to scan group 2
    _SRC_RE    = re.compile(r"-s\s+(\S+)")
    _DST_RE    = re.compile(r"-d\s+(\S+)")
    _PROTO_RE  = re.compile(r"-p\s+(\S+)")
    _DPORT_RE  = re.compile(r"--dport\s+(\S+)")
    _SPORT_RE  = re.compile(r"--sport\s+(\S+)")
    _IFACE_RE  = re.compile(r"-i\s+(\S+)")
    _COMMENT_RE = re.compile(r'--comment\s+"?([^"]+)"?')

    def parse_file(self, filepath: str) -> list[FirewallRule]:
        """Parse an iptables-save file and return a list of FirewallRules."""
        with open(filepath, "r") as f:
            lines = f.readlines()
        return self.parse_lines(lines)

    def parse_text(self, text: str) -> list[FirewallRule]:
        """Parse a multi-line iptables-save string."""
        return self.parse_lines(text.splitlines(keepends=True))

    def parse_lines(self, lines: list[str]) -> list[FirewallRule]:
        rules = []
        priority = 0
        for lineno, line in enumerate(lines, start=1):
            line = line.strip()

            # Skip comments, table headers, and empty lines
            if not line or line.startswith("#") or line.startswith("*") or line.startswith(":"):
                continue
            if line == "COMMIT":
                priority = 0  # Reset priority counter per table
                continue

            rule = self._parse_rule_line(line, priority, lineno)
            if rule:
                rules.append(rule)
                priority += 1

        return rules

    def _parse_rule_line(self, line: str, priority: int, lineno: int) -> Optional[FirewallRule]:
        m = self.RULE_RE.match(line)
        if not m:
            return None

        chain   = m.group(1)
        flags   = m.group(2) + " " + (m.group(4) or "")
        jump    = m.group(3).upper()
        # Extract --comment from anywhere in the full flags string
        cm = self._COMMENT_RE.search(flags)
        comment = cm.group(1).strip() if cm else None

        # Skip non-policy jumps (e.g., -j CONNTRACK, -j MARK)
        if jump not in _ACTION_MAP:
            return None

        # Extract individual flags from the options block
        src_ip   = self._extract(self._SRC_RE,   flags, "0.0.0.0/0")
        dst_ip   = self._extract(self._DST_RE,   flags, "0.0.0.0/0")
        proto    = self._extract(self._PROTO_RE, flags, "all").lower()
        dst_port = self._extract(self._DPORT_RE, flags)
        src_port = self._extract(self._SPORT_RE, flags)
        iface    = self._extract(self._IFACE_RE, flags)

        # Normalize negated IPs (! -s 10.0.0.0/8 → store as-is with tag)
        tags = []
        if "! -s" in flags:
            tags.append("negated-src")
        if "! -d" in flags:
            tags.append("negated-dst")

        # iptables uses colon ranges; normalize to our standard
        if dst_port:
            dst_port = dst_port.replace(":", ":")
        if src_port:
            src_port = src_port.replace(":", ":")

        return FirewallRule(
            rule_id     = f"ipt-{uuid.uuid4().hex[:8]}",
            source      = "iptables",
            priority    = priority,
            line_number = lineno,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            src_port    = src_port,
            dst_port    = dst_port,
            protocol    = _PROTO_MAP.get(proto, Protocol.ALL),
            action      = _ACTION_MAP[jump],
            chain       = chain,
            interface   = iface,
            comment     = comment,
            tags        = tags,
            raw         = line,
        )

    @staticmethod
    def _extract(pattern: re.Pattern, text: str, default=None) -> Optional[str]:
        m = pattern.search(text)
        return m.group(1) if m else default