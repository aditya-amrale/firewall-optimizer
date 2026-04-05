"""
cisco_acl_parser.py — Parse Cisco IOS/IOS-XE Access Control List configs.

Supports both standard and extended ACLs:

  Standard ACL (named):
    ip access-list standard BLOCK_RFC1918
      deny   10.0.0.0 0.255.255.255
      permit any

  Extended ACL (numbered):
    access-list 101 permit tcp 192.168.1.0 0.0.0.255 any eq 443
    access-list 101 deny   ip any any

  Extended ACL (named):
    ip access-list extended OUTSIDE_IN
      permit tcp host 203.0.113.5 any eq 80
      permit udp any any eq 53
      deny   ip any any log

Usage:
    from parser.cisco_acl_parser import CiscoACLParser
    rules = CiscoACLParser().parse_file("acl.txt")
"""

import re
import uuid
from typing import Optional
from .models import Action, FirewallRule, Protocol


_ACTION_MAP = {
    "permit": Action.ALLOW,
    "allow":  Action.ALLOW,
    "deny":   Action.DENY,
}

_PROTO_MAP = {
    "tcp":  Protocol.TCP,
    "udp":  Protocol.UDP,
    "icmp": Protocol.ICMP,
    "ip":   Protocol.ALL,
    "any":  Protocol.ALL,
}

# Cisco wildcard mask → CIDR prefix length conversion
def _wildcard_to_cidr(ip: str, wildcard: str) -> str:
    """
    Convert a Cisco wildcard mask to CIDR notation.
    e.g. 192.168.1.0 / 0.0.0.255  →  192.168.1.0/24
    """
    wild_octets = [int(x) for x in wildcard.split(".")]
    prefix_len = sum(bin(255 - o).count("1") for o in wild_octets)
    return f"{ip}/{prefix_len}"


def _parse_address(tokens: list[str], pos: int) -> tuple[str, int]:
    """
    Parse a Cisco address specification starting at tokens[pos].
    Returns (cidr_string, new_pos).

    Handles:
      any               → 0.0.0.0/0
      host <ip>         → <ip>/32
      <ip> <wildcard>   → CIDR notation
    """
    token = tokens[pos].lower()

    if token == "any":
        return "0.0.0.0/0", pos + 1

    if token == "host":
        return f"{tokens[pos + 1]}/32", pos + 2

    # Must be <ip> <wildcard>
    ip       = tokens[pos]
    wildcard = tokens[pos + 1]
    return _wildcard_to_cidr(ip, wildcard), pos + 2


def _parse_port(tokens: list[str], pos: int) -> tuple[Optional[str], int]:
    """
    Parse an optional port specifier starting at tokens[pos].
    Returns (port_string_or_None, new_pos).

    Handles:
      eq <port>            → "80"
      range <lo> <hi>      → "lo:hi"
      lt <port>            → "0:<port-1>"
      gt <port>            → "<port+1>:65535"
      neq <port>           → None  (complex; skip with tag)
    """
    if pos >= len(tokens):
        return None, pos

    op = tokens[pos].lower()

    if op == "eq":
        return tokens[pos + 1], pos + 2
    if op == "range":
        return f"{tokens[pos + 1]}:{tokens[pos + 2]}", pos + 3
    if op == "lt":
        val = int(tokens[pos + 1])
        return f"0:{val - 1}", pos + 2
    if op == "gt":
        val = int(tokens[pos + 1])
        return f"{val + 1}:65535", pos + 2

    # Not a port specifier; don't consume any tokens
    return None, pos


class CiscoACLParser:
    """
    Parses Cisco IOS / IOS-XE ACL configuration blocks into FirewallRule objects.
    """

    # Named ACL header: "ip access-list extended|standard <name>"
    NAMED_HEADER_RE = re.compile(
        r"^ip\s+access-list\s+(extended|standard)\s+(\S+)", re.IGNORECASE
    )
    # Numbered ACL: "access-list <num> permit|deny ..."
    NUMBERED_RE = re.compile(
        r"^access-list\s+(\d+)\s+(permit|deny)\s+(.*)", re.IGNORECASE
    )
    # Remark / comment line inside a named ACL block
    REMARK_RE = re.compile(r"^\s*remark\s+(.*)", re.IGNORECASE)
    # ACE entry inside a named ACL block (leading whitespace)
    ACE_RE = re.compile(r"^\s+(permit|deny)\s+(.*)", re.IGNORECASE)

    def parse_file(self, filepath: str) -> list[FirewallRule]:
        with open(filepath, "r") as f:
            return self.parse_text(f.read())

    def parse_text(self, text: str) -> list[FirewallRule]:
        lines = text.splitlines()
        rules: list[FirewallRule] = []
        priority = 0

        current_acl_name: Optional[str] = None
        current_acl_type: Optional[str] = None  # "standard" | "extended"
        last_remark: Optional[str] = None

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue

            # Named ACL header
            hdr = self.NAMED_HEADER_RE.match(stripped)
            if hdr:
                current_acl_type = hdr.group(1).lower()
                current_acl_name = hdr.group(2)
                last_remark = None
                continue

            # Remark inside named block
            rem = self.REMARK_RE.match(line)
            if rem and current_acl_name:
                last_remark = rem.group(1).strip()
                continue

            # ACE inside named block
            ace = self.ACE_RE.match(line)
            if ace and current_acl_name:
                action_str = ace.group(1)
                rest       = ace.group(2)
                rule = self._parse_extended_ace(
                    action_str, rest, priority, lineno,
                    chain=current_acl_name,
                    comment=last_remark,
                    acl_type=current_acl_type or "extended",
                )
                if rule:
                    rules.append(rule)
                    priority += 1
                last_remark = None
                continue

            # Numbered ACL
            num = self.NUMBERED_RE.match(stripped)
            if num:
                acl_num    = num.group(1)
                action_str = num.group(2)
                rest       = num.group(3)
                # Standard ACLs (1-99, 1300-1999) match source IP only
                acl_number = int(acl_num)
                acl_type = "standard" if (1 <= acl_number <= 99 or
                                          1300 <= acl_number <= 1999) else "extended"
                rule = self._parse_extended_ace(
                    action_str, rest, priority, lineno,
                    chain=f"acl-{acl_num}",
                    acl_type=acl_type,
                )
                if rule:
                    rules.append(rule)
                    priority += 1
                continue

            # Any line without indentation breaks out of a named ACL block
            if not line.startswith(" "):
                current_acl_name = None
                current_acl_type = None

        return rules

    def _parse_extended_ace(
        self,
        action_str: str,
        rest: str,
        priority: int,
        lineno: int,
        chain: Optional[str] = None,
        comment: Optional[str] = None,
        acl_type: str = "extended",
    ) -> Optional[FirewallRule]:
        """
        Parse the action + rest-of-line portion of an ACE into a FirewallRule.
        """
        action = _ACTION_MAP.get(action_str.lower(), Action.DENY)
        tokens = rest.split()

        if not tokens:
            return None

        tags = []
        # Check for log keyword (last token)
        if tokens and tokens[-1].lower() == "log":
            tags.append("logged")
            tokens = tokens[:-1]

        pos = 0

        # Standard ACL lines have no protocol — go straight to source address
        if acl_type == "standard":
            try:
                src_ip, pos = _parse_address(tokens, pos)
            except IndexError:
                return None
            return FirewallRule(
                rule_id     = f"cisco-{uuid.uuid4().hex[:8]}",
                source      = "cisco_acl",
                priority    = priority,
                line_number = lineno,
                src_ip      = src_ip,
                dst_ip      = "0.0.0.0/0",
                protocol    = Protocol.ALL,
                action      = action,
                chain       = chain,
                comment     = comment,
                tags        = tags,
                raw         = f"{action_str} {rest}",
            )

        # --- Protocol (extended ACL only) ---
        proto_raw = tokens[pos].lower()
        protocol  = _PROTO_MAP.get(proto_raw, Protocol.ALL)
        pos += 1

        # --- Extended ACL: src addr [src port] dst addr [dst port] ---
        try:
            src_ip, pos = _parse_address(tokens, pos)
            src_port, pos = _parse_port(tokens, pos)
            dst_ip, pos = _parse_address(tokens, pos)
            dst_port, pos = _parse_port(tokens, pos)
        except IndexError:
            # Malformed line — return what we have
            return None

        return FirewallRule(
            rule_id     = f"cisco-{uuid.uuid4().hex[:8]}",
            source      = "cisco_acl",
            priority    = priority,
            line_number = lineno,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            src_port    = src_port,
            dst_port    = dst_port,
            protocol    = protocol,
            action      = action,
            chain       = chain,
            comment     = comment,
            tags        = tags,
            raw         = f"{action_str} {rest}",
        )