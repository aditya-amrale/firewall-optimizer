"""
models.py — Unified FirewallRule dataclass
All parsers normalize their native format into this single representation.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import ipaddress


class Action(str, Enum):
    ALLOW  = "ALLOW"
    DENY   = "DENY"
    DROP   = "DROP"
    LOG    = "LOG"
    REJECT = "REJECT"


class Protocol(str, Enum):
    TCP  = "tcp"
    UDP  = "udp"
    ICMP = "icmp"
    ALL  = "all"


@dataclass
class FirewallRule:
    """
    Normalized representation of a single firewall rule.

    Every parser must produce a list of FirewallRule objects so the
    analysis engine can work format-agnostically.
    """

    # Identity
    rule_id:     str            # Unique ID (generated or from source)
    source:      str            # Parser that produced this rule
    priority:    int            # Lower = evaluated first (0 = highest)
    line_number: Optional[int]  # Original line/index in source file

    # Match conditions
    src_ip:   str = "0.0.0.0/0"   # CIDR notation; "0.0.0.0/0" = any
    dst_ip:   str = "0.0.0.0/0"
    src_port: Optional[str] = None  # "80", "1024:65535", or None (any)
    dst_port: Optional[str] = None
    protocol: Protocol = Protocol.ALL

    # Decision
    action: Action = Action.DENY

    # Metadata
    comment:    Optional[str] = None
    chain:      Optional[str] = None   # iptables chain / AWS SG direction
    interface:  Optional[str] = None   # Inbound interface (if specified)
    tags:       list = field(default_factory=list)  # e.g. ["legacy", "auto-generated"]
    raw:        Optional[str] = None   # Original unparsed string (for debugging)

    # ------------------------------------------------------------------ helpers

    def src_network(self) -> ipaddress.IPv4Network:
        """Return src_ip as an IPv4Network for range comparisons."""
        return ipaddress.ip_network(self.src_ip, strict=False)

    def dst_network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.dst_ip, strict=False)

    def port_range(self, port_str: Optional[str]) -> Optional[tuple[int, int]]:
        """
        Parse a port string into an inclusive (low, high) tuple.
        Accepts: "80"  →  (80, 80)
                 "1024:65535"  →  (1024, 65535)
                 None  →  None  (any port)
        """
        if port_str is None:
            return None
        if ":" in port_str:
            lo, hi = port_str.split(":")
            return int(lo), int(hi)
        return int(port_str), int(port_str)

    def to_dict(self) -> dict:
        return {
            "rule_id":     self.rule_id,
            "source":      self.source,
            "priority":    self.priority,
            "line_number": self.line_number,
            "src_ip":      self.src_ip,
            "dst_ip":      self.dst_ip,
            "src_port":    self.src_port,
            "dst_port":    self.dst_port,
            "protocol":    self.protocol.value,
            "action":      self.action.value,
            "comment":     self.comment,
            "chain":       self.chain,
            "interface":   self.interface,
            "tags":        self.tags,
            "raw":         self.raw,
        }

    def __repr__(self) -> str:
        return (
            f"FirewallRule(id={self.rule_id!r}, "
            f"{self.src_ip}->{self.dst_ip}:{self.dst_port or 'any'} "
            f"[{self.protocol.value}] {self.action.value})"
        )