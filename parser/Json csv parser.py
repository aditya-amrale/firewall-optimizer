"""
json_csv_parser.py — Parse JSON and CSV firewall rule files into FirewallRule objects.

Expected JSON format (list of rule objects):
    [
      {
        "priority": 10,
        "src_ip": "192.168.1.0/24",
        "dst_ip": "0.0.0.0/0",
        "dst_port": "443",
        "protocol": "tcp",
        "action": "ALLOW",
        "comment": "Allow HTTPS outbound"
      },
      ...
    ]

Expected CSV format (header row required):
    priority,src_ip,dst_ip,src_port,dst_port,protocol,action,comment
    10,192.168.1.0/24,0.0.0.0/0,,443,tcp,ALLOW,Allow HTTPS outbound

Usage:
    from parser.json_csv_parser import JsonCsvParser
    rules = JsonCsvParser().parse_file("rules.json")
    rules = JsonCsvParser().parse_file("rules.csv")
"""

import csv
import json
import uuid
from pathlib import Path
from typing import Optional
from .models import Action, FirewallRule, Protocol


# Canonical field names we look for in JSON/CSV. Aliases handle common variations.
_FIELD_ALIASES = {
    "src_ip":   ["src_ip", "source_ip", "source", "from_ip", "src"],
    "dst_ip":   ["dst_ip", "dest_ip", "destination", "destination_ip", "to_ip", "dst"],
    "src_port": ["src_port", "source_port", "sport"],
    "dst_port": ["dst_port", "dest_port", "dport", "port"],
    "protocol": ["protocol", "proto"],
    "action":   ["action", "verdict", "policy", "jump"],
    "priority": ["priority", "order", "seq", "sequence"],
    "comment":  ["comment", "description", "name", "note", "remarks"],
    "chain":    ["chain", "direction", "table"],
}

_ACTION_MAP = {
    "allow":  Action.ALLOW,
    "permit": Action.ALLOW,
    "accept": Action.ALLOW,
    "pass":   Action.ALLOW,
    "deny":   Action.DENY,
    "drop":   Action.DROP,
    "block":  Action.DENY,
    "reject": Action.REJECT,
    "log":    Action.LOG,
}

_PROTO_MAP = {
    "tcp":  Protocol.TCP,
    "udp":  Protocol.UDP,
    "icmp": Protocol.ICMP,
    "any":  Protocol.ALL,
    "all":  Protocol.ALL,
    "-1":   Protocol.ALL,
}


class JsonCsvParser:
    """
    Parses JSON and CSV rule files.

    Field lookup is alias-tolerant: "dest_ip", "destination_ip", and "dst_ip"
    all resolve to dst_ip. Auto-detects format from file extension or content.
    """

    def parse_file(self, filepath: str) -> list[FirewallRule]:
        """Auto-detect JSON or CSV and parse accordingly."""
        path = Path(filepath)
        suffix = path.suffix.lower()

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        if suffix == ".json":
            return self.parse_json(content)
        elif suffix in (".csv", ".tsv"):
            return self.parse_csv(content)
        else:
            # Sniff: if first non-whitespace char is '[' or '{', treat as JSON
            stripped = content.lstrip()
            if stripped.startswith(("[", "{")):
                return self.parse_json(content)
            return self.parse_csv(content)

    def parse_json(self, text: str) -> list[FirewallRule]:
        """Parse a JSON string containing a list of rule dicts."""
        data = json.loads(text)
        if isinstance(data, dict):
            # Support {"rules": [...]} wrapper
            data = data.get("rules", data.get("firewall_rules", [data]))
        if not isinstance(data, list):
            raise ValueError("JSON must contain a list of rule objects at the top level.")

        return [
            self._dict_to_rule(row, idx)
            for idx, row in enumerate(data)
        ]

    def parse_csv(self, text: str) -> list[FirewallRule]:
        """Parse a CSV string into FirewallRule objects."""
        reader = csv.DictReader(text.splitlines())
        # Normalize header keys (lowercase + strip whitespace)
        rows = []
        for row in reader:
            normalized = {k.strip().lower(): v.strip() for k, v in row.items()}
            rows.append(normalized)

        return [self._dict_to_rule(row, idx) for idx, row in enumerate(rows)]

    # ------------------------------------------------------------------ helpers

    def _dict_to_rule(self, row: dict, idx: int) -> FirewallRule:
        """Convert a normalized dict (from JSON or CSV) to a FirewallRule."""
        get = lambda field: self._resolve(row, field)

        priority_raw = get("priority")
        try:
            priority = int(priority_raw) if priority_raw else idx
        except (ValueError, TypeError):
            priority = idx

        action_raw = (get("action") or "deny").lower()
        action = _ACTION_MAP.get(action_raw, Action.DENY)

        proto_raw = (get("protocol") or "all").lower()
        protocol = _PROTO_MAP.get(proto_raw, Protocol.ALL)

        # Normalize empty string → None for optional fields
        def opt(v): return v if v else None

        return FirewallRule(
            rule_id     = f"jscsv-{uuid.uuid4().hex[:8]}",
            source      = "json_csv",
            priority    = priority,
            line_number = idx + 1,
            src_ip      = get("src_ip")  or "0.0.0.0/0",
            dst_ip      = get("dst_ip")  or "0.0.0.0/0",
            src_port    = opt(get("src_port")),
            dst_port    = opt(get("dst_port")),
            protocol    = protocol,
            action      = action,
            chain       = opt(get("chain")),
            comment     = opt(get("comment")),
            raw         = json.dumps(row),
        )

    def _resolve(self, row: dict, canonical: str) -> Optional[str]:
        """
        Look up a canonical field in a row dict, trying all known aliases.
        Returns the first matching value, or None.
        """
        for alias in _FIELD_ALIASES.get(canonical, [canonical]):
            val = row.get(alias)
            if val is not None and val != "":
                return str(val)
        return None