"""
feature_engineering.py — Feature extraction for the ML rule optimizer.

Transforms (FirewallRule, traffic_logs) pairs into numeric feature vectors
suitable for gradient boosted tree training.

Features are grouped into three families:

  1. RULE INTRINSIC FEATURES (from the rule's own attributes)
     These capture properties of the rule itself independent of traffic.
     e.g. specificity (a /32 rule is more specific than a /8 rule)

  2. TRAFFIC-DERIVED FEATURES (from matching observed traffic logs)
     These capture how often and how heavily this rule is hit.
     e.g. hit_count, bytes_matched, hit_rate_pct

  3. POSITIONAL FEATURES (from the rule's place in the current ordering)
     These capture the current priority and position within chains.
     e.g. current_priority_rank, rules_before_in_chain

The target label for ranking is: hit_count (higher = should be evaluated sooner)

Usage:
    from ml.feature_engineering import FeatureExtractor
    from ml.traffic_generator import TrafficGenerator
    from parser import RuleParser

    rules  = RuleParser().parse("rules.iptables")
    logs   = TrafficGenerator().generate(10_000)
    X, y, feature_names = FeatureExtractor().extract(rules, logs)
    # X: np.ndarray shape (n_rules, n_features)
    # y: np.ndarray shape (n_rules,) -- hit counts (ranking target)
"""

from __future__ import annotations

import ipaddress
from typing import Optional

import numpy as np

from parser.models import Action, FirewallRule, Protocol
from ml.traffic_generator import TrafficLog


# Port classification buckets
_WEB_PORTS   = {80, 443, 8080, 8443, 3000, 5000}
_DB_PORTS    = {3306, 5432, 1433, 27017, 6379, 9200}
_MGMT_PORTS  = {22, 3389, 5900, 5901, 23}
_DNS_NTP     = {53, 123}
_EMAIL_PORTS = {25, 465, 587, 110, 995, 143, 993}
_FILE_PORTS  = {21, 22, 445, 139, 2049}


def _port_to_int(port_str: Optional[str]) -> int:
    if port_str is None:
        return 0
    if ":" in port_str:
        return int(port_str.split(":")[0])
    return int(port_str)


def _prefix_len(cidr: str) -> int:
    if cidr.startswith("sg:"):
        return 32
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except ValueError:
        return 0


def _specificity_score(rule: FirewallRule) -> float:
    """
    Normalized specificity in [0, 1].
    /32 host + single port + specific protocol = 1.0
    0.0.0.0/0 + any port + any protocol = 0.0
    """
    src_len  = _prefix_len(rule.src_ip) / 32
    dst_len  = _prefix_len(rule.dst_ip) / 32

    if rule.dst_port is None:
        port_spec = 0.0
    elif ":" in str(rule.dst_port):
        lo, hi = (int(x) for x in str(rule.dst_port).split(":"))
        port_spec = 1.0 - ((hi - lo + 1) / 65535)
    else:
        port_spec = 1.0

    proto_spec = 0.0 if rule.protocol == Protocol.ALL else 0.5
    return (src_len + dst_len + port_spec + proto_spec) / 4.0


def _port_category(port: Optional[int]) -> int:
    if port is None:    return 0
    if port in _WEB_PORTS:   return 1
    if port in _DB_PORTS:    return 2
    if port in _MGMT_PORTS:  return 3
    if port in _DNS_NTP:     return 4
    if port in _EMAIL_PORTS: return 5
    if port in _FILE_PORTS:  return 6
    if port == 0:            return 7
    return 8


def _action_int(action: Action) -> int:
    return 1 if action == Action.ALLOW else 0


def _protocol_int(protocol: Protocol) -> int:
    return {Protocol.TCP: 0, Protocol.UDP: 1,
            Protocol.ICMP: 2, Protocol.ALL: 3}.get(protocol, 3)


def _ip_in_cidr(ip: str, cidr: str) -> bool:
    if cidr in ("0.0.0.0/0", "::/0") or cidr.startswith("sg:"):
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _port_in_range(port: int, port_str: Optional[str]) -> bool:
    if port_str is None:
        return True
    if ":" in str(port_str):
        lo, hi = (int(x) for x in str(port_str).split(":"))
        return lo <= port <= hi
    return port == int(port_str)


class FeatureExtractor:
    """
    Converts (rules, traffic_logs) into a feature matrix for ML training.

    For each rule, counts how many traffic logs match under first-match
    semantics, then combines with structural rule properties.
    """

    FEATURE_NAMES = [
        # Traffic-derived (most predictive for hit-rate ranking)
        "hit_count",
        "hit_rate_pct",
        "bytes_matched",
        "avg_bytes_per_hit",
        "allow_hit_count",
        "deny_hit_count",

        # Rule intrinsic
        "specificity_score",
        "src_prefix_len",
        "dst_prefix_len",
        "dst_port_lo",
        "dst_port_hi",
        "port_range_width",
        "port_category",
        "protocol_int",
        "action_int",
        "is_default_deny",
        "is_catch_all_allow",

        # Positional
        "current_priority",
        "priority_rank_normalized",
        "rules_before_in_chain",
    ]

    def extract(
        self,
        rules: list[FirewallRule],
        logs: list[TrafficLog],
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """
        Extract feature matrix X and label vector y.

        Returns:
            X: shape (n_rules, n_features)
            y: shape (n_rules,) -- hit_count as ranking target
            feature_names: list of feature name strings
        """
        sorted_rules = sorted(rules, key=lambda r: r.priority)
        n = len(sorted_rules)
        hit_stats = self._compute_hit_stats(sorted_rules, logs)

        chain_seen: dict[str, int] = {}
        rows = []

        for rank, rule in enumerate(sorted_rules):
            stats    = hit_stats[rule.rule_id]
            chain_key = rule.chain or "default"
            pos_in_chain = chain_seen.get(chain_key, 0)
            chain_seen[chain_key] = pos_in_chain + 1

            hit_count     = stats["hit_count"]
            bytes_matched = stats["bytes_matched"]
            total_logs    = max(len(logs), 1)

            port_lo = _port_to_int(rule.dst_port)
            port_hi = port_lo
            if rule.dst_port and ":" in str(rule.dst_port):
                parts = str(rule.dst_port).split(":")
                port_lo, port_hi = int(parts[0]), int(parts[1])
            port_width = (port_hi - port_lo + 1) if rule.dst_port else 65535

            is_default_deny = int(
                rule.src_ip == "0.0.0.0/0" and
                rule.dst_ip == "0.0.0.0/0" and
                rule.dst_port is None and
                rule.action == Action.DENY
            )
            is_catch_all_allow = int(
                rule.src_ip == "0.0.0.0/0" and
                rule.dst_ip == "0.0.0.0/0" and
                rule.dst_port is None and
                rule.action == Action.ALLOW
            )

            row = [
                float(hit_count),
                float(hit_count) / total_logs * 100,
                float(bytes_matched),
                float(bytes_matched) / max(hit_count, 1),
                float(stats["allow_hits"]),
                float(stats["deny_hits"]),

                _specificity_score(rule),
                float(_prefix_len(rule.src_ip)),
                float(_prefix_len(rule.dst_ip)),
                float(port_lo),
                float(port_hi),
                float(port_width),
                float(_port_category(port_lo if rule.dst_port else None)),
                float(_protocol_int(rule.protocol)),
                float(_action_int(rule.action)),
                float(is_default_deny),
                float(is_catch_all_allow),

                float(rule.priority),
                float(rank) / max(n - 1, 1),
                float(pos_in_chain),
            ]
            rows.append(row)

        X = np.array(rows, dtype=np.float32)
        y = X[:, 0].copy()  # hit_count column
        return X, y, self.FEATURE_NAMES

    def _compute_hit_stats(
        self,
        rules: list[FirewallRule],
        logs: list[TrafficLog],
    ) -> dict[str, dict]:
        """
        First-match simulation: for each packet, walk rules until first match.
        Increment that rule's hit count.
        """
        stats = {
            rule.rule_id: {
                "hit_count": 0, "bytes_matched": 0,
                "allow_hits": 0, "deny_hits": 0,
            }
            for rule in rules
        }

        for log in logs:
            for rule in rules:
                if self._matches(rule, log):
                    s = stats[rule.rule_id]
                    s["hit_count"]     += 1
                    s["bytes_matched"] += log.bytes_
                    if rule.action == Action.ALLOW:
                        s["allow_hits"] += 1
                    else:
                        s["deny_hits"]  += 1
                    break  # first-match semantics

        return stats

    @staticmethod
    def _matches(rule: FirewallRule, log: TrafficLog) -> bool:
        if rule.protocol != Protocol.ALL:
            if rule.protocol.value != log.protocol:
                return False
        if not _ip_in_cidr(log.src_ip, rule.src_ip):
            return False
        if not _ip_in_cidr(log.dst_ip, rule.dst_ip):
            return False
        if not _port_in_range(log.dst_port, rule.dst_port):
            return False
        return True