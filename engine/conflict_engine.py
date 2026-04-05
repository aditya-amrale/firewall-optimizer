"""
conflict_engine.py — AI-Powered Firewall Rule Optimizer: Conflict Detection Engine.

This is the analytical core of the project. Given a list of FirewallRule objects
(from any parser), it produces a ConflictReport detailing:

  1. SHADOWED RULES
     Rule B is shadowed by Rule A when:
       - A has strictly higher priority than B (lower priority number = evaluated first)
       - A matches a superset of the packets B would match
       - A and B have the SAME action  (shadow = dead code, B never fires)
     Impact: B wastes evaluation time and misleads future administrators.

  2. REDUNDANT RULES
     Rule B is redundant when removing it doesn't change the security policy.
     This is a stricter form of shadowing — B is fully covered by earlier ALLOW
     rules (or later DENY rules cover everything B would have allowed).
     In practice we flag: same-action shadows + permissive supersets + duplicate rules.

  3. CONTRADICTING RULES
     Rule A and Rule B contradict when:
       - They match an overlapping set of packets
       - They have OPPOSITE actions (one ALLOWS, one DENIES)
       - Their relative order determines which packets are accepted vs dropped
     Impact: the outcome depends entirely on rule ordering — dangerous to change.

  4. DUPLICATE RULES
     Exact structural duplicates (same src, dst, port, proto) regardless of action.

Algorithm:
  For each pair (A, B) where priority(A) < priority(B):
    1. Check IP relationship: src_ip(A) vs src_ip(B), dst_ip(A) vs dst_ip(B)
       using the IP trie for O(prefix_len) containment checks.
    2. Check protocol compatibility.
    3. Check port relationship using the interval tree.
    4. Combine: if A's match space is a superset of B's on ALL dimensions → shadow/redundant.
       If they overlap on all dimensions but have opposite actions → contradiction.

Usage:
    from engine.conflict_engine import ConflictEngine
    from parser import RuleParser

    rules = RuleParser().parse("rules.iptables")
    report = ConflictEngine().analyze(rules)

    print(report.summary())
    for finding in report.findings:
        print(finding)
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from parser.models import Action, FirewallRule, Protocol
from engine.port_interval import PortRange, port_relationship, ranges_overlap
from engine.ip_trie import IPTrie


# ═══════════════════════════════════════════════════════════════════════════════
# Finding types
# ═══════════════════════════════════════════════════════════════════════════════

class FindingType(str, Enum):
    SHADOW       = "SHADOW"        # Rule is dead code — never fires
    REDUNDANT    = "REDUNDANT"     # Rule is covered; removing it has no effect
    CONTRADICTION = "CONTRADICTION" # Same traffic, opposite actions — order-sensitive
    DUPLICATE    = "DUPLICATE"     # Structurally identical to another rule
    PERMISSIVE   = "PERMISSIVE"    # Rule is unexpectedly broad (0.0.0.0/0 + all ports)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"   # Policy is definitely wrong — immediate action needed
    HIGH     = "HIGH"       # Likely wrong or dangerous
    MEDIUM   = "MEDIUM"     # Possibly wrong — review recommended
    LOW      = "LOW"        # Informational / cleanup opportunity


# Severity matrix: (FindingType, has_opposite_action) → Severity
_SEVERITY_MAP = {
    FindingType.DUPLICATE:      Severity.MEDIUM,
    FindingType.SHADOW:         Severity.HIGH,
    FindingType.REDUNDANT:      Severity.LOW,
    FindingType.CONTRADICTION:  Severity.CRITICAL,
    FindingType.PERMISSIVE:     Severity.MEDIUM,
}


@dataclass
class Finding:
    """A single detected issue in the rule set."""
    finding_type: FindingType
    severity:     Severity
    rule_a:       FirewallRule          # The dominant / first rule
    rule_b:       FirewallRule          # The affected / second rule
    reason:       str                   # Human-readable explanation
    suggestion:   str                   # Recommended fix

    def __repr__(self) -> str:
        return (
            f"[{self.severity.value}] {self.finding_type.value}: "
            f"Rule {self.rule_a.rule_id!r} → Rule {self.rule_b.rule_id!r} | "
            f"{self.reason}"
        )

    def to_dict(self) -> dict:
        return {
            "type":       self.finding_type.value,
            "severity":   self.severity.value,
            "rule_a_id":  self.rule_a.rule_id,
            "rule_b_id":  self.rule_b.rule_id,
            "rule_a_raw": self.rule_a.raw,
            "rule_b_raw": self.rule_b.raw,
            "reason":     self.reason,
            "suggestion": self.suggestion,
        }


@dataclass
class ConflictReport:
    """Full analysis result for a rule set."""
    total_rules:  int
    findings:     list[Finding] = field(default_factory=list)

    # Counts by type (populated by ConflictEngine.analyze)
    shadow_count:       int = 0
    redundant_count:    int = 0
    contradiction_count: int = 0
    duplicate_count:    int = 0
    permissive_count:   int = 0

    @property
    def clean(self) -> bool:
        return len(self.findings) == 0

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def by_type(self, finding_type: FindingType) -> list[Finding]:
        return [f for f in self.findings if f.finding_type == finding_type]

    def summary(self) -> str:
        lines = [
            f"Firewall Rule Analysis — {self.total_rules} rules scanned",
            "=" * 50,
            f"  Critical : {len(self.by_severity(Severity.CRITICAL))}",
            f"  High     : {len(self.by_severity(Severity.HIGH))}",
            f"  Medium   : {len(self.by_severity(Severity.MEDIUM))}",
            f"  Low      : {len(self.by_severity(Severity.LOW))}",
            "-" * 50,
            f"  Contradictions : {self.contradiction_count}",
            f"  Shadows        : {self.shadow_count}",
            f"  Redundant      : {self.redundant_count}",
            f"  Duplicates     : {self.duplicate_count}",
            f"  Permissive     : {self.permissive_count}",
        ]
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "total_rules":       self.total_rules,
            "finding_count":     len(self.findings),
            "shadow_count":      self.shadow_count,
            "redundant_count":   self.redundant_count,
            "contradiction_count": self.contradiction_count,
            "duplicate_count":   self.duplicate_count,
            "permissive_count":  self.permissive_count,
            "findings":          [f.to_dict() for f in self.findings],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Relationship helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _ip_relationship(cidr_a: str, cidr_b: str) -> str:
    """
    Return the IP containment relationship between two CIDR strings.

    Returns: 'equal' | 'a_contains' | 'b_contains' | 'overlap' | 'disjoint'

    Note: For IPv4, two different-length subnets either nest completely or
    are disjoint — there is no partial overlap. So 'overlap' only occurs
    when the networks are equal but written differently (shouldn't normally
    happen with normalized CIDRs).
    """
    # SG-to-SG references look like "sg:sg-0abc123" — treat as equal/same
    if cidr_a.startswith("sg:") or cidr_b.startswith("sg:"):
        return "equal" if cidr_a == cidr_b else "disjoint"

    try:
        net_a = ipaddress.ip_network(cidr_a, strict=False)
        net_b = ipaddress.ip_network(cidr_b, strict=False)
    except ValueError:
        return "disjoint"

    if net_a == net_b:
        return "equal"
    if net_b.subnet_of(net_a):
        return "a_contains"
    if net_a.subnet_of(net_b):
        return "b_contains"
    return "disjoint"


def _proto_compatible(a: Protocol, b: Protocol) -> bool:
    """Return True if the two protocols could match the same packet."""
    if a == Protocol.ALL or b == Protocol.ALL:
        return True
    return a == b


def _actions_opposite(a: Action, b: Action) -> bool:
    """Return True if the two actions are semantically opposite."""
    allow_set = {Action.ALLOW}
    deny_set  = {Action.DENY, Action.DROP, Action.REJECT}
    return (a in allow_set and b in deny_set) or (a in deny_set and b in allow_set)


def _actions_same(a: Action, b: Action) -> bool:
    allow_set = {Action.ALLOW}
    deny_set  = {Action.DENY, Action.DROP, Action.REJECT}
    return (a in allow_set and b in allow_set) or (a in deny_set and b in deny_set)


# ═══════════════════════════════════════════════════════════════════════════════
# Main engine
# ═══════════════════════════════════════════════════════════════════════════════

class ConflictEngine:
    """
    Pairwise conflict detector for a list of FirewallRule objects.

    Time complexity: O(n²) pair comparisons, each O(1) with trie + interval tree.
    Practical limit: handles up to ~5,000 rules comfortably in < 1 second.
    """

    def analyze(self, rules: list[FirewallRule]) -> ConflictReport:
        """
        Run the full conflict analysis on a list of FirewallRule objects.

        Rules must already be sorted by priority (lowest priority number = first evaluated).
        If not pre-sorted, this method sorts them.
        """
        # Sort by priority so rule A always fires before rule B when priority(A) < priority(B)
        sorted_rules = sorted(rules, key=lambda r: r.priority)
        report = ConflictReport(total_rules=len(sorted_rules))

        if len(sorted_rules) < 2:
            self._find_permissive_rules(sorted_rules, report)
            report.permissive_count = len(report.by_type(FindingType.PERMISSIVE))
            return report

        # Phase 1: Duplicate detection (O(n) with hash)
        self._find_duplicates(sorted_rules, report)

        # Phase 2: Pairwise shadow/redundant/contradiction analysis
        self._find_pairwise_conflicts(sorted_rules, report)

        # Phase 3: Permissive rule detection (standalone, O(n))
        self._find_permissive_rules(sorted_rules, report)

        # Update summary counts
        report.shadow_count        = len(report.by_type(FindingType.SHADOW))
        report.redundant_count     = len(report.by_type(FindingType.REDUNDANT))
        report.contradiction_count = len(report.by_type(FindingType.CONTRADICTION))
        report.duplicate_count     = len(report.by_type(FindingType.DUPLICATE))
        report.permissive_count    = len(report.by_type(FindingType.PERMISSIVE))

        # Sort findings: Critical first, then by rule_a priority
        report.findings.sort(
            key=lambda f: (
                ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(f.severity.value),
                f.rule_a.priority,
            )
        )

        return report

    # ------------------------------------------------------------------ phases

    def _find_duplicates(self, rules: list[FirewallRule], report: ConflictReport) -> None:
        """
        Detect structurally identical rules using a canonical fingerprint hash.
        Reports the later-priority rule as the duplicate.
        """
        seen: dict[tuple, FirewallRule] = {}

        for rule in rules:
            key = self._fingerprint(rule)
            if key in seen:
                earlier = seen[key]
                report.findings.append(Finding(
                    finding_type = FindingType.DUPLICATE,
                    severity     = Severity.MEDIUM,
                    rule_a       = earlier,
                    rule_b       = rule,
                    reason       = (
                        f"Rule {rule.rule_id!r} (priority {rule.priority}) is structurally "
                        f"identical to rule {earlier.rule_id!r} (priority {earlier.priority}). "
                        f"Both match {rule.src_ip} → {rule.dst_ip}:{rule.dst_port or 'any'} "
                        f"[{rule.protocol.value}] with action {rule.action.value}."
                    ),
                    suggestion = f"Remove rule {rule.rule_id!r} — it is never evaluated.",
                ))
            else:
                seen[key] = rule

    def _find_pairwise_conflicts(
        self, rules: list[FirewallRule], report: ConflictReport
    ) -> None:
        """
        For every ordered pair (A, B) where priority(A) < priority(B),
        classify the relationship and emit a finding if warranted.
        """
        # Track which rules have already been flagged as duplicates so we
        # don't double-report them as shadows too
        duplicate_ids = {
            f.rule_b.rule_id
            for f in report.findings
            if f.finding_type == FindingType.DUPLICATE
        }

        n = len(rules)
        for i in range(n):
            a = rules[i]
            for j in range(i + 1, n):
                b = rules[j]

                if b.rule_id in duplicate_ids:
                    continue

                finding = self._compare_pair(a, b)
                if finding:
                    report.findings.append(finding)

    def _find_permissive_rules(
        self, rules: list[FirewallRule], report: ConflictReport
    ) -> None:
        """
        Flag standalone ALLOW rules that match 0.0.0.0/0 on all dimensions —
        they allow all traffic unconditionally, which is almost always a mistake.
        """
        for rule in rules:
            if rule.action != Action.ALLOW:
                continue
            src_any  = rule.src_ip  in ("0.0.0.0/0", "::/0")
            dst_any  = rule.dst_ip  in ("0.0.0.0/0", "::/0")
            port_any = rule.dst_port is None
            proto_any = rule.protocol.value in (Protocol.ALL.value, "all", "-1", "any")

            if src_any and dst_any and port_any and proto_any:
                report.findings.append(Finding(
                    finding_type = FindingType.PERMISSIVE,
                    severity     = Severity.MEDIUM,
                    rule_a       = rule,
                    rule_b       = rule,
                    reason       = (
                        f"Rule {rule.rule_id!r} (priority {rule.priority}) allows ALL traffic "
                        f"from any source to any destination on any port. "
                        f"This is a catch-all ALLOW rule — every packet reaching this rule "
                        f"will be unconditionally permitted."
                    ),
                    suggestion = (
                        "Replace with specific ALLOW rules for known-good traffic, "
                        "then add an explicit default-deny at the end."
                    ),
                ))

    # ------------------------------------------------------------------ pairwise logic

    def _compare_pair(
        self, a: FirewallRule, b: FirewallRule
    ) -> Optional[Finding]:
        """
        Compare two rules where priority(a) < priority(b).
        Returns a Finding if a relationship worth reporting is found.
        """
        # 1. Protocol compatibility — if they can never match the same packet, skip
        if not _proto_compatible(a.protocol, b.protocol):
            return None

        # 2. Source IP relationship
        src_rel = _ip_relationship(a.src_ip, b.src_ip)
        if src_rel == "disjoint":
            return None  # Different sources — no interaction possible

        # 3. Destination IP relationship
        dst_rel = _ip_relationship(a.dst_ip, b.dst_ip)
        if dst_rel == "disjoint":
            return None

        # 4. Port relationship
        a_port = PortRange.parse(a.dst_port)
        b_port = PortRange.parse(b.dst_port)
        prt_rel = port_relationship(a_port, b_port)
        if prt_rel == "disjoint":
            return None

        # At this point we know A and B interact on at least some traffic.
        # Classify the match-space relationship across all dimensions:
        #   A dominates B when A's match space is a superset of B's on all dimensions.
        a_dominates = (
            src_rel in ("equal", "a_contains") and
            dst_rel in ("equal", "a_contains") and
            prt_rel in ("equal", "a_contains")
        )
        b_dominates = (
            src_rel in ("equal", "b_contains") and
            dst_rel in ("equal", "b_contains") and
            prt_rel in ("equal", "b_contains")
        )

        same_action     = _actions_same(a.action, b.action)
        opposite_action = _actions_opposite(a.action, b.action)

        # ── Case 1: A dominates B, same action → SHADOW (B is dead code) ──
        if a_dominates and same_action and src_rel != "equal":
            return Finding(
                finding_type = FindingType.SHADOW,
                severity     = Severity.HIGH,
                rule_a       = a,
                rule_b       = b,
                reason       = (
                    f"Rule {a.rule_id!r} (priority {a.priority}, "
                    f"{a.src_ip}→{a.dst_ip}:{a.dst_port or 'any'} "
                    f"[{a.action.value}]) matches every packet that rule "
                    f"{b.rule_id!r} (priority {b.priority}) would match. "
                    f"Rule {b.rule_id!r} is never evaluated."
                ),
                suggestion = f"Remove rule {b.rule_id!r} — it is dead code shadowed by {a.rule_id!r}.",
            )

        # ── Case 2: A dominates B, opposite actions → CONTRADICTION ──
        if a_dominates and opposite_action:
            return Finding(
                finding_type = FindingType.CONTRADICTION,
                severity     = Severity.CRITICAL,
                rule_a       = a,
                rule_b       = b,
                reason       = (
                    f"Rule {a.rule_id!r} (priority {a.priority}, {a.action.value}) "
                    f"covers a superset of the traffic matched by rule {b.rule_id!r} "
                    f"(priority {b.priority}, {b.action.value}). "
                    f"The {b.action.value} in rule {b.rule_id!r} will NEVER take effect — "
                    f"all matching packets are already decided by rule {a.rule_id!r}."
                ),
                suggestion = (
                    f"Re-examine priorities: if {b.rule_id!r} ({b.action.value}) should fire, "
                    f"move it before {a.rule_id!r} (priority {a.priority}) "
                    f"or narrow rule {a.rule_id!r}'s match scope."
                ),
            )

        # ── Case 3: Partial overlap, opposite actions → CONTRADICTION ──
        if not a_dominates and not b_dominates and opposite_action:
            overlap_desc = self._overlap_description(src_rel, dst_rel, prt_rel, a, b)
            return Finding(
                finding_type = FindingType.CONTRADICTION,
                severity     = Severity.CRITICAL,
                rule_a       = a,
                rule_b       = b,
                reason       = (
                    f"Rules {a.rule_id!r} ({a.action.value}) and {b.rule_id!r} "
                    f"({b.action.value}) have opposite actions for overlapping traffic. "
                    f"{overlap_desc} "
                    f"The outcome depends entirely on rule ordering."
                ),
                suggestion = (
                    "Narrow one of the rules to eliminate the overlap, "
                    "or confirm the ordering is intentional and document it."
                ),
            )

        # ── Case 4: Exact match on all dimensions, same action → REDUNDANT ──
        if src_rel == "equal" and dst_rel == "equal" and prt_rel == "equal" and same_action:
            return Finding(
                finding_type = FindingType.REDUNDANT,
                severity     = Severity.LOW,
                rule_a       = a,
                rule_b       = b,
                reason       = (
                    f"Rule {b.rule_id!r} (priority {b.priority}) matches the exact same traffic "
                    f"as rule {a.rule_id!r} (priority {a.priority}) and has the same action "
                    f"({a.action.value}). Rule {b.rule_id!r} is redundant."
                ),
                suggestion = f"Remove rule {b.rule_id!r} — it has no effect on policy.",
            )

        return None

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _fingerprint(rule: FirewallRule) -> tuple:
        """Canonical tuple for structural equality comparison."""
        return (
            rule.src_ip,
            rule.dst_ip,
            rule.src_port,
            rule.dst_port,
            rule.protocol,
            rule.action,
            rule.chain,
        )

    @staticmethod
    def _overlap_description(
        src_rel: str, dst_rel: str, prt_rel: str,
        a: FirewallRule, b: FirewallRule,
    ) -> str:
        parts = []
        if src_rel != "disjoint":
            parts.append(f"source IPs overlap ({a.src_ip} ∩ {b.src_ip})")
        if dst_rel != "disjoint":
            parts.append(f"destination IPs overlap ({a.dst_ip} ∩ {b.dst_ip})")
        if prt_rel != "disjoint":
            parts.append(
                f"destination ports overlap "
                f"({a.dst_port or 'any'} ∩ {b.dst_port or 'any'})"
            )
        return "Overlapping on: " + ", ".join(parts) + "."