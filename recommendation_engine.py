"""
recommendation_engine.py — Unifies ConflictReport + OptimizationResult into
a ranked, deduplicated, human-readable list of Recommendations.

The engine applies three layers of intelligence on top of raw findings:

  1. DEDUPLICATION
     A single badly-placed rule can appear in multiple findings
     (shadow of rule A, contradiction with rule B, redundant to rule C).
     We collapse these into one recommendation per affected rule.

  2. EFFORT SCORING
     Each recommendation is scored by estimated fix effort (LOW/MED/HIGH)
     so the developer can prioritize quick wins vs deep restructuring.

  3. IMPACT SCORING
     Security impact is computed from severity + finding type + rule breadth.
     A catch-all ALLOW contradicting a deny gets a higher impact score than
     two redundant rules on a /32 host route.

Usage:
    from recommendation_engine import RecommendationEngine
    from engine.conflict_engine import ConflictEngine
    from ml.rule_optimizer import RuleOptimizer
    from ml.traffic_generator import TrafficGenerator
    from parser import RuleParser

    rules  = RuleParser().parse("rules.iptables")
    logs   = TrafficGenerator().generate(5000)

    conflict_report = ConflictEngine().analyze(rules)
    opt_result      = RuleOptimizer().optimize(rules, logs)

    recs = RecommendationEngine().generate(conflict_report, opt_result, rules)
    for r in recs:
        print(r)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from parser.models import FirewallRule
from engine.conflict_engine import ConflictReport, Finding, FindingType, Severity
from ml.rule_optimizer import OptimizationResult, RuleMove


# ═══════════════════════════════════════════════════════════════════════════════
# Recommendation types
# ═══════════════════════════════════════════════════════════════════════════════

class FixType(str, Enum):
    REMOVE_RULE       = "REMOVE_RULE"        # Delete a rule entirely
    REORDER_RULE      = "REORDER_RULE"       # Change a rule's priority
    NARROW_RULE       = "NARROW_RULE"        # Reduce match scope (IP / port)
    SPLIT_RULE        = "SPLIT_RULE"         # Break one broad rule into specific ones
    REVIEW_RULE       = "REVIEW_RULE"        # Manual review required
    ADD_DEFAULT_DENY  = "ADD_DEFAULT_DENY"   # Add explicit default-deny at end
    DOCUMENT_RULE     = "DOCUMENT_RULE"      # Add a comment to explain intent


class Effort(str, Enum):
    LOW    = "LOW"     # < 5 min — single-line edit
    MEDIUM = "MEDIUM"  # 5–30 min — requires understanding context
    HIGH   = "HIGH"    # > 30 min — policy review / stakeholder discussion


@dataclass
class Recommendation:
    """A single, actionable recommendation derived from one or more findings."""

    rec_id:       str
    fix_type:     FixType
    severity:     Severity
    effort:       Effort
    impact_score: float          # 0.0–10.0 composite score
    title:        str            # One-line summary
    description:  str            # Detailed explanation
    suggestion:   str            # Concrete fix instruction
    affected_rules: list[str]    # rule_ids involved
    source_findings: list[str]   # finding types that generated this
    reorder_move: Optional[RuleMove] = None   # populated for REORDER_RULE recs

    def __repr__(self) -> str:
        return (
            f"[{self.severity.value}/{self.effort.value}] "
            f"{self.fix_type.value}: {self.title} "
            f"(impact={self.impact_score:.1f})"
        )

    def to_dict(self) -> dict:
        d = {
            "rec_id":          self.rec_id,
            "fix_type":        self.fix_type.value,
            "severity":        self.severity.value,
            "effort":          self.effort.value,
            "impact_score":    round(self.impact_score, 2),
            "title":           self.title,
            "description":     self.description,
            "suggestion":      self.suggestion,
            "affected_rules":  self.affected_rules,
            "source_findings": self.source_findings,
        }
        if self.reorder_move:
            d["reorder_move"] = self.reorder_move.to_dict()
        return d


# ═══════════════════════════════════════════════════════════════════════════════
# Engine
# ═══════════════════════════════════════════════════════════════════════════════

class RecommendationEngine:
    """
    Converts raw findings + optimization moves into ranked Recommendations.

    Deduplication strategy:
      - Each affected rule_id gets at most ONE recommendation per fix_type.
      - Multiple findings targeting the same rule are merged into one rec.
      - The highest-severity finding wins on severity; reasons are concatenated.
    """

    def generate(
        self,
        conflict_report: ConflictReport,
        opt_result:      Optional[OptimizationResult],
        rules:           list[FirewallRule],
    ) -> list[Recommendation]:
        """
        Generate a ranked list of recommendations.

        Args:
            conflict_report: Output of ConflictEngine.analyze()
            opt_result:      Output of RuleOptimizer.optimize() — may be None
                             if no traffic logs are available.
            rules:           The original sorted rule list.

        Returns:
            List of Recommendation objects, sorted by impact_score descending.
        """
        recs: list[Recommendation] = []
        rec_counter = [0]

        def next_id() -> str:
            rec_counter[0] += 1
            return f"REC-{rec_counter[0]:04d}"

        rule_map = {r.rule_id: r for r in rules}

        # ── Layer 1: Conflict findings → recommendations ─────────────────────
        recs.extend(self._from_conflict_findings(conflict_report.findings,
                                                  rule_map, next_id))

        # ── Layer 2: ML reorder moves → recommendations ──────────────────────
        if opt_result and opt_result.rules_moved > 0:
            recs.extend(self._from_optimization_moves(opt_result, next_id))

        # ── Layer 3: Structural heuristics (no traffic logs needed) ──────────
        recs.extend(self._heuristic_checks(rules, conflict_report, next_id))

        # Deduplicate: merge recs targeting the same rule with same fix_type
        recs = self._deduplicate(recs)

        # Sort: impact_score desc, then severity, then effort
        _sev_order  = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                       Severity.MEDIUM: 2, Severity.LOW: 3}
        _eff_order  = {Effort.LOW: 0, Effort.MEDIUM: 1, Effort.HIGH: 2}

        recs.sort(key=lambda r: (
            -r.impact_score,
            _sev_order.get(r.severity, 9),
            _eff_order.get(r.effort, 9),
        ))

        # Re-number after deduplication + sort
        for i, rec in enumerate(recs, start=1):
            rec.rec_id = f"REC-{i:04d}"

        return recs

    # ─────────────────────────────────────────────── layer 1

    def _from_conflict_findings(
        self,
        findings:  list[Finding],
        rule_map:  dict[str, FirewallRule],
        next_id,
    ) -> list[Recommendation]:
        recs = []

        for f in findings:
            rule_b = rule_map.get(f.rule_b.rule_id, f.rule_b)

            if f.finding_type == FindingType.DUPLICATE:
                recs.append(Recommendation(
                    rec_id         = next_id(),
                    fix_type       = FixType.REMOVE_RULE,
                    severity       = f.severity,
                    effort         = Effort.LOW,
                    impact_score   = self._impact(f, rule_b),
                    title          = f"Remove duplicate rule {f.rule_b.rule_id!r}",
                    description    = f.reason,
                    suggestion     = f.suggestion,
                    affected_rules = [f.rule_b.rule_id],
                    source_findings = [f.finding_type.value],
                ))

            elif f.finding_type == FindingType.SHADOW:
                recs.append(Recommendation(
                    rec_id         = next_id(),
                    fix_type       = FixType.REMOVE_RULE,
                    severity       = f.severity,
                    effort         = Effort.LOW,
                    impact_score   = self._impact(f, rule_b),
                    title          = f"Remove shadowed rule {f.rule_b.rule_id!r}",
                    description    = f.reason,
                    suggestion     = f.suggestion,
                    affected_rules = [f.rule_b.rule_id, f.rule_a.rule_id],
                    source_findings = [f.finding_type.value],
                ))

            elif f.finding_type == FindingType.REDUNDANT:
                recs.append(Recommendation(
                    rec_id         = next_id(),
                    fix_type       = FixType.REMOVE_RULE,
                    severity       = f.severity,
                    effort         = Effort.LOW,
                    impact_score   = self._impact(f, rule_b),
                    title          = f"Remove redundant rule {f.rule_b.rule_id!r}",
                    description    = f.reason,
                    suggestion     = f.suggestion,
                    affected_rules = [f.rule_b.rule_id],
                    source_findings = [f.finding_type.value],
                ))

            elif f.finding_type == FindingType.CONTRADICTION:
                recs.append(Recommendation(
                    rec_id         = next_id(),
                    fix_type       = FixType.REVIEW_RULE,
                    severity       = f.severity,
                    effort         = Effort.HIGH,
                    impact_score   = self._impact(f, rule_b),
                    title          = (
                        f"Resolve contradiction between "
                        f"{f.rule_a.rule_id!r} and {f.rule_b.rule_id!r}"
                    ),
                    description    = f.reason,
                    suggestion     = f.suggestion,
                    affected_rules = [f.rule_a.rule_id, f.rule_b.rule_id],
                    source_findings = [f.finding_type.value],
                ))

            elif f.finding_type == FindingType.PERMISSIVE:
                recs.append(Recommendation(
                    rec_id         = next_id(),
                    fix_type       = FixType.NARROW_RULE,
                    severity       = f.severity,
                    effort         = Effort.MEDIUM,
                    impact_score   = self._impact(f, f.rule_a),
                    title          = f"Narrow catch-all ALLOW rule {f.rule_a.rule_id!r}",
                    description    = f.reason,
                    suggestion     = f.suggestion,
                    affected_rules = [f.rule_a.rule_id],
                    source_findings = [f.finding_type.value],
                ))

        return recs

    # ─────────────────────────────────────────────── layer 2

    def _from_optimization_moves(
        self,
        opt_result: OptimizationResult,
        next_id,
    ) -> list[Recommendation]:
        recs = []
        # Only recommend significant moves (rank delta >= 2) to avoid noise
        significant = [m for m in opt_result.moves if m.delta_rank >= 2]

        for move in significant[:10]:  # cap at top 10 reorder recs
            speedup_note = (
                f"Moving this rule {move.delta_rank} positions earlier "
                f"reduces average packet evaluation steps. "
                f"This rule was hit {move.actual_hits} times in the traffic sample."
            )
            recs.append(Recommendation(
                rec_id          = next_id(),
                fix_type        = FixType.REORDER_RULE,
                severity        = Severity.LOW,
                effort          = Effort.LOW,
                impact_score    = min(3.0 + move.delta_rank * 0.2, 5.0),
                title           = (
                    f"Move rule {move.rule_id!r} "
                    f"from rank {move.old_rank} to rank {move.new_rank}"
                ),
                description     = speedup_note,
                suggestion      = (
                    f"Change priority from {move.old_priority} to "
                    f"{move.new_priority}. "
                    f"Estimated global speedup: {opt_result.estimated_speedup:.2f}x."
                ),
                affected_rules  = [move.rule_id],
                source_findings = ["ML_OPTIMIZER"],
                reorder_move    = move,
            ))

        return recs

    # ─────────────────────────────────────────────── layer 3

    def _heuristic_checks(
        self,
        rules:           list[FirewallRule],
        conflict_report: ConflictReport,
        next_id,
    ) -> list[Recommendation]:
        recs = []

        from parser.models import Action, Protocol

        # Check: no explicit default-deny at end
        last_rule = rules[-1] if rules else None
        has_default_deny = last_rule and (
            last_rule.action in (Action.DENY, Action.DROP) and
            last_rule.src_ip == "0.0.0.0/0" and
            last_rule.dst_ip == "0.0.0.0/0" and
            last_rule.dst_port is None
        )
        if not has_default_deny:
            recs.append(Recommendation(
                rec_id          = next_id(),
                fix_type        = FixType.ADD_DEFAULT_DENY,
                severity        = Severity.HIGH,
                effort          = Effort.LOW,
                impact_score    = 8.5,
                title           = "Add explicit default-deny rule at the end",
                description     = (
                    "The rule set has no explicit default-deny rule as its final entry. "
                    "Without it, traffic that doesn't match any rule falls through to the "
                    "platform's implicit default — which may be ALLOW on some systems "
                    "(e.g., AWS SGs, iptables ACCEPT policy). "
                    "An explicit default-deny closes this gap and makes intent clear."
                ),
                suggestion      = (
                    "Add as the final rule: "
                    "src=0.0.0.0/0, dst=0.0.0.0/0, port=any, proto=all, action=DENY. "
                    "In iptables: -A INPUT -j DROP"
                ),
                affected_rules  = [],
                source_findings = ["HEURISTIC_NO_DEFAULT_DENY"],
            ))

        # Check: undocumented rules (no comment) in a large rule set
        undocumented = [r for r in rules if not r.comment and len(rules) > 5]
        if len(undocumented) > len(rules) * 0.5:
            recs.append(Recommendation(
                rec_id          = next_id(),
                fix_type        = FixType.DOCUMENT_RULE,
                severity        = Severity.LOW,
                effort          = Effort.MEDIUM,
                impact_score    = 2.0,
                title           = f"{len(undocumented)} rules have no comment or description",
                description     = (
                    f"{len(undocumented)} of {len(rules)} rules have no explanatory comment. "
                    "Undocumented rules make auditing, incident response, and rule cleanup "
                    "significantly harder — the original intent is lost over time."
                ),
                suggestion      = (
                    "Add comments to every rule explaining: who requested it, "
                    "what traffic it handles, and when it was added. "
                    "In iptables use: -m comment --comment \"your description\""
                ),
                affected_rules  = [r.rule_id for r in undocumented[:20]],
                source_findings = ["HEURISTIC_UNDOCUMENTED"],
            ))

        # Check: rules with very broad source + specific deny (potential block-all risk)
        from engine.conflict_engine import _ip_relationship
        for rule in rules:
            if (rule.action in (Action.DENY, Action.DROP) and
                    rule.src_ip == "0.0.0.0/0" and
                    rule.dst_port is not None and
                    rule.protocol != Protocol.ALL):
                # A deny-all-sources on a specific port early in the chain
                # can silently block legitimate traffic
                if rule.priority < 50:
                    recs.append(Recommendation(
                        rec_id          = next_id(),
                        fix_type        = FixType.REVIEW_RULE,
                        severity        = Severity.MEDIUM,
                        effort          = Effort.MEDIUM,
                        impact_score    = 5.5,
                        title           = (
                            f"Rule {rule.rule_id!r} denies all sources on "
                            f"port {rule.dst_port} — confirm this is intentional"
                        ),
                        description     = (
                            f"Rule {rule.rule_id!r} (priority {rule.priority}) "
                            f"blocks ALL traffic to port {rule.dst_port} from any source. "
                            f"If any legitimate traffic uses this port, it will be silently dropped. "
                            f"This is a common misconfiguration when a block rule is meant to "
                            f"target only specific source ranges."
                        ),
                        suggestion      = (
                            f"Verify that port {rule.dst_port} should be blocked from ALL sources. "
                            f"If not, narrow the src_ip from 0.0.0.0/0 to the specific "
                            f"range you intend to block."
                        ),
                        affected_rules  = [rule.rule_id],
                        source_findings = ["HEURISTIC_BROAD_DENY"],
                    ))

        return recs

    # ─────────────────────────────────────────────── dedup + scoring

    def _deduplicate(self, recs: list[Recommendation]) -> list[Recommendation]:
        """
        Merge recommendations targeting the same primary rule with the same fix type.
        Keeps the highest-severity version; appends descriptions from others.
        """
        _sev_order = {Severity.CRITICAL: 0, Severity.HIGH: 1,
                      Severity.MEDIUM: 2, Severity.LOW: 3}

        seen: dict[tuple, Recommendation] = {}
        for rec in recs:
            primary_rule = rec.affected_rules[0] if rec.affected_rules else "__none__"
            key = (primary_rule, rec.fix_type)

            if key not in seen:
                seen[key] = rec
            else:
                existing = seen[key]
                # Keep higher severity
                if _sev_order[rec.severity] < _sev_order[existing.severity]:
                    rec.description    = existing.description + "\n\n" + rec.description
                    rec.affected_rules = list(set(existing.affected_rules + rec.affected_rules))
                    rec.source_findings = list(set(existing.source_findings + rec.source_findings))
                    seen[key] = rec
                else:
                    existing.impact_score  = max(existing.impact_score, rec.impact_score)
                    existing.source_findings = list(set(existing.source_findings + rec.source_findings))

        return list(seen.values())

    @staticmethod
    def _impact(finding: Finding, rule: FirewallRule) -> float:
        """
        Compute a 0–10 impact score from severity + finding type + rule breadth.

        Broader rules (shorter prefix = more IPs affected) get higher scores.
        Contradictions always score highest.
        """
        import ipaddress

        base = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH:     7.0,
            Severity.MEDIUM:   4.5,
            Severity.LOW:      2.0,
        }[finding.severity]

        # Breadth bonus: /0 = +1.0, /8 = +0.75, /16 = +0.5, /32 = 0
        try:
            prefix = ipaddress.ip_network(rule.src_ip, strict=False).prefixlen
            breadth_bonus = max(0.0, (32 - prefix) / 32)
        except ValueError:
            breadth_bonus = 0.0

        # Finding type modifier
        type_mod = {
            FindingType.CONTRADICTION: 1.0,
            FindingType.SHADOW:        0.5,
            FindingType.PERMISSIVE:    0.8,
            FindingType.DUPLICATE:     0.0,
            FindingType.REDUNDANT:    -0.5,
        }.get(finding.finding_type, 0.0)

        return min(10.0, base + breadth_bonus + type_mod)