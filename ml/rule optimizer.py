"""
rule_optimizer.py — ML-based firewall rule reordering optimizer.

Core idea:
  Firewall engines evaluate rules in priority order and stop at the FIRST match.
  If a rule that matches 40% of traffic is ranked #50 while rule #1 matches
  0.01% of traffic, every packet wastes 49 rule checks before hitting the
  high-traffic rule. Reordering by predicted hit rate reduces average
  evaluation steps — measurably improving firewall throughput.

Algorithm:
  1. Simulate rule hit counts against traffic logs (FeatureExtractor)
  2. Extract feature vectors for each rule
  3. Train a GradientBoostingRegressor to predict hit_count from rule features
  4. Use predicted hit counts to produce an optimized ordering
  5. Validate that the NEW ordering is policy-equivalent to the original
     (same accept/deny decision for every traffic log)
  6. Emit an OptimizationResult with the reordered rules + performance estimates

Policy-safety guarantee:
  The optimizer NEVER moves a rule past another rule that would produce a
  different outcome for the same traffic. Rules that contradict each other
  (detected by ConflictEngine) are kept in their original relative order.
  Safe reordering only happens within groups of non-contradicting rules.

Usage:
    from ml.rule_optimizer import RuleOptimizer
    from ml.traffic_generator import TrafficGenerator
    from parser import RuleParser

    rules  = RuleParser().parse("rules.iptables")
    logs   = TrafficGenerator(seed=42).generate(10_000)

    result = RuleOptimizer().optimize(rules, logs)
    print(result.summary())
    for move in result.moves:
        print(move)
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sklearn.ensemble import GradientBoostingRegressor
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler

from parser.models import Action, FirewallRule
from ml.feature_engineering import FeatureExtractor
from ml.traffic_generator import TrafficLog


warnings.filterwarnings("ignore", category=UserWarning)


# ═══════════════════════════════════════════════════════════════════════════════
# Result types
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class RuleMove:
    """A single rule reordering recommendation."""
    rule_id:          str
    old_priority:     int
    new_priority:     int
    old_rank:         int          # 0-indexed position before reordering
    new_rank:         int          # 0-indexed position after reordering
    predicted_hits:   float
    actual_hits:      int
    delta_rank:       int          # positive = moved earlier (good for hot rules)
    reason:           str

    def to_dict(self) -> dict:
        return {
            "rule_id":        self.rule_id,
            "old_priority":   self.old_priority,
            "new_priority":   self.new_priority,
            "old_rank":       self.old_rank,
            "new_rank":       self.new_rank,
            "predicted_hits": round(self.predicted_hits, 2),
            "actual_hits":    self.actual_hits,
            "delta_rank":     self.delta_rank,
            "reason":         self.reason,
        }


@dataclass
class ModelMetrics:
    """Training metrics for transparency / academic reporting."""
    model_type:        str
    n_estimators:      int
    learning_rate:     float
    max_depth:         int
    cv_r2_mean:        float
    cv_r2_std:         float
    feature_importances: dict  # {feature_name: importance_score}
    n_training_rules:  int
    n_traffic_logs:    int


@dataclass
class OptimizationResult:
    """Full output of the ML optimizer."""
    original_rules:    list[FirewallRule]
    optimized_rules:   list[FirewallRule]
    moves:             list[RuleMove]
    metrics:           ModelMetrics
    policy_equivalent: bool           # True if reordering preserves all decisions
    estimated_speedup: float          # Ratio: avg_checks_before / avg_checks_after

    @property
    def rules_moved(self) -> int:
        return len([m for m in self.moves if m.delta_rank != 0])

    def summary(self) -> str:
        lines = [
            "ML Rule Optimizer Results",
            "=" * 50,
            f"  Rules analyzed       : {len(self.original_rules)}",
            f"  Rules reordered      : {self.rules_moved}",
            f"  Policy equivalent    : {self.policy_equivalent}",
            f"  Estimated speedup    : {self.estimated_speedup:.2f}x",
            f"  Model R² (CV)        : {self.metrics.cv_r2_mean:.3f} "
            f"± {self.metrics.cv_r2_std:.3f}",
            "",
            "Top 5 most significant moves:",
        ]
        top_moves = sorted(self.moves, key=lambda m: abs(m.delta_rank), reverse=True)[:5]
        for m in top_moves:
            direction = "↑ earlier" if m.delta_rank > 0 else "↓ later"
            lines.append(
                f"  {m.rule_id!r:20s} rank {m.old_rank} → {m.new_rank} "
                f"({direction} by {abs(m.delta_rank)})  hits={m.actual_hits}"
            )
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "rules_analyzed":    len(self.original_rules),
            "rules_moved":       self.rules_moved,
            "policy_equivalent": self.policy_equivalent,
            "estimated_speedup": round(self.estimated_speedup, 3),
            "model_metrics": {
                "cv_r2_mean": round(self.metrics.cv_r2_mean, 4),
                "cv_r2_std":  round(self.metrics.cv_r2_std, 4),
                "feature_importances": {
                    k: round(v, 4)
                    for k, v in sorted(
                        self.metrics.feature_importances.items(),
                        key=lambda x: -x[1]
                    )
                },
            },
            "moves": [m.to_dict() for m in self.moves],
        }


# ═══════════════════════════════════════════════════════════════════════════════
# Optimizer
# ═══════════════════════════════════════════════════════════════════════════════

class RuleOptimizer:
    """
    ML-based firewall rule reordering optimizer.

    Uses a GradientBoostingRegressor trained on rule features + traffic hit counts
    to predict which rules should be evaluated first (highest predicted hit rate).

    Safety constraint: reordering never moves a rule past a contradicting rule.
    """

    def __init__(
        self,
        n_estimators:  int   = 100,
        learning_rate: float = 0.1,
        max_depth:     int   = 4,
        random_state:  int   = 42,
    ):
        self.n_estimators  = n_estimators
        self.learning_rate = learning_rate
        self.max_depth     = max_depth
        self.random_state  = random_state

    def optimize(
        self,
        rules: list[FirewallRule],
        logs:  list[TrafficLog],
    ) -> OptimizationResult:
        """
        Run the full ML optimization pipeline.

        Steps:
          1. Extract features
          2. Train GBT model
          3. Predict hit rates for all rules
          4. Compute safe reordering respecting policy constraints
          5. Verify policy equivalence
          6. Return OptimizationResult
        """
        if not rules:
            raise ValueError("Rule list is empty.")
        if not logs:
            raise ValueError("Traffic log list is empty — needed for hit count labels.")

        sorted_rules = sorted(rules, key=lambda r: r.priority)

        # ── Step 1: Feature extraction ──────────────────────────────────────
        extractor = FeatureExtractor()
        X, y, feature_names = extractor.extract(sorted_rules, logs)

        # Actual hit counts from simulation (column 0 of X)
        actual_hits = {rule.rule_id: int(y[i]) for i, rule in enumerate(sorted_rules)}

        # ── Step 2: Train GBT ───────────────────────────────────────────────
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        model = GradientBoostingRegressor(
            n_estimators  = self.n_estimators,
            learning_rate = self.learning_rate,
            max_depth     = self.max_depth,
            random_state  = self.random_state,
            subsample     = 0.8,
        )

        # Cross-validate for academic reporting
        cv_scores = cross_val_score(model, X_scaled, y, cv=min(5, len(sorted_rules)),
                                     scoring="r2")
        model.fit(X_scaled, y)

        # Feature importances
        importances = dict(zip(feature_names, model.feature_importances_))

        metrics = ModelMetrics(
            model_type        = "GradientBoostingRegressor",
            n_estimators      = self.n_estimators,
            learning_rate     = self.learning_rate,
            max_depth         = self.max_depth,
            cv_r2_mean        = float(cv_scores.mean()),
            cv_r2_std         = float(cv_scores.std()),
            feature_importances = importances,
            n_training_rules  = len(sorted_rules),
            n_traffic_logs    = len(logs),
        )

        # ── Step 3: Predict hit rates ────────────────────────────────────────
        predicted_hits = model.predict(X_scaled)
        predicted_hits = np.maximum(predicted_hits, 0)  # clip negatives

        # ── Step 4: Safe reordering ──────────────────────────────────────────
        optimized_rules = self._safe_reorder(
            sorted_rules, predicted_hits, extractor
        )

        # ── Step 5: Policy equivalence check ────────────────────────────────
        policy_ok = self._verify_policy_equivalence(sorted_rules, optimized_rules, logs)

        # ── Step 6: Compute moves + speedup ─────────────────────────────────
        moves = self._compute_moves(
            sorted_rules, optimized_rules, predicted_hits, actual_hits
        )
        speedup = self._estimate_speedup(sorted_rules, optimized_rules, actual_hits)

        return OptimizationResult(
            original_rules   = sorted_rules,
            optimized_rules  = optimized_rules,
            moves            = moves,
            metrics          = metrics,
            policy_equivalent = policy_ok,
            estimated_speedup = speedup,
        )

    # ─────────────────────────────────────────────── safe reordering

    def _safe_reorder(
        self,
        rules:          list[FirewallRule],
        predicted_hits: np.ndarray,
        extractor:      FeatureExtractor,
    ) -> list[FirewallRule]:
        """
        Reorder rules by predicted hit rate, subject to the safety constraint:

        SAFETY RULE: For any pair (A, B) in the original ordering where
        swapping them would change the verdict for any matching packet
        (i.e., they have overlapping match spaces AND opposite actions),
        their relative order is preserved.

        Implementation: topological sort.
          - Build a dependency graph where A → B means "A must come before B"
          - Sort by predicted hits descending within topological constraints
        """
        n = len(rules)
        if n <= 1:
            return list(rules)

        # Build must-come-before constraints
        # must_before[i] = set of indices j where rules[i] must precede rules[j]
        must_before: list[set] = [set() for _ in range(n)]

        for i in range(n):
            for j in range(i + 1, n):
                a, b = rules[i], rules[j]
                if self._would_conflict_if_swapped(a, b, extractor):
                    must_before[i].add(j)

        # Topological sort respecting constraints, ordering by predicted_hits desc
        # Use a greedy approach: always pick the highest-hit unconstrained rule
        in_degree = [0] * n
        dependents: list[list[int]] = [[] for _ in range(n)]

        for i in range(n):
            for j in must_before[i]:
                in_degree[j] += 1
                dependents[i].append(j)

        # Min-heap keyed by negative predicted_hits (so highest hits come first)
        import heapq
        available = []
        for i in range(n):
            if in_degree[i] == 0:
                heapq.heappush(available, (-predicted_hits[i], i))

        ordered_indices = []
        while available:
            _, idx = heapq.heappop(available)
            ordered_indices.append(idx)
            for dep in dependents[idx]:
                in_degree[dep] -= 1
                if in_degree[dep] == 0:
                    heapq.heappush(available, (-predicted_hits[dep], dep))

        # If cycle detected (shouldn't happen with acyclic firewall rules),
        # fall back to original order
        if len(ordered_indices) != n:
            return list(rules)

        # Reassign priorities to match new order
        reordered = [rules[i] for i in ordered_indices]
        # Create new FirewallRule objects with updated priorities
        result = []
        for new_rank, rule in enumerate(reordered):
            import dataclasses
            updated = dataclasses.replace(rule, priority=new_rank * 10)
            result.append(updated)

        return result

    def _would_conflict_if_swapped(
        self,
        a: FirewallRule,
        b: FirewallRule,
        extractor: FeatureExtractor,
    ) -> bool:
        """
        Return True if swapping the order of A and B would change any
        packet's verdict — meaning A must come before B in the optimized order.

        A must precede B when:
          - Their match spaces overlap (some packet matches both)
          - They have opposite actions (ALLOW vs DENY)
        In this case, moving B before A would change that packet's verdict.

        If they have the same action, order doesn't affect the outcome — safe to swap.
        """
        from engine.conflict_engine import _ip_relationship, _proto_compatible, _actions_opposite
        from engine.port_interval import PortRange, ranges_overlap

        # Protocol gate
        if not _proto_compatible(a.protocol, b.protocol):
            return False

        # IP gate — if disjoint on src or dst, no packet can match both
        src_rel = _ip_relationship(a.src_ip, b.src_ip)
        if src_rel == "disjoint":
            return False
        dst_rel = _ip_relationship(a.dst_ip, b.dst_ip)
        if dst_rel == "disjoint":
            return False

        # Port gate
        a_port = PortRange.parse(a.dst_port)
        b_port = PortRange.parse(b.dst_port)
        if not ranges_overlap(a_port, b_port):
            return False

        # All match — check actions
        return _actions_opposite(a.action, b.action)

    # ─────────────────────────────────────────────── policy verification

    def _verify_policy_equivalence(
        self,
        original:   list[FirewallRule],
        optimized:  list[FirewallRule],
        logs:       list[TrafficLog],
    ) -> bool:
        """
        Verify that every packet in logs gets the same ALLOW/DENY verdict
        from both the original and optimized rule sets.

        Samples up to 2,000 logs for speed.
        """
        extractor = FeatureExtractor()
        sample = logs[:2000]

        for log in sample:
            orig_action = self._first_match_action(original, log, extractor)
            opt_action  = self._first_match_action(optimized, log, extractor)
            if orig_action != opt_action:
                return False
        return True

    @staticmethod
    def _first_match_action(
        rules:     list[FirewallRule],
        log:       TrafficLog,
        extractor: FeatureExtractor,
    ) -> Optional[str]:
        for rule in rules:
            if extractor._matches(rule, log):
                return rule.action.value
        return None  # implicit default

    # ─────────────────────────────────────────────── moves + speedup

    def _compute_moves(
        self,
        original:       list[FirewallRule],
        optimized:      list[FirewallRule],
        predicted_hits: np.ndarray,
        actual_hits:    dict[str, int],
    ) -> list[RuleMove]:
        orig_rank  = {r.rule_id: i for i, r in enumerate(original)}
        new_rank   = {r.rule_id: i for i, r in enumerate(optimized)}
        pred_map   = {r.rule_id: float(predicted_hits[i])
                      for i, r in enumerate(original)}

        moves = []
        for rule in original:
            old_r = orig_rank[rule.rule_id]
            new_r = new_rank[rule.rule_id]
            delta = old_r - new_r  # positive = moved earlier

            reason = ""
            if delta > 0:
                reason = (
                    f"High predicted hit rate ({pred_map[rule.rule_id]:.1f}) — "
                    f"moving earlier reduces avg packet evaluation steps."
                )
            elif delta < 0:
                reason = (
                    f"Low predicted hit rate ({pred_map[rule.rule_id]:.1f}) — "
                    f"moving later frees evaluation cycles for hotter rules."
                )
            else:
                reason = "No change — already in optimal position."

            moves.append(RuleMove(
                rule_id        = rule.rule_id,
                old_priority   = rule.priority,
                new_priority   = optimized[new_r].priority,
                old_rank       = old_r,
                new_rank       = new_r,
                predicted_hits = pred_map[rule.rule_id],
                actual_hits    = actual_hits.get(rule.rule_id, 0),
                delta_rank     = delta,
                reason         = reason,
            ))

        # Sort: biggest moves first
        moves.sort(key=lambda m: abs(m.delta_rank), reverse=True)
        return moves

    def _estimate_speedup(
        self,
        original:    list[FirewallRule],
        optimized:   list[FirewallRule],
        actual_hits: dict[str, int],
    ) -> float:
        """
        Estimate throughput speedup as:
            avg_checks_original / avg_checks_optimized

        avg_checks = weighted average of (rank + 1) where weight = hit_count.
        """
        total_hits = sum(actual_hits.values())
        if total_hits == 0:
            return 1.0

        def avg_checks(rules: list[FirewallRule]) -> float:
            total = 0.0
            for rank, rule in enumerate(rules):
                hits = actual_hits.get(rule.rule_id, 0)
                total += hits * (rank + 1)
            return total / total_hits

        orig_avg = avg_checks(original)
        opt_avg  = avg_checks(optimized)

        if opt_avg == 0:
            return 1.0
        return orig_avg / opt_avg