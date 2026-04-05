"""
pipeline.py — End-to-end firewall optimization pipeline.

This is the single entry point that orchestrates all four phases:

  Phase 1: Parse          → RuleParser
  Phase 2: Detect         → ConflictEngine
  Phase 3: Optimize       → RuleOptimizer  (optional — requires traffic logs)
  Phase 4: Recommend      → RecommendationEngine
  Phase 4: Export         → Exporter

Usage — from a script:
    from pipeline import FirewallOptimizer

    optimizer = FirewallOptimizer()

    # Analyze only (no ML reordering)
    result = optimizer.analyze("rules.iptables")
    result.print_summary()
    result.export("output/")

    # Analyze + ML optimize
    result = optimizer.analyze("rules.iptables", traffic_logs="traffic.csv")
    result.export("output/")

    # Analyze rule text directly
    result = optimizer.analyze_text(iptables_text, format="iptables")

Usage — from CLI:
    python pipeline.py rules.iptables --traffic traffic.csv --output ./output
    python pipeline.py rules.json --output ./output
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from parser import RuleParser
from parser.models import FirewallRule
from engine.conflict_engine import ConflictEngine, ConflictReport
from ml.traffic_generator import TrafficGenerator, TrafficLog
from ml.rule_optimizer import OptimizationResult, RuleOptimizer
from recommendation_engine import Recommendation, RecommendationEngine
from exporter import Exporter


@dataclass
class PipelineResult:
    """Full output of the optimization pipeline."""
    original_rules:  list[FirewallRule]
    optimized_rules: list[FirewallRule]
    conflict_report: ConflictReport
    opt_result:      Optional[OptimizationResult]
    recommendations: list[Recommendation]
    elapsed_sec:     float

    def print_summary(self) -> None:
        """Print a human-readable summary to stdout."""
        r = self.conflict_report
        recs = self.recommendations

        print()
        print("=" * 60)
        print("  FIREWALL RULE OPTIMIZER — ANALYSIS COMPLETE")
        print("=" * 60)
        print(f"  Rules analyzed       : {r.total_rules}")
        print(f"  Analysis time        : {self.elapsed_sec:.2f}s")
        print()
        print("  CONFLICT FINDINGS")
        print(f"  {'🔴 Contradictions':<30}: {r.contradiction_count}")
        print(f"  {'🟠 Shadows':<30}: {r.shadow_count}")
        print(f"  {'🟡 Duplicates':<30}: {r.duplicate_count}")
        print(f"  {'🟡 Permissive rules':<30}: {r.permissive_count}")
        print(f"  {'🟢 Redundant':<30}: {r.redundant_count}")

        if self.opt_result:
            print()
            print("  ML OPTIMIZATION")
            print(f"  {'Rules reordered':<30}: {self.opt_result.rules_moved}")
            print(f"  {'Estimated speedup':<30}: {self.opt_result.estimated_speedup:.2f}x")
            print(f"  {'Policy equivalent':<30}: {self.opt_result.policy_equivalent}")

        print()
        print("  RECOMMENDATIONS")
        for rec in recs[:10]:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠",
                    "MEDIUM": "🟡", "LOW": "🟢"}.get(rec.severity.value, "⚪")
            print(f"  {icon} [{rec.rec_id}] {rec.title[:55]}")
        if len(recs) > 10:
            print(f"  ... and {len(recs) - 10} more")
        print("=" * 60)
        print()

    def export(self, output_dir: str) -> dict[str, str]:
        """Export all formats to output_dir. Returns dict of format→filepath."""
        paths = Exporter().export_all(
            output_dir       = output_dir,
            original_rules   = self.original_rules,
            optimized_rules  = self.optimized_rules,
            recommendations  = self.recommendations,
            conflict_report  = self.conflict_report,
            opt_result       = self.opt_result,
        )
        print(f"Exported {len(paths)} files to: {output_dir}")
        for fmt, path in paths.items():
            print(f"  {fmt:<25} → {path}")
        return paths


class FirewallOptimizer:
    """
    High-level pipeline orchestrator.

    Wires together: Parser → ConflictEngine → RuleOptimizer → RecommendationEngine → Exporter
    """

    def __init__(
        self,
        n_estimators:  int   = 100,
        learning_rate: float = 0.1,
        max_depth:     int   = 4,
        random_state:  int   = 42,
        verbose:       bool  = True,
    ):
        self.optimizer_kwargs = dict(
            n_estimators  = n_estimators,
            learning_rate = learning_rate,
            max_depth     = max_depth,
            random_state  = random_state,
        )
        self.verbose = verbose

    def analyze(
        self,
        rules_filepath:   str,
        traffic_filepath: Optional[str] = None,
        rule_format:      Optional[str] = None,
        synthetic_logs:   int           = 0,
    ) -> PipelineResult:
        """
        Run the full pipeline on a rule file.

        Args:
            rules_filepath:   Path to rule file (any supported format).
            traffic_filepath: Optional path to traffic log CSV.
            rule_format:      Force format (iptables/json/csv/cisco/aws).
                              Leave None for auto-detect.
            synthetic_logs:   If > 0 and no traffic_filepath, generate this
                              many synthetic traffic records for ML training.

        Returns:
            PipelineResult with all findings and recommendations.
        """
        t0 = time.time()
        self._log(f"Parsing rules from: {rules_filepath}")

        rules = RuleParser().parse(rules_filepath, format=rule_format)
        self._log(f"Parsed {len(rules)} rules.")

        logs = self._load_or_generate_logs(traffic_filepath, synthetic_logs)
        return self._run(rules, logs, t0)

    def analyze_text(
        self,
        text:           str,
        format:         str,
        traffic_logs:   Optional[list[TrafficLog]] = None,
        synthetic_logs: int = 0,
    ) -> PipelineResult:
        """Analyze a raw text rule string."""
        t0 = time.time()
        rules = RuleParser().parse_text(text, format=format)
        self._log(f"Parsed {len(rules)} rules from text.")
        logs = traffic_logs or (
            TrafficGenerator().generate(synthetic_logs) if synthetic_logs > 0 else []
        )
        return self._run(rules, logs, t0)

    def analyze_rules(
        self,
        rules:          list[FirewallRule],
        traffic_logs:   Optional[list[TrafficLog]] = None,
        synthetic_logs: int = 0,
    ) -> PipelineResult:
        """Analyze a pre-parsed list of FirewallRule objects."""
        t0 = time.time()
        logs = traffic_logs or (
            TrafficGenerator().generate(synthetic_logs) if synthetic_logs > 0 else []
        )
        return self._run(rules, logs, t0)

    # ─────────────────────────────────────────────── internals

    def _run(
        self,
        rules: list[FirewallRule],
        logs:  list[TrafficLog],
        t0:    float,
    ) -> PipelineResult:
        # Phase 2: Conflict detection
        self._log("Running conflict detection...")
        conflict_report = ConflictEngine().analyze(rules)
        self._log(
            f"Found {len(conflict_report.findings)} findings: "
            f"{conflict_report.contradiction_count} contradictions, "
            f"{conflict_report.shadow_count} shadows, "
            f"{conflict_report.duplicate_count} duplicates."
        )

        # Phase 3: ML optimization (only if logs available)
        opt_result = None
        optimized_rules = list(rules)
        if logs:
            self._log(f"Running ML optimizer on {len(logs)} traffic records...")
            try:
                opt_result    = RuleOptimizer(**self.optimizer_kwargs).optimize(rules, logs)
                optimized_rules = opt_result.optimized_rules
                self._log(
                    f"Reordered {opt_result.rules_moved} rules. "
                    f"Estimated speedup: {opt_result.estimated_speedup:.2f}x. "
                    f"Policy equivalent: {opt_result.policy_equivalent}."
                )
            except Exception as e:
                self._log(f"ML optimization skipped: {e}")

        # Phase 4: Recommendations
        self._log("Generating recommendations...")
        recommendations = RecommendationEngine().generate(
            conflict_report, opt_result, rules
        )
        self._log(f"Generated {len(recommendations)} recommendations.")

        elapsed = time.time() - t0
        return PipelineResult(
            original_rules   = rules,
            optimized_rules  = optimized_rules,
            conflict_report  = conflict_report,
            opt_result       = opt_result,
            recommendations  = recommendations,
            elapsed_sec      = elapsed,
        )

    def _load_or_generate_logs(
        self,
        traffic_filepath: Optional[str],
        synthetic_count:  int,
    ) -> list[TrafficLog]:
        if traffic_filepath:
            self._log(f"Loading traffic logs from: {traffic_filepath}")
            logs = TrafficGenerator.load_csv(traffic_filepath)
            self._log(f"Loaded {len(logs)} traffic records.")
            return logs
        if synthetic_count > 0:
            self._log(f"Generating {synthetic_count} synthetic traffic records...")
            logs = TrafficGenerator().generate(synthetic_count)
            self._log("Traffic generation complete.")
            return logs
        return []

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[optimizer] {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def _cli():
    parser = argparse.ArgumentParser(
        description="AI-Powered Firewall Rule Optimizer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pipeline.py rules.iptables --output ./report
  python pipeline.py rules.json --traffic traffic.csv --output ./report
  python pipeline.py acl.txt --format cisco --synthetic 5000 --output ./report
        """,
    )
    parser.add_argument("rules",     help="Path to firewall rule file")
    parser.add_argument("--format",  help="Rule format (iptables/json/csv/cisco/aws)")
    parser.add_argument("--traffic", help="Path to traffic log CSV file")
    parser.add_argument("--synthetic", type=int, default=0,
                        help="Generate N synthetic traffic records for ML training")
    parser.add_argument("--output",  default="./output",
                        help="Output directory for reports (default: ./output)")
    parser.add_argument("--quiet",   action="store_true",
                        help="Suppress progress output")

    args = parser.parse_args()

    optimizer = FirewallOptimizer(verbose=not args.quiet)
    result = optimizer.analyze(
        rules_filepath   = args.rules,
        traffic_filepath = args.traffic,
        rule_format      = args.format,
        synthetic_logs   = args.synthetic,
    )
    result.print_summary()
    result.export(args.output)


if __name__ == "__main__":
    _cli()