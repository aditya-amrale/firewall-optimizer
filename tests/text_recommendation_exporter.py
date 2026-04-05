"""
test_recommendation_exporter.py — Tests for the recommendation engine and exporter.

Run with:  pytest tests/test_recommendation_exporter.py -v
"""

import json
import pytest
from pathlib import Path

from parser.models import Action, FirewallRule, Protocol
from engine.conflict_engine import ConflictEngine, ConflictReport
from recommendation_engine import RecommendationEngine, Recommendation, FixType
from engine.conflict_engine import Severity
from exporter import Exporter


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def make_rule(rule_id="r1", priority=10, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
              dst_port=None, protocol=Protocol.TCP, action=Action.ALLOW,
              comment=None) -> FirewallRule:
    return FirewallRule(
        rule_id=rule_id, source="test", priority=priority, line_number=None,
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        protocol=protocol, action=action, comment=comment,
    )


def _make_conflicting_ruleset():
    """A deliberately problematic rule set for testing."""
    return [
        make_rule("catch_all_allow", 5,   src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                  dst_port=None, protocol=Protocol.ALL, action=Action.ALLOW,
                  comment=None),                                     # permissive
        make_rule("deny_rfc",        10,  src_ip="10.0.0.0/8", action=Action.DENY),  # shadowed
        make_rule("allow_ssh",       20,  src_ip="10.10.0.0/16", dst_port="22",
                  action=Action.ALLOW, comment="Allow SSH from mgmt"),
        make_rule("allow_ssh_dup",   30,  src_ip="10.10.0.0/16", dst_port="22",
                  action=Action.ALLOW),                              # duplicate
        make_rule("allow_http",      40,  dst_port="80",  action=Action.ALLOW),
        make_rule("allow_https",     50,  dst_port="443", action=Action.ALLOW),
    ]


def _analyze(rules):
    report = ConflictEngine().analyze(rules)
    recs   = RecommendationEngine().generate(report, None, rules)
    return report, recs


# ═══════════════════════════════════════════════════════════════════════════════
# RecommendationEngine tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRecommendationEngine:

    def test_returns_list_of_recommendations(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        assert isinstance(recs, list)
        assert all(isinstance(r, Recommendation) for r in recs)

    def test_critical_recs_before_low(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        # Impact scores should be non-increasing
        scores = [r.impact_score for r in recs]
        assert scores == sorted(scores, reverse=True)

    def test_permissive_rule_generates_narrow_recommendation(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        narrow = [r for r in recs if r.fix_type == FixType.NARROW_RULE]
        assert len(narrow) >= 1
        assert any("catch_all_allow" in r.affected_rules for r in narrow)

    def test_duplicate_generates_remove_recommendation(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        removes = [r for r in recs if r.fix_type == FixType.REMOVE_RULE]
        assert any("allow_ssh_dup" in r.affected_rules for r in removes)

    def test_no_default_deny_generates_add_recommendation(self):
        """A rule set without a catch-all deny should trigger ADD_DEFAULT_DENY."""
        rules = [
            make_rule("allow_all", 10, action=Action.ALLOW, protocol=Protocol.ALL),
        ]
        _, recs = _analyze(rules)
        add_deny = [r for r in recs if r.fix_type.value == "ADD_DEFAULT_DENY"]
        assert len(add_deny) >= 1

    def test_has_default_deny_no_add_recommendation(self):
        """A rule set that ends with a default deny should NOT trigger ADD_DEFAULT_DENY."""
        rules = [
            make_rule("allow_http",  10, dst_port="80",  action=Action.ALLOW),
            make_rule("default_deny",99, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                      dst_port=None, protocol=Protocol.ALL, action=Action.DENY),
        ]
        _, recs = _analyze(rules)
        add_deny = [r for r in recs if r.fix_type.value == "ADD_DEFAULT_DENY"]
        assert len(add_deny) == 0

    def test_undocumented_rules_flag(self):
        """More than 50% undocumented rules should trigger a DOCUMENT_RULE rec."""
        rules = [make_rule(f"r{i}", i * 10) for i in range(10)]
        _, recs = _analyze(rules)
        doc_recs = [r for r in recs if r.fix_type.value == "DOCUMENT_RULE"]
        assert len(doc_recs) >= 1

    def test_documented_rules_no_doc_flag(self):
        """If all rules have comments, no DOCUMENT_RULE rec should be generated."""
        rules = [
            make_rule(f"r{i}", i * 10, comment=f"This is rule {i}")
            for i in range(6)
        ]
        # Add a default deny to avoid ADD_DEFAULT_DENY noise
        rules.append(make_rule("deny", 999, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                               dst_port=None, protocol=Protocol.ALL, action=Action.DENY,
                               comment="Default deny"))
        _, recs = _analyze(rules)
        doc_recs = [r for r in recs if r.fix_type.value == "DOCUMENT_RULE"]
        assert len(doc_recs) == 0

    def test_rec_ids_are_sequential(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        ids = [r.rec_id for r in recs]
        assert ids == [f"REC-{i:04d}" for i in range(1, len(recs) + 1)]

    def test_to_dict_is_json_serializable(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        for rec in recs:
            d = rec.to_dict()
            json.dumps(d)  # must not raise

    def test_impact_score_range(self):
        rules = _make_conflicting_ruleset()
        _, recs = _analyze(rules)
        for rec in recs:
            assert 0.0 <= rec.impact_score <= 10.0

    def test_no_findings_minimal_recs(self):
        """A clean rule set should produce only heuristic recs (no-default-deny, docs)."""
        rules = [
            make_rule("allow_http",  10, dst_port="80",  action=Action.ALLOW,
                      comment="HTTP", protocol=Protocol.TCP),
            make_rule("allow_https", 20, dst_port="443", action=Action.ALLOW,
                      comment="HTTPS", protocol=Protocol.TCP),
            make_rule("deny_all",    99, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                      dst_port=None, protocol=Protocol.ALL, action=Action.DENY,
                      comment="Default deny"),
        ]
        _, recs = _analyze(rules)
        conflict_types = {FixType.REMOVE_RULE, FixType.NARROW_RULE,
                          FixType.REVIEW_RULE, FixType.SPLIT_RULE}
        conflict_recs = [r for r in recs if r.fix_type in conflict_types]
        assert len(conflict_recs) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Exporter tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestExporter:

    def _setup(self):
        rules = [
            make_rule("allow_ssh",   10, src_ip="10.10.0.0/16", dst_port="22",
                      protocol=Protocol.TCP, action=Action.ALLOW, comment="Mgmt SSH"),
            make_rule("allow_http",  20, dst_port="80",
                      protocol=Protocol.TCP, action=Action.ALLOW),
            make_rule("allow_https", 30, dst_port="443",
                      protocol=Protocol.TCP, action=Action.ALLOW),
            make_rule("deny_all",    99, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                      dst_port=None, protocol=Protocol.ALL, action=Action.DENY,
                      comment="Default deny"),
        ]
        report, recs = _analyze(rules)
        return rules, recs, report

    # ── iptables ──────────────────────────────────────────────────────────────

    def test_iptables_output_contains_chain(self, tmp_path):
        rules, _, _ = self._setup()
        path = str(tmp_path / "test.iptables")
        text = Exporter().to_iptables(rules, path)
        assert "-A INPUT" in text

    def test_iptables_contains_commit(self, tmp_path):
        rules, _, _ = self._setup()
        text = Exporter().to_iptables(rules, str(tmp_path / "r.iptables"))
        assert "COMMIT" in text

    def test_iptables_allow_becomes_accept(self, tmp_path):
        rules, _, _ = self._setup()
        text = Exporter().to_iptables(rules, str(tmp_path / "r.iptables"))
        assert "-j ACCEPT" in text

    def test_iptables_deny_becomes_drop(self, tmp_path):
        rules, _, _ = self._setup()
        text = Exporter().to_iptables(rules, str(tmp_path / "r.iptables"))
        assert "-j DROP" in text

    def test_iptables_dport_included(self, tmp_path):
        rules, _, _ = self._setup()
        text = Exporter().to_iptables(rules, str(tmp_path / "r.iptables"))
        assert "--dport 22" in text

    def test_iptables_comment_included(self, tmp_path):
        rules, _, _ = self._setup()
        text = Exporter().to_iptables(rules, str(tmp_path / "r.iptables"))
        assert "Mgmt SSH" in text

    def test_iptables_file_created(self, tmp_path):
        rules, _, _ = self._setup()
        path = tmp_path / "out.iptables"
        Exporter().to_iptables(rules, str(path))
        assert path.exists()

    # ── JSON ──────────────────────────────────────────────────────────────────

    def test_json_output_valid(self, tmp_path):
        rules, recs, report = self._setup()
        text = Exporter().to_json(rules, recs, str(tmp_path / "audit.json"), report)
        doc  = json.loads(text)
        assert "rules" in doc
        assert "recommendations" in doc

    def test_json_rule_count_matches(self, tmp_path):
        rules, recs, report = self._setup()
        text = Exporter().to_json(rules, recs, str(tmp_path / "audit.json"), report)
        doc  = json.loads(text)
        assert doc["summary"]["total_rules"] == len(rules)

    def test_json_recommendations_present(self, tmp_path):
        rules, recs, report = self._setup()
        text = Exporter().to_json(rules, recs, str(tmp_path / "audit.json"), report)
        doc  = json.loads(text)
        assert isinstance(doc["recommendations"], list)

    # ── YAML ──────────────────────────────────────────────────────────────────

    def test_yaml_starts_with_dashes(self, tmp_path):
        rules, recs, _ = self._setup()
        text = Exporter().to_yaml(rules, recs, str(tmp_path / "audit.yaml"))
        assert text.startswith("---")

    def test_yaml_contains_rules_key(self, tmp_path):
        rules, recs, _ = self._setup()
        text = Exporter().to_yaml(rules, recs, str(tmp_path / "audit.yaml"))
        assert "rules:" in text

    def test_yaml_contains_recommendations_key(self, tmp_path):
        rules, recs, _ = self._setup()
        text = Exporter().to_yaml(rules, recs, str(tmp_path / "audit.yaml"))
        assert "recommendations:" in text

    # ── Markdown ──────────────────────────────────────────────────────────────

    def test_markdown_has_header(self, tmp_path):
        rules, recs, report = self._setup()
        text = Exporter().to_markdown(rules, rules, recs, report, None,
                                       str(tmp_path / "audit.md"))
        assert "# Firewall Rule Audit Report" in text

    def test_markdown_has_executive_summary(self, tmp_path):
        rules, recs, report = self._setup()
        text = Exporter().to_markdown(rules, rules, recs, report, None,
                                       str(tmp_path / "audit.md"))
        assert "Executive Summary" in text

    def test_markdown_has_rule_table(self, tmp_path):
        rules, recs, report = self._setup()
        text = Exporter().to_markdown(rules, rules, recs, report, None,
                                       str(tmp_path / "audit.md"))
        assert "Current Rule Set" in text

    def test_markdown_contains_rec_ids(self, tmp_path):
        rules = _make_conflicting_ruleset()
        report, recs = _analyze(rules)
        text = Exporter().to_markdown(rules, rules, recs, report, None,
                                       str(tmp_path / "audit.md"))
        assert len(recs) > 0, "conflicting ruleset should produce recommendations"
        assert "REC-0001" in text

    # ── CSV ───────────────────────────────────────────────────────────────────

    def test_csv_has_header(self, tmp_path):
        _, recs, _ = self._setup()
        text = Exporter().to_csv(recs, str(tmp_path / "recs.csv"))
        assert "severity" in text
        assert "impact_score" in text

    def test_csv_row_count(self, tmp_path):
        _, recs, _ = self._setup()
        text = Exporter().to_csv(recs, str(tmp_path / "recs.csv"))
        lines = [l for l in text.splitlines() if l.strip()]
        assert len(lines) == len(recs) + 1  # +1 for header

    # ── export_all ────────────────────────────────────────────────────────────

    def test_export_all_creates_all_files(self, tmp_path):
        rules, recs, report = self._setup()
        paths = Exporter().export_all(
            str(tmp_path), rules, rules, recs, report
        )
        for fmt, path in paths.items():
            assert Path(path).exists(), f"Missing: {path} ({fmt})"

    def test_export_all_returns_six_formats(self, tmp_path):
        rules, recs, report = self._setup()
        paths = Exporter().export_all(str(tmp_path), rules, rules, recs, report)
        assert len(paths) == 6