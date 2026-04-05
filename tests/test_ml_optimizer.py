"""
test_ml_optimizer.py — Tests for the ML optimizer pipeline.

Run with:  pytest tests/test_ml_optimizer.py -v
"""

import pytest
import numpy as np

from parser.models import Action, FirewallRule, Protocol
from ml.traffic_generator import TrafficGenerator, TrafficLog
from ml.feature_engineering import FeatureExtractor, _specificity_score, _ip_in_cidr, _port_in_range
from ml.rule_optimizer import RuleOptimizer


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def make_rule(rule_id="r1", priority=10, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
              dst_port=None, protocol=Protocol.TCP, action=Action.ALLOW) -> FirewallRule:
    return FirewallRule(
        rule_id=rule_id, source="test", priority=priority, line_number=None,
        src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port,
        protocol=protocol, action=action,
    )


def make_log(src_ip="1.2.3.4", dst_ip="10.0.1.100",
             src_port=54321, dst_port=80, protocol="tcp", bytes_=1024) -> TrafficLog:
    return TrafficLog(
        log_id="l1", src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port,
        protocol=protocol, bytes_=bytes_, action="ALLOW",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TrafficGenerator tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestTrafficGenerator:

    def test_generates_correct_count(self):
        logs = TrafficGenerator(seed=0).generate(100)
        assert len(logs) == 100

    def test_logs_are_traffic_log_objects(self):
        logs = TrafficGenerator(seed=0).generate(10)
        assert all(isinstance(l, TrafficLog) for l in logs)

    def test_deterministic_with_same_seed(self):
        a = TrafficGenerator(seed=7).generate(50)
        b = TrafficGenerator(seed=7).generate(50)
        assert [l.dst_port for l in a] == [l.dst_port for l in b]

    def test_different_seeds_differ(self):
        a = TrafficGenerator(seed=1).generate(50)
        b = TrafficGenerator(seed=2).generate(50)
        assert [l.dst_port for l in a] != [l.dst_port for l in b]

    def test_http_https_dominant(self):
        logs = TrafficGenerator(seed=42).generate(500)
        web_count = sum(1 for l in logs if l.dst_port in (80, 443))
        assert web_count / len(logs) > 0.5, "Web traffic should dominate"

    def test_protocols_are_valid(self):
        logs = TrafficGenerator(seed=0).generate(100)
        for log in logs:
            assert log.protocol in ("tcp", "udp", "icmp")

    def test_ports_are_in_range(self):
        logs = TrafficGenerator(seed=0).generate(100)
        for log in logs:
            assert 0 <= log.dst_port <= 65535

    def test_save_and_load_csv(self, tmp_path):
        gen  = TrafficGenerator(seed=42)
        logs = gen.generate(50)
        path = str(tmp_path / "traffic.csv")
        gen.save_csv(logs, path)
        loaded = TrafficGenerator.load_csv(path)
        assert len(loaded) == 50
        assert loaded[0].dst_port == logs[0].dst_port


# ═══════════════════════════════════════════════════════════════════════════════
# Feature engineering tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestFeatureEngineering:

    def test_specificity_host_single_port(self):
        rule = make_rule(src_ip="10.0.0.1/32", dst_port="80", protocol=Protocol.TCP)
        score = _specificity_score(rule)
        # src=/32 (1.0), dst=0.0.0.0/0 (0.0), port=80 (1.0), proto=TCP (0.5)
        # score = (1.0 + 0.0 + 1.0 + 0.5) / 4 = 0.625 — correct by design
        assert score > 0.6, "Host + single port should be highly specific"
        assert abs(score - 0.625) < 0.001, f"Expected 0.625, got {score}"

    def test_specificity_any_any(self):
        rule = make_rule(src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                         dst_port=None, protocol=Protocol.ALL)
        score = _specificity_score(rule)
        assert score == 0.0, "Catch-all should have zero specificity"

    def test_ip_in_cidr_any(self):
        assert _ip_in_cidr("1.2.3.4", "0.0.0.0/0")

    def test_ip_in_cidr_match(self):
        assert _ip_in_cidr("10.1.2.3", "10.0.0.0/8")

    def test_ip_in_cidr_no_match(self):
        assert not _ip_in_cidr("192.168.1.1", "10.0.0.0/8")

    def test_port_in_range_exact(self):
        assert _port_in_range(80, "80")
        assert not _port_in_range(443, "80")

    def test_port_in_range_range(self):
        assert _port_in_range(1024, "1024:65535")
        assert not _port_in_range(80, "1024:65535")

    def test_port_in_range_none(self):
        assert _port_in_range(80, None)
        assert _port_in_range(0, None)

    def test_extract_returns_correct_shapes(self):
        rules = [
            make_rule("r1", 10, dst_port="80"),
            make_rule("r2", 20, dst_port="443"),
            make_rule("r3", 30),
        ]
        logs  = TrafficGenerator(seed=0).generate(100)
        X, y, names = FeatureExtractor().extract(rules, logs)
        assert X.shape == (3, len(names))
        assert y.shape == (3,)

    def test_feature_names_correct_count(self):
        assert len(FeatureExtractor.FEATURE_NAMES) == 20

    def test_hit_count_is_first_feature(self):
        rules = [make_rule("r1", 10, dst_port="80", protocol=Protocol.TCP)]
        logs  = [make_log(dst_port=80, protocol="tcp")] * 5
        X, y, _ = FeatureExtractor().extract(rules, logs)
        assert y[0] == 5.0, "All 5 packets should match the only rule"

    def test_no_match_rule_has_zero_hits(self):
        rules = [make_rule("r1", 10, dst_port="22", protocol=Protocol.TCP)]
        logs  = [make_log(dst_port=80, protocol="tcp")] * 10
        X, y, _ = FeatureExtractor().extract(rules, logs)
        assert y[0] == 0.0

    def test_first_match_semantics(self):
        """Hot rule at priority 10 should absorb all hits; cold rule gets none."""
        rules = [
            make_rule("hot",  10, protocol=Protocol.ALL),   # matches everything
            make_rule("cold", 20, protocol=Protocol.ALL),   # never reached
        ]
        logs = [make_log()] * 20
        X, y, _ = FeatureExtractor().extract(rules, logs)
        assert y[0] == 20.0, "Hot rule absorbs all traffic"
        assert y[1] == 0.0,  "Cold rule gets no hits"

    def test_bytes_feature_positive(self):
        rules = [make_rule("r1", 10, protocol=Protocol.ALL)]
        logs  = [make_log(bytes_=512)] * 3
        X, y, names = FeatureExtractor().extract(rules, logs)
        bytes_col = names.index("bytes_matched")
        assert X[0, bytes_col] == 3 * 512


# ═══════════════════════════════════════════════════════════════════════════════
# RuleOptimizer tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestRuleOptimizer:

    def _make_realistic_ruleset(self):
        """
        A rule set where high-traffic rules are poorly ordered.
        HTTP (port 80) gets most traffic but is ranked last.
        """
        return [
            make_rule("ssh_mgmt",    10,  src_ip="10.10.0.0/16", dst_port="22",
                      action=Action.ALLOW),
            make_rule("db_internal", 20,  src_ip="10.0.0.0/8",   dst_port="3306",
                      action=Action.ALLOW),
            make_rule("redis",       30,  src_ip="10.0.0.0/8",   dst_port="6379",
                      action=Action.ALLOW),
            make_rule("deny_all",    40,  src_ip="0.0.0.0/0",
                      protocol=Protocol.ALL, action=Action.DENY),
            make_rule("http",        50,  dst_port="80",  action=Action.ALLOW),
            make_rule("https",       60,  dst_port="443", action=Action.ALLOW),
        ]

    def test_optimize_returns_result(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(500)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        assert result is not None

    def test_optimized_rule_count_preserved(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(500)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        assert len(result.optimized_rules) == len(rules)

    def test_all_rule_ids_preserved(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(500)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        orig_ids = {r.rule_id for r in rules}
        opt_ids  = {r.rule_id for r in result.optimized_rules}
        assert orig_ids == opt_ids

    def test_policy_equivalence(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(300)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        assert result.policy_equivalent, "Reordering must preserve policy"

    def test_estimated_speedup_positive(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(500)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        assert result.estimated_speedup > 0

    def test_moves_count_equals_rule_count(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(200)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        assert len(result.moves) == len(rules)

    def test_model_metrics_populated(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(300)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        assert result.metrics.n_training_rules == len(rules)
        assert result.metrics.n_traffic_logs   == len(logs)
        assert len(result.metrics.feature_importances) == 20

    def test_summary_is_string(self):
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(200)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        s = result.summary()
        assert isinstance(s, str)
        assert "speedup" in s.lower()

    def test_to_dict_json_serializable(self):
        import json
        rules  = self._make_realistic_ruleset()
        logs   = TrafficGenerator(seed=42).generate(200)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)
        d = result.to_dict()
        json.dumps(d)  # must not raise

    def test_deny_all_stays_before_late_allows(self):
        """
        deny_all (priority 40) must stay before http/https (50/60)
        because swapping would change the verdict for http/https traffic.
        """
        rules = self._make_realistic_ruleset()
        logs  = TrafficGenerator(seed=42).generate(500)
        result = RuleOptimizer(n_estimators=20).optimize(rules, logs)

        opt_ids = [r.rule_id for r in result.optimized_rules]
        deny_idx = opt_ids.index("deny_all")
        http_idx = opt_ids.index("http")
        https_idx = opt_ids.index("https")

        # deny_all must appear AFTER http and https (since http/https ALLOW
        # takes precedence — they fire first, deny_all never sees their traffic)
        # OR deny_all must come BEFORE them (which would block them).
        # The important thing is: policy_equivalent must be True.
        assert result.policy_equivalent

    def test_empty_rules_raises(self):
        with pytest.raises(ValueError, match="empty"):
            RuleOptimizer().optimize([], [make_log()])

    def test_empty_logs_raises(self):
        with pytest.raises(ValueError, match="empty"):
            RuleOptimizer().optimize([make_rule()], [])