"""
test_conflict_engine.py — Tests for the conflict detection engine.

Run with:  pytest tests/test_conflict_engine.py -v
"""

import pytest
from parser.models import Action, FirewallRule, Protocol
from engine.ip_trie import IPTrie
from engine.port_interval import PortRange, port_relationship, ranges_overlap, range_contains
from engine.conflict_engine import (
    ConflictEngine, FindingType, Severity,
    _ip_relationship, _actions_opposite, _actions_same,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def make_rule(
    rule_id="r1", priority=10,
    src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
    src_port=None, dst_port=None,
    protocol=Protocol.TCP,
    action=Action.ALLOW,
    chain="INPUT",
) -> FirewallRule:
    return FirewallRule(
        rule_id=rule_id, source="test", priority=priority,
        line_number=None, src_ip=src_ip, dst_ip=dst_ip,
        src_port=src_port, dst_port=dst_port, protocol=protocol,
        action=action, chain=chain,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# IPTrie tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestIPTrie:

    def test_exact_lookup(self):
        trie = IPTrie()
        r = make_rule(src_ip="10.0.0.0/8")
        trie.insert("10.0.0.0/8", r)
        assert trie.exact("10.0.0.0/8") == [r]

    def test_ancestors_finds_broader_prefix(self):
        trie = IPTrie()
        broad = make_rule(rule_id="broad", src_ip="10.0.0.0/8")
        narrow = make_rule(rule_id="narrow", src_ip="10.1.0.0/16")
        trie.insert("10.0.0.0/8",   broad)
        trie.insert("10.1.0.0/16",  narrow)
        anc = trie.ancestors("10.1.0.0/16")
        assert broad in anc
        assert narrow not in anc

    def test_descendants_finds_narrower_prefix(self):
        trie = IPTrie()
        broad  = make_rule(rule_id="broad",  src_ip="10.0.0.0/8")
        narrow = make_rule(rule_id="narrow", src_ip="10.1.0.0/16")
        trie.insert("10.0.0.0/8",   broad)
        trie.insert("10.1.0.0/16",  narrow)
        desc = trie.descendants("10.0.0.0/8")
        assert narrow in desc
        assert broad not in desc

    def test_disjoint_prefixes_no_relation(self):
        trie = IPTrie()
        r1 = make_rule(rule_id="r1", src_ip="10.0.0.0/8")
        r2 = make_rule(rule_id="r2", src_ip="192.168.0.0/16")
        trie.insert("10.0.0.0/8",      r1)
        trie.insert("192.168.0.0/16",  r2)
        assert trie.ancestors("192.168.0.0/16") == []
        assert trie.descendants("10.0.0.0/8")   == []

    def test_host_route_in_subnet(self):
        trie = IPTrie()
        subnet = make_rule(rule_id="subnet", src_ip="10.0.0.0/24")
        trie.insert("10.0.0.0/24", subnet)
        anc = trie.ancestors("10.0.0.1/32")
        assert subnet in anc

    def test_all_rules_returns_everything(self):
        trie = IPTrie()
        rules = [make_rule(rule_id=f"r{i}") for i in range(5)]
        for r in rules:
            trie.insert(r.src_ip, r)
        all_r = trie.all_rules()
        assert len(all_r) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# PortRange tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPortInterval:

    def test_parse_single_port(self):
        p = PortRange.parse("80")
        assert p == PortRange(80, 80)

    def test_parse_range(self):
        p = PortRange.parse("1024:65535")
        assert p == PortRange(1024, 65535)

    def test_parse_none_is_any(self):
        p = PortRange.parse(None)
        assert p.is_any

    def test_overlap_partial(self):
        a = PortRange.parse("1:1024")
        b = PortRange.parse("512:2048")
        assert ranges_overlap(a, b)

    def test_no_overlap(self):
        a = PortRange.parse("80")
        b = PortRange.parse("443")
        assert not ranges_overlap(a, b)

    def test_contains(self):
        outer = PortRange.parse("0:1024")
        inner = PortRange.parse("80")
        assert range_contains(outer, inner)
        assert not range_contains(inner, outer)

    def test_any_contains_everything(self):
        any_port  = PortRange.parse(None)
        specific  = PortRange.parse("8080")
        assert range_contains(any_port, specific)

    def test_port_relationship_equal(self):
        assert port_relationship(PortRange.parse("80"), PortRange.parse("80")) == "equal"

    def test_port_relationship_a_contains(self):
        assert port_relationship(PortRange.parse("1:1024"), PortRange.parse("80")) == "a_contains"

    def test_port_relationship_disjoint(self):
        assert port_relationship(PortRange.parse("80"), PortRange.parse("443")) == "disjoint"

    def test_port_relationship_overlap(self):
        assert port_relationship(PortRange.parse("1:500"), PortRange.parse("400:1000")) == "overlap"


# ═══════════════════════════════════════════════════════════════════════════════
# IP relationship helper tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestIPRelationship:

    def test_equal(self):
        assert _ip_relationship("10.0.0.0/8", "10.0.0.0/8") == "equal"

    def test_a_contains_b(self):
        assert _ip_relationship("10.0.0.0/8", "10.1.0.0/16") == "a_contains"

    def test_b_contains_a(self):
        assert _ip_relationship("10.1.0.0/16", "10.0.0.0/8") == "b_contains"

    def test_disjoint(self):
        assert _ip_relationship("10.0.0.0/8", "192.168.0.0/16") == "disjoint"

    def test_host_in_subnet(self):
        assert _ip_relationship("192.168.1.0/24", "192.168.1.5/32") == "a_contains"

    def test_any_contains_everything(self):
        assert _ip_relationship("0.0.0.0/0", "10.0.0.0/8") == "a_contains"


# ═══════════════════════════════════════════════════════════════════════════════
# ConflictEngine tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestConflictEngineNoFindings:

    def test_single_rule_no_findings(self):
        rules = [make_rule()]
        report = ConflictEngine().analyze(rules)
        assert report.clean

    def test_disjoint_rules_no_findings(self):
        rules = [
            make_rule("r1", 10, src_ip="10.0.0.0/8",    dst_port="80",  action=Action.ALLOW),
            make_rule("r2", 20, src_ip="192.168.0.0/16", dst_port="443", action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        assert report.clean

    def test_different_protocols_no_findings(self):
        rules = [
            make_rule("r1", 10, protocol=Protocol.TCP, dst_port="53", action=Action.DENY),
            make_rule("r2", 20, protocol=Protocol.UDP, dst_port="53", action=Action.ALLOW),
        ]
        report = ConflictEngine().analyze(rules)
        assert report.clean


class TestShadowDetection:

    def test_broad_allow_shadows_narrow_allow(self):
        """A /8 ALLOW rule before a /24 ALLOW rule → shadow."""
        rules = [
            make_rule("broad",  10, src_ip="10.0.0.0/8",   dst_port="80", action=Action.ALLOW),
            make_rule("narrow", 20, src_ip="10.1.0.0/24",  dst_port="80", action=Action.ALLOW),
        ]
        report = ConflictEngine().analyze(rules)
        shadows = report.by_type(FindingType.SHADOW)
        assert len(shadows) == 1
        assert shadows[0].rule_a.rule_id == "broad"
        assert shadows[0].rule_b.rule_id == "narrow"

    def test_any_deny_shadows_specific_deny(self):
        """0.0.0.0/0 DENY before specific DENY → shadow."""
        rules = [
            make_rule("all_deny",  10, src_ip="0.0.0.0/0",    action=Action.DENY),
            make_rule("spec_deny", 20, src_ip="10.0.0.0/8",   action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        shadows = report.by_type(FindingType.SHADOW)
        assert any(f.rule_b.rule_id == "spec_deny" for f in shadows)

    def test_shadow_severity_is_high(self):
        rules = [
            make_rule("a", 10, src_ip="10.0.0.0/8",  dst_port="443", action=Action.ALLOW),
            make_rule("b", 20, src_ip="10.1.0.0/16", dst_port="443", action=Action.ALLOW),
        ]
        report = ConflictEngine().analyze(rules)
        for f in report.by_type(FindingType.SHADOW):
            assert f.severity == Severity.HIGH


class TestContradictionDetection:

    def test_broad_allow_contradicts_narrow_deny(self):
        """0.0.0.0/0 ALLOW before 10.0.0.0/8 DENY → critical contradiction."""
        rules = [
            make_rule("allow_all", 10, src_ip="0.0.0.0/0",  action=Action.ALLOW),
            make_rule("deny_rfc",  20, src_ip="10.0.0.0/8", action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        contradictions = report.by_type(FindingType.CONTRADICTION)
        assert len(contradictions) == 1
        assert contradictions[0].severity == Severity.CRITICAL

    def test_overlapping_subnets_opposite_actions(self):
        """Two overlapping port ranges with opposite actions."""
        rules = [
            make_rule("r1", 10, dst_port="1:1024",  action=Action.ALLOW),
            make_rule("r2", 20, dst_port="512:2048", action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        contradictions = report.by_type(FindingType.CONTRADICTION)
        assert len(contradictions) >= 1

    def test_narrow_allow_before_broad_deny_not_contradiction(self):
        """
        Specific ALLOW before broad DENY is correct firewall practice — not a contradiction.
        e.g. allow SSH from mgmt, then deny all SSH.
        """
        rules = [
            make_rule("allow_mgmt", 10, src_ip="10.10.0.0/24", dst_port="22", action=Action.ALLOW),
            make_rule("deny_ssh",   20, src_ip="0.0.0.0/0",    dst_port="22", action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        # This is NOT a contradiction — it's intentional tiered access
        contradictions = report.by_type(FindingType.CONTRADICTION)
        assert len(contradictions) == 0

    def test_contradiction_suggestion_mentions_priority(self):
        rules = [
            make_rule("a", 10, src_ip="0.0.0.0/0", action=Action.ALLOW),
            make_rule("b", 20, src_ip="10.0.0.0/8", action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        c = report.by_type(FindingType.CONTRADICTION)
        assert len(c) > 0
        assert "priority" in c[0].suggestion.lower() or "before" in c[0].suggestion.lower()


class TestDuplicateDetection:

    def test_identical_rules_flagged(self):
        rule_a = make_rule("r1", 10, src_ip="10.0.0.0/8", dst_port="80", action=Action.ALLOW)
        rule_b = make_rule("r2", 20, src_ip="10.0.0.0/8", dst_port="80", action=Action.ALLOW)
        report = ConflictEngine().analyze([rule_a, rule_b])
        dups = report.by_type(FindingType.DUPLICATE)
        assert len(dups) == 1
        assert dups[0].rule_b.rule_id == "r2"

    def test_duplicate_severity_is_medium(self):
        rule_a = make_rule("r1", 10, dst_port="443")
        rule_b = make_rule("r2", 20, dst_port="443")
        report = ConflictEngine().analyze([rule_a, rule_b])
        dups = report.by_type(FindingType.DUPLICATE)
        assert all(d.severity == Severity.MEDIUM for d in dups)

    def test_same_match_different_action_not_duplicate(self):
        """Same match space but different actions → contradiction, not duplicate."""
        rule_a = make_rule("r1", 10, dst_port="80", action=Action.ALLOW)
        rule_b = make_rule("r2", 20, dst_port="80", action=Action.DENY)
        report = ConflictEngine().analyze([rule_a, rule_b])
        dups = report.by_type(FindingType.DUPLICATE)
        assert len(dups) == 0


class TestRedundantDetection:

    def test_same_src_dst_port_flagged(self):
        """Two rules with identical match AND action → redundant."""
        rule_a = make_rule("r1", 10, src_ip="192.168.1.0/24", dst_port="443")
        rule_b = make_rule("r2", 20, src_ip="192.168.1.0/24", dst_port="443")
        report = ConflictEngine().analyze([rule_a, rule_b])
        # Could be duplicate OR redundant depending on chain equality
        assert (
            len(report.by_type(FindingType.DUPLICATE)) > 0 or
            len(report.by_type(FindingType.REDUNDANT)) > 0
        )


class TestPermissiveDetection:

    def test_catch_all_allow_flagged(self):
        rules = [
            make_rule("catch_all", 10, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                      dst_port=None, protocol=Protocol.ALL, action=Action.ALLOW),
        ]
        report = ConflictEngine().analyze(rules)
        perm = report.by_type(FindingType.PERMISSIVE)
        assert len(perm) == 1
        assert perm[0].severity == Severity.MEDIUM

    def test_specific_allow_not_permissive(self):
        rules = [
            make_rule("specific", 10, src_ip="10.0.0.0/8", dst_port="443",
                      protocol=Protocol.TCP, action=Action.ALLOW),
        ]
        report = ConflictEngine().analyze(rules)
        assert len(report.by_type(FindingType.PERMISSIVE)) == 0

    def test_catch_all_deny_not_flagged(self):
        """Default-deny catch-all is perfectly normal — should not be flagged."""
        rules = [
            make_rule("default_deny", 999, src_ip="0.0.0.0/0", dst_ip="0.0.0.0/0",
                      dst_port=None, protocol=Protocol.ALL, action=Action.DENY),
        ]
        report = ConflictEngine().analyze(rules)
        assert len(report.by_type(FindingType.PERMISSIVE)) == 0


class TestReportStructure:

    def _complex_ruleset(self):
        return [
            make_rule("r1",  10,  src_ip="0.0.0.0/0",    dst_port="22",  action=Action.ALLOW),
            make_rule("r2",  20,  src_ip="10.0.0.0/8",   dst_port="22",  action=Action.DENY),   # contradiction
            make_rule("r3",  30,  src_ip="10.1.0.0/16",  dst_port="22",  action=Action.ALLOW),  # shadow of r1
            make_rule("r4",  40,  src_ip="10.1.0.0/16",  dst_port="22",  action=Action.ALLOW),  # dup of r3
            make_rule("r5",  50,  src_ip="0.0.0.0/0",    dst_ip="0.0.0.0/0",
                      dst_port=None, protocol=Protocol.ALL, action=Action.ALLOW),                # permissive
        ]

    def test_summary_string_contains_counts(self):
        report = ConflictEngine().analyze(self._complex_ruleset())
        s = report.summary()
        assert "rules scanned" in s
        assert "Critical" in s

    def test_to_dict_is_serializable(self):
        import json
        report = ConflictEngine().analyze(self._complex_ruleset())
        d = report.to_dict()
        serialized = json.dumps(d)  # should not raise
        assert '"findings"' in serialized

    def test_findings_sorted_critical_first(self):
        report = ConflictEngine().analyze(self._complex_ruleset())
        if len(report.findings) > 1:
            severities = [f.severity for f in report.findings]
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            indices = [order.index(s.value) for s in severities]
            assert indices == sorted(indices)

    def test_count_attributes_populated(self):
        report = ConflictEngine().analyze(self._complex_ruleset())
        total = (
            report.shadow_count + report.redundant_count +
            report.contradiction_count + report.duplicate_count +
            report.permissive_count
        )
        assert total == len(report.findings)