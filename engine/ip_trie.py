"""
ip_trie.py — Binary IP prefix trie for O(prefix_length) subnet containment checks.

Instead of comparing every rule pair naively (O(n²) × O(32) per comparison),
we build a trie over all src/dst CIDRs so we can answer:
  "Is network A a subset of / superset of / equal to network B?"
in O(prefix_length) time.

This module is intentionally standalone — no dependency on FirewallRule —
so it can be unit-tested and reused independently.

Usage:
    trie = IPTrie()
    trie.insert("10.0.0.0/8",  rule_a)
    trie.insert("10.1.0.0/16", rule_b)

    # Are there any rules whose network contains 10.1.0.0/16?
    ancestors = trie.ancestors("10.1.0.0/16")   # → [rule_a]

    # Are there any rules whose network is contained by 10.0.0.0/8?
    descendants = trie.descendants("10.0.0.0/8") # → [rule_b]
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class _TrieNode:
    children: dict = field(default_factory=dict)   # {0: node, 1: node}
    rules: list = field(default_factory=list)       # rules anchored at this prefix
    prefix: Optional[str] = None                   # CIDR string, set when a rule is stored here


class IPTrie:
    """
    Binary trie over IPv4 prefixes.

    Each level represents one bit of the 32-bit address. A node at depth d
    represents a /d prefix. Rules are stored at the node matching their
    exact prefix length.
    """

    def __init__(self):
        self._root = _TrieNode()

    # ------------------------------------------------------------------ write

    def insert(self, cidr: str, rule: Any) -> None:
        """Insert a rule under its CIDR prefix."""
        network = self._parse(cidr)
        node    = self._root
        bits    = self._to_bits(network)

        for bit in bits:
            if bit not in node.children:
                node.children[bit] = _TrieNode()
            node = node.children[bit]

        node.rules.append(rule)
        node.prefix = str(network)

    # ------------------------------------------------------------------ read

    def ancestors(self, cidr: str) -> list:
        """
        Return all rules stored at prefixes that are proper supersets of `cidr`.

        e.g. ancestors("10.1.0.0/16") returns rules for "10.0.0.0/8" and
        "10.0.0.0/24" if they exist — anything broader that would match
        every packet the given prefix would also match.
        """
        network = self._parse(cidr)
        node    = self._root
        bits    = self._to_bits(network)
        found   = []

        # Collect rules at every node we pass through before reaching
        # the exact prefix node (those nodes = shorter/broader prefixes)
        for bit in bits:
            if node.rules:
                found.extend(node.rules)
            if bit not in node.children:
                break
            node = node.children[bit]

        return found

    def descendants(self, cidr: str) -> list:
        """
        Return all rules stored at prefixes that are proper subsets of `cidr`.

        e.g. descendants("10.0.0.0/8") returns rules for "10.1.0.0/16",
        "10.2.3.0/24", etc. — but NOT rules stored at "10.0.0.0/8" itself.
        """
        network  = self._parse(cidr)
        bits     = self._to_bits(network)
        # Navigate to the node for this exact prefix
        node = self._root
        for bit in bits:
            if bit not in node.children:
                return []
            node = node.children[bit]

        # Collect only the subtrees of child nodes — exclude this node's own rules
        result = []
        for child in node.children.values():
            result.extend(self._collect_subtree(child))
        return result

    def exact(self, cidr: str) -> list:
        """Return rules stored at exactly this CIDR."""
        network = self._parse(cidr)
        node    = self._root
        for bit in self._to_bits(network):
            if bit not in node.children:
                return []
            node = node.children[bit]
        return list(node.rules)

    def all_rules(self) -> list:
        """Return all rules in the trie (in prefix order)."""
        return self._collect_subtree(self._root)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _parse(cidr: str) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(cidr, strict=False)

    @staticmethod
    def _to_bits(network: ipaddress.IPv4Network) -> list[int]:
        """Return the significant bits of the network address (up to prefix_length)."""
        addr_int = int(network.network_address)
        prefix   = network.prefixlen
        bits = []
        for shift in range(31, 31 - prefix, -1):
            bits.append((addr_int >> shift) & 1)
        return bits

    def _collect_subtree(self, node: _TrieNode) -> list:
        result = list(node.rules)
        for child in node.children.values():
            result.extend(self._collect_subtree(child))
        return result