"""
traffic_generator.py — Synthetic network traffic log generator for ML training.

Real traffic logs come from tools like:
  - iptables LOG target
  - AWS VPC Flow Logs
  - Cisco NetFlow / IPFIX
  - pfSense firewall logs

Since most students won't have production logs, this module generates
realistic synthetic traffic that mimics real-world distributions:

  - HTTP/HTTPS dominates (~60% of traffic)
  - SSH is rare but bursty (~5%)
  - DNS is frequent but tiny packets (~15%)
  - Port scans / noise appear occasionally
  - Internal subnet traffic is heavier than external

Usage:
    from ml.traffic_generator import TrafficGenerator, TrafficLog

    gen  = TrafficGenerator(seed=42)
    logs = gen.generate(n_packets=10_000)
    gen.save_csv(logs, "traffic_logs.csv")

    # Or load real logs from a CSV / VPC Flow Log file
    logs = TrafficGenerator.load_csv("real_traffic.csv")
"""

import csv
import random
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class TrafficLog:
    """A single observed network packet / connection record."""
    log_id:    str
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  str          # "tcp" | "udp" | "icmp"
    bytes_:    int          # packet / flow size in bytes
    action:    str          # "ALLOW" | "DENY" (what the current rule set decided)
    matched_rule_id: Optional[str] = None  # Which rule fired (if known)
    timestamp: Optional[str] = None


# ─── Traffic profile: (dst_port, protocol, weight, typical_src_subnet) ───────
_TRAFFIC_PROFILE = [
    # (port, proto, relative_weight, src_subnet_pool)
    (80,   "tcp", 30, ["0.0.0.0/0"]),           # HTTP — mostly external
    (443,  "tcp", 35, ["0.0.0.0/0"]),            # HTTPS — mostly external
    (53,   "udp", 15, ["10.0.0.0/8", "0.0.0.0/0"]),  # DNS
    (22,   "tcp",  4, ["10.10.0.0/16"]),         # SSH — management subnet only
    (3306, "tcp",  3, ["10.0.0.0/8"]),           # MySQL — internal only
    (5432, "tcp",  2, ["10.0.0.0/8"]),           # Postgres — internal only
    (8080, "tcp",  4, ["0.0.0.0/0"]),            # Alt-HTTP
    (6379, "tcp",  1, ["10.0.0.0/8"]),           # Redis — internal only
    (25,   "tcp",  1, ["0.0.0.0/0"]),            # SMTP
    (123,  "udp",  2, ["0.0.0.0/0"]),            # NTP
    (445,  "tcp",  1, ["10.0.0.0/8"]),           # SMB — internal
    (3389, "tcp",  1, ["10.10.0.0/16"]),         # RDP — management
    (0,    "icmp", 2, ["0.0.0.0/0"]),            # ICMP ping
]
_TOTAL_WEIGHT = sum(p[2] for p in _TRAFFIC_PROFILE)


def _random_ip(subnet: str, rng: random.Random) -> str:
    """Generate a random IP within a CIDR subnet without enumerating all hosts."""
    import ipaddress
    network = ipaddress.ip_network(subnet, strict=False)
    num_hosts = network.num_addresses
    if num_hosts <= 1:
        return str(network.network_address)
    # Pick a random offset within the network range
    offset = rng.randint(1, max(1, num_hosts - 2))  # skip network/broadcast
    ip_int = int(network.network_address) + offset
    return str(ipaddress.IPv4Address(ip_int))


class TrafficGenerator:
    """
    Generates synthetic network traffic logs with realistic port distributions.

    The generated traffic is designed to:
      1. Mirror real enterprise traffic patterns (HTTP/S dominant)
      2. Include both internal (RFC 1918) and external sources
      3. Have some "noisy" / scanner traffic that good rules should drop
    """

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)

    def generate(self, n_packets: int = 5000) -> list[TrafficLog]:
        """Generate n_packets synthetic traffic records."""
        logs = []
        for _ in range(n_packets):
            logs.append(self._make_packet())
        return logs

    def _make_packet(self) -> TrafficLog:
        # Weighted choice of traffic type
        r = self._rng.random() * _TOTAL_WEIGHT
        cumulative = 0.0
        profile = _TRAFFIC_PROFILE[-1]
        for p in _TRAFFIC_PROFILE:
            cumulative += p[2]
            if r <= cumulative:
                profile = p
                break

        port, proto, _, src_subnets = profile
        src_subnet = self._rng.choice(src_subnets)
        src_ip = _random_ip(src_subnet, self._rng)

        # Destination is always a "server" in 10.0.1.0/24
        dst_ip = _random_ip("10.0.1.0/24", self._rng)

        # Ephemeral source port (client side)
        src_port = self._rng.randint(1024, 65535) if proto != "icmp" else 0

        # Packet size: small for DNS/ICMP, larger for HTTP payloads
        if port in (53, 123) or proto == "icmp":
            bytes_ = self._rng.randint(40, 512)
        elif port in (80, 443, 8080):
            bytes_ = self._rng.randint(200, 65535)
        else:
            bytes_ = self._rng.randint(64, 4096)

        # Simulate action: most legitimate traffic is allowed; scanner/noisy ports denied
        action = "ALLOW" if port in (80, 443, 22, 53, 3306, 5432, 8080, 6379,
                                      25, 123, 445, 3389, 3306, 0) else "DENY"
        # Some traffic gets denied by ACL even for allowed ports
        if self._rng.random() < 0.05:
            action = "DENY"

        return TrafficLog(
            log_id   = f"log-{uuid.uuid4().hex[:8]}",
            src_ip   = src_ip,
            dst_ip   = dst_ip,
            src_port = src_port,
            dst_port = port,
            protocol = proto,
            bytes_   = bytes_,
            action   = action,
        )

    # ------------------------------------------------------------------ I/O

    def save_csv(self, logs: list[TrafficLog], filepath: str) -> None:
        """Save traffic logs to a CSV file."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "log_id", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "bytes_", "action", "matched_rule_id", "timestamp"
            ])
            writer.writeheader()
            for log in logs:
                writer.writerow(asdict(log))

    @staticmethod
    def load_csv(filepath: str) -> list[TrafficLog]:
        """Load traffic logs from a CSV file."""
        logs = []
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                logs.append(TrafficLog(
                    log_id   = row.get("log_id", ""),
                    src_ip   = row.get("src_ip", ""),
                    dst_ip   = row.get("dst_ip", ""),
                    src_port = int(row.get("src_port", 0) or 0),
                    dst_port = int(row.get("dst_port", 0) or 0),
                    protocol = row.get("protocol", "tcp"),
                    bytes_   = int(row.get("bytes_", 0) or 0),
                    action   = row.get("action", "ALLOW"),
                    matched_rule_id = row.get("matched_rule_id") or None,
                    timestamp = row.get("timestamp") or None,
                ))
        return logs