"""
aws_sg_parser.py — Parse AWS Security Group rules (JSON from AWS CLI / Boto3).

Handles the exact structure returned by:
    aws ec2 describe-security-groups --output json

and the simplified format from Boto3:
    ec2.describe_security_groups()

Expected structure (abbreviated):
{
  "SecurityGroups": [
    {
      "GroupId": "sg-0abc1234",
      "GroupName": "web-servers",
      "Description": "Web tier SG",
      "IpPermissions": [           ← inbound rules
        {
          "IpProtocol": "tcp",
          "FromPort": 443,
          "ToPort": 443,
          "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Public HTTPS"}],
          "Ipv6Ranges": [],
          "UserIdGroupPairs": []
        }
      ],
      "IpPermissionsEgress": [     ← outbound rules
        {
          "IpProtocol": "-1",
          "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
        }
      ]
    }
  ]
}

Usage:
    from parser.aws_sg_parser import AWSSGParser
    rules = AWSSGParser().parse_file("security_groups.json")
"""

import json
import uuid
from typing import Optional
from .models import Action, FirewallRule, Protocol


_PROTO_MAP = {
    "tcp":  Protocol.TCP,
    "udp":  Protocol.UDP,
    "icmp": Protocol.ICMP,
    "-1":   Protocol.ALL,   # AWS uses "-1" for "all traffic"
    "all":  Protocol.ALL,
}


class AWSSGParser:
    """
    Parses AWS Security Group JSON (from CLI or Boto3) into FirewallRule objects.

    Key design notes:
    - All inbound rules → Action.ALLOW  (SGs are allow-only; default deny is implicit)
    - All outbound rules → Action.ALLOW
    - chain is set to "inbound" or "outbound"
    - UserIdGroupPairs (SG-to-SG rules) are recorded with src_ip = "sg:<GroupId>"
    - Port range -1 (all ports) → dst_port = None
    """

    def parse_file(self, filepath: str) -> list[FirewallRule]:
        with open(filepath, "r") as f:
            data = json.load(f)
        return self.parse_dict(data)

    def parse_text(self, text: str) -> list[FirewallRule]:
        return self.parse_dict(json.loads(text))

    def parse_dict(self, data: dict) -> list[FirewallRule]:
        """Accept the full describe-security-groups response dict."""
        groups = data.get("SecurityGroups", [])
        if not groups and isinstance(data, list):
            groups = data  # Handle a bare list of SG objects

        rules: list[FirewallRule] = []
        priority = 0

        for sg in groups:
            group_id   = sg.get("GroupId", "unknown")
            group_name = sg.get("GroupName", group_id)
            sg_comment = sg.get("Description", "")

            # Inbound rules
            for perm in sg.get("IpPermissions", []):
                new_rules = self._expand_permission(
                    perm, "inbound", group_id, group_name, sg_comment, priority
                )
                rules.extend(new_rules)
                priority += len(new_rules)

            # Outbound rules
            for perm in sg.get("IpPermissionsEgress", []):
                new_rules = self._expand_permission(
                    perm, "outbound", group_id, group_name, sg_comment, priority
                )
                rules.extend(new_rules)
                priority += len(new_rules)

        return rules

    # ------------------------------------------------------------------ helpers

    def _expand_permission(
        self,
        perm: dict,
        direction: str,
        group_id: str,
        group_name: str,
        sg_comment: str,
        base_priority: int,
    ) -> list[FirewallRule]:
        """
        A single AWS IpPermission can target multiple CIDR ranges.
        We expand each CIDR into its own FirewallRule.
        """
        rules = []

        proto_raw = perm.get("IpProtocol", "-1")
        protocol  = _PROTO_MAP.get(proto_raw.lower(), Protocol.ALL)

        from_port = perm.get("FromPort")  # None if protocol is "-1"
        to_port   = perm.get("ToPort")
        dst_port  = self._build_port_string(from_port, to_port)

        # IPv4 CIDR ranges
        for i, ip_range in enumerate(perm.get("IpRanges", [])):
            cidr        = ip_range.get("CidrIp", "0.0.0.0/0")
            description = ip_range.get("Description", "")

            rules.append(self._make_rule(
                direction    = direction,
                src_ip       = cidr if direction == "inbound" else "0.0.0.0/0",
                dst_ip       = "0.0.0.0/0" if direction == "inbound" else cidr,
                dst_port     = dst_port,
                protocol     = protocol,
                group_id     = group_id,
                group_name   = group_name,
                comment      = description or sg_comment,
                priority     = base_priority + i,
                tags         = ["ipv4"],
            ))

        # IPv6 CIDR ranges
        for i, ip_range in enumerate(perm.get("Ipv6Ranges", [])):
            cidr        = ip_range.get("CidrIpv6", "::/0")
            description = ip_range.get("Description", "")

            rules.append(self._make_rule(
                direction  = direction,
                src_ip     = cidr if direction == "inbound" else "::/0",
                dst_ip     = "::/0" if direction == "inbound" else cidr,
                dst_port   = dst_port,
                protocol   = protocol,
                group_id   = group_id,
                group_name = group_name,
                comment    = description or sg_comment,
                priority   = base_priority + len(perm.get("IpRanges", [])) + i,
                tags       = ["ipv6"],
            ))

        # SG-to-SG rules (UserIdGroupPairs)
        for i, pair in enumerate(perm.get("UserIdGroupPairs", [])):
            ref_sg_id = pair.get("GroupId", "unknown-sg")
            rules.append(self._make_rule(
                direction  = direction,
                src_ip     = f"sg:{ref_sg_id}",   # not a real CIDR but parseable
                dst_ip     = "0.0.0.0/0",
                dst_port   = dst_port,
                protocol   = protocol,
                group_id   = group_id,
                group_name = group_name,
                comment    = f"SG reference: {ref_sg_id}",
                priority   = base_priority + len(perm.get("IpRanges", [])) + i,
                tags       = ["sg-reference"],
            ))

        # If no targets at all, emit one catch-all rule
        if not rules:
            rules.append(self._make_rule(
                direction  = direction,
                src_ip     = "0.0.0.0/0",
                dst_ip     = "0.0.0.0/0",
                dst_port   = dst_port,
                protocol   = protocol,
                group_id   = group_id,
                group_name = group_name,
                comment    = sg_comment,
                priority   = base_priority,
                tags       = ["no-source-specified"],
            ))

        return rules

    @staticmethod
    def _make_rule(
        direction: str,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[str],
        protocol: Protocol,
        group_id: str,
        group_name: str,
        comment: str,
        priority: int,
        tags: list,
    ) -> FirewallRule:
        return FirewallRule(
            rule_id     = f"awssg-{uuid.uuid4().hex[:8]}",
            source      = "aws_sg",
            priority    = priority,
            line_number = None,
            src_ip      = src_ip,
            dst_ip      = dst_ip,
            dst_port    = dst_port,
            protocol    = protocol,
            # AWS SGs are stateful allow-only; there's no explicit deny in rules
            action      = Action.ALLOW,
            chain       = direction,
            comment     = comment or None,
            tags        = tags + [f"sg:{group_id}", f"sg-name:{group_name}"],
        )

    @staticmethod
    def _build_port_string(from_port: Optional[int], to_port: Optional[int]) -> Optional[str]:
        """Convert from_port / to_port to our canonical port string."""
        if from_port is None or to_port is None:
            return None  # All traffic (protocol -1) or ICMP without port
        if from_port == to_port:
            return str(from_port)
        if from_port == 0 and to_port == 65535:
            return None  # All ports — represent as None
        return f"{from_port}:{to_port}"