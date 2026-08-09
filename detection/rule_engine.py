"""
Rule Engine for my-sentinel.
"""
import os
import yaml
from typing import List
from storage.models import PacketInfo, AlertInfo, DetectionRule


class RuleEngine:
    """Loads and evaluates detection rules against packets."""

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules: List[DetectionRule] = []
        self.load_rules()

    def load_rules(self) -> List[DetectionRule]:
        """Load rules from YAML files in the rules directory."""
        self.rules = []
        if not os.path.exists(self.rules_dir):
            return self.rules

        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith((".yaml", ".yml")):
                    path = os.path.join(root, file)
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if not isinstance(data, dict):
                                continue

                            rule = DetectionRule(
                                name=data.get("name", "Unknown"),
                                description=data.get("description", ""),
                                severity=data.get("severity", "INFO"),
                                match=data.get("match", {}),
                                action=data.get("action", {}),
                            )
                            self.rules.append(rule)
                    except Exception:
                        pass  # Handle invalid YAML gracefully
        return self.rules

    def evaluate(self, packet: PacketInfo) -> List[AlertInfo]:
        """Check a packet against all loaded rules."""
        alerts = []
        for rule in self.rules:
            if self._match_rule(packet, rule):
                action = rule.action
                if action.get("alert", True):
                    msg_template = action.get("message", "Rule matched: {name}")

                    try:
                        msg = msg_template.format(
                            name=rule.name,
                            src_ip=packet.src_ip,
                            dst_ip=packet.dst_ip,
                            dst_port=packet.dst_port,
                            service=packet.service,
                            dns_query=getattr(packet, "dns_query", ""),
                            entropy=getattr(packet, "entropy", 0.0),
                            old_mac=getattr(packet, "old_mac", ""),
                            new_mac=getattr(packet, "new_mac", ""),
                        )
                    except Exception:
                        msg = f"Rule matched: {rule.name} ({packet.src_ip} -> {packet.dst_ip})"

                    alert = AlertInfo(
                        rule_name=rule.name,
                        severity=rule.severity,
                        message=msg,
                        src_ip=packet.src_ip,
                        dst_ip=packet.dst_ip,
                        dst_port=packet.dst_port,
                        protocol=packet.protocol,
                        timestamp=packet.timestamp,
                        timestamp_str=packet.timestamp_str,
                    )
                    alerts.append(alert)
        return alerts

    def _match_rule(self, packet: PacketInfo, rule: DetectionRule) -> bool:
        match = rule.match
        if not match:
            return False

        # Match protocol
        rule_proto = match.get("protocol")
        if rule_proto and packet.protocol.upper() != rule_proto.upper():
            return False

        # Match port
        rule_ports = match.get("dst_port")
        if rule_ports:
            if isinstance(rule_ports, list):
                if packet.dst_port not in rule_ports:
                    return False
            elif isinstance(rule_ports, int):
                if packet.dst_port != rule_ports:
                    return False

        # Match TCP flags
        rule_flags = match.get("flags")
        if rule_flags and packet.protocol == "TCP":
            packet_flags = packet.flags or []
            for flag in rule_flags:
                if flag not in packet_flags and flag not in packet.flags_raw:
                    return False

        # Condition types
        condition = match.get("condition")
        if condition == "port_match":
            pass  # Already matched port above
        elif condition == "cleartext":
            from utils.constants import CLEARTEXT_PORTS

            if packet.dst_port not in CLEARTEXT_PORTS:
                return False
        elif condition == "high_port":
            threshold = match.get("threshold", 1024)
            if packet.dst_port is None or packet.dst_port <= threshold:
                return False

        return True

    def reload(self):
        """Re-read rules from disk."""
        self.load_rules()
