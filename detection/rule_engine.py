"""
Rule Engine for my-sentinel.
"""
import logging
import os
import yaml
from typing import List
from detection.anomaly import shannon_entropy
from storage.models import PacketInfo, AlertInfo, DetectionRule

logger = logging.getLogger(__name__)


class RuleEngine:
    """Loads and evaluates detection rules against packets."""

    def __init__(self, rules_dir: str = "rules"):
        if not os.path.isabs(rules_dir):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            rules_dir = os.path.abspath(os.path.join(base_dir, rules_dir))
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
                                logger.warning(f"Rule file {path} did not contain a valid dictionary")
                                continue

                            rule = DetectionRule(
                                name=str(data.get("name", "Unknown")),
                                description=str(data.get("description", "")),
                                severity=str(data.get("severity", "INFO")),
                                enabled=bool(data.get("enabled", True)),
                                match=data.get("match", {}) if isinstance(data.get("match"), dict) else {},
                                action=data.get("action", {}) if isinstance(data.get("action"), dict) else {},
                            )
                            if self._is_valid_rule(rule):
                                self.rules.append(rule)
                            else:
                                logger.warning(f"Invalid rule structure in {path}")
                    except Exception as e:
                        logger.warning(f"Error loading rule file {path}: {e}")
        return self.rules

    def evaluate(self, packet: PacketInfo) -> List[AlertInfo]:
        """Check a packet against all loaded rules."""
        alerts = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
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
            except Exception as e:
                logger.error(f"Error evaluating rule '{rule.name}': {e}")
        return alerts

    def _is_valid_rule(self, rule: DetectionRule) -> bool:
        if not rule.name or not isinstance(rule.match, dict):
            return False
        severity = str(rule.severity).upper()
        if severity not in {"INFO", "WARNING", "HIGH", "CRITICAL"}:
            return False
        return True

    def _match_rule(self, packet: PacketInfo, rule: DetectionRule) -> bool:
        match = rule.match
        if not match:
            return False

        # Match protocol
        rule_proto = match.get("protocol")
        if rule_proto and packet.protocol.upper() != str(rule_proto).upper():
            return False

        # Match port
        rule_ports = match.get("dst_port")
        if rule_ports:
            if isinstance(rule_ports, list):
                if packet.dst_port not in rule_ports:
                    return False
            elif isinstance(rule_ports, (int, float)):
                if packet.dst_port != int(rule_ports):
                    return False

        # Match TCP flags
        rule_flags = match.get("flags")
        if rule_flags and packet.protocol == "TCP":
            packet_flags = packet.flags or []
            if isinstance(rule_flags, list):
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
            try:
                threshold = int(match.get("threshold", 1024))
            except (ValueError, TypeError):
                threshold = 1024
            if packet.dst_port is None or packet.dst_port <= threshold:
                return False
        elif condition == "high_entropy_subdomain":
            if packet.protocol != "DNS" or not getattr(packet, "dns_query", None):
                return False
            query = str(packet.dns_query).strip().rstrip(".")
            if not query:
                return False
            labels = [lbl for lbl in query.split(".") if lbl]
            if not labels:
                return False
            candidate_labels = labels[:-1] if len(labels) >= 2 else labels
            try:
                min_length = int(match.get("min_subdomain_length", 20))
                threshold = float(match.get("entropy_threshold", 3.5))
            except (ValueError, TypeError):
                min_length = 20
                threshold = 3.5

            max_ent = 0.0
            matched = False
            for lbl in candidate_labels:
                if len(lbl) > min_length:
                    ent = shannon_entropy(lbl.lower())
                    if ent > threshold:
                        matched = True
                        if ent > max_ent:
                            max_ent = ent

            if matched:
                packet.entropy = round(max_ent, 2)
                return True
            return False
        elif condition == "mac_change":
            if packet.protocol != "ARP" or not packet.old_mac or not packet.new_mac:
                return False
        elif condition:
            return False

        return True

    def reload(self):
        """Re-read rules from disk."""
        self.load_rules()
