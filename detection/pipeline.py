"""
Shared packet detection pipeline.
"""
from typing import List

from detection.anomaly import AnomalyDetector
from detection.arp_monitor import ArpMonitor
from detection.rule_engine import RuleEngine
from storage.models import AlertInfo, PacketInfo


class PacketDetectionPipeline:
    """Runs all packet detection sources in a consistent order."""

    def __init__(
        self,
        rule_engine: RuleEngine,
        anomaly_detector: AnomalyDetector,
        arp_monitor: ArpMonitor,
    ):
        self.rule_engine = rule_engine
        self.anomaly_detector = anomaly_detector
        self.arp_monitor = arp_monitor

    def evaluate(self, packet: PacketInfo) -> List[AlertInfo]:
        alerts = list(self.rule_engine.evaluate(packet))

        dns_alert = self.anomaly_detector.check_dns_exfiltration(packet)
        if dns_alert:
            alerts.append(dns_alert)

        scan_alert = self.anomaly_detector.check_port_scan(packet)
        if scan_alert:
            alerts.append(scan_alert)

        if packet.protocol == "ARP":
            arp_alert = self.arp_monitor.check(packet)
            if arp_alert:
                alerts.append(arp_alert)

        return alerts
