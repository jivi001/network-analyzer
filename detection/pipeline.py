import logging
from typing import List

from detection.anomaly import AnomalyDetector
from detection.arp_monitor import ArpMonitor
from detection.rule_engine import RuleEngine
from storage.models import AlertInfo, PacketInfo

logger = logging.getLogger(__name__)


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
        alerts: List[AlertInfo] = []

        try:
            alerts.extend(self.rule_engine.evaluate(packet))
        except Exception as e:
            logger.error(f"RuleEngine error evaluating packet: {e}")

        try:
            dns_alert = self.anomaly_detector.check_dns_exfiltration(packet)
            if dns_alert:
                # If both RuleEngine and AnomalyDetector fired for the same
                # rule_name, keep the AnomalyDetector's alert (it has stateful
                # severity escalation) and remove the RuleEngine's static one.
                alerts = [
                    a for a in alerts
                    if a.rule_name != dns_alert.rule_name
                ]
                alerts.append(dns_alert)
        except Exception as e:
            logger.error(f"DNS exfiltration check error: {e}")

        try:
            scan_alert = self.anomaly_detector.check_port_scan(packet)
            if scan_alert:
                alerts.append(scan_alert)
        except Exception as e:
            logger.error(f"Port scan check error: {e}")

        if packet.protocol == "ARP":
            try:
                arp_alert = self.arp_monitor.check(packet)
                if arp_alert:
                    alerts.append(arp_alert)
            except Exception as e:
                logger.error(f"ARP monitor check error: {e}")

        return alerts
