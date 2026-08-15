import unittest
import time
from storage.models import PacketInfo
from detection.anomaly import AnomalyDetector, shannon_entropy
from detection.rule_engine import RuleEngine
from detection.pipeline import PacketDetectionPipeline
from detection.arp_monitor import ArpMonitor
from detection.alerts import AlertManager


class DnsExfiltrationHardeningTests(unittest.TestCase):
    """Comprehensive tests for DNS exfiltration detection rule hardening."""

    def setUp(self):
        self.anomaly_detector = AnomalyDetector()
        self.rule_engine = RuleEngine(rules_dir="rules")
        self.arp_monitor = ArpMonitor()
        self.pipeline = PacketDetectionPipeline(
            self.rule_engine, self.anomaly_detector, self.arp_monitor
        )
        self.alert_manager = AlertManager()

    # 1. Legitimate Traffic - False Positive Resistance
    def test_ordinary_dns_queries_do_not_alert(self):
        """Verify normal short and medium domain queries never trigger exfiltration alerts."""
        legitimate_queries = [
            "google.com",
            "www.example.org",
            "api.github.com",
            "static.xx.fbcdn.net",
            "portal.azure.com",
            "mail.google.com",
            "sensordiscoveryendpoint.googleapis.com",  # 23 char English subdomain (entropy 3.44 <= 3.5)
            "cdn-edge-cache-01.cloudflare.net",        # CDN hostname with hyphens (entropy 3.36 <= 3.5)
        ]

        for query in legitimate_queries:
            pkt = PacketInfo(
                id=1,
                timestamp=time.time(),
                protocol="DNS",
                src_ip="192.168.1.50",
                dst_ip="8.8.8.8",
                dst_port=53,
                dns_query=query,
            )
            alerts = self.pipeline.evaluate(pkt)
            exfil_alerts = [a for a in alerts if a.rule_name == "DNS Exfiltration Tunnel"]
            self.assertEqual(
                exfil_alerts,
                [],
                f"Legitimate query '{query}' falsely triggered DNS exfiltration alert",
            )

    # 2. Suspicious Traffic - Detection Semantics
    def test_suspicious_high_entropy_detection(self):
        """Verify high-entropy subdomains (>20 chars, >3.5 entropy) are accurately detected."""
        suspicious_queries = [
            "xq9z8v7w6r5t4y3u2i1opa.example.com",          # Standard Base32/Base64 chunk
            "ns1.xq9z8v7w6r5t4y3u2i1opa.tunnel.org",       # Multi-label with payload in 2nd label
            "payload7x8y9z0a1b2c3d4e5f.exfil.attacker.net", # High-entropy chunk
        ]

        for query in suspicious_queries:
            pkt = PacketInfo(
                id=2,
                timestamp=time.time(),
                protocol="DNS",
                src_ip="10.0.0.99",
                dst_ip="1.1.1.1",
                dst_port=53,
                dns_query=query,
            )
            alerts = self.pipeline.evaluate(pkt)
            exfil_alerts = [a for a in alerts if a.rule_name == "DNS Exfiltration Tunnel"]
            self.assertTrue(
                len(exfil_alerts) > 0,
                f"Suspicious query '{query}' failed to trigger DNS exfiltration alert",
            )
            # Message should contain the query and entropy info regardless of escalation level
            msg = exfil_alerts[0].message
            self.assertTrue(
                "DNS Exfiltration" in msg or "Suspicious DNS query" in msg,
                f"Alert message format unexpected: {msg}"
            )

    # 3. Multi-Signal Escalation under Sustained Queries
    def test_sustained_tunnel_query_multi_signal_correlation(self):
        """Verify repeated unique high-entropy queries to same domain escalate with query counts."""
        ad = AnomalyDetector()
        ad.reset()

        alerts = []
        for i in range(5):
            pkt = PacketInfo(
                id=10 + i,
                timestamp=time.time() + i,
                protocol="DNS",
                src_ip="10.0.0.5",
                dst_ip="8.8.8.8",
                dst_port=53,
                dns_query=f"chunk{i}a8b7c6d5e4f3g2h1i0j9k.tunnel.com",
            )
            alert = ad.check_dns_exfiltration(pkt)
            if alert:
                alerts.append(alert)

        self.assertEqual(len(alerts), 5)
        # Final alert should reflect multi-signal query accumulation
        self.assertIn("queries=", alerts[-1].message)

    # 4. Length Boundary Tests
    def test_length_boundary_conditions(self):
        """Verify strict length boundary: <=20 chars ignored, >20 chars evaluated."""
        # 19 chars high entropy
        query_19 = "a1b2c3d4e5f6g7h8i9j.test.com"
        # 20 chars high entropy
        query_20 = "a1b2c3d4e5f6g7h8i9j0.test.com"
        # 21 chars high entropy
        query_21 = "a1b2c3d4e5f6g7h8i9j0k.test.com"

        pkt_19 = PacketInfo(id=1, timestamp=time.time(), protocol="DNS", dns_query=query_19)
        pkt_20 = PacketInfo(id=2, timestamp=time.time(), protocol="DNS", dns_query=query_20)
        pkt_21 = PacketInfo(id=3, timestamp=time.time(), protocol="DNS", dns_query=query_21)

        self.assertIsNone(self.anomaly_detector.check_dns_exfiltration(pkt_19))
        self.assertIsNone(self.anomaly_detector.check_dns_exfiltration(pkt_20))
        self.assertIsNotNone(self.anomaly_detector.check_dns_exfiltration(pkt_21))

    # 5. Entropy Calculation and Boundary Conditions
    def test_entropy_edge_cases(self):
        """Verify entropy boundary and edge cases."""
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("a"), 0.0)
        self.assertEqual(shannon_entropy(None), 0.0)

        # Repetitive characters have 0.0 entropy regardless of length
        self.assertEqual(shannon_entropy("a" * 50), 0.0)

        # 25 characters of single character should NOT alert
        pkt_rep = PacketInfo(id=1, timestamp=time.time(), protocol="DNS", dns_query=f"{'a'*25}.com")
        self.assertIsNone(self.anomaly_detector.check_dns_exfiltration(pkt_rep))

    # 6. Malformed & Untrusted DNS Input Safety
    def test_malformed_dns_inputs_do_not_crash(self):
        """Verify anomalous, malformed, null, or extreme inputs never crash the engine."""
        malformed_inputs = [
            None,
            "",
            "...",
            "....com",
            ".",
            "   ",
            "host\x00nullbyte.com",
            "unicøde-tëst-exfîltration-123456789.com",
            "a" * 500 + ".com",
            "123.456",
        ]

        for bad_query in malformed_inputs:
            pkt = PacketInfo(
                id=99,
                timestamp=time.time(),
                protocol="DNS",
                dns_query=bad_query,
            )
            try:
                alert_ad = self.anomaly_detector.check_dns_exfiltration(pkt)
                alerts_rule = self.rule_engine.evaluate(pkt)
                alerts_pipe = self.pipeline.evaluate(pkt)
            except Exception as e:
                self.fail(f"DNS engine crashed on malformed query '{bad_query}': {e}")


if __name__ == "__main__":
    unittest.main()
