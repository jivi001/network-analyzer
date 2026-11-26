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
        """Verify correct length boundary: labels >= min_length (20) are evaluated."""
        # 19 chars (below min_length 20, should NOT trigger)
        query_19 = "a1b2c3d4e5f6g7h8i9j.test.com"
        # 20 chars (exactly at min_length 20, should trigger when entropy > 3.5)
        query_20 = "a1b2c3d4e5f6g7h8i9j0.test.com"
        # 21 chars (above min_length 20, should trigger when entropy > 3.5)
        query_21 = "a1b2c3d4e5f6g7h8i9j0k.test.com"

        pkt_19 = PacketInfo(id=1, timestamp=time.time(), protocol="DNS", dns_query=query_19)
        pkt_20 = PacketInfo(id=2, timestamp=time.time(), protocol="DNS", dns_query=query_20)
        pkt_21 = PacketInfo(id=3, timestamp=time.time(), protocol="DNS", dns_query=query_21)

        self.assertIsNone(self.anomaly_detector.check_dns_exfiltration(pkt_19))
        # 20 chars: at the inclusive boundary (>=) and high entropy (4.32 > 3.5),
        # so it MUST be evaluated and MUST trigger. This is the exact-length PoC:
        # it fails against the old strict `>` check and passes against the fix.
        self.assertIsNotNone(
            self.anomaly_detector.check_dns_exfiltration(pkt_20),
            "20-char high-entropy label at the minimum length must be detected (>= fix)",
        )
        # 21 chars: should trigger if entropy > 3.5
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

    # 7. Position-aware DNS detection tests
    def test_position_aware_dns_detection(self):
        """Verify DNS detection analyzes all labels, not just subdomains."""
        ad = AnomalyDetector()
        ad.reset()
        
        # Test 1: High-entropy in first label (previously excluded)
        query_first = "xyz123abc456def789ghi123jkl.tunnel.com"
        pkt_first = PacketInfo(
            id=1, 
            timestamp=time.time(), 
            protocol="DNS", 
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8", 
            dns_query=query_first
        )
        alert_first = ad.check_dns_exfiltration(pkt_first)
        self.assertIsNotNone(alert_first, f"Failed to detect high-entropy in first label: {query_first}")
        self.assertIn("position=1", alert_first.message, "Alert message should include position information")
        
        # Test 2: High-entropy in middle label
        query_middle = "normal.xq9z8v7w6r5t4y3u2i1opa.exfil.net"
        pkt_middle = PacketInfo(
            id=2,
            timestamp=time.time(), 
            protocol="DNS",
            src_ip="10.0.0.2", 
            dst_ip="1.1.1.1",
            dns_query=query_middle
        )
        alert_middle = ad.check_dns_exfiltration(pkt_middle)
        self.assertIsNotNone(alert_middle, f"Failed to detect high-entropy in middle label: {query_middle}")
        self.assertIn("position=2", alert_middle.message, "Alert message should include position information")
        
        # Test 3: High-entropy in last label (previously excluded as TLD)
        query_last = "legitimate.normal.payload123456789.tld"
        pkt_last = PacketInfo(
            id=3,
            timestamp=time.time(), 
            protocol="DNS",
            src_ip="10.0.0.3", 
            dst_ip="8.8.4.4",
            dns_query=query_last
        )
        # This might still not trigger if the last label isn't >20 chars or high entropy
        # but it should be analyzed now (position-independent)
        try:
            result = ad.check_dns_exfiltration(pkt_last)
        except Exception as e:
            self.fail(f"Failed to analyze query with potential high-entropy in last label: {query_last}, error: {e}")
        
        # Test 4: Multiple labels with high entropy
        query_multi = "abc123def456ghi789jkl012mno345pqr678.sts.malicious.net"
        pkt_multi = PacketInfo(
            id=4,
            timestamp=time.time(), 
            protocol="DNS",
            src_ip="10.0.0.4", 
            dst_ip="1.1.1.1",
            dns_query=query_multi
        )
        alert_multi = ad.check_dns_exfiltration(pkt_multi)
        self.assertIsNotNone(alert_multi, f"Failed to detect multiple high-entropy labels: {query_multi}")
        
        # Test 5: Single label DNS name
        query_single = "payload123456789012345abcde.tld"
        pkt_single = PacketInfo(
            id=6,
            timestamp=time.time(), 
            protocol="DNS",
            src_ip="10.0.0.6", 
            dst_ip="8.8.8.8",
            dns_query=query_single
        )
        alert_single = ad.check_dns_exfiltration(pkt_single)
        self.assertIsNotNone(alert_single, f"Failed to detect high-entropy in single-label DNS: {query_single}")
        
        # Test 6: Trailing dot DNS name
        query_trailing = "abc123def456ghi789jkl012.sts.tld."
        pkt_trailing = PacketInfo(
            id=7,
            timestamp=time.time(), 
            protocol="DNS",
            src_ip="10.0.0.7", 
            dst_ip="8.8.8.8",
            dns_query=query_trailing
        )
        alert_trailing = ad.check_dns_exfiltration(pkt_trailing)
        self.assertIsNotNone(alert_trailing, f"Failed to detect high-entropy in trailing-dot DNS: {query_trailing}")


if __name__ == "__main__":
    unittest.main()
