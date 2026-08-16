"""
test_unit_storage_database.py — Comprehensive unit tests for storage, database, models, and exporters.
"""

import os
import tempfile
import pytest

from storage.database import Database
from storage.models import SessionInfo, AlertInfo, HostInfo, PacketInfo
from storage.exporter import Exporter


@pytest.fixture
def temp_db():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name
    db = Database(db_path)
    yield db
    db.close()
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass


class TestStorageDatabase:
    def test_session_lifecycle(self, temp_db):
        session = SessionInfo(
            session_type="live_capture",
            interface="Ethernet",
            start_time="2026-08-16 10:00:00",
            status="running",
        )
        session_id = temp_db.create_session(session)
        assert session_id > 0

        fetched = temp_db.get_session(session_id)
        assert fetched is not None
        assert fetched.session_type == "live_capture"

        # Update session
        session.id = session_id
        session.status = "completed"
        session.packet_count = 150
        session.total_bytes = 12000
        session.alert_count = 3
        temp_db.update_session(session)

        updated = temp_db.get_session(session_id)
        assert updated.status == "completed"
        assert updated.packet_count == 150
        assert updated.alert_count == 3

    def test_alerts_batch_and_filtering(self, temp_db):
        session_id = temp_db.create_session(SessionInfo(session_type="test"))
        alerts = [
            AlertInfo(session_id=session_id, rule_name="SYN Probe", severity="HIGH", src_ip="192.168.1.50", dst_ip="10.0.0.1", dst_port=80, message="SYN Alert"),
            AlertInfo(session_id=session_id, rule_name="DNS Exfil", severity="CRITICAL", src_ip="192.168.1.50", dst_ip="8.8.8.8", dst_port=53, message="DNS Alert"),
            AlertInfo(session_id=session_id, rule_name="Port Scan", severity="WARNING", src_ip="192.168.1.60", dst_ip="10.0.0.1", dst_port=22, message="Scan Alert"),
        ]
        temp_db.save_alerts_batch(alerts)

        all_alerts = temp_db.get_alerts(session_id=session_id)
        assert len(all_alerts) == 3

        crit_alerts = temp_db.get_alerts(session_id=session_id, severity="CRITICAL")
        assert len(crit_alerts) == 1
        assert crit_alerts[0].rule_name == "DNS Exfil"

    def test_hosts_save_and_update(self, temp_db):
        host1 = HostInfo(ip_address="192.168.1.10", mac_address="00:11:22:33:44:55", hostname="host-a", open_ports=[80])
        temp_db.save_host(host1)

        hosts = temp_db.get_hosts()
        assert len(hosts) == 1
        assert hosts[0].ip_address == "192.168.1.10"

        host1_updated = HostInfo(ip_address="192.168.1.10", mac_address="00:11:22:33:44:55", hostname="host-a-renamed", open_ports=[80, 443])
        temp_db.save_host(host1_updated)

        hosts_after = temp_db.get_hosts()
        assert len(hosts_after) == 1
        assert hosts_after[0].hostname == "host-a-renamed"
        assert 443 in hosts_after[0].open_ports

    def test_search_sessions_and_packets(self, temp_db):
        s1 = temp_db.create_session(SessionInfo(session_type="live_capture", target="192.168.1.1", status="completed"))
        s2 = temp_db.create_session(SessionInfo(session_type="nmap_scan", target="10.0.0.99", status="completed"))

        results = temp_db.search_sessions("192.168.1.1")
        assert len(results) >= 1
        assert results[0].target == "192.168.1.1"

        results_injection = temp_db.search_sessions("' OR '1'='1")
        assert isinstance(results_injection, list)


class TestStorageExporter:
    def test_validate_export_path_traversal_rejection(self):
        exporter = Exporter()
        with pytest.raises(ValueError):
            exporter.validate_export_path("../../../etc/passwd.json")

        with pytest.raises(ValueError):
            exporter.validate_export_path("test.invalid_ext")

    def test_export_csv_packets_and_alerts(self):
        exporter = Exporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "packets.csv")
            pkts = [
                PacketInfo(id=1, timestamp=100.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="TCP", length=64)
            ]
            exporter.export_csv(csv_path, packets=pkts)
            assert os.path.exists(csv_path)

            with open(csv_path, "r", encoding="utf-8") as f:
                content = f.read()
                assert "src_ip" in content
                assert "1.1.1.1" in content
