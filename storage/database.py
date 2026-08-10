import sqlite3
import json
import threading
from typing import List, Optional
from datetime import datetime
from storage.models import SessionInfo, AlertInfo, HostInfo, ScanResult, StatsSnapshot


CURRENT_SCHEMA_VERSION = 2


class Database:
    """SQLite Database Manager for my-sentinel."""

    def __init__(self, db_path: str = "sentinel_data.db"):
        """Create/open SQLite database with WAL mode."""
        import os
        if not os.path.isabs(db_path):
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.abspath(os.path.join(base_dir, db_path))
        self.db_path = db_path
        self.lock = threading.RLock()
        self._local = threading.local()
        self._all_connections: List[sqlite3.Connection] = []
        self._create_tables()

    @property
    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            conn = sqlite3.connect(
                self.db_path, check_same_thread=False, timeout=5.0
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
            with self.lock:
                self._all_connections.append(conn)
        return self._local.conn

    def _safe_json_loads(self, val, default=None):
        if not val:
            return default if default is not None else []
        try:
            return json.loads(val)
        except Exception:
            return default if default is not None else []

    def _format_time(self, val) -> str:
        """Safely format a timestamp or string value for DB insertion."""
        if val is None:
            return ""
        if isinstance(val, (int, float)):
            return datetime.fromtimestamp(val).strftime("%Y-%m-%d %H:%M:%S")
        if isinstance(val, datetime):
            return val.strftime("%Y-%m-%d %H:%M:%S")
        return str(val)

    def _create_tables(self):
        """Create all tables if they don't exist and run migrations."""
        with self.lock:
            c = self.conn.cursor()
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_type TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    packet_count INTEGER,
                    total_bytes INTEGER,
                    alert_count INTEGER,
                    interface TEXT,
                    filter_applied TEXT,
                    status TEXT,
                    target TEXT
                )
            """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    timestamp TEXT,
                    severity TEXT,
                    rule_name TEXT,
                    message TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                )
            """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS discovered_hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE,
                    mac_address TEXT,
                    hostname TEXT,
                    open_ports TEXT,
                    services TEXT,
                    os_guess TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    source TEXT,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    state TEXT
                )
            """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    target TEXT,
                    scan_type TEXT,
                    scan_args TEXT,
                    hosts_found INTEGER,
                    results TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                )
            """
            )
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS packet_summaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    protocol_counts TEXT,
                    top_talkers TEXT,
                    total_packets INTEGER,
                    total_bytes INTEGER,
                    unique_hosts INTEGER,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                )
            """
            )
            self._migrate(c)
            self.conn.commit()

    def _migrate(self, cursor: sqlite3.Cursor):
        """Schema versioning migration."""
        version = cursor.execute("PRAGMA user_version").fetchone()[0]
        if version < 2:
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session_id ON alerts(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_results_session_id ON scan_results(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_packet_summaries_session_id ON packet_summaries(session_id)")
            cursor.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")

    def create_session(self, session: SessionInfo) -> int:
        """Insert new session, return ID."""
        with self.lock:
            c = self.conn.cursor()
            c.execute(
                """
                INSERT INTO sessions (session_type, start_time, end_time, packet_count, total_bytes, alert_count, interface, filter_applied, status, target)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session.session_type,
                    self._format_time(session.start_time),
                    self._format_time(session.end_time),
                    session.packet_count,
                    session.total_bytes,
                    session.alert_count,
                    session.interface,
                    session.filter_applied,
                    session.status,
                    session.target,
                ),
            )
            self.conn.commit()
            return c.lastrowid

    def update_session(self, session: SessionInfo):
        """Update existing session."""
        if not session.id:
            return
        with self.lock:
            c = self.conn.cursor()
            c.execute(
                """
                UPDATE sessions SET
                    session_type=?, start_time=?, end_time=?, packet_count=?, total_bytes=?, alert_count=?, interface=?, filter_applied=?, status=?, target=?
                WHERE id=?
            """,
                (
                    session.session_type,
                    self._format_time(session.start_time),
                    self._format_time(session.end_time),
                    session.packet_count,
                    session.total_bytes,
                    session.alert_count,
                    session.interface,
                    session.filter_applied,
                    session.status,
                    session.target,
                    session.id,
                ),
            )
            self.conn.commit()

    def end_session(
        self,
        session_id: int,
        packet_count: int,
        total_bytes: int,
        alert_count: int,
    ):
        """Mark session completed."""
        with self.lock:
            c = self.conn.cursor()
            c.execute(
                """
                UPDATE sessions SET
                    end_time=?, packet_count=?, total_bytes=?, alert_count=?, status='completed'
                WHERE id=?
            """,
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    packet_count,
                    total_bytes,
                    alert_count,
                    session_id,
                ),
            )
            self.conn.commit()

    def save_alert(self, alert: AlertInfo):
        """Insert alert record."""
        with self.lock:
            c = self.conn.cursor()
            ts_str = alert.timestamp_str or self._format_time(alert.timestamp)
            c.execute(
                """
                INSERT INTO alerts (session_id, timestamp, severity, rule_name, message, src_ip, dst_ip, dst_port, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    alert.session_id,
                    ts_str,
                    alert.severity,
                    alert.rule_name,
                    alert.message,
                    alert.src_ip,
                    alert.dst_ip,
                    alert.dst_port,
                    alert.protocol,
                ),
            )
            self.conn.commit()

    def save_alerts_batch(self, alerts: List[AlertInfo]):
        """Batch insert alerts."""
        if not alerts:
            return
        with self.lock:
            c = self.conn.cursor()
            c.executemany(
                """
                INSERT INTO alerts (session_id, timestamp, severity, rule_name, message, src_ip, dst_ip, dst_port, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                [
                    (
                        a.session_id,
                        a.timestamp_str or self._format_time(a.timestamp),
                        a.severity,
                        a.rule_name,
                        a.message,
                        a.src_ip,
                        a.dst_ip,
                        a.dst_port,
                        a.protocol,
                    )
                    for a in alerts
                ],
            )
            self.conn.commit()

    def save_host(self, host: HostInfo):
        """Upsert discovered host."""
        with self.lock:
            c = self.conn.cursor()
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            first_seen = self._format_time(host.first_seen) or now_str
            last_seen = self._format_time(host.last_seen) or now_str

            c.execute(
                """
                INSERT INTO discovered_hosts (ip_address, mac_address, hostname, open_ports, services, os_guess, first_seen, last_seen, source, packet_count, byte_count, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    mac_address=excluded.mac_address,
                    hostname=excluded.hostname,
                    open_ports=excluded.open_ports,
                    services=excluded.services,
                    os_guess=excluded.os_guess,
                    last_seen=excluded.last_seen,
                    source=excluded.source,
                    packet_count=excluded.packet_count,
                    byte_count=excluded.byte_count,
                    state=excluded.state
            """,
                (
                    host.ip_address,
                    host.mac_address,
                    host.hostname,
                    json.dumps(host.open_ports) if host.open_ports is not None else "[]",
                    json.dumps(host.services) if host.services is not None else "{}",
                    host.os_guess,
                    first_seen,
                    last_seen,
                    host.source,
                    host.packet_count,
                    host.byte_count,
                    host.state,
                ),
            )
            self.conn.commit()

    def save_scan_result(self, result: ScanResult):
        """Insert scan result."""
        with self.lock:
            c = self.conn.cursor()
            hosts_data = [
                {
                    "ip": h.ip_address,
                    "mac": h.mac_address,
                    "hostname": h.hostname,
                    "open_ports": h.open_ports,
                    "os": h.os_guess,
                    "state": h.state,
                }
                for h in result.hosts
            ]
            c.execute(
                """
                INSERT INTO scan_results (session_id, target, scan_type, scan_args, hosts_found, results, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    result.session_id,
                    result.target,
                    result.scan_type,
                    result.scan_args,
                    result.hosts_found,
                    json.dumps(hosts_data),
                    self._format_time(result.start_time),
                    self._format_time(result.end_time),
                ),
            )
            self.conn.commit()

    def save_packet_summary(self, session_id: int, stats: StatsSnapshot):
        """Save aggregated stats."""
        with self.lock:
            c = self.conn.cursor()
            c.execute(
                """
                INSERT INTO packet_summaries (session_id, protocol_counts, top_talkers, total_packets, total_bytes, unique_hosts)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    session_id,
                    json.dumps(stats.protocol_counts),
                    json.dumps(stats.top_talkers),
                    stats.total_packets,
                    stats.total_bytes,
                    stats.unique_hosts_total,
                ),
            )
            self.conn.commit()

    def get_recent_sessions(self, n: int = 10) -> List[SessionInfo]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT ?", (n,))
        rows = c.fetchall()
        res = []
        for r in rows:
            si = SessionInfo(
                id=r["id"],
                session_type=r["session_type"] or r["type"] if "type" in r.keys() else r["session_type"],
                start_time=r["start_time"] or "",
                end_time=r["end_time"] or "",
                packet_count=r["packet_count"] or 0,
                total_bytes=r["total_bytes"] or 0,
                alert_count=r["alert_count"] or 0,
                interface=r["interface"] or "",
                filter_applied=r["filter_applied"] or "",
                status=r["status"] or "",
                target=r["target"] or "",
            )
            res.append(si)
        return res

    def get_session(self, session_id: int) -> Optional[SessionInfo]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        r = c.fetchone()
        if not r:
            return None
        return SessionInfo(
            id=r["id"],
            session_type=r["session_type"] if "session_type" in r.keys() and r["session_type"] else (r["type"] if "type" in r.keys() else ""),
            start_time=r["start_time"] or "",
            end_time=r["end_time"] or "",
            packet_count=r["packet_count"] or 0,
            total_bytes=r["total_bytes"] or 0,
            alert_count=r["alert_count"] or 0,
            interface=r["interface"] or "",
            filter_applied=r["filter_applied"] or "",
            status=r["status"] or "",
            target=r["target"] or "",
        )

    def get_alerts(
        self, session_id: Optional[int] = None, severity: Optional[str] = None
    ) -> List[AlertInfo]:
        c = self.conn.cursor()
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if session_id is not None:
            query += " AND session_id=?"
            params.append(session_id)
        if severity is not None:
            query += " AND severity=?"
            params.append(severity)

        query += " ORDER BY id DESC"

        c.execute(query, tuple(params))
        rows = c.fetchall()
        res = []
        for r in rows:
            res.append(
                AlertInfo(
                    id=r["id"],
                    session_id=r["session_id"],
                    timestamp_str=r["timestamp"] or "",
                    severity=r["severity"] or "INFO",
                    rule_name=r["rule_name"] or "",
                    message=r["message"] or "",
                    src_ip=r["src_ip"] or "",
                    dst_ip=r["dst_ip"] or "",
                    dst_port=r["dst_port"] or 0,
                    protocol=r["protocol"] or "",
                )
            )
        return res

    def get_hosts(self) -> List[HostInfo]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM discovered_hosts ORDER BY id DESC")
        rows = c.fetchall()
        res = []
        for r in rows:
            res.append(
                HostInfo(
                    id=r["id"],
                    ip_address=r["ip_address"] or "",
                    mac_address=r["mac_address"] or "",
                    hostname=r["hostname"] or "",
                    open_ports=self._safe_json_loads(r["open_ports"], []),
                    services=self._safe_json_loads(r["services"], {}),
                    os_guess=r["os_guess"] or "",
                    first_seen=r["first_seen"] or "",
                    last_seen=r["last_seen"] or "",
                    source=r["source"] or "",
                    packet_count=r["packet_count"] or 0,
                    byte_count=r["byte_count"] or 0,
                    state=r["state"] or "up",
                )
            )
        return res

    def get_host_by_ip(self, ip: str) -> Optional[HostInfo]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM discovered_hosts WHERE ip_address=?", (ip,))
        r = c.fetchone()
        if not r:
            return None
        return HostInfo(
            id=r["id"],
            ip_address=r["ip_address"] or "",
            mac_address=r["mac_address"] or "",
            hostname=r["hostname"] or "",
            open_ports=self._safe_json_loads(r["open_ports"], []),
            services=self._safe_json_loads(r["services"], {}),
            os_guess=r["os_guess"] or "",
            first_seen=r["first_seen"] or "",
            last_seen=r["last_seen"] or "",
            source=r["source"] or "",
            packet_count=r["packet_count"] or 0,
            byte_count=r["byte_count"] or 0,
            state=r["state"] or "up",
        )

    def search_sessions(self, query: str) -> List[SessionInfo]:
        """Search sessions by target or interface."""
        c = self.conn.cursor()
        search_term = f"%{query}%"
        c.execute(
            """
            SELECT * FROM sessions 
            WHERE target LIKE ? OR interface LIKE ? OR filter_applied LIKE ?
            ORDER BY id DESC
        """,
            (search_term, search_term, search_term),
        )
        rows = c.fetchall()
        res = []
        for r in rows:
            si = SessionInfo(
                id=r["id"],
                session_type=r["session_type"] or r["type"] if "type" in r.keys() else r["session_type"],
                start_time=r["start_time"] or "",
                end_time=r["end_time"] or "",
                packet_count=r["packet_count"] or 0,
                total_bytes=r["total_bytes"] or 0,
                alert_count=r["alert_count"] or 0,
                interface=r["interface"] or "",
                filter_applied=r["filter_applied"] or "",
                status=r["status"] or "",
                target=r["target"] or "",
            )
            res.append(si)
        return res

    def close_all(self):
        """Close all tracked database connections across threads."""
        with self.lock:
            for conn in list(self._all_connections):
                try:
                    conn.close()
                except Exception:
                    pass
            self._all_connections.clear()
        if hasattr(self._local, "conn"):
            del self._local.conn

    def close(self):
        """Close the database connections."""
        self.close_all()
