"""
test_security_xml_architecture.py — XXE and XML Security Architecture Test Suite.

Verifies:
1. No unhardened or unsafe XML parsers exist in the production codebase (AST audit).
2. Boundary controls strictly reject direct and disguised XML files.
3. Local and remote XXE, entity expansion, and external DTD payloads cannot trigger parsing or network callbacks.
4. Export and scanner interfaces reject XML redirection and markup injection.
5. Error isolation ensures malformed XML inputs produce controlled exceptions.
"""

import ast
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from core.scanner import NetworkScanner
from storage.database import Database
from storage.exporter import Exporter
from storage.importer import Importer


PROJECT_ROOT = Path(__file__).resolve().parent.parent

PRODUCTION_DIRS = [
    PROJECT_ROOT / "core",
    PROJECT_ROOT / "detection",
    PROJECT_ROOT / "network",
    PROJECT_ROOT / "storage",
    PROJECT_ROOT / "tui",
    PROJECT_ROOT / "utils",
]

PRODUCTION_FILES = [
    PROJECT_ROOT / "sentinel.py",
    PROJECT_ROOT / "traffic_lab.py",
]

FORBIDDEN_XML_MODULES = {
    "xml.etree",
    "xml.etree.ElementTree",
    "xml.dom",
    "xml.dom.minidom",
    "xml.dom.pulldom",
    "xml.sax",
    "lxml",
    "lxml.etree",
}


class TestXmlSecurityArchitecture(unittest.TestCase):
    """AST-level static audit enforcing zero unsafe XML parsing in production code."""

    def _get_production_python_files(self):
        files = list(PRODUCTION_FILES)
        for pdir in PRODUCTION_DIRS:
            if pdir.exists():
                for root, _, filenames in os.walk(pdir):
                    if "__pycache__" in root:
                        continue
                    for fn in filenames:
                        if fn.endswith(".py"):
                            files.append(Path(root) / fn)
        return files

    def test_no_unsafe_xml_parser_imported_in_production_code(self):
        """Guarantee no production module imports or references unsafe XML parsers."""
        violations = []
        py_files = self._get_production_python_files()
        self.assertGreater(len(py_files), 10, "Should inspect all production Python modules")

        for py_file in py_files:
            rel_path = py_file.relative_to(PROJECT_ROOT)
            content = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(content, filename=str(py_file))
            except Exception as e:
                self.fail(f"Failed to parse AST for {rel_path}: {e}")

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for forbidden in FORBIDDEN_XML_MODULES:
                            if alias.name == forbidden or alias.name.startswith(forbidden + "."):
                                violations.append(f"{rel_path}: import {alias.name}")

                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for forbidden in FORBIDDEN_XML_MODULES:
                        if module == forbidden or module.startswith(forbidden + "."):
                            violations.append(f"{rel_path}: from {module} import ...")

        self.assertEqual(
            violations,
            [],
            f"Found unsafe XML parser imports in production code: {violations}",
        )

    def test_pyproject_dependencies_do_not_include_unnecessary_xml_libs(self):
        """Confirm dependencies do not introduce lxml or other unneeded XML libraries."""
        pyproject_path = PROJECT_ROOT / "pyproject.toml"
        self.assertTrue(pyproject_path.exists())
        content = pyproject_path.read_text(encoding="utf-8").lower()
        self.assertNotIn("lxml", content, "lxml must not be added to dependencies")
        self.assertNotIn("defusedxml", content, "defusedxml must not be added without an active XML path")


class TestXmlBoundaryRejectionAndHardening(unittest.TestCase):
    """Dynamic boundary tests ensuring XML and XXE payloads are rejected before parsing."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_sec.db"
        self.db = Database(str(self.db_path))
        self.importer = Importer(self.db)
        self.exporter = Exporter()

    def tearDown(self):
        self.db.close()
        self.temp_dir.cleanup()

    def test_importer_rejects_direct_xml_file(self):
        """Attempting to import any .xml file must be rejected immediately."""
        xml_file = Path(self.temp_dir.name) / "scan_output.xml"
        xml_payload = """<?xml version="1.0"?>
        <!DOCTYPE foo [
            <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
        ]>
        <scan><host>&xxe;</host></scan>"""
        xml_file.write_text(xml_payload, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            self.importer.import_json(str(xml_file), raise_on_error=True)
        self.assertIn("Unsupported import file type '.xml'", str(ctx.exception))

    def test_importer_rejects_disguised_xml_with_local_xxe(self):
        """An XML file renamed with a .json extension must fail JSON decoding cleanly."""
        fake_json = Path(self.temp_dir.name) / "xxe_payload.json"
        xml_payload = """<?xml version="1.0"?>
        <!DOCTYPE data [
            <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>"""
        fake_json.write_text(xml_payload, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            self.importer.import_json(str(fake_json), raise_on_error=True)
        self.assertIn("Invalid JSON format", str(ctx.exception))

    def test_importer_rejects_disguised_xml_with_http_callback_xxe(self):
        """An HTTP XXE payload must NOT trigger any network request or callback."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        callback_received = [False]

        def listen_worker():
            listener.settimeout(0.5)
            try:
                conn, _ = listener.accept()
                callback_received[0] = True
                conn.close()
            except socket.timeout:
                pass
            finally:
                listener.close()

        t = threading.Thread(target=listen_worker)
        t.daemon = True
        t.start()

        try:
            http_xxe = Path(self.temp_dir.name) / "http_xxe.json"
            payload = f"""<?xml version="1.0"?>
            <!DOCTYPE test [
                <!ENTITY xxe SYSTEM "http://127.0.0.1:{port}/ssrf">
            ]>
            <root>&xxe;</root>"""
            http_xxe.write_text(payload, encoding="utf-8")

            with self.assertRaises(ValueError) as ctx:
                self.importer.import_json(str(http_xxe), raise_on_error=True)
            self.assertIn("Invalid JSON format", str(ctx.exception))
        finally:
            t.join(timeout=1.0)

        self.assertFalse(
            callback_received[0],
            "Security failure: XML parsing triggered an outbound HTTP connection callback!",
        )

    def test_importer_rejects_disguised_xml_billion_laughs(self):
        """Billion laughs XML bomb disguised as JSON must be rejected without resource exhaustion."""
        bomb_json = Path(self.temp_dir.name) / "bomb.json"
        bomb_payload = """<?xml version="1.0"?>
        <!DOCTYPE lolz [
            <!ENTITY lol "lol">
            <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
            <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
            <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
        ]>
        <lolz>&lol4;</lolz>"""
        bomb_json.write_text(bomb_payload, encoding="utf-8")

        with self.assertRaises(ValueError) as ctx:
            self.importer.import_json(str(bomb_json), raise_on_error=True)
        self.assertIn("Invalid JSON format", str(ctx.exception))

    def test_exporter_rejects_xml_format(self):
        """Exporting to .xml must be strictly prohibited."""
        for filename in ["report.xml", "out.XML", "data.xmL"]:
            with self.assertRaises(ValueError) as ctx:
                self.exporter.validate_export_path(filename, export_dir=self.temp_dir.name)
            self.assertIn("Unsupported export format", str(ctx.exception))

    def test_scanner_rejects_xml_redirection_arguments(self):
        """NetworkScanner must reject -oX or -oA XML redirection flags."""
        scanner = NetworkScanner.__new__(NetworkScanner)
        scanner.config = {}

        dangerous_args = [
            "-oX -",
            "-oX scan.xml",
            "-oA scan_all",
            "-oN scan.txt -oX evil.xml",
            "--stylesheet evil.xsl",
        ]
        for arg in dangerous_args:
            with self.assertRaises(ValueError, msg=f"Should reject: {arg}"):
                scanner._validate_scan_args(arg)

    def test_scanner_target_rejects_xml_injection_payloads(self):
        """NetworkScanner target validation must reject strings containing XML markup or entities."""
        scanner = NetworkScanner.__new__(NetworkScanner)
        scanner.config = {}

        injection_targets = [
            "<xml>192.168.1.1</xml>",
            "192.168.1.1 &xxe;",
            "<!DOCTYPE foo>",
            "127.0.0.1<tag>",
            "host.local' or 1=1--",
        ]
        for target in injection_targets:
            with self.assertRaises(ValueError, msg=f"Should reject target: {target}"):
                scanner.validate_target(target)

    def test_security_policy_documentation_integrity(self):
        """Confirm docs/security.md explicitly defines the XML security policy."""
        sec_doc = PROJECT_ROOT / "docs" / "security.md"
        self.assertTrue(sec_doc.exists(), "docs/security.md must exist")
        content = sec_doc.read_text(encoding="utf-8")
        self.assertIn("## 3. XML & XXE Security Policy", content)
        self.assertIn("defusedxml", content)
        self.assertIn("xml.etree.ElementTree.parse()", content)
        self.assertIn("No production XML parsing path exists", content)
