"""
test_coverage_privileges_and_env.py — System privilege and prerequisite environment branch tests for utils/privileges.py:
Admin checks on Windows/Linux, Nmap PATH detection across platforms, Npcap driver checks,
and prerequisite summary aggregations.
"""

import os
import sys
from unittest.mock import patch, MagicMock
import pytest

from utils.privileges import (
    check_privileges,
    check_nmap_installed,
    check_npcap_installed,
    run_all_checks,
)


class TestPrivilegesAndEnvironment:
    def test_check_privileges_windows_admin_and_non_admin(self):
        with patch.object(sys, "platform", "win32"):
            # 1. Running as Administrator
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=1):
                assert check_privileges(require_exit=False) is True

            # 2. Running as Standard User with require_exit=False
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
                assert check_privileges(require_exit=False) is False

            # 3. Running as Standard User with require_exit=True (must call sys.exit(1))
            with patch("ctypes.windll.shell32.IsUserAnAdmin", return_value=0):
                with pytest.raises(SystemExit) as exc:
                    check_privileges(require_exit=True)
                assert exc.value.code == 1

    def test_check_privileges_unix_root_and_non_root(self):
        with patch.object(sys, "platform", "linux"):
            # 1. Running as root (UID 0)
            with patch("os.geteuid", create=True, return_value=0):
                assert check_privileges(require_exit=False) is True

            # 2. Running as unprivileged user (UID 1000)
            with patch("os.geteuid", create=True, return_value=1000):
                assert check_privileges(require_exit=False) is False

    def test_check_nmap_installed_cross_platform(self):
        # 1. Nmap found in PATH
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            assert check_nmap_installed() is True

        # 2. Nmap missing on Windows
        with patch.object(sys, "platform", "win32"), patch("shutil.which", return_value=None):
            assert check_nmap_installed() is False

        # 3. Nmap missing on macOS (darwin)
        with patch.object(sys, "platform", "darwin"), patch("shutil.which", return_value=None):
            assert check_nmap_installed() is False

        # 4. Nmap missing on Linux
        with patch.object(sys, "platform", "linux"), patch("shutil.which", return_value=None):
            assert check_nmap_installed() is False

    def test_check_npcap_installed_windows_and_linux(self):
        # 1. Windows with Npcap directory present
        with patch.object(sys, "platform", "win32"), patch("os.path.isdir", return_value=True):
            assert check_npcap_installed() is True

        # 2. Windows with Npcap missing
        with patch.object(sys, "platform", "win32"), patch("os.path.isdir", return_value=False):
            assert check_npcap_installed() is False

        # 3. Linux / macOS (libpcap assumed available)
        with patch.object(sys, "platform", "linux"):
            assert check_npcap_installed() is True

    def test_run_all_checks_summary(self):
        with patch("utils.privileges.check_privileges", return_value=True), \
             patch("utils.privileges.check_nmap_installed", return_value=True), \
             patch("utils.privileges.check_npcap_installed", return_value=True):
            res = run_all_checks(require_admin=False)
            assert res["privileges"] is True
            assert res["nmap"] is True
            assert res["pcap"] is True
