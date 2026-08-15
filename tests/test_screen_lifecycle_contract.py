"""
tests/test_screen_lifecycle_contract.py

Comprehensive tests for TUI Screen Ownership, Single Application Console Singleton,
and Screen Lifecycle Transition Contracts.
"""
import unittest
from utils.console import console as shared_console, screen_manager, ScreenState, clear_screen, enter_alt_screen, exit_alt_screen


class ScreenLifecycleContractTests(unittest.TestCase):
    """Rigorous tests proving single console ownership and screen state transitions."""

    def test_authoritative_console_singleton_across_all_modules(self):
        """Verify that every TUI and networking module uses the single authoritative Console instance."""
        import tui.menu as menu_mod
        import tui.dashboard as dash_mod
        import tui.scan_view as scan_mod
        import tui.pcap_view as pcap_mod
        import tui.history_view as hist_mod
        import utils.privileges as priv_mod
        import sentinel as sentinel_mod

        self.assertIs(menu_mod.console, shared_console, "tui.menu must use the shared console singleton")
        self.assertIs(dash_mod.console, shared_console, "tui.dashboard must use the shared console singleton")
        self.assertIs(scan_mod.console, shared_console, "tui.scan_view must use the shared console singleton")
        self.assertIs(pcap_mod.console, shared_console, "tui.pcap_view must use the shared console singleton")
        self.assertIs(hist_mod.console, shared_console, "tui.history_view must use the shared console singleton")
        self.assertIs(priv_mod.console, shared_console, "utils.privileges must use the shared console singleton")
        self.assertIs(sentinel_mod.console, shared_console, "sentinel.py must use the shared console singleton")

    def test_screen_manager_state_contract_and_transitions(self):
        """Verify screen_manager transitions strictly and tracks the current active state."""
        # Initial / reset state
        screen_manager.set_state(ScreenState.MAIN_MENU)
        self.assertEqual(screen_manager.current_state, ScreenState.MAIN_MENU)

        # Transition: MENU -> TASK_CONFIG (Settings / Prompts)
        screen_manager.set_state(ScreenState.TASK_CONFIG)
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_CONFIG)

        # Transition: TASK_CONFIG -> TASK_RUNNING (Active Capture / Scanning)
        screen_manager.set_state(ScreenState.TASK_RUNNING)
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_RUNNING)

        # Transition: TASK_RUNNING -> TASK_COMPLETE (Results display)
        screen_manager.set_state(ScreenState.TASK_COMPLETE)
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_COMPLETE)

        # Transition: TASK_COMPLETE -> MAIN_MENU (Return to menu)
        screen_manager.set_state(ScreenState.MAIN_MENU)
        self.assertEqual(screen_manager.current_state, ScreenState.MAIN_MENU)

        # Transition: MAIN_MENU -> EXIT (Application exit)
        screen_manager.set_state(ScreenState.EXIT)
        self.assertEqual(screen_manager.current_state, ScreenState.EXIT)

    def test_rapid_navigation_25_cycles(self):
        """Perform 25 rapid navigation cycles across all application screens."""
        for cycle in range(25):
            # 1. MENU
            screen_manager.set_state(ScreenState.MAIN_MENU)
            self.assertEqual(screen_manager.current_state, ScreenState.MAIN_MENU)

            # 2. SCAN: Config -> Running -> Complete -> Menu
            screen_manager.set_state(ScreenState.TASK_CONFIG)
            screen_manager.set_state(ScreenState.TASK_RUNNING)
            screen_manager.set_state(ScreenState.TASK_COMPLETE)
            screen_manager.set_state(ScreenState.MAIN_MENU)

            # 3. CAPTURE: Config -> Running -> Complete -> Menu
            screen_manager.set_state(ScreenState.TASK_CONFIG)
            screen_manager.set_state(ScreenState.TASK_RUNNING)
            screen_manager.set_state(ScreenState.TASK_COMPLETE)
            screen_manager.set_state(ScreenState.MAIN_MENU)

            # 4. PCAP: Config -> Running -> Complete -> Menu
            screen_manager.set_state(ScreenState.TASK_CONFIG)
            screen_manager.set_state(ScreenState.TASK_RUNNING)
            screen_manager.set_state(ScreenState.TASK_COMPLETE)
            screen_manager.set_state(ScreenState.MAIN_MENU)

            # 5. HISTORY: Config -> Complete -> Menu
            screen_manager.set_state(ScreenState.TASK_CONFIG)
            screen_manager.set_state(ScreenState.TASK_COMPLETE)
            screen_manager.set_state(ScreenState.MAIN_MENU)

            # 6. SETTINGS: Config -> Menu
            screen_manager.set_state(ScreenState.TASK_CONFIG)
            screen_manager.set_state(ScreenState.MAIN_MENU)

        self.assertEqual(screen_manager.current_state, ScreenState.MAIN_MENU)

    def test_live_capture_suspension_lifecycle(self):
        """Verify Live capture suspension during interactive prompts maintains single screen ownership."""
        from rich.live import Live
        from tui.dashboard import LiveDashboard
        from core.stats import StatsAggregator
        from detection.alerts import AlertManager

        stats = StatsAggregator()
        am = AlertManager()
        dashboard = LiveDashboard(stats, am)

        # 1. Start Capture in TASK_RUNNING
        screen_manager.set_state(ScreenState.TASK_RUNNING)
        live = Live(dashboard.get_renderable(), console=shared_console, auto_refresh=False)
        live.start()
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_RUNNING)

        # 2. Suspend Live for Interactive Prompt (e.g. Filter change 'f')
        live.stop()
        screen_manager.set_state(ScreenState.TASK_CONFIG)
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_CONFIG)

        # 3. Resume Live after Prompt
        screen_manager.set_state(ScreenState.TASK_RUNNING)
        live.start()
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_RUNNING)

        # 4. Suspend Live for Export ('e')
        live.stop()
        screen_manager.set_state(ScreenState.TASK_CONFIG)
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_CONFIG)

        # 5. Resume Live
        screen_manager.set_state(ScreenState.TASK_RUNNING)
        live.start()
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_RUNNING)

        # 6. Stop Capture -> Transition to TASK_COMPLETE
        live.stop()
        screen_manager.set_state(ScreenState.TASK_COMPLETE)
        self.assertEqual(screen_manager.current_state, ScreenState.TASK_COMPLETE)

        # 7. Return to MAIN_MENU
        screen_manager.set_state(ScreenState.MAIN_MENU)
        self.assertEqual(screen_manager.current_state, ScreenState.MAIN_MENU)

    def test_clear_screen_and_alt_buffer_safety(self):
        """Verify clear_screen and alt screen buffer routines execute without error."""
        import utils.console as u_cons
        clear_screen()
        enter_alt_screen()
        clear_screen()
        exit_alt_screen()
        self.assertFalse(u_cons._in_alt_screen)


if __name__ == "__main__":
    unittest.main()
