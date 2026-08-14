import atexit
import signal
import sys
from enum import Enum, auto
from rich.console import Console

# Single shared Console instance across the entire application lifecycle.
# All TUI views, panels, prompts, and Live renderers MUST use this instance.
console = Console()

_in_alt_screen = False


class ScreenState(Enum):
    """Isolated TUI rendering states for strict lifecycle management."""
    MAIN_MENU = auto()
    TASK_CONFIG = auto()
    TASK_RUNNING = auto()
    TASK_COMPLETE = auto()
    EXIT = auto()


def enter_alt_screen():
    """
    1. Alternate Screen Buffer Handling:
       On application startup or view activation, switch to terminal's
       alternate screen buffer (\033[?1049h), wipe screen, and reset cursor to (1,1).
    """
    global _in_alt_screen
    if not _in_alt_screen and sys.stdout.isatty():
        sys.stdout.write("\033[?1049h\033[2J\033[H\033[?25h")
        sys.stdout.flush()
        _in_alt_screen = True


def exit_alt_screen():
    """
    1. Alternate Screen Buffer Handling:
       Guarantee restoration to standard buffer (\033[?1049l) and re-enable
       cursor visibility (\033[?25h) on normal exit, SIGINT, or unhandled exceptions.
    """
    global _in_alt_screen
    if sys.stdout.isatty():
        sys.stdout.write("\033[?1049l\033[?25h")
        sys.stdout.flush()
    _in_alt_screen = False


def clear_screen():
    """
    2. Explicit State Transitions & Screen Wiping:
       Centralized screen-clearing and cursor-reset routine (\033[2J\033[H).
       Executed immediately before any new view or menu renders.
       3. Input Stream & Cursor Isolation:
       Flushes stdout immediately after sending ANSI control sequences.
    """
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[H\033[?25h")
        sys.stdout.flush()
    console.clear()
    if sys.stdout.isatty():
        sys.stdout.flush()


class ScreenManager:
    """State-driven terminal rendering lifecycle manager."""

    def __init__(self):
        self._state = ScreenState.MAIN_MENU

    @property
    def current_state(self) -> ScreenState:
        return self._state

    def set_state(self, new_state: ScreenState):
        """
        Transition to an isolated render state.
        Wipes screen and homes cursor before rendering new view.
        """
        self._state = new_state
        clear_screen()


screen_manager = ScreenManager()

# Ensure terminal restoration on normal exit or unhandled exceptions via atexit
atexit.register(exit_alt_screen)


def _signal_handler(sig, frame):
    """Signal handler for SIGINT / SIGTERM ensuring clean buffer teardown."""
    exit_alt_screen()
    sys.exit(0)


try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
except (AttributeError, ValueError):
    # Operating system / environment does not support signal handlers (e.g. non-main thread)
    pass
