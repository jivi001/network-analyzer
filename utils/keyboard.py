"""
utils/keyboard.py — Cross-platform non-blocking keyboard input listener.
Supports Windows (msvcrt) and POSIX / Linux / macOS (termios + select).
"""

import atexit
import os
import sys
from typing import Optional

if sys.platform != "win32":
    try:
        import select
        import termios
        import tty
    except ImportError:
        select = None
        termios = None
        tty = None
else:
    select = None
    termios = None
    tty = None


class NonBlockingInput:
    """
    Context manager for reading single non-blocking keypresses
    in interactive terminal loops across Windows, Linux, and macOS.
    """

    def __init__(self):
        self.is_windows = sys.platform == "win32"
        self._old_settings = None
        self._active = False
        self._is_tty = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self):
        """Put POSIX terminal in cbreak/no-echo mode for single-keystroke detection."""
        if self._active:
            return
        if not self.is_windows and self._is_tty and termios and tty:
            try:
                self._old_settings = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
                # Disable ECHO so pressed keys don't clutter the Live render
                cbreak_settings = termios.tcgetattr(sys.stdin.fileno())
                cbreak_settings[3] = cbreak_settings[3] & ~termios.ECHO
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, cbreak_settings)
                atexit.register(self.stop)
                self._active = True
            except Exception:
                self._old_settings = None
                self._active = False
        else:
            self._active = True

    def stop(self):
        """Restore POSIX terminal to original cooked settings."""
        if not self.is_windows and self._old_settings is not None and self._active and termios:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_settings)
            except Exception:
                pass
            finally:
                self._old_settings = None
                self._active = False

    def get_key(self) -> Optional[str]:
        """
        Check for an available keypress without blocking.
        Returns lowercased character string if a key was pressed, otherwise None.
        """
        if self.is_windows:
            try:
                import msvcrt
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    return ch.decode("utf-8", "ignore").lower()
            except Exception:
                return None
            return None
        else:
            if not self._is_tty or not self._active or not select:
                return None
            try:
                fd = 0
                if hasattr(sys.stdin, "fileno"):
                    try:
                        fd = sys.stdin.fileno()
                    except Exception:
                        fd = 0
                rlist, _, _ = select.select([fd], [], [], 0)
                if rlist:
                    raw_bytes = os.read(fd, 1)
                    if raw_bytes:
                        return raw_bytes.decode("utf-8", "ignore").lower()
            except Exception:
                return None
            return None
