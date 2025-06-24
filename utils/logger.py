# utils/logger.py

import threading
import sys
import datetime

class Logger:
    """
    Simple thread-safe logger with color-coded output for terminal.
    """

    _lock = threading.Lock()

    COLOR_RESET = "\033[0m"
    COLORS = {
        "INFO": "\033[94m",     # Blue
        "WARNING": "\033[93m",  # Yellow
        "ERROR": "\033[91m",    # Red
        "SUCCESS": "\033[92m",  # Green
        "DEBUG": "\033[95m",    # Magenta
        "BANNER": "\033[96m",   # Cyan
    }

    def __init__(self, debug: bool = False):
        self.debug_enabled = debug

    def _log(self, level: str, message: str):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = self.COLORS.get(level, self.COLOR_RESET)
        with self._lock:
            print(f"{color}[{timestamp}] [{level}] {message}{self.COLOR_RESET}", file=sys.stdout)

    def info(self, message: str):
        self._log("INFO", message)

    def warning(self, message: str):
        self._log("WARNING", message)

    def error(self, message: str):
        self._log("ERROR", message)

    def success(self, message: str):
        self._log("SUCCESS", message)

    def debug(self, message: str):
        if self.debug_enabled:
            self._log("DEBUG", message)

    def banner(self, message: str):
        """
        Prints a banner-style message with decoration.
        """
        with self._lock:
            print()
            print(self.COLORS["BANNER"] + "=" * 80 + self.COLOR_RESET)
            print(self.COLORS["BANNER"] + f"{message:^80}" + self.COLOR_RESET)
            print(self.COLORS["BANNER"] + "=" * 80 + self.COLOR_RESET)
            print()

    def set_debug(self, enabled: bool):
        self.debug_enabled = enabled
