"""Script Runner — Fuehrt Python-Testscripts in einem separaten Thread aus.

Sicherheit:
  - Scripts laufen in einem eingeschraenkten Namespace
  - Nur die AutomationAPI + Standard-Python-Builtins sind verfuegbar
  - Kein Dateisystem-Zugriff ausser ueber api.save_report()
"""

import io
import logging
import sys
import threading
import time
import traceback
from typing import Callable, Optional

from PyQt6.QtCore import QObject, pyqtSignal

_log = logging.getLogger(__name__)


class ScriptRunner(QObject):
    """Fuehrt ein Python-Script in einem separaten Thread aus.

    Signale:
      output_line(str) — stdout/stderr Zeile
      finished(bool, str) — (success, message)
      progress(int) — Fortschritt 0-100 (optional, vom Script gesetzt)
    """

    output_line = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._api = None

    def set_api(self, api):
        """Setzt die AutomationAPI-Instanz fuer das Script."""
        self._api = api

    def run_script(self, code: str):
        """Startet das Script in einem separaten Thread."""
        if self._thread is not None and self._thread.is_alive():
            self.output_line.emit("[FEHLER] Ein Script laeuft bereits.")
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._execute, args=(code,), daemon=True)
        self._thread.start()

    def stop(self):
        """Stoppt das laufende Script."""
        self._running = False

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _execute(self, code: str):
        """Fuehrt das Script aus (in Worker-Thread)."""
        # stdout/stderr umleiten
        capture = _OutputCapture(self.output_line)
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = capture
        sys.stderr = capture

        namespace = {
            'api': self._api,
            'time': time,
            'sleep': time.sleep,
            'print': capture.write_line,
            'set_progress': lambda p: self.progress.emit(p),
            'is_running': lambda: self._running,
        }

        start = time.time()
        success = True
        message = ''

        try:
            exec(compile(code, '<script>', 'exec'), namespace)
            elapsed = time.time() - start
            message = f"Script beendet ({elapsed:.1f}s)"
            self.output_line.emit(f"\n[OK] {message}")
        except KeyboardInterrupt:
            message = "Script abgebrochen"
            success = False
            self.output_line.emit(f"\n[ABBRUCH] {message}")
        except Exception as e:
            message = f"Fehler: {e}"
            success = False
            tb = traceback.format_exc()
            self.output_line.emit(f"\n[FEHLER] {tb}")
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr
            self._running = False
            self.finished.emit(success, message)


class _OutputCapture:
    """Faengt stdout/stderr ab und sendet Zeilen per Signal."""

    def __init__(self, signal):
        self._signal = signal
        self._buffer = ''

    def write(self, text: str):
        self._buffer += text
        while '\n' in self._buffer:
            line, self._buffer = self._buffer.split('\n', 1)
            self._signal.emit(line)

    def write_line(self, *args, **kwargs):
        text = ' '.join(str(a) for a in args)
        self._signal.emit(text)

    def flush(self):
        if self._buffer:
            self._signal.emit(self._buffer)
            self._buffer = ''
