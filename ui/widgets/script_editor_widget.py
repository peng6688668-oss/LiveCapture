"""Script Editor Widget — Python-Script-Editor mit Ausfuehrung.

Features:
  - Syntax-Highlighting (Python)
  - Run/Stop Buttons
  - Output-Konsole
  - Beispiel-Scripts laden
"""

import os
import time

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPlainTextEdit,
    QPushButton, QLabel, QSplitter, QComboBox, QFileDialog,
    QMessageBox,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat

from core.automation_api import AutomationAPI
from core.script_runner import ScriptRunner

_MONO = QFont("Consolas", 10)

# ── Beispiel-Scripts ──

_EXAMPLE_READ_VIN = '''# VIN auslesen (UDS ReadDataByIdentifier)
api.set_test_name("VIN auslesen")

# Extended Session starten
api.can_send(0x7DF, bytes([0x02, 0x10, 0x03, 0, 0, 0, 0, 0]))
sleep(0.5)

# VIN lesen (DID 0xF190)
resp = api.uds_request(0x22, did=0xF190)
if resp:
    print(f"VIN Response: {resp.hex()}")
else:
    print("Keine Antwort")

print(api.summary)
'''

_EXAMPLE_CAN_ECHO = '''# CAN Echo-Test
api.set_test_name("CAN Echo-Test")
api.clear_rx_buffer()

# Frame senden
api.can_send(0x123, bytes([0x01, 0x02, 0x03, 0x04]))
print("Frame 0x123 gesendet")

# Auf Echo warten
api.assert_frame('CAN', 0x123, timeout=2.0, step_name="Echo-Check")

print(api.summary)
api.save_report("/tmp/can_echo_report.txt")
'''

_EXAMPLE_CYCLIC = '''# Zyklischer CAN-Test (10 Frames, 100ms Intervall)
api.set_test_name("Zyklischer Sende-Test")

for i in range(10):
    if not is_running():
        print("Abgebrochen")
        break
    data = bytes([i, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])
    api.can_send(0x200, data)
    print(f"Frame {i+1}/10 gesendet")
    set_progress(int((i+1) * 100 / 10))
    sleep(0.1)

print(api.summary)
'''

_EXAMPLES = {
    'VIN auslesen': _EXAMPLE_READ_VIN,
    'CAN Echo-Test': _EXAMPLE_CAN_ECHO,
    'Zyklischer Test': _EXAMPLE_CYCLIC,
}


class PythonHighlighter(QSyntaxHighlighter):
    """Einfacher Python-Syntax-Highlighter."""

    def __init__(self, document):
        super().__init__(document)
        self._rules = []

        # Keywords
        kw_format = QTextCharFormat()
        kw_format.setForeground(QColor('#0078d4'))
        kw_format.setFontWeight(700)
        keywords = [
            'def', 'class', 'import', 'from', 'return', 'if', 'else',
            'elif', 'for', 'while', 'break', 'continue', 'try', 'except',
            'finally', 'with', 'as', 'and', 'or', 'not', 'in', 'is',
            'True', 'False', 'None', 'pass', 'raise', 'yield', 'lambda',
        ]
        for kw in keywords:
            self._rules.append((f'\\b{kw}\\b', kw_format))

        # Strings
        str_format = QTextCharFormat()
        str_format.setForeground(QColor('#A31515'))
        self._rules.append(("'[^']*'", str_format))
        self._rules.append(('"[^"]*"', str_format))

        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor('#008000'))
        self._rules.append(('#.*$', comment_format))

        # Numbers
        num_format = QTextCharFormat()
        num_format.setForeground(QColor('#098658'))
        self._rules.append(('\\b\\d+\\.?\\d*\\b', num_format))

        # API calls
        api_format = QTextCharFormat()
        api_format.setForeground(QColor('#795E26'))
        api_calls = [
            'api\\.can_send', 'api\\.lin_send', 'api\\.uds_request',
            'api\\.wait_for', 'api\\.assert_frame', 'api\\.assert_did',
            'api\\.save_report', 'api\\.set_test_name', 'api\\.clear_rx_buffer',
            'sleep', 'print', 'set_progress', 'is_running',
        ]
        for call in api_calls:
            self._rules.append((call, api_format))

    def highlightBlock(self, text):
        import re
        for pattern, fmt in self._rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)


class ScriptEditorWidget(QWidget):
    """Python-Script-Editor mit Run/Stop und Output-Konsole."""

    def __init__(self, api: AutomationAPI, parent=None):
        super().__init__(parent)
        self._api = api
        self._runner = ScriptRunner(self)
        self._runner.set_api(api)
        self._runner.output_line.connect(self._on_output)
        self._runner.finished.connect(self._on_finished)
        self._runner.progress.connect(self._on_progress)
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Toolbar
        tb = QHBoxLayout()
        tb.setSpacing(4)

        title = QLabel("Automation Script")
        title.setStyleSheet("font-weight: bold; font-size: 11px;")
        tb.addWidget(title)

        # Beispiel-Dropdown
        self._example_combo = QComboBox()
        self._example_combo.addItem("Beispiel laden...")
        for name in _EXAMPLES:
            self._example_combo.addItem(name)
        self._example_combo.currentTextChanged.connect(self._load_example)
        self._example_combo.setMinimumWidth(150)
        tb.addWidget(self._example_combo)

        # Datei oeffnen
        open_btn = QPushButton("\U0001F4C2 Oeffnen")
        open_btn.setMinimumWidth(80)
        open_btn.clicked.connect(self._open_file)
        tb.addWidget(open_btn)

        tb.addStretch()

        # Run/Stop
        self._run_btn = QPushButton("\u25b6 Ausfuehren")
        self._run_btn.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;")
        self._run_btn.setMinimumWidth(100)
        self._run_btn.clicked.connect(self._on_run)
        tb.addWidget(self._run_btn)

        self._stop_btn = QPushButton("\u2b1b Stop")
        self._stop_btn.setStyleSheet(
            "background-color: #f44336; color: white; font-weight: bold;")
        self._stop_btn.setMinimumWidth(80)
        self._stop_btn.clicked.connect(self._on_stop)
        self._stop_btn.setEnabled(False)
        tb.addWidget(self._stop_btn)

        layout.addLayout(tb)

        # Splitter: Editor oben, Output unten
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Editor
        self._editor = QPlainTextEdit()
        self._editor.setFont(_MONO)
        self._editor.setPlaceholderText(
            "# Python-Script hier eingeben...\n"
            "# Verfuegbare API:\n"
            "#   api.can_send(id, data)\n"
            "#   api.wait_for(bus, frame_id, timeout)\n"
            "#   api.assert_frame(bus, id, expected_data)\n"
            "#   api.uds_request(sid, did=0xF190)\n"
            "#   api.save_report(path)\n")
        self._highlighter = PythonHighlighter(self._editor.document())
        splitter.addWidget(self._editor)

        # Output
        self._output = QPlainTextEdit()
        self._output.setFont(_MONO)
        self._output.setReadOnly(True)
        self._output.setMaximumHeight(150)
        self._output.setStyleSheet(
            "QPlainTextEdit { background: #1e1e2e; color: #d4d4d4; }")
        splitter.addWidget(self._output)

        splitter.setSizes([300, 150])
        layout.addWidget(splitter, 1)

    def _load_example(self, name: str):
        if name in _EXAMPLES:
            self._editor.setPlainText(_EXAMPLES[name])
            self._example_combo.setCurrentIndex(0)

    def _open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Script oeffnen", "",
            "Python (*.py);;Alle (*)")
        if path:
            with open(path, 'r', encoding='utf-8') as f:
                self._editor.setPlainText(f.read())

    def _on_run(self):
        code = self._editor.toPlainText()
        if not code.strip():
            return
        self._output.clear()
        self._output.appendPlainText(
            f"[START] {time.strftime('%H:%M:%S')}\n")
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._runner.run_script(code)

    def _on_stop(self):
        self._runner.stop()

    def _on_output(self, line: str):
        self._output.appendPlainText(line)

    def _on_finished(self, success: bool, message: str):
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)

    def _on_progress(self, value: int):
        pass  # Koennte einen Fortschrittsbalken aktualisieren

    def cleanup(self):
        self._runner.stop()
