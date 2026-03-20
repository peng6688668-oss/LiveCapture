"""Echtzeit CAN-Signal-Plot Widget (CANape-Style Measurement Window).

Zeigt DBC-dekodierte CAN-Signale als Zeitreihe. Mehrere Signale
gleichzeitig darstellbar mit Auto-Scroll und konfigurierbarem Zeitfenster.
"""

import time
import logging
from collections import deque
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QComboBox, QSpinBox, QLabel, QCheckBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

try:
    import pyqtgraph as pg
    PG_AVAILABLE = True
except ImportError:
    PG_AVAILABLE = False

_log = logging.getLogger(__name__)

_COLORS = [
    '#4CAF50', '#2196F3', '#F44336', '#FF9800',
    '#9C27B0', '#00BCD4', '#FFEB3B', '#E91E63',
]

_MAX_POINTS = 5000


class CanSignalPlotWidget(QWidget):
    """Echtzeit-Plot fuer DBC-dekodierte CAN-Signale."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._dbc = None
        self._tracked: Dict[str, dict] = {}  # signal_name → {msg, deque_t, deque_v, curve, color}
        self._color_idx = 0
        self._t0 = 0.0
        self._time_window = 10  # Sekunden
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # ── Toolbar ──
        tb = QHBoxLayout()
        tb.setSpacing(4)

        tb.addWidget(QLabel("Signal:"))
        self._sig_combo = QComboBox()
        self._sig_combo.setMinimumWidth(200)
        self._sig_combo.setFont(QFont("Consolas", 8))
        tb.addWidget(self._sig_combo, 1)

        add_btn = QPushButton("+ Hinzu")
        add_btn.setFixedWidth(70)
        add_btn.clicked.connect(self._add_selected_signal)
        tb.addWidget(add_btn)

        rm_btn = QPushButton("- Entfernen")
        rm_btn.setFixedWidth(80)
        rm_btn.clicked.connect(self._remove_selected_signal)
        tb.addWidget(rm_btn)

        tb.addWidget(QLabel("Fenster:"))
        self._window_spin = QSpinBox()
        self._window_spin.setRange(2, 300)
        self._window_spin.setValue(10)
        self._window_spin.setSuffix(" s")
        self._window_spin.setFixedWidth(70)
        self._window_spin.valueChanged.connect(self._on_window_changed)
        tb.addWidget(self._window_spin)

        self._auto_scroll = QCheckBox("Auto-Scroll")
        self._auto_scroll.setChecked(True)
        tb.addWidget(self._auto_scroll)

        clear_btn = QPushButton("Loeschen")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self._clear_all)
        tb.addWidget(clear_btn)

        layout.addLayout(tb)

        # ── Plot ──
        if PG_AVAILABLE:
            pg.setConfigOptions(antialias=True)
            self._plot = pg.PlotWidget()
            self._plot.setBackground('#1e1e2e')
            self._plot.showGrid(x=True, y=True, alpha=0.3)
            self._plot.setLabel('bottom', 'Zeit', units='s')
            self._plot.setLabel('left', 'Wert')
            self._legend = self._plot.addLegend(offset=(10, 10))
            layout.addWidget(self._plot, 1)
        else:
            layout.addWidget(QLabel("pyqtgraph nicht installiert"), 1)
            self._plot = None

    def set_dbc(self, dbc):
        """Setzt die DBC-Datenbank und fuellt die Signal-Auswahl."""
        self._dbc = dbc
        self._sig_combo.clear()
        if dbc is None:
            return
        for msg in sorted(dbc.messages, key=lambda m: m.frame_id):
            for sig in msg.signals:
                unit = f" [{sig.unit}]" if sig.unit else ""
                self._sig_combo.addItem(
                    f"0x{msg.frame_id:03X} {msg.name}.{sig.name}{unit}",
                    userData=(msg.name, sig.name),
                )

    def feed_can_frame(self, timestamp: float, can_id: int, data: bytes):
        """Empfaengt einen CAN-Frame und aktualisiert getrackete Signale."""
        if not self._tracked or self._dbc is None or self._plot is None:
            return

        try:
            msg = self._dbc.get_message_by_frame_id(can_id)
        except KeyError:
            return

        # Nur decodieren wenn mindestens ein Signal dieses Messages getrackt wird
        msg_signals = [name for name, info in self._tracked.items()
                       if info['msg_name'] == msg.name]
        if not msg_signals:
            return

        try:
            decoded = msg.decode(data, scaling=True)
        except Exception:
            return

        if self._t0 == 0.0:
            self._t0 = timestamp
        t = timestamp - self._t0

        for sig_name in msg_signals:
            if sig_name in decoded:
                info = self._tracked[sig_name]
                info['t'].append(t)
                info['v'].append(decoded[sig_name])

        # Plot aktualisieren (jedes 3. Frame fuer Performance)
        self._frame_counter = getattr(self, '_frame_counter', 0) + 1
        if self._frame_counter % 3 == 0:
            self._update_plot()

    def _add_selected_signal(self):
        """Fuegt das ausgewaehlte Signal zum Plot hinzu."""
        idx = self._sig_combo.currentIndex()
        if idx < 0 or self._plot is None:
            return
        data = self._sig_combo.itemData(idx)
        if data is None:
            return
        msg_name, sig_name = data
        if sig_name in self._tracked:
            return  # Schon getrackt

        color = _COLORS[self._color_idx % len(_COLORS)]
        self._color_idx += 1

        pen = pg.mkPen(color=color, width=2)
        curve = self._plot.plot([], [], pen=pen, name=sig_name)

        self._tracked[sig_name] = {
            'msg_name': msg_name,
            't': deque(maxlen=_MAX_POINTS),
            'v': deque(maxlen=_MAX_POINTS),
            'curve': curve,
            'color': color,
        }

    def _remove_selected_signal(self):
        """Entfernt das ausgewaehlte Signal aus dem Plot."""
        idx = self._sig_combo.currentIndex()
        if idx < 0 or self._plot is None:
            return
        data = self._sig_combo.itemData(idx)
        if data is None:
            return
        _, sig_name = data
        if sig_name not in self._tracked:
            return
        info = self._tracked.pop(sig_name)
        self._plot.removeItem(info['curve'])

    def _update_plot(self):
        """Aktualisiert die Plot-Kurven."""
        if self._plot is None:
            return
        for info in self._tracked.values():
            t_list = list(info['t'])
            v_list = list(info['v'])
            if t_list:
                info['curve'].setData(t_list, v_list)

        if self._auto_scroll.isChecked() and self._tracked:
            # Neueste Zeit aus allen Kurven
            max_t = max(
                (info['t'][-1] for info in self._tracked.values() if info['t']),
                default=0,
            )
            if max_t > self._time_window:
                self._plot.setXRange(max_t - self._time_window, max_t)

    def _on_window_changed(self, value: int):
        self._time_window = value

    def _clear_all(self):
        """Loescht alle Daten und Kurven."""
        for info in self._tracked.values():
            info['t'].clear()
            info['v'].clear()
            info['curve'].setData([], [])
        self._t0 = 0.0
