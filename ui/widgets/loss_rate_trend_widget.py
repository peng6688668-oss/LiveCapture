"""Loss Rate Trend Widget — 60s Echtzeit-Diagramm fuer PLP/TECMP/CMP Verlustraten.

Zeigt pro Protokoll-Quelle und Geraet eine eigene Kurve.
Verschiedene Farben fuer verschiedene Bus-Typen (CAN, LIN, FlexRay, etc.).
"""

import time
from collections import deque

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtGui import QFont

try:
    import pyqtgraph as pg
    PG_AVAILABLE = True
except ImportError:
    PG_AVAILABLE = False

_MONO = QFont("Consolas", 8)
_MAX_POINTS = 60  # 60s bei 1s Intervall

# Farben pro Bus-Typ
_BUS_COLORS = {
    'CAN': '#4CAF50',       # Gruen
    'LIN': '#FF9800',       # Orange
    'FlexRay': '#F44336',   # Rot
    'Ethernet': '#9C27B0',  # Lila
    'Analog': '#2196F3',    # Blau
    'Digital': '#00BCD4',   # Cyan
    'Total': '#607D8B',     # Grau (Gesamtrate)
}


class LossRateTrendWidget(QWidget):
    """60-Sekunden Loss-Rate Trend pro Bus-Typ und Geraet."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._start_time = time.time()
        self._timestamps = deque(maxlen=_MAX_POINTS)
        # {key: {'rates': deque, 'curve': PlotDataItem,
        #        'prev_total': int, 'prev_lost': int}}
        self._curves = {}
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(1)

        if PG_AVAILABLE:
            self._plot = pg.PlotWidget()
            self._plot.setBackground('#f5f5f7')
            self._plot.showGrid(x=True, y=True, alpha=0.3)
            self._plot.setLabel('bottom', 'Zeit', units='s')
            self._plot.setLabel('left', 'Verlust %')
            self._plot.setMinimumHeight(90)
            self._plot.setMaximumHeight(150)
            self._plot.addLegend(offset=(10, 10))

            # Schwellenwert-Linie bei 0.01%
            threshold = pg.InfiniteLine(
                pos=0.01, angle=0,
                pen=pg.mkPen('#F44336', width=1,
                             style=pg.QtCore.Qt.PenStyle.DashLine))
            self._plot.addItem(threshold)

            layout.addWidget(self._plot, 1)
        else:
            self._plot = None
            layout.addWidget(QLabel("pyqtgraph nicht installiert"), 1)

        self._info_label = QLabel("")
        self._info_label.setFont(_MONO)
        self._info_label.setStyleSheet("color: #666;")
        layout.addWidget(self._info_label)

    def update_tick(self, bus_stats: dict):
        """Wird 1x/s aufgerufen mit aktuellen kumulativen Zaehlerstaenden.

        Args:
            bus_stats: {key: {'total': int, 'lost': int, 'bus': str, 'device': int}}
                key z.B. "TECMP CAN", "CMP LIN 0x0025", "PLP CAN"
                bus: 'CAN', 'LIN', 'FlexRay', etc.
        """
        elapsed = time.time() - self._start_time
        self._timestamps.append(elapsed)

        info_parts = []
        for key, data in bus_stats.items():
            total = data.get('total', 0)
            lost = data.get('lost', 0)
            bus = data.get('bus', 'Total')

            if key not in self._curves:
                color = _BUS_COLORS.get(bus, '#607D8B')
                self._curves[key] = {
                    'rates': deque(maxlen=_MAX_POINTS),
                    'prev_total': total,
                    'prev_lost': lost,
                    'curve': None,
                }
                if self._plot is not None:
                    self._curves[key]['curve'] = self._plot.plot(
                        [], [], pen=pg.mkPen(color, width=2), name=key)

            entry = self._curves[key]
            dt = total - entry['prev_total']
            dl = lost - entry['prev_lost']
            entry['prev_total'] = total
            entry['prev_lost'] = lost
            rate = (dl / max(dt + dl, 1)) * 100.0 if dt + dl > 0 else 0.0
            entry['rates'].append(rate)

            cum_rate = (lost / max(total + lost, 1)) * 100.0
            if cum_rate > 0:
                info_parts.append(f"{key}: {cum_rate:.4f}%")

        # Plot aktualisieren
        if self._plot is not None and self._timestamps:
            t = list(self._timestamps)
            for entry in self._curves.values():
                if entry['curve'] is not None:
                    rates = list(entry['rates'])
                    n = min(len(t), len(rates))
                    if n > 0:
                        entry['curve'].setData(t[-n:], rates[-n:])

        self._info_label.setText("  ".join(info_parts) if info_parts else "")

    def clear(self):
        """Setzt alle Daten zurueck."""
        self._timestamps.clear()
        if self._plot is not None:
            for entry in self._curves.values():
                if entry['curve'] is not None:
                    self._plot.removeItem(entry['curve'])
        self._curves.clear()
        self._start_time = time.time()
        self._info_label.setText("")

    def cleanup(self):
        pass  # Kein eigener Timer — wird extern getriggert
