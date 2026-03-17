"""Wireshark-ähnliches Panel für Auto-Ethernet-Datenanalyse."""

import os
import json
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
    QTextEdit, QLineEdit, QPushButton, QLabel, QComboBox,
    QFileDialog, QMessageBox, QHeaderView, QTabWidget,
    QGroupBox, QFormLayout, QProgressBar, QMenu, QToolBar,
    QDialog, QDialogButtonBox, QInputDialog, QCheckBox,
    QColorDialog, QListWidget, QListWidgetItem, QFrame,
    QTableView, QGridLayout, QScrollArea, QSlider
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QProcess, QTimer, QModelIndex, QAbstractTableModel, QObject, QSocketNotifier
from PyQt6.QtGui import QAction, QFont, QColor, QBrush, QImage, QPixmap
import logging
import subprocess
import struct
import sys
import socket
import shutil
import array
import time
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import mmap
import select

from ui.widgets.native_combo_box import NativeComboBox
from ui.ip_history_combo import IpHistoryCombo

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except ImportError:
    CV2_AVAILABLE = False

try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
    from PyQt6.QtCore import QUrl
    WEBENGINE_AVAILABLE = True
except Exception as _we_err:
    WEBENGINE_AVAILABLE = False
    import logging as _welog
    _welog.getLogger(__name__).warning("WebEngine import failed: %s", _we_err)


# =============================================================================
# PLP Counter Monitor — eigenstaendiger Prozess (kein GIL, eigener CPU-Kern)
# =============================================================================
# SharedMemory Layout pro Interface (5 x int64 = 40 Bytes):
#   [0]  total     — empfangene Pakete
#   [1]  gaps      — Anzahl Luecken
#   [2]  lost      — verlorene Counter-Werte
#   [3..10]  stream_ids  — bis zu 8 erkannte Stream-IDs (0 = leer)
# Separates Array: since_hour, since_min, since_sec (3 x int, global)

# Max Interfaces
_CM_MAX_IFACES = 4
# Felder pro Interface im shared array (Legacy Counter Monitor Prozess)
_CM_FIELDS = 11  # total, gaps, lost, + 8 stream_id slots
_CM_TOTAL = 0
_CM_GAPS = 1
_CM_LOST = 2
_CM_STREAMS_START = 3  # stream_ids[0..7]

# ── Inline Counter (in CaptureWorker, kein extra Socket) ──
_ICT_FIELDS = 13  # total, gaps, lost, stream_id[0..7], timestamp, kern_drops
_ICT_TOTAL = 0
_ICT_GAPS = 1
_ICT_LOST = 2
_ICT_STREAMS_START = 3  # stream_ids[0..7]
_ICT_TIMESTAMP = 11
_ICT_KERN_DROPS = 12


def _counter_monitor_worker(interfaces, stats_arr, since_arr,
                             stop_event, reset_event, pause_event=None):
    """Eigenstaendiger Prozess: TPACKET_V3 MMAP Counter-Check.

    Laeuft auf eigenem CPU-Kern, beeinflusst Video-Pipeline nicht.
    """
    import select as _sel
    # CPU-Affinitaet: auf CPU 15 pinnen (weg von NAPI CPU 4/5 und Video-CPUs)
    try:
        os.sched_setaffinity(0, {15})
    except Exception:
        pass

    # TPACKET_V3 Konstanten
    SOL_PACKET = 263
    PACKET_VERSION = 10
    PACKET_RX_RING = 5
    TPACKET_V3 = 2
    TP_STATUS_USER = 1
    TP_STATUS_KERNEL = 0
    BD_STATUS = 8
    BD_NUM_PKTS = 12
    BD_FIRST_PKT = 16
    PH_NEXT = 0
    PH_SNAPLEN = 12
    PH_MAC = 24

    _up_H = struct.Struct('>H').unpack_from
    _up_I = struct.Struct('>I').unpack_from
    _le_I = struct.Struct('<I').unpack_from
    _le_H = struct.Struct('<H').unpack_from

    BLOCK_SIZE = 1 << 20   # 1 MB
    BLOCK_NR = 64           # 64 MB Ring pro Interface
    FRAME_SIZE = 1 << 14    # 16 KB
    FRAME_NR = (BLOCK_SIZE * BLOCK_NR) // FRAME_SIZE

    # Pro Interface: Socket + MMAP
    iface_data = []  # [(idx, sock, ring, block_idx)]
    # Per-Interface + per-ProbeID Status: {iface_idx: {probe_id: state}}
    probe_states = {}  # idx → {probe_id → {prev, total, gaps, lost, streams}}
    # Haupt-ProbeID pro Interface (die mit den meisten Paketen)
    probe_pkt_counts = {}  # idx → {probe_id → count}

    for i, iface in enumerate(interfaces):
        if i >= _CM_MAX_IFACES:
            break
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x2090))
            sock.bind((iface, 0))
            # Snaplen auf 64 Bytes begrenzen (nur Header noetig, spart DMA)
            PACKET_COPY_THRESH = 7  # SOL_PACKET option
            try:
                sock.setsockopt(SOL_PACKET, PACKET_COPY_THRESH,
                                struct.pack('i', 64))
            except Exception:
                pass
            ver = struct.pack('i', TPACKET_V3)
            sock.setsockopt(SOL_PACKET, PACKET_VERSION, ver)
            req = struct.pack('IIIIIII',
                              BLOCK_SIZE, BLOCK_NR, FRAME_SIZE, FRAME_NR,
                              50, 0, 0)
            sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
            ring = mmap.mmap(sock.fileno(), BLOCK_SIZE * BLOCK_NR,
                             mmap.MAP_SHARED,
                             mmap.PROT_READ | mmap.PROT_WRITE)
            iface_data.append((i, sock, ring, 0))
            probe_states[i] = {}
            probe_pkt_counts[i] = {}
        except Exception:
            continue

    if not iface_data:
        return

    poller = _sel.poll()
    for _, sock, *_ in iface_data:
        poller.register(sock, _sel.POLLIN)

    # Seit-Zeitpunkt initial setzen
    t = time.localtime()
    since_arr[0] = t.tm_hour
    since_arr[1] = t.tm_min
    since_arr[2] = t.tm_sec

    last_write = time.monotonic()

    try:
        while not stop_event.is_set():
            # Reset-Check
            if reset_event.is_set():
                reset_event.clear()
                t = time.localtime()
                since_arr[0] = t.tm_hour
                since_arr[1] = t.tm_min
                since_arr[2] = t.tm_sec
                for idx in probe_states:
                    probe_states[idx] = {}
                    probe_pkt_counts[idx] = {}
                # Shared Array leeren
                for k in range(len(stats_arr)):
                    stats_arr[k] = 0

            # Pause-Check: Socket offen lassen, aber Pakete nur durchlaufen lassen
            if pause_event is not None and pause_event.is_set():
                time.sleep(0.2)
                # Ring-Bloecke zurueckgeben damit kein Backlog entsteht
                for di in range(len(iface_data)):
                    _a, _s, ring, bidx = iface_data[di]
                    while True:
                        offset = bidx * BLOCK_SIZE
                        bstatus = _le_I(ring, offset + BD_STATUS)[0]
                        if not (bstatus & TP_STATUS_USER):
                            break
                        struct.pack_into('<I', ring, offset + BD_STATUS,
                                         TP_STATUS_KERNEL)
                        bidx = (bidx + 1) % BLOCK_NR
                    iface_data[di] = (_a, _s, ring, bidx)
                continue

            poller.poll(200)

            # Alle Interfaces drainieren
            for di in range(len(iface_data)):
                arr_idx, sock, ring, bidx = iface_data[di]

                while True:
                    offset = bidx * BLOCK_SIZE
                    bstatus = _le_I(ring, offset + BD_STATUS)[0]
                    if not (bstatus & TP_STATUS_USER):
                        break

                    num_pkts = _le_I(ring, offset + BD_NUM_PKTS)[0]
                    first_off = _le_I(ring, offset + BD_FIRST_PKT)[0]
                    pkt_pos = offset + first_off

                    for _ in range(num_pkts):
                        tp_next = _le_I(ring, pkt_pos + PH_NEXT)[0]
                        tp_snaplen = _le_I(ring, pkt_pos + PH_SNAPLEN)[0]
                        tp_mac = _le_H(ring, pkt_pos + PH_MAC)[0]

                        if tp_snaplen >= 30:
                            eth_off = pkt_pos + tp_mac
                            probe_id = _up_H(ring, eth_off + 14)[0]
                            counter = _up_H(ring, eth_off + 16)[0]
                            stream_id = _up_I(ring, eth_off + 26)[0]

                            # Per-ProbeID Zustand
                            ps = probe_states[arr_idx]
                            if probe_id not in ps:
                                ps[probe_id] = {
                                    'prev': -1, 'total': 0,
                                    'gaps': 0, 'lost': 0,
                                    'streams': set(),
                                }
                                probe_pkt_counts[arr_idx][probe_id] = 0
                            ls = ps[probe_id]
                            ls['total'] += 1
                            ls['streams'].add(stream_id)
                            probe_pkt_counts[arr_idx][probe_id] += 1

                            prev = ls['prev']
                            if prev >= 0:
                                expected = (prev + 1) & 0xFFFF
                                if counter != expected:
                                    if counter > prev:
                                        gap = counter - prev
                                    else:
                                        gap = (65536 - prev) + counter
                                    ls['gaps'] += 1
                                    ls['lost'] += gap - 1
                            ls['prev'] = counter

                        pkt_pos += tp_next

                    struct.pack_into('<I', ring,
                                     offset + BD_STATUS,
                                     TP_STATUS_KERNEL)
                    bidx = (bidx + 1) % BLOCK_NR

                iface_data[di] = (arr_idx, sock, ring, bidx)

            # Shared Array jede Sekunde aktualisieren (nur Haupt-ProbeID)
            now = time.monotonic()
            if now - last_write >= 1.0:
                last_write = now
                for di in range(len(iface_data)):
                    arr_idx = iface_data[di][0]
                    ps = probe_states.get(arr_idx, {})
                    pc = probe_pkt_counts.get(arr_idx, {})
                    if not ps:
                        continue
                    # Haupt-ProbeID = die mit den meisten Paketen
                    main_pid = max(pc, key=pc.get) if pc else None
                    if main_pid is None:
                        continue
                    ls = ps[main_pid]
                    base = arr_idx * _CM_FIELDS
                    stats_arr[base + _CM_TOTAL] = ls['total']
                    stats_arr[base + _CM_GAPS] = ls['gaps']
                    stats_arr[base + _CM_LOST] = ls['lost']
                    sids = sorted(ls['streams'])
                    for si in range(8):
                        stats_arr[base + _CM_STREAMS_START + si] = (
                            sids[si] if si < len(sids) else 0)
    finally:
        for _, sock, ring, _ in iface_data:
            try:
                ring.close()
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass


# =============================================================================
# Farbregeln (Coloring Rules) - wie Wireshark
# =============================================================================

@dataclass
class ColorRule:
    """Eine Farbregel fuer die Paketanzeige."""
    name: str
    filter_expression: str
    foreground: str = "#000000"
    background: str = "#ffffff"
    enabled: bool = True
    priority: int = 0  # Hoehere Prioritaet = wird zuerst geprueft

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'ColorRule':
        return cls(**d)


class ColorRulesManager:
    """Verwaltet die Farbregeln und evaluiert sie fuer Pakete."""

    # Vordefinierte Regeln
    DEFAULT_RULES = [
        # UDS-Regeln
        ColorRule(
            name="UDS Negative Response (NRC)",
            filter_expression="uds.nrc or info contains 'NRC:'",
            foreground="#000000",
            background="#ffcdd2",  # Rot
            priority=100
        ),
        ColorRule(
            name="UDS Positive Response",
            filter_expression="uds.positive_response",
            foreground="#000000",
            background="#c8e6c9",  # Gruen
            priority=90
        ),
        # DoIP-Regeln
        ColorRule(
            name="DoIP Routing Activation",
            filter_expression="doip.type == 0x0005 or doip.type == 0x0006",
            foreground="#000000",
            background="#fff9c4",  # Gelb
            priority=85
        ),
        ColorRule(
            name="DoIP Negative ACK",
            filter_expression="doip.type == 0x8003 or doip.type == 0x0000",
            foreground="#000000",
            background="#ffcdd2",  # Rot
            priority=95
        ),
        ColorRule(
            name="DoIP Diagnostic Message",
            filter_expression="doip.type == 0x8001",
            foreground="#000000",
            background="#e8f5e9",  # Hellgruen
            priority=50
        ),
        # SOME/IP-Regeln
        ColorRule(
            name="SOME/IP Error",
            filter_expression="someip.message_type == 0x81 or someip.message_type == 0xA1",
            foreground="#000000",
            background="#ffcdd2",  # Rot
            priority=95
        ),
        ColorRule(
            name="SOME/IP Return Code != E_OK",
            filter_expression="someip.return_code != 0x00",
            foreground="#000000",
            background="#ffcdd2",  # Rot
            priority=94
        ),
        ColorRule(
            name="SOME/IP Response",
            filter_expression="someip.message_type == 0x80",
            foreground="#000000",
            background="#c8e6c9",  # Gruen
            priority=60
        ),
        ColorRule(
            name="SOME/IP Request",
            filter_expression="someip.message_type == 0x00",
            foreground="#000000",
            background="#e3f2fd",  # Blau
            priority=55
        ),
        # Protokoll-basierte Regeln (niedrige Prioritaet)
        ColorRule(
            name="DoIP Protokoll",
            filter_expression="protocol == 'DoIP'",
            foreground="#000000",
            background="#e8f5e9",
            priority=10
        ),
        ColorRule(
            name="SOME/IP Protokoll",
            filter_expression="protocol == 'SOME/IP'",
            foreground="#000000",
            background="#e3f2fd",
            priority=10
        ),
        ColorRule(
            name="UDS Protokoll",
            filter_expression="protocol == 'UDS'",
            foreground="#000000",
            background="#fff3e0",
            priority=10
        ),
        ColorRule(
            name="TCP Protokoll",
            filter_expression="protocol == 'TCP'",
            foreground="#000000",
            background="#fce4ec",
            priority=5
        ),
        ColorRule(
            name="UDP Protokoll",
            filter_expression="protocol == 'UDP'",
            foreground="#000000",
            background="#f3e5f5",
            priority=5
        ),
        ColorRule(
            name="PLP/TECMP Protokoll",
            filter_expression="protocol == 'PLP/TECMP'",
            foreground="#000000",
            background="#e0f7fa",
            priority=5
        ),
    ]

    def __init__(self):
        self.rules: List[ColorRule] = []
        self._config_path = Path.home() / ".messtechnik" / "color_rules.json"
        self._load_rules()

    def _load_rules(self):
        """Laedt Regeln aus der Konfigurationsdatei oder verwendet Standardregeln."""
        if self._config_path.exists():
            try:
                with open(self._config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.rules = [ColorRule.from_dict(r) for r in data]
                    return
            except Exception:
                pass
        # Standardregeln verwenden
        self.rules = list(self.DEFAULT_RULES)

    def save_rules(self):
        """Speichert die Regeln in die Konfigurationsdatei."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, 'w', encoding='utf-8') as f:
            json.dump([r.to_dict() for r in self.rules], f, indent=2, ensure_ascii=False)

    def reset_to_defaults(self):
        """Setzt die Regeln auf die Standardwerte zurueck."""
        self.rules = list(self.DEFAULT_RULES)
        self.save_rules()

    def evaluate(self, packet_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """
        Evaluiert alle Regeln fuer ein Paket und gibt die Farben zurueck.

        Args:
            packet_data: Dict mit Paketinformationen:
                - protocol: str
                - info: str
                - src, dst: str
                - uds_sid, uds_nrc: Optional[int]
                - doip_type: Optional[int]
                - someip_message_type, someip_return_code: Optional[int]

        Returns:
            Tuple (foreground_color, background_color) oder (None, None)
        """
        # Regeln nach Prioritaet sortieren (hoechste zuerst)
        sorted_rules = sorted(
            [r for r in self.rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True
        )

        for rule in sorted_rules:
            if self._matches(rule.filter_expression, packet_data):
                return (rule.foreground, rule.background)

        return (None, None)

    def _matches(self, expression: str, data: Dict[str, Any]) -> bool:
        """Prueft ob ein Filterausdruck auf die Paketdaten zutrifft."""
        expr = expression.lower().strip()

        # Protokoll-basierte Regeln
        if expr.startswith("protocol =="):
            match = re.search(r"protocol\s*==\s*['\"]?([^'\"]+)['\"]?", expr)
            if match:
                proto = match.group(1).strip().lower()
                return data.get('protocol', '').lower() == proto

        # Info-basierte Regeln (substring match)
        if "info contains" in expr:
            match = re.search(r"info\s+contains\s+['\"]([^'\"]+)['\"]", expr)
            if match:
                substring = match.group(1).lower()
                return substring in data.get('info', '').lower()

        # UDS-Regeln
        if "uds.nrc" in expr:
            # Prueft auf UDS Negative Response Code
            if data.get('uds_nrc') is not None:
                return True
            if 'NRC:' in data.get('info', ''):
                return True
            return False

        if "uds.positive_response" in expr:
            # Prueft auf UDS Positive Response (SID | 0x40)
            return data.get('uds_positive_response', False)

        # DoIP-Regeln
        if "doip.type ==" in expr:
            match = re.search(r"doip\.type\s*==\s*(0x[0-9a-fA-F]+|\d+)", expr)
            if match:
                expected_type = int(match.group(1), 0)
                return data.get('doip_type') == expected_type

        # SOME/IP-Regeln
        if "someip.message_type ==" in expr:
            match = re.search(r"someip\.message_type\s*==\s*(0x[0-9a-fA-F]+|\d+)", expr)
            if match:
                expected_type = int(match.group(1), 0)
                return data.get('someip_message_type') == expected_type

        if "someip.return_code !=" in expr:
            match = re.search(r"someip\.return_code\s*!=\s*(0x[0-9a-fA-F]+|\d+)", expr)
            if match:
                expected_code = int(match.group(1), 0)
                return_code = data.get('someip_return_code')
                if return_code is not None:
                    return return_code != expected_code
            return False

        if "someip.return_code ==" in expr:
            match = re.search(r"someip\.return_code\s*==\s*(0x[0-9a-fA-F]+|\d+)", expr)
            if match:
                expected_code = int(match.group(1), 0)
                return data.get('someip_return_code') == expected_code

        # OR-Verknuepfung
        if " or " in expr:
            parts = expr.split(" or ")
            return any(self._matches(p.strip(), data) for p in parts)

        # AND-Verknuepfung
        if " and " in expr:
            parts = expr.split(" and ")
            return all(self._matches(p.strip(), data) for p in parts)

        return False


class ColorRulesDialog(QDialog):
    """Dialog zum Bearbeiten der Farbregeln."""

    def __init__(self, manager: ColorRulesManager, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.setWindowTitle("Farbregeln bearbeiten")
        self.resize(800, 600)
        self._init_ui()
        self._populate_list()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Info-Label
        info = QLabel(
            "Farbregeln werden von oben nach unten nach Prioritaet ausgewertet.\n"
            "Die erste passende Regel bestimmt die Farbe des Pakets."
        )
        info.setStyleSheet("background: #e3f2fd; padding: 8px; border-radius: 4px;")
        layout.addWidget(info)

        # Hauptbereich: Liste + Bearbeitungsbereich
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Linke Seite: Regelliste
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.rules_list = QListWidget()
        self.rules_list.setAlternatingRowColors(True)
        self.rules_list.currentRowChanged.connect(self._on_rule_selected)
        left_layout.addWidget(self.rules_list)

        # Buttons unter der Liste
        btn_layout = QHBoxLayout()
        self.btn_add = QPushButton("+ Neu")
        self.btn_add.clicked.connect(self._add_rule)
        btn_layout.addWidget(self.btn_add)

        self.btn_delete = QPushButton("- Loeschen")
        self.btn_delete.clicked.connect(self._delete_rule)
        btn_layout.addWidget(self.btn_delete)

        self.btn_up = QPushButton("▲")
        self.btn_up.clicked.connect(self._move_up)
        btn_layout.addWidget(self.btn_up)

        self.btn_down = QPushButton("▼")
        self.btn_down.clicked.connect(self._move_down)
        btn_layout.addWidget(self.btn_down)

        left_layout.addLayout(btn_layout)
        main_splitter.addWidget(left_widget)

        # Rechte Seite: Bearbeitungsbereich
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # Name
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("Name:"))
        self.name_edit = QLineEdit()
        self.name_edit.textChanged.connect(self._on_edit_changed)
        name_layout.addWidget(self.name_edit)
        right_layout.addLayout(name_layout)

        # Filter
        filter_layout = QVBoxLayout()
        filter_layout.addWidget(QLabel("Filter-Ausdruck:"))
        self.filter_edit = QTextEdit()
        self.filter_edit.setMaximumHeight(80)
        self.filter_edit.setFont(QFont("Consolas", 10))
        self.filter_edit.textChanged.connect(self._on_edit_changed)
        filter_layout.addWidget(self.filter_edit)

        # Filter-Hilfe
        help_text = QLabel(
            "Beispiele:\n"
            "• protocol == 'DoIP'\n"
            "• info contains 'NRC:'\n"
            "• uds.nrc or uds.positive_response\n"
            "• someip.return_code != 0x00\n"
            "• doip.type == 0x0005"
        )
        help_text.setStyleSheet("color: #666; font-size: 10px;")
        filter_layout.addWidget(help_text)
        right_layout.addLayout(filter_layout)

        # Prioritaet
        prio_layout = QHBoxLayout()
        prio_layout.addWidget(QLabel("Prioritaet:"))
        self.priority_edit = QLineEdit()
        self.priority_edit.setMaximumWidth(80)
        self.priority_edit.textChanged.connect(self._on_edit_changed)
        prio_layout.addWidget(self.priority_edit)
        prio_layout.addWidget(QLabel("(hoeher = wird zuerst geprueft)"))
        prio_layout.addStretch()
        right_layout.addLayout(prio_layout)

        # Farben
        colors_layout = QHBoxLayout()

        # Hintergrundfarbe
        bg_layout = QVBoxLayout()
        bg_layout.addWidget(QLabel("Hintergrund:"))
        self.bg_preview = QFrame()
        self.bg_preview.setFixedSize(60, 30)
        self.bg_preview.setStyleSheet("background: #ffffff; border: 1px solid #ccc;")
        self.bg_preview.mousePressEvent = lambda e: self._pick_color('bg')
        bg_layout.addWidget(self.bg_preview)
        self.bg_btn = QPushButton("Waehlen...")
        self.bg_btn.clicked.connect(lambda: self._pick_color('bg'))
        bg_layout.addWidget(self.bg_btn)
        colors_layout.addLayout(bg_layout)

        # Vordergrundfarbe
        fg_layout = QVBoxLayout()
        fg_layout.addWidget(QLabel("Vordergrund:"))
        self.fg_preview = QFrame()
        self.fg_preview.setFixedSize(60, 30)
        self.fg_preview.setStyleSheet("background: #000000; border: 1px solid #ccc;")
        self.fg_preview.mousePressEvent = lambda e: self._pick_color('fg')
        fg_layout.addWidget(self.fg_preview)
        self.fg_btn = QPushButton("Waehlen...")
        self.fg_btn.clicked.connect(lambda: self._pick_color('fg'))
        fg_layout.addWidget(self.fg_btn)
        colors_layout.addLayout(fg_layout)

        # Vorschau
        preview_layout = QVBoxLayout()
        preview_layout.addWidget(QLabel("Vorschau:"))
        self.preview_label = QLabel("Beispiel-Paket")
        self.preview_label.setFixedSize(150, 30)
        self.preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.preview_label.setStyleSheet(
            "background: #ffffff; color: #000000; border: 1px solid #ccc;"
        )
        preview_layout.addWidget(self.preview_label)
        colors_layout.addLayout(preview_layout)

        colors_layout.addStretch()
        right_layout.addLayout(colors_layout)

        # Aktiviert-Checkbox
        self.enabled_check = QCheckBox("Regel aktiviert")
        self.enabled_check.stateChanged.connect(self._on_edit_changed)
        right_layout.addWidget(self.enabled_check)

        right_layout.addStretch()
        main_splitter.addWidget(right_widget)

        main_splitter.setSizes([300, 500])
        layout.addWidget(main_splitter)

        # Dialog-Buttons
        btn_box_layout = QHBoxLayout()

        self.btn_reset = QPushButton("Auf Standard zuruecksetzen")
        self.btn_reset.clicked.connect(self._reset_to_defaults)
        btn_box_layout.addWidget(self.btn_reset)

        btn_box_layout.addStretch()

        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.clicked.connect(self.reject)
        btn_box_layout.addWidget(self.btn_cancel)

        self.btn_ok = QPushButton("OK")
        self.btn_ok.clicked.connect(self._save_and_close)
        btn_box_layout.addWidget(self.btn_ok)

        layout.addLayout(btn_box_layout)

        self._current_bg = "#ffffff"
        self._current_fg = "#000000"
        self._updating = False

    def _populate_list(self):
        """Fuellt die Regelliste."""
        self.rules_list.clear()
        for rule in self.manager.rules:
            item = QListWidgetItem(rule.name)
            if rule.enabled:
                item.setBackground(QColor(rule.background))
                item.setForeground(QColor(rule.foreground))
            else:
                item.setForeground(QColor("#999999"))
            self.rules_list.addItem(item)

        if self.rules_list.count() > 0:
            self.rules_list.setCurrentRow(0)

    def _on_rule_selected(self, row: int):
        """Wird aufgerufen wenn eine Regel ausgewaehlt wird."""
        if row < 0 or row >= len(self.manager.rules):
            return

        self._updating = True
        rule = self.manager.rules[row]

        self.name_edit.setText(rule.name)
        self.filter_edit.setPlainText(rule.filter_expression)
        self.priority_edit.setText(str(rule.priority))
        self.enabled_check.setChecked(rule.enabled)

        self._current_bg = rule.background
        self._current_fg = rule.foreground
        self._update_color_previews()
        self._updating = False

    def _on_edit_changed(self):
        """Wird aufgerufen wenn ein Feld bearbeitet wird."""
        if self._updating:
            return

        row = self.rules_list.currentRow()
        if row < 0 or row >= len(self.manager.rules):
            return

        rule = self.manager.rules[row]
        rule.name = self.name_edit.text()
        rule.filter_expression = self.filter_edit.toPlainText()
        try:
            rule.priority = int(self.priority_edit.text())
        except ValueError:
            pass
        rule.enabled = self.enabled_check.isChecked()
        rule.background = self._current_bg
        rule.foreground = self._current_fg

        # Liste aktualisieren
        item = self.rules_list.item(row)
        if item:
            item.setText(rule.name)
            if rule.enabled:
                item.setBackground(QColor(rule.background))
                item.setForeground(QColor(rule.foreground))
            else:
                item.setBackground(QColor("#ffffff"))
                item.setForeground(QColor("#999999"))

    def _pick_color(self, color_type: str):
        """Oeffnet den Farbauswahldialog."""
        current = self._current_bg if color_type == 'bg' else self._current_fg
        color = QColorDialog.getColor(QColor(current), self, "Farbe waehlen")
        if color.isValid():
            if color_type == 'bg':
                self._current_bg = color.name()
            else:
                self._current_fg = color.name()
            self._update_color_previews()
            self._on_edit_changed()

    def _update_color_previews(self):
        """Aktualisiert die Farbvorschauen."""
        self.bg_preview.setStyleSheet(
            f"background: {self._current_bg}; border: 1px solid #ccc;"
        )
        self.fg_preview.setStyleSheet(
            f"background: {self._current_fg}; border: 1px solid #ccc;"
        )
        self.preview_label.setStyleSheet(
            f"background: {self._current_bg}; color: {self._current_fg}; "
            f"border: 1px solid #ccc;"
        )

    def _add_rule(self):
        """Fuegt eine neue Regel hinzu."""
        new_rule = ColorRule(
            name="Neue Regel",
            filter_expression="protocol == 'TCP'",
            priority=50
        )
        self.manager.rules.append(new_rule)
        self._populate_list()
        self.rules_list.setCurrentRow(len(self.manager.rules) - 1)

    def _delete_rule(self):
        """Loescht die ausgewaehlte Regel."""
        row = self.rules_list.currentRow()
        if row >= 0 and row < len(self.manager.rules):
            del self.manager.rules[row]
            self._populate_list()

    def _move_up(self):
        """Verschiebt die Regel nach oben."""
        row = self.rules_list.currentRow()
        if row > 0:
            self.manager.rules[row], self.manager.rules[row - 1] = \
                self.manager.rules[row - 1], self.manager.rules[row]
            self._populate_list()
            self.rules_list.setCurrentRow(row - 1)

    def _move_down(self):
        """Verschiebt die Regel nach unten."""
        row = self.rules_list.currentRow()
        if row < len(self.manager.rules) - 1:
            self.manager.rules[row], self.manager.rules[row + 1] = \
                self.manager.rules[row + 1], self.manager.rules[row]
            self._populate_list()
            self.rules_list.setCurrentRow(row + 1)

    def _reset_to_defaults(self):
        """Setzt auf Standardregeln zurueck."""
        reply = QMessageBox.question(
            self, "Zuruecksetzen",
            "Alle Regeln auf Standard zuruecksetzen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.manager.reset_to_defaults()
            self._populate_list()

    def _save_and_close(self):
        """Speichert und schliesst den Dialog."""
        self.manager.save_rules()
        self.accept()

try:
    from scapy.all import rdpcap, Ether, IP, TCP, UDP, Raw, Packet, sniff, get_if_list, conf, PcapReader, raw as scapy_raw
    from scapy.layers.inet import ICMP
    from scapy.layers.l2 import ARP
    SCAPY_AVAILABLE = True
    # DLT 148 (TECMP) als Raw registrieren, um Scapy-Warnung zu unterdruecken
    if 148 not in conf.l2types.num2layer:
        conf.l2types.register(148, Raw)
except ImportError:
    SCAPY_AVAILABLE = False

# Pfad zu dumpcap — plattformabhaengig ermittelt
from core.platform import find_dumpcap as _find_dumpcap
DUMPCAP_PATH = _find_dumpcap() or "/mnt/c/Program Files/Wireshark/dumpcap.exe"


class DoIPDecoder:
    """Decoder für DoIP (Diagnostics over IP) Protokoll."""

    DOIP_PORT = 13400

    PAYLOAD_TYPES = {
        0x0000: "Generic DoIP header NACK",
        0x0001: "Vehicle identification request",
        0x0002: "Vehicle identification request with EID",
        0x0003: "Vehicle identification request with VIN",
        0x0004: "Vehicle announcement/identification response",
        0x0005: "Routing activation request",
        0x0006: "Routing activation response",
        0x0007: "Alive check request",
        0x0008: "Alive check response",
        0x4001: "DoIP entity status request",
        0x4002: "DoIP entity status response",
        0x4003: "Diagnostic power mode info request",
        0x4004: "Diagnostic power mode info response",
        0x8001: "Diagnostic message",
        0x8002: "Diagnostic message positive ACK",
        0x8003: "Diagnostic message negative ACK",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert DoIP-Daten."""
        result = {"protocol": "DoIP", "fields": []}

        if len(data) < 8:
            result["error"] = "DoIP header too short"
            return result

        version = data[0]
        inv_version = data[1]
        payload_type = int.from_bytes(data[2:4], 'big')
        payload_length = int.from_bytes(data[4:8], 'big')

        result["fields"].append(("Protocol Version", f"0x{version:02X}"))
        result["fields"].append(("Inverse Version", f"0x{inv_version:02X}"))
        result["fields"].append(("Payload Type", f"0x{payload_type:04X} ({cls.PAYLOAD_TYPES.get(payload_type, 'Unknown')})"))
        result["fields"].append(("Payload Length", str(payload_length)))

        if payload_type == 0x8001 and len(data) > 12:
            # Diagnostic message
            source_addr = int.from_bytes(data[8:10], 'big')
            target_addr = int.from_bytes(data[10:12], 'big')
            result["fields"].append(("Source Address", f"0x{source_addr:04X}"))
            result["fields"].append(("Target Address", f"0x{target_addr:04X}"))

            uds_data = data[12:]
            if uds_data:
                uds_result = UDSDecoder.decode(uds_data)
                result["uds"] = uds_result

        return result


class SOMEIPDecoder:
    """Decoder für SOME/IP Protokoll."""

    SOMEIP_PORT = 30490

    MESSAGE_TYPES = {
        0x00: "REQUEST",
        0x01: "REQUEST_NO_RETURN",
        0x02: "NOTIFICATION",
        0x80: "RESPONSE",
        0x81: "ERROR",
        0x20: "TP_REQUEST",
        0x21: "TP_REQUEST_NO_RETURN",
        0x22: "TP_NOTIFICATION",
        0xA0: "TP_RESPONSE",
        0xA1: "TP_ERROR",
    }

    RETURN_CODES = {
        0x00: "E_OK",
        0x01: "E_NOT_OK",
        0x02: "E_UNKNOWN_SERVICE",
        0x03: "E_UNKNOWN_METHOD",
        0x04: "E_NOT_READY",
        0x05: "E_NOT_REACHABLE",
        0x06: "E_TIMEOUT",
        0x07: "E_WRONG_PROTOCOL_VERSION",
        0x08: "E_WRONG_INTERFACE_VERSION",
        0x09: "E_MALFORMED_MESSAGE",
        0x0A: "E_WRONG_MESSAGE_TYPE",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert SOME/IP-Daten."""
        result = {"protocol": "SOME/IP", "fields": []}

        if len(data) < 16:
            result["error"] = "SOME/IP header too short"
            return result

        service_id = int.from_bytes(data[0:2], 'big')
        method_id = int.from_bytes(data[2:4], 'big')
        length = int.from_bytes(data[4:8], 'big')
        client_id = int.from_bytes(data[8:10], 'big')
        session_id = int.from_bytes(data[10:12], 'big')
        protocol_version = data[12]
        interface_version = data[13]
        message_type = data[14]
        return_code = data[15]

        result["fields"].append(("Service ID", f"0x{service_id:04X}"))
        result["fields"].append(("Method ID", f"0x{method_id:04X}"))
        result["fields"].append(("Length", str(length)))
        result["fields"].append(("Client ID", f"0x{client_id:04X}"))
        result["fields"].append(("Session ID", f"0x{session_id:04X}"))
        result["fields"].append(("Protocol Version", f"0x{protocol_version:02X}"))
        result["fields"].append(("Interface Version", f"0x{interface_version:02X}"))
        result["fields"].append(("Message Type", f"0x{message_type:02X} ({cls.MESSAGE_TYPES.get(message_type, 'Unknown')})"))
        result["fields"].append(("Return Code", f"0x{return_code:02X} ({cls.RETURN_CODES.get(return_code, 'Unknown')})"))

        if len(data) > 16:
            result["payload"] = data[16:]

        return result


class UDSDecoder:
    """Decoder für UDS (Unified Diagnostic Services) Protokoll."""

    SERVICES = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x14: "ClearDiagnosticInformation",
        0x19: "ReadDTCInformation",
        0x22: "ReadDataByIdentifier",
        0x23: "ReadMemoryByAddress",
        0x24: "ReadScalingDataByIdentifier",
        0x27: "SecurityAccess",
        0x28: "CommunicationControl",
        0x2A: "ReadDataByPeriodicIdentifier",
        0x2C: "DynamicallyDefineDataIdentifier",
        0x2E: "WriteDataByIdentifier",
        0x2F: "InputOutputControlByIdentifier",
        0x31: "RoutineControl",
        0x34: "RequestDownload",
        0x35: "RequestUpload",
        0x36: "TransferData",
        0x37: "RequestTransferExit",
        0x38: "RequestFileTransfer",
        0x3D: "WriteMemoryByAddress",
        0x3E: "TesterPresent",
        0x83: "AccessTimingParameter",
        0x84: "SecuredDataTransmission",
        0x85: "ControlDTCSetting",
        0x86: "ResponseOnEvent",
        0x87: "LinkControl",
    }

    NRC = {
        0x10: "generalReject",
        0x11: "serviceNotSupported",
        0x12: "subFunctionNotSupported",
        0x13: "incorrectMessageLengthOrInvalidFormat",
        0x14: "responseTooLong",
        0x21: "busyRepeatRequest",
        0x22: "conditionsNotCorrect",
        0x24: "requestSequenceError",
        0x25: "noResponseFromSubnetComponent",
        0x26: "failurePreventsExecutionOfRequestedAction",
        0x31: "requestOutOfRange",
        0x33: "securityAccessDenied",
        0x35: "invalidKey",
        0x36: "exceededNumberOfAttempts",
        0x37: "requiredTimeDelayNotExpired",
        0x70: "uploadDownloadNotAccepted",
        0x71: "transferDataSuspended",
        0x72: "generalProgrammingFailure",
        0x73: "wrongBlockSequenceCounter",
        0x78: "requestCorrectlyReceivedResponsePending",
        0x7E: "subFunctionNotSupportedInActiveSession",
        0x7F: "serviceNotSupportedInActiveSession",
    }

    @classmethod
    def decode(cls, data: bytes) -> Dict[str, Any]:
        """Dekodiert UDS-Daten."""
        result = {"protocol": "UDS", "fields": []}

        if len(data) < 1:
            result["error"] = "UDS data too short"
            return result

        sid = data[0]
        is_response = sid & 0x40
        base_sid = sid & 0x3F if is_response else sid

        service_name = cls.SERVICES.get(base_sid, "Unknown")

        if is_response:
            result["fields"].append(("Type", "Response"))
            result["fields"].append(("Service", f"0x{base_sid:02X} ({service_name})"))

            if sid == 0x7F and len(data) >= 3:
                # Negative response
                rejected_sid = data[1]
                nrc = data[2]
                result["fields"].append(("Rejected Service", f"0x{rejected_sid:02X} ({cls.SERVICES.get(rejected_sid, 'Unknown')})"))
                result["fields"].append(("NRC", f"0x{nrc:02X} ({cls.NRC.get(nrc, 'Unknown')})"))
        else:
            result["fields"].append(("Type", "Request"))
            result["fields"].append(("Service", f"0x{sid:02X} ({service_name})"))

        if len(data) > 1:
            result["fields"].append(("Sub-function/Data", data[1:].hex().upper()))

        return result


# TECMPDecoder aus dem gemeinsamen Modul importieren
from core.protocol_decoders import TECMPDecoder  # noqa: E402

# Weitere Decoder für Live-Video-Dekodierung
try:
    from core.protocol_decoders import GMSLDecoder, FPDLinkDecoder, IEEE1722Decoder  # noqa: E402
    DECODERS_AVAILABLE = True
except ImportError:
    DECODERS_AVAILABLE = False


class PacketStore:
    """Speichert Paket-Metadaten und bietet lazy Zugriff auf Scapy-Pakete.

    Fuer File-basierte PCAPs: speichert nur Offsets + Summaries (wenig RAM).
    Fuer Live-Capture: speichert Scapy-Pakete direkt.
    """

    def __init__(self):
        self._file_path: Optional[str] = None
        self._offsets = array.array('Q')      # uint64 file offsets
        self._cap_lens = array.array('I')     # uint32 capture lengths
        self._timestamps = array.array('d')   # float64 timestamps
        self._summaries: List[tuple] = []     # (src, dst, proto, info, raw_len)
        self._color_extras: List[dict] = []   # color rule data per packet
        self._link_type: int = 1
        self._is_pcapng: bool = False
        # Raw-Cache fuer pcapng (kein Offset-basiertes Lesen moeglich)
        self._raw_cache: List[bytes] = []
        # Cache fuer Live-Capture (Scapy-Pakete ohne File-Backing)
        self._live_packets: List = []

    def __len__(self):
        if self._live_packets:
            return len(self._live_packets)
        return len(self._offsets) if not self._raw_cache else len(self._raw_cache)

    def __getitem__(self, index):
        """Lazy: liest Scapy-Paket bei Bedarf von Disk."""
        if self._live_packets:
            return self._live_packets[index]
        if self._raw_cache:
            raw = self._raw_cache[index]
        else:
            offset = self._offsets[index]
            cap_len = self._cap_lens[index]
            with open(self._file_path, 'rb') as f:
                f.seek(offset + 16)  # Skip pcap record header
                raw = f.read(cap_len)
        pkt = self._dissect(raw)
        pkt.time = self._timestamps[index]
        return pkt

    def __iter__(self):
        """Iterator ueber alle Scapy-Pakete (fuer Filter/Statistiken)."""
        for i in range(len(self)):
            yield self[i]

    def _dissect(self, raw):
        """Erstellt Scapy-Paket aus raw bytes."""
        if self._link_type == 1:  # Ethernet
            return Ether(raw)
        else:
            return Raw(raw)

    @property
    def is_live(self):
        return bool(self._live_packets)

    def get_summary(self, index) -> tuple:
        return self._summaries[index]

    def get_color_extra(self, index) -> dict:
        return self._color_extras[index]

    def get_timestamp(self, index) -> float:
        if self._live_packets:
            pkt = self._live_packets[index]
            return float(pkt.time) if hasattr(pkt, 'time') else 0.0
        return self._timestamps[index]

    def get_raw_bytes(self, index) -> bytes:
        if self._live_packets:
            return bytes(self._live_packets[index])
        if self._raw_cache:
            return self._raw_cache[index]
        offset = self._offsets[index]
        cap_len = self._cap_lens[index]
        with open(self._file_path, 'rb') as f:
            f.seek(offset + 16)
            return f.read(cap_len)

    def get_indices_by_proto(self, proto: str) -> list:
        """Gibt Indices aller Pakete mit gegebenem Protokoll zurueck."""
        return [i for i, s in enumerate(self._summaries) if s[2] == proto]

    def add_batch(self, offsets, cap_lens, timestamps, summaries, color_extras):
        """Fuegt einen Batch von Paket-Metadaten hinzu."""
        self._offsets.extend(array.array('Q', offsets))
        self._cap_lens.extend(array.array('I', cap_lens))
        self._timestamps.extend(array.array('d', timestamps))
        self._summaries.extend(summaries)
        self._color_extras.extend(color_extras)

    def add_batch_pcapng(self, raw_list, timestamps, summaries, color_extras):
        """Fuegt einen Batch fuer pcapng hinzu (raw bytes im Speicher)."""
        self._raw_cache.extend(raw_list)
        self._timestamps.extend(array.array('d', timestamps))
        self._summaries.extend(summaries)
        self._color_extras.extend(color_extras)

    def clear(self):
        self._offsets = array.array('Q')
        self._cap_lens = array.array('I')
        self._timestamps = array.array('d')
        self._summaries.clear()
        self._color_extras.clear()
        self._raw_cache.clear()
        self._live_packets.clear()
        self._file_path = None

    def append_live(self, pkt):
        """Fuer Live-Capture: Scapy-Paket direkt speichern."""
        self._live_packets.append(pkt)

    def trim_oldest(self, n: int):
        """Entfernt die aeltesten n Live-Pakete (Ring-Buffer)."""
        del self._live_packets[:n]


class PacketTableModel(QAbstractTableModel):
    """Leichtgewichtiges Model für die Paketliste (Model/View-Pattern)."""

    HEADERS = ["Nr.", "Zeit", "Quelle", "Ziel", "Protokoll", "Länge", "Info"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[tuple] = []
        self._colors: List[tuple] = []

    def rowCount(self, parent=QModelIndex()):
        return len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return 7

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._rows[row][col]
        elif role == Qt.ItemDataRole.BackgroundRole:
            bg = self._colors[row][1]
            return QColor(bg) if bg else None
        elif role == Qt.ItemDataRole.ForegroundRole:
            fg = self._colors[row][0]
            return QColor(fg) if fg else None
        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.HEADERS[section]
        return None

    def append_rows(self, rows: list, colors: list):
        """Batch-Append für neue Zeilen."""
        if not rows:
            return
        start = len(self._rows)
        self.beginInsertRows(QModelIndex(), start, start + len(rows) - 1)
        self._rows.extend(rows)
        self._colors.extend(colors)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._rows.clear()
        self._colors.clear()
        self.endResetModel()

    def reset_with_data(self, rows: list, colors: list):
        """Komplett-Ersetzung (für Filter)."""
        self.beginResetModel()
        self._rows = rows
        self._colors = colors
        self.endResetModel()


class PacketLoaderThread(QThread):
    """Thread zum schnellen Laden von PCAP-Dateien (binary reader, kein Scapy)."""

    progress = pyqtSignal(int)
    batch_ready = pyqtSignal(object)   # dict mit batch-Daten
    file_info_ready = pyqtSignal(object)  # dict mit link_type etc.
    finished = pyqtSignal()
    error = pyqtSignal(str)

    BATCH_SIZE = 5000

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path
        self._stop_requested = False

    def stop(self):
        self._stop_requested = True

    def run(self):
        try:
            file_size = os.path.getsize(self.file_path)

            with open(self.file_path, 'rb') as f:
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    self.error.emit("Datei zu kurz")
                    return

                magic = struct.unpack('<I', magic_bytes)[0]

                # pcapng erkennen (Section Header Block magic)
                if magic == 0x0A0D0D0A:
                    f.close()
                    self._read_pcapng(file_size)
                    return

                # PCAP: Endian und Timestamp-Aufloesung bestimmen
                if magic == 0xa1b2c3d4:
                    endian, ts_nano = '<', False
                elif magic == 0xd4c3b2a1:
                    endian, ts_nano = '>', False
                elif magic == 0xa1b23c4d:
                    endian, ts_nano = '<', True
                elif magic == 0x4d3cb2a1:
                    endian, ts_nano = '>', True
                else:
                    self.error.emit(f"Unbekanntes PCAP-Format: magic=0x{magic:08X}")
                    return

                rest = f.read(20)
                if len(rest) < 20:
                    self.error.emit("PCAP Global Header zu kurz")
                    return

                ver_major, ver_minor, thiszone, sigfigs, snaplen, link_type = \
                    struct.unpack(endian + 'HHiIII', rest)

                self.file_info_ready.emit({
                    'link_type': link_type,
                    'is_pcapng': False,
                })

                batch_offsets = []
                batch_cap_lens = []
                batch_timestamps = []
                batch_summaries = []
                batch_color_extras = []
                last_progress = -1

                while not self._stop_requested:
                    pkt_offset = f.tell()
                    hdr = f.read(16)
                    if len(hdr) < 16:
                        break
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
                    raw = f.read(incl_len)
                    if len(raw) < incl_len:
                        break

                    timestamp = ts_sec + ts_usec / (1e9 if ts_nano else 1e6)
                    summary, color_extra = self._fast_parse(raw, link_type, orig_len)

                    batch_offsets.append(pkt_offset)
                    batch_cap_lens.append(incl_len)
                    batch_timestamps.append(timestamp)
                    batch_summaries.append(summary)
                    batch_color_extras.append(color_extra)

                    if len(batch_offsets) >= self.BATCH_SIZE:
                        self.batch_ready.emit({
                            'offsets': batch_offsets,
                            'cap_lens': batch_cap_lens,
                            'timestamps': batch_timestamps,
                            'summaries': batch_summaries,
                            'color_extras': batch_color_extras,
                            'pcapng': False,
                        })
                        batch_offsets, batch_cap_lens = [], []
                        batch_timestamps, batch_summaries, batch_color_extras = [], [], []

                        if file_size > 0:
                            pct = int(f.tell() * 100 / file_size)
                            if pct != last_progress:
                                last_progress = pct
                                self.progress.emit(pct)

                if not self._stop_requested:
                    if batch_offsets:
                        self.batch_ready.emit({
                            'offsets': batch_offsets,
                            'cap_lens': batch_cap_lens,
                            'timestamps': batch_timestamps,
                            'summaries': batch_summaries,
                            'color_extras': batch_color_extras,
                            'pcapng': False,
                        })
                    self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))

    def _read_pcapng(self, file_size: int):
        """Fallback fuer pcapng-Dateien mit RawPcapReader."""
        try:
            from scapy.all import RawPcapNgReader
            reader = RawPcapNgReader(self.file_path)
        except Exception:
            reader = PcapReader(self.file_path)
            self._read_pcapng_scapy_fallback(reader, file_size)
            return

        try:
            link_type = reader.linktype if hasattr(reader, 'linktype') else 0
            self.file_info_ready.emit({
                'link_type': link_type if link_type else 1,
                'is_pcapng': True,
            })

            batch_raw = []
            batch_timestamps = []
            batch_summaries = []
            batch_color_extras = []
            last_progress = -1

            for raw_data, metadata in reader:
                if self._stop_requested:
                    break
                # metadata kann PacketMetadataNg oder Tuple sein
                if hasattr(metadata, 'tshigh'):
                    # PacketMetadataNg: tshigh/tslow + tsresol
                    tsresol = getattr(metadata, 'tsresol', 1000000)
                    ts_raw = (metadata.tshigh << 32) | metadata.tslow
                    timestamp = ts_raw / tsresol
                    wirelen = getattr(metadata, 'wirelen', len(raw_data))
                    if link_type == 0:
                        link_type = getattr(metadata, 'linktype', 1)
                elif isinstance(metadata, tuple):
                    if len(metadata) >= 4:
                        sec, usec, wirelen = metadata[1], metadata[2], metadata[3]
                    else:
                        sec, usec, wirelen = 0, 0, len(raw_data)
                    timestamp = sec + usec / 1e6
                else:
                    sec = getattr(metadata, 'sec', 0)
                    usec = getattr(metadata, 'usec', 0)
                    wirelen = getattr(metadata, 'wirelen', len(raw_data))
                    timestamp = sec + usec / 1e6
                summary, color_extra = self._fast_parse(raw_data, link_type, wirelen)

                batch_raw.append(raw_data)
                batch_timestamps.append(timestamp)
                batch_summaries.append(summary)
                batch_color_extras.append(color_extra)

                if len(batch_raw) >= self.BATCH_SIZE:
                    self.batch_ready.emit({
                        'raw_list': batch_raw,
                        'timestamps': batch_timestamps,
                        'summaries': batch_summaries,
                        'color_extras': batch_color_extras,
                        'pcapng': True,
                    })
                    batch_raw, batch_timestamps = [], []
                    batch_summaries, batch_color_extras = [], []

                    if file_size > 0:
                        try:
                            pos = reader.f.tell() if hasattr(reader, 'f') else 0
                            pct = int(pos * 100 / file_size)
                            if pct != last_progress:
                                last_progress = pct
                                self.progress.emit(pct)
                        except Exception:
                            pass

            if not self._stop_requested:
                if batch_raw:
                    self.batch_ready.emit({
                        'raw_list': batch_raw,
                        'timestamps': batch_timestamps,
                        'summaries': batch_summaries,
                        'color_extras': batch_color_extras,
                        'pcapng': True,
                    })
                self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))
        finally:
            reader.close()

    def _read_pcapng_scapy_fallback(self, reader, file_size: int):
        """Letzter Fallback: pcapng mit Scapy PcapReader (langsam)."""
        try:
            link_type = 1
            self.file_info_ready.emit({
                'link_type': link_type,
                'is_pcapng': True,
            })

            batch_raw = []
            batch_timestamps = []
            batch_summaries = []
            batch_color_extras = []

            while not self._stop_requested:
                pkt = reader.read_packet()
                if pkt is None:
                    break
                raw_data = bytes(pkt)
                timestamp = float(pkt.time) if hasattr(pkt, 'time') else 0.0
                summary, color_extra = self._fast_parse(raw_data, link_type, len(raw_data))

                batch_raw.append(raw_data)
                batch_timestamps.append(timestamp)
                batch_summaries.append(summary)
                batch_color_extras.append(color_extra)

                if len(batch_raw) >= self.BATCH_SIZE:
                    self.batch_ready.emit({
                        'raw_list': batch_raw,
                        'timestamps': batch_timestamps,
                        'summaries': batch_summaries,
                        'color_extras': batch_color_extras,
                        'pcapng': True,
                    })
                    batch_raw, batch_timestamps = [], []
                    batch_summaries, batch_color_extras = [], []

            if not self._stop_requested:
                if batch_raw:
                    self.batch_ready.emit({
                        'raw_list': batch_raw,
                        'timestamps': batch_timestamps,
                        'summaries': batch_summaries,
                        'color_extras': batch_color_extras,
                        'pcapng': True,
                    })
                self.finished.emit()
        except Exception as e:
            self.error.emit(str(e))
        finally:
            reader.close()

    def _fast_parse(self, raw: bytes, link_type: int, length: int) -> tuple:
        """Extrahiert (src, dst, proto, info, raw_len) aus raw bytes - ohne Scapy."""
        color_extra = {
            'doip_type': None,
            'uds_nrc': None,
            'uds_positive_response': False,
            'someip_message_type': None,
            'someip_return_code': None,
        }

        # DLT 148 (TECMP): Embedded Ethernet at offset 12
        if link_type == 148:
            device_id = int.from_bytes(raw[0:2], 'big') if len(raw) >= 2 else 0
            tecmp_prefix = f"[TECMP 0x{device_id:04X}] "
            if len(raw) >= 26:
                ethertype = int.from_bytes(raw[24:26], 'big')
                if ethertype == 0x0800:  # IPv4
                    (src, dst, proto, info, raw_len), ce = self._parse_ipv4(raw, 26, length, color_extra)
                    return (src, dst, proto, tecmp_prefix + info, raw_len), ce
                elif ethertype == 0x99FE:  # PLP/TECMP EtherType
                    dst_mac = ":".join(f"{b:02x}" for b in raw[12:18])
                    src_mac = ":".join(f"{b:02x}" for b in raw[18:24])
                    return (src_mac, dst_mac, "PLP/TECMP", tecmp_prefix, length), color_extra
                else:
                    dst_mac = ":".join(f"{b:02x}" for b in raw[12:18])
                    src_mac = ":".join(f"{b:02x}" for b in raw[18:24])
                    proto = {0x0806: "ARP", 0x86DD: "IPv6"}.get(ethertype, "Ethernet")
                    return (src_mac, dst_mac, proto, f"{tecmp_prefix}EtherType: 0x{ethertype:04X}", length), color_extra
            if len(raw) >= 2:
                return ("", "", "PLP/TECMP", f"[TECMP Dev:0x{device_id:04X}]", length), color_extra
            return ("", "", "PLP/TECMP", "", length), color_extra

        # Standard Ethernet (DLT 1)
        if link_type == 1 and len(raw) >= 14:
            dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
            src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
            ethertype = int.from_bytes(raw[12:14], 'big')

            # VLAN (802.1Q)
            offset = 14
            if ethertype == 0x8100 and len(raw) >= 18:
                ethertype = int.from_bytes(raw[16:18], 'big')
                offset = 18

            if ethertype == 0x0800:  # IPv4
                return self._parse_ipv4(raw, offset, length, color_extra)
            elif ethertype == 0x0806:  # ARP
                return (src_mac, dst_mac, "ARP", "", length), color_extra
            elif ethertype == 0x86DD:  # IPv6
                return (src_mac, dst_mac, "IPv6", "", length), color_extra
            elif ethertype == 0x99FE:  # PLP/TECMP EtherType
                return (src_mac, dst_mac, "PLP/TECMP", "", length), color_extra
            else:
                return (src_mac, dst_mac, "Ethernet", f"EtherType: 0x{ethertype:04X}", length), color_extra

        return ("", "", "Unknown", "", length), color_extra

    def _parse_ipv4(self, raw: bytes, offset: int, length: int, color_extra: dict) -> tuple:
        """Parst IPv4 + TCP/UDP Header aus raw bytes."""
        if len(raw) < offset + 20:
            return ("", "", "IP", "", length), color_extra

        ihl = (raw[offset] & 0x0F) * 4
        protocol = raw[offset + 9]
        src = f"{raw[offset+12]}.{raw[offset+13]}.{raw[offset+14]}.{raw[offset+15]}"
        dst = f"{raw[offset+16]}.{raw[offset+17]}.{raw[offset+18]}.{raw[offset+19]}"

        if protocol == 6:  # TCP
            tp_offset = offset + ihl
            if len(raw) >= tp_offset + 14:
                sport = int.from_bytes(raw[tp_offset:tp_offset+2], 'big')
                dport = int.from_bytes(raw[tp_offset+2:tp_offset+4], 'big')

                # TCP Flags
                flags_byte = raw[tp_offset + 13]
                flags = []
                if flags_byte & 0x02: flags.append("SYN")
                if flags_byte & 0x10: flags.append("ACK")
                if flags_byte & 0x01: flags.append("FIN")
                if flags_byte & 0x04: flags.append("RST")
                if flags_byte & 0x08: flags.append("PSH")
                flags_str = ", ".join(flags)

                proto = "TCP"
                info = f"{sport} \u2192 {dport} [{flags_str}]"

                # TCP Data Offset
                tcp_data_off = ((raw[tp_offset + 12] >> 4) & 0x0F) * 4
                payload_offset = tp_offset + tcp_data_off

                # DoIP Erkennung (Port 13400)
                if sport == 13400 or dport == 13400:
                    proto = "DoIP"
                    if len(raw) > payload_offset + 8:
                        payload = raw[payload_offset:]
                        if len(payload) >= 8:
                            doip_type = int.from_bytes(payload[2:4], 'big')
                            color_extra['doip_type'] = doip_type
                            info = DoIPDecoder.PAYLOAD_TYPES.get(doip_type, f"Type: 0x{doip_type:04X}")

                            # UDS in DoIP Diagnostic Message
                            if doip_type == 0x8001 and len(payload) > 12:
                                uds_data = payload[12:]
                                if uds_data:
                                    sid = uds_data[0]
                                    if sid == 0x7F and len(uds_data) >= 3:
                                        rejected_sid = uds_data[1]
                                        nrc = uds_data[2]
                                        color_extra['uds_nrc'] = nrc
                                        svc = UDSDecoder.SERVICES.get(rejected_sid, f"0x{rejected_sid:02X}")
                                        nrc_name = UDSDecoder.NRC.get(nrc, f"0x{nrc:02X}")
                                        info = f"Diag Msg [UDS NRC: {svc} - {nrc_name}]"
                                    elif sid & 0x40:
                                        base_sid = sid & 0x3F
                                        svc = UDSDecoder.SERVICES.get(base_sid, f"0x{base_sid:02X}")
                                        color_extra['uds_positive_response'] = True
                                        info = f"Diag Msg [UDS +Resp {svc}]"
                                    else:
                                        svc = UDSDecoder.SERVICES.get(sid, f"0x{sid:02X}")
                                        info = f"Diag Msg [UDS Req {svc}]"
                elif sport == 80 or dport == 80:
                    proto = "HTTP"
                elif sport == 443 or dport == 443:
                    proto = "TLS"
                elif sport == 53 or dport == 53:
                    proto = "DNS"
                elif sport == 22 or dport == 22:
                    proto = "SSH"
                elif sport == 445 or dport == 445:
                    proto = "SMB"
                elif sport == 139 or dport == 139:
                    proto = "NetBIOS-SSN"
                elif sport == 3389 or dport == 3389:
                    proto = "RDP"

                return (f"{src}:{sport}", f"{dst}:{dport}", proto, info, length), color_extra

            return (src, dst, "TCP", "", length), color_extra

        elif protocol == 17:  # UDP
            tp_offset = offset + ihl
            if len(raw) >= tp_offset + 8:
                sport = int.from_bytes(raw[tp_offset:tp_offset+2], 'big')
                dport = int.from_bytes(raw[tp_offset+2:tp_offset+4], 'big')

                proto = "UDP"
                info = f"{sport} \u2192 {dport}"
                payload_offset = tp_offset + 8
                sports_dports = {sport, dport}

                # SOME/IP
                if 30490 <= sport <= 30510 or 30490 <= dport <= 30510:
                    proto = "SOME/IP"
                    if len(raw) > payload_offset + 16:
                        payload = raw[payload_offset:]
                        if len(payload) >= 16:
                            service_id = int.from_bytes(payload[0:2], 'big')
                            method_id = int.from_bytes(payload[2:4], 'big')
                            message_type = payload[14]
                            return_code = payload[15]
                            color_extra['someip_message_type'] = message_type
                            color_extra['someip_return_code'] = return_code
                            msg_type_str = SOMEIPDecoder.MESSAGE_TYPES.get(message_type, "")
                            info = f"Service: 0x{service_id:04X}, Method: 0x{method_id:04X} [{msg_type_str}]"

                # PLP/TECMP via UDP
                elif sport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT or dport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT:
                    proto = "PLP/TECMP"
                    if len(raw) > payload_offset + 12:
                        payload = raw[payload_offset:]
                        device_id = int.from_bytes(payload[0:2], 'big')
                        msg_type = payload[5]
                        data_type = int.from_bytes(payload[6:8], 'big')
                        msg_type_str = TECMPDecoder.MESSAGE_TYPES.get(msg_type, f"0x{msg_type:02X}")
                        data_type_str = TECMPDecoder.DATA_TYPES.get(data_type, f"0x{data_type:04X}")
                        info = f"Device: 0x{device_id:04X}, {msg_type_str}, {data_type_str}"

                # Bekannte UDP-Protokolle
                elif sports_dports & {67, 68}:
                    proto = "DHCP"
                    info = "DHCP"
                    if len(raw) > payload_offset:
                        payload = raw[payload_offset:]
                        if len(payload) > 0:
                            op = payload[0]
                            info = "DHCP Request (Boot Request)" if op == 1 else "DHCP Reply (Boot Reply)" if op == 2 else "DHCP"
                elif sports_dports & {137}:
                    proto = "NBNS"
                    info = f"NBNS Name Query {sport} \u2192 {dport}"
                elif sports_dports & {138}:
                    proto = "BROWSER"
                    info = f"Browser Protocol {sport} \u2192 {dport}"
                elif sports_dports & {53}:
                    proto = "DNS"
                    if len(raw) > payload_offset + 4:
                        payload = raw[payload_offset:]
                        flags = (payload[2] << 8) | payload[3]
                        info = "DNS Response" if flags & 0x8000 else "DNS Query"
                    else:
                        info = f"DNS {sport} \u2192 {dport}"
                elif sports_dports & {5353}:
                    proto = "mDNS"
                    info = f"Multicast DNS {sport} \u2192 {dport}"
                elif sports_dports & {1900}:
                    proto = "SSDP"
                    info = f"SSDP {sport} \u2192 {dport}"
                elif sports_dports & {5355}:
                    proto = "LLMNR"
                    info = f"LLMNR {sport} \u2192 {dport}"
                elif sports_dports & {161, 162}:
                    proto = "SNMP"
                    info = f"SNMP {sport} \u2192 {dport}"
                elif sports_dports & {123}:
                    proto = "NTP"
                    info = f"NTP {sport} \u2192 {dport}"
                elif sports_dports & {514}:
                    proto = "Syslog"
                    info = f"Syslog {sport} \u2192 {dport}"

                return (f"{src}:{sport}", f"{dst}:{dport}", proto, info, length), color_extra

            return (src, dst, "UDP", "", length), color_extra

        elif protocol == 1:  # ICMP
            icmp_type = raw[offset + ihl] if len(raw) > offset + ihl else 0
            icmp_code = raw[offset + ihl + 1] if len(raw) > offset + ihl + 1 else 0
            return (src, dst, "ICMP", f"Type: {icmp_type}, Code: {icmp_code}", length), color_extra

        return (src, dst, "IP", f"Proto: {protocol}", length), color_extra


class LiveCaptureThread(QThread):
    """Thread für Live-Capture von Netzwerkpaketen."""

    packet_received = pyqtSignal(object)
    error = pyqtSignal(str)
    started_capture = pyqtSignal()

    def __init__(self, interface: str, capture_filter: str = "", packet_limit: int = 0):
        super().__init__()
        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_limit = packet_limit
        self._running = True

    def run(self):
        try:
            self.started_capture.emit()
            sniff(
                iface=self.interface if self.interface else None,  # str oder list
                filter=self.capture_filter if self.capture_filter else None,
                prn=self._process_packet,
                stop_filter=lambda p: not self._running,
                count=self.packet_limit if self.packet_limit > 0 else 0,
                store=False
            )
        except Exception as e:
            self.error.emit(str(e))

    def _process_packet(self, pkt):
        """Verarbeitet ein empfangenes Paket."""
        if self._running:
            self.packet_received.emit(pkt)

    def stop(self):
        """Stoppt die Live-Capture."""
        self._running = False


class WindowsCaptureThread(QThread):
    """Thread fuer Live-Capture ueber dumpcap.exe (Windows physische Interfaces).

    0x2090 Video-Pakete werden in eine Queue geschrieben statt per Signal
    gesendet — der Capture-Thread blockiert NIE beim Frame-Assembly.
    Ein dedizierter Assembly-Thread verarbeitet die Queue.
    """

    packet_received = pyqtSignal(object)
    raw_video_packet = pyqtSignal(object)  # bytes — 0x2090 Schnellpfad
    error = pyqtSignal(str)
    started_capture = pyqtSignal()

    def __init__(self, interface: str, capture_filter: str = "", packet_limit: int = 0):
        super().__init__()
        self.interface = interface
        self.capture_filter = capture_filter
        self.packet_limit = packet_limit
        self._running = True
        self._process = None
        # ── Einzelne Queue (einfachste + schnellste Architektur wegen GIL) ──
        self._video_queue: deque = deque(maxlen=200_000)
        self._video_pkt_count = 0

    def run(self):
        try:
            dumpcap_path = getattr(self, '_dumpcap_path', DUMPCAP_PATH)
            if not os.path.exists(dumpcap_path):
                self.error.emit(f"dumpcap nicht gefunden: {dumpcap_path}")
                return

            # Multi-Interface: dumpcap unterstuetzt mehrere -i Flags
            cmd = [dumpcap_path]
            if isinstance(self.interface, list):
                for iface in self.interface:
                    cmd += ["-i", iface]
            elif self.interface:
                cmd += ["-i", self.interface]
            cmd += ["-w", "-", "-P", "-q"]
            if self.capture_filter:
                cmd += ["-f", self.capture_filter]

            self._process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            # ── Pipe-Buffer vergroessern (1 MB statt ~64 KB) ──
            try:
                import fcntl
                fcntl.fcntl(self._process.stdout.fileno(),
                            1031, 1_048_576)  # F_SETPIPE_SZ = 1031
            except Exception:
                pass  # Nicht kritisch, funktioniert auch ohne

            # PCAP Global Header lesen (24 Bytes)
            global_header = self._read_exact(24)
            if global_header is None:
                return

            magic = struct.unpack("<I", global_header[:4])[0]
            if magic == 0xa1b2c3d4:
                endian = "<"
            elif magic == 0xd4c3b2a1:
                endian = ">"
            else:
                self.error.emit(f"Ungueltiger PCAP Magic: 0x{magic:08x}")
                return

            self.started_capture.emit()
            packet_count = 0
            vq_append = self._video_queue.append  # Lokale Referenz = schneller

            while self._running:
                # Paket-Header lesen (16 Bytes: ts_sec, ts_usec, incl_len, orig_len)
                pkt_header = self._read_exact(16)
                if pkt_header is None:
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    endian + "IIII", pkt_header
                )

                # Paketdaten lesen
                pkt_data = self._read_exact(incl_len)
                if pkt_data is None:
                    break

                # Schnellpfad: 0x2090 Video-Pakete in Queue (NICHT blockierend)
                if len(pkt_data) >= 14 and pkt_data[12:14] == b'\x20\x90':
                    vq_append(pkt_data)
                    self._video_pkt_count += 1
                    packet_count += 1
                    if self.packet_limit > 0 and packet_count >= self.packet_limit:
                        break
                    continue

                # Alle anderen Protokolle: Scapy Ether-Paket erstellen
                try:
                    pkt = Ether(pkt_data)
                    pkt.time = ts_sec + ts_usec / 1_000_000
                except Exception:
                    continue

                if self._running:
                    self.packet_received.emit(pkt)

                packet_count += 1
                if self.packet_limit > 0 and packet_count >= self.packet_limit:
                    break

        except Exception as e:
            if self._running:
                self.error.emit(str(e))
        finally:
            self._terminate_process()

    def _read_exact(self, n: int) -> bytes:
        """Liest exakt n Bytes aus dem Prozess-stdout."""
        if self._process is None or self._process.stdout is None:
            return None
        data = b""
        while len(data) < n and self._running:
            chunk = self._process.stdout.read(n - len(data))
            if not chunk:
                return None
            data += chunk
        if not self._running:
            return None
        return data

    def _terminate_process(self):
        """Beendet den dumpcap-Subprozess."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

    def stop(self):
        """Stoppt die Live-Capture."""
        self._running = False
        self._terminate_process()


class DoIPStreamDialog(QDialog):
    """Dialog zur Anzeige aller Pakete eines DoIP-Streams (TCP-Verbindung)."""

    def __init__(self, stream_packets: list, stream_key: str, parent=None):
        """
        Args:
            stream_packets: Liste von (original_index, packet) Tupeln
            stream_key: z.B. "192.168.1.10:54321 ↔ 192.168.1.20:13400"
        """
        super().__init__(parent)
        self.stream_packets = stream_packets
        self.stream_key = stream_key
        self.setWindowTitle(f"DoIP Stream: {stream_key}")
        self.resize(900, 600)
        self._init_ui()
        self._populate_table()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Info-Label
        info_label = QLabel(f"TCP-Verbindung: {self.stream_key}\nPakete: {len(self.stream_packets)}")
        info_label.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(info_label)

        # Tabelle
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Nr.", "Zeit", "Richtung", "DoIP Typ", "UDS Info", "Daten"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        # Schließen-Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("Schließen")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _determine_client(self) -> Optional[str]:
        """Ermittelt die Client-Seite (dport == 13400)."""
        for _, pkt in self.stream_packets:
            if TCP in pkt:
                if pkt[TCP].dport == 13400:
                    return pkt[IP].src if IP in pkt else None
                elif pkt[TCP].sport == 13400:
                    return pkt[IP].dst if IP in pkt else None
        return None

    def _populate_table(self):
        """Befüllt die Tabelle mit Stream-Paketen."""
        self.table.setRowCount(len(self.stream_packets))
        client_ip = self._determine_client()

        base_time = None
        for row, (orig_idx, pkt) in enumerate(self.stream_packets):
            # Nr.
            self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))

            # Zeit
            if hasattr(pkt, 'time'):
                if base_time is None:
                    base_time = pkt.time
                rel_time = pkt.time - base_time
                self.table.setItem(row, 1, QTableWidgetItem(f"{rel_time:.4f}"))

            # Richtung
            direction = ""
            is_negative_uds = False
            if IP in pkt:
                if pkt[IP].src == client_ip:
                    direction = "→"
                else:
                    direction = "←"
            self.table.setItem(row, 2, QTableWidgetItem(direction))

            # DoIP Typ und UDS Info
            doip_type = ""
            uds_info = ""
            data_hex = ""
            if Raw in pkt:
                raw_data = bytes(pkt[Raw].load)
                if len(raw_data) >= 8:
                    payload_type = int.from_bytes(raw_data[2:4], 'big')
                    doip_type = DoIPDecoder.PAYLOAD_TYPES.get(payload_type, f"0x{payload_type:04X}")
                    data_hex = raw_data[:16].hex().upper()

                    # UDS-Info aus Diagnostic Message
                    if payload_type == 0x8001 and len(raw_data) > 12:
                        uds_data = raw_data[12:]
                        if uds_data:
                            sid = uds_data[0]
                            if sid == 0x7F and len(uds_data) >= 3:
                                rejected_sid = uds_data[1]
                                nrc = uds_data[2]
                                svc_name = UDSDecoder.SERVICES.get(rejected_sid, f"0x{rejected_sid:02X}")
                                nrc_name = UDSDecoder.NRC.get(nrc, f"0x{nrc:02X}")
                                uds_info = f"NRC: {svc_name} - {nrc_name}"
                                is_negative_uds = True
                            elif sid & 0x40:
                                base_sid = sid & 0x3F
                                svc_name = UDSDecoder.SERVICES.get(base_sid, f"0x{base_sid:02X}")
                                uds_info = f"+Resp {svc_name}"
                            else:
                                svc_name = UDSDecoder.SERVICES.get(sid, f"0x{sid:02X}")
                                uds_info = svc_name

            self.table.setItem(row, 3, QTableWidgetItem(doip_type))
            self.table.setItem(row, 4, QTableWidgetItem(uds_info))
            self.table.setItem(row, 5, QTableWidgetItem(data_hex))

            # Farbkodierung
            if is_negative_uds:
                color = QColor("#ffcdd2")
            elif direction == "→":
                color = QColor("#e3f2fd")
            else:
                color = QColor("#e8f5e9")

            for col in range(6):
                item = self.table.item(row, col)
                if item:
                    item.setBackground(color)


class UDSSequenzDialog(QDialog):
    """Dialog für UDS Sequenz-Analyse: Paart Requests mit Responses."""

    def __init__(self, packets: list, parent_panel=None, parent=None):
        """
        Args:
            packets: Komplette Paketliste
            parent_panel: Referenz auf WiresharkPanel (für Sprung-zu-Paket)
        """
        super().__init__(parent)
        self.packets = packets
        self.parent_panel = parent_panel
        self.transactions = []
        self.setWindowTitle("UDS Sequenz-Analyse")
        self.resize(1100, 650)
        self._init_ui()
        self._extract_uds_transactions()
        self._populate_table()

    def _init_ui(self):
        layout = QVBoxLayout(self)

        # Info-Label
        self.info_label = QLabel("Analyse läuft...")
        self.info_label.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(self.info_label)

        # Tabelle
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "Nr.", "Zeit", "Quelle → Ziel", "UDS Service",
            "Request", "Response", "Status", "Antwortzeit", "Pkt-Nr."
        ])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.doubleClicked.connect(self._on_double_click)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table)

        # Schließen-Button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("Schließen")
        close_btn.clicked.connect(self.close)
        btn_layout.addWidget(close_btn)
        layout.addLayout(btn_layout)

    def _extract_uds_transactions(self):
        """Extrahiert und paart UDS-Transaktionen."""
        # Schritt 1: Alle DoIP 0x8001-Pakete mit UDS-Daten extrahieren
        diag_packets = []  # (index, pkt, source_addr, target_addr, uds_data, time)
        for idx, pkt in enumerate(self.packets):
            if TCP not in pkt or Raw not in pkt:
                continue
            tcp = pkt[TCP]
            if tcp.sport != 13400 and tcp.dport != 13400:
                continue
            raw_data = bytes(pkt[Raw].load)
            if len(raw_data) < 13:
                continue
            payload_type = int.from_bytes(raw_data[2:4], 'big')
            if payload_type != 0x8001:
                continue
            source_addr = int.from_bytes(raw_data[8:10], 'big')
            target_addr = int.from_bytes(raw_data[10:12], 'big')
            uds_data = raw_data[12:]
            pkt_time = float(pkt.time) if hasattr(pkt, 'time') else 0.0
            diag_packets.append((idx, pkt, source_addr, target_addr, uds_data, pkt_time))

        # Schritt 2: Requests identifizieren und mit Responses paaren
        used_responses = set()
        self.transactions = []

        for i, (idx, pkt, src_addr, tgt_addr, uds_data, req_time) in enumerate(diag_packets):
            sid = uds_data[0]
            # Überspringe Responses (SID & 0x40 oder 0x7F)
            if sid & 0x40 or sid == 0x7F:
                continue

            # IP-Adressen für Anzeige
            ip_src = pkt[IP].src if IP in pkt else ""
            ip_dst = pkt[IP].dst if IP in pkt else ""

            service_name = UDSDecoder.SERVICES.get(sid, f"0x{sid:02X}")

            tx = {
                "request_idx": idx,
                "response_idx": None,
                "request_time": req_time,
                "response_time": None,
                "src_addr": src_addr,
                "tgt_addr": tgt_addr,
                "ip_src": ip_src,
                "ip_dst": ip_dst,
                "service_name": service_name,
                "request_data": uds_data,
                "response_data": None,
                "status": "Keine Antwort",
                "response_time_ms": None,
            }

            # Vorwärts nach passender Response suchen
            for j in range(i + 1, len(diag_packets)):
                if j in used_responses:
                    continue
                r_idx, r_pkt, r_src, r_tgt, r_uds, r_time = diag_packets[j]

                # Adressen müssen getauscht sein
                if r_src != tgt_addr or r_tgt != src_addr:
                    continue

                r_sid = r_uds[0]

                # Negative Response (0x7F)
                if r_sid == 0x7F and len(r_uds) >= 3:
                    rejected_sid = r_uds[1]
                    nrc = r_uds[2]
                    if rejected_sid == sid:
                        # NRC 0x78 = requestCorrectlyReceivedResponsePending
                        if nrc == 0x78:
                            used_responses.add(j)
                            continue  # Weiter suchen nach finaler Antwort
                        nrc_name = UDSDecoder.NRC.get(nrc, f"0x{nrc:02X}")
                        tx["response_idx"] = r_idx
                        tx["response_time"] = r_time
                        tx["response_data"] = r_uds
                        tx["status"] = f"NRC: {nrc_name}"
                        tx["response_time_ms"] = (r_time - req_time) * 1000
                        used_responses.add(j)
                        break

                # Positive Response (SID + 0x40)
                elif r_sid == (sid | 0x40):
                    tx["response_idx"] = r_idx
                    tx["response_time"] = r_time
                    tx["response_data"] = r_uds
                    tx["status"] = "OK"
                    tx["response_time_ms"] = (r_time - req_time) * 1000
                    used_responses.add(j)
                    break

            self.transactions.append(tx)

    def _populate_table(self):
        """Befüllt die Tabelle mit Transaktionen."""
        no_response = sum(1 for t in self.transactions if t["status"] == "Keine Antwort")
        nrc_count = sum(1 for t in self.transactions if t["status"].startswith("NRC:"))

        self.info_label.setText(
            f"Gefundene UDS-Transaktionen: {len(self.transactions)}  |  "
            f"Ohne Antwort: {no_response}  |  Negative Antworten: {nrc_count}"
        )

        self.table.setRowCount(len(self.transactions))

        base_time = self.transactions[0]["request_time"] if self.transactions else 0

        for row, tx in enumerate(self.transactions):
            # Nr.
            self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))

            # Zeit
            rel_time = tx["request_time"] - base_time
            self.table.setItem(row, 1, QTableWidgetItem(f"{rel_time:.4f}"))

            # Quelle → Ziel
            addr_str = f"{tx['ip_src']} (0x{tx['src_addr']:04X}) → {tx['ip_dst']} (0x{tx['tgt_addr']:04X})"
            self.table.setItem(row, 2, QTableWidgetItem(addr_str))

            # UDS Service
            self.table.setItem(row, 3, QTableWidgetItem(tx["service_name"]))

            # Request-Daten
            req_hex = tx["request_data"].hex().upper() if tx["request_data"] else ""
            self.table.setItem(row, 4, QTableWidgetItem(req_hex))

            # Response-Daten
            resp_hex = tx["response_data"].hex().upper() if tx["response_data"] else ""
            self.table.setItem(row, 5, QTableWidgetItem(resp_hex))

            # Status
            self.table.setItem(row, 6, QTableWidgetItem(tx["status"]))

            # Antwortzeit
            if tx["response_time_ms"] is not None:
                self.table.setItem(row, 7, QTableWidgetItem(f"{tx['response_time_ms']:.2f} ms"))
            else:
                self.table.setItem(row, 7, QTableWidgetItem("—"))

            # Pkt-Nr.
            pkt_info = f"Req: {tx['request_idx'] + 1}"
            if tx["response_idx"] is not None:
                pkt_info += f" / Rsp: {tx['response_idx'] + 1}"
            self.table.setItem(row, 8, QTableWidgetItem(pkt_info))

            # Farbkodierung
            if tx["status"].startswith("NRC:"):
                color = QColor("#ffcdd2")
            elif tx["status"] == "Keine Antwort":
                color = QColor("#fff3e0")
            else:
                color = None  # Standard (weiß)

            if color:
                for col in range(9):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(color)

    def _on_double_click(self, index):
        """Doppelklick → Sprung zum Paket in Haupttabelle."""
        row = index.row()
        if row < len(self.transactions) and self.parent_panel:
            tx = self.transactions[row]
            self.parent_panel._jump_to_packet(tx["request_idx"])


# =============================================================================
# LiveVideoDecoder — Echtzeit-Video-Dekodierung aus Live-Capture-Paketen
# =============================================================================

class LiveVideoDecoder(QObject):
    """Echtzeit-Video-Dekodierung aus Live-Capture-Paketen.

    Unterstützte Protokolle:
    - TECMP/GMSL (CSI-2 RAW12/10/8, YUV422, RGB888)
    - TECMP/FPD-Link (CSI-2)
    - TECMP → RTP (innere Ethernet-Payload)
    - RTP MJPEG (PT=26)
    - RTP H.264 (PT=96-127, FU-A Fragmentierung)
    - IEEE 1722 AVTP/CVF (MJPEG, H.264)
    - GigE Vision (GVSP) — BayerRG/GB/GR/BG8, Mono8, RGB8, BGR8
    - Direkt CSI-2 (Magic-Pattern)
    """

    frame_ready = pyqtSignal(object, int)    # (BGR numpy array, display_index)
    stream_detected = pyqtSignal(int, int)   # (stream_id, display_index)
    info_updated = pyqtSignal(dict)     # {resolution, fps, codec, frames}

    def __init__(self, protocol='auto', parent=None):
        super().__init__(parent)
        self._protocol = protocol
        self._paused = False

        # RTP-Reassembly-State
        self._rtp_fragments: Dict[int, bytearray] = {}
        self._rtp_seq: Dict[int, int] = {}

        # CSI-2 Reassembly-State (GMSL/FPD-Link)
        self._csi2_lines: list = []
        self._csi2_width = 0
        self._csi2_height = 0
        self._csi2_data_type = 0

        # GVSP Reassembly-State (GigE Vision)
        # Pro Block-ID: {packet_id → payload_bytes}
        self._gvsp_buf: Dict[int, Dict[int, bytes]] = {}
        self._gvsp_width = 0
        self._gvsp_height = 0
        self._gvsp_pixel_format = 0
        self._gvsp_detected = False  # Leader schon empfangen?

        # 0x2090 Reassembly-State (kundenspezifischer EtherType, CSI-2 RAW Stream)
        # Dict: stream_id → {'data': bytearray, 'frame_started': bool}
        self._eth2090_streams: Dict[int, dict] = {}
        self._eth2090_stream_slots: Dict[int, int] = {}  # stream_id → display_index

        # Sensor-Cache für ISP Temporal Consistency
        self._sensor_cache: Dict[str, Any] = {}

        # Per-Stream ISP-Parameter (einstellbar ueber UI)
        # stream_id → {'r_fac': float, 'b_fac': float, 'mode': str}
        self._stream_isp_params: Dict[int, dict] = {}

        # Statistik
        self._frame_count = 0
        self._fps_counter = 0
        self._fps_last_time = 0.0
        self._current_fps = 0.0
        self._real_fps_last_time = 0.0
        self._real_fps_last_count = 0
        self._resolution = ""
        self._codec = ""

        # Frame-Rate-Limiting pro Display-Slot
        self._last_frame_times = {}   # display_index → timestamp
        self._min_frame_interval = 1.0 / 20  # Max 20 FPS pro Stream

        # ISP ThreadPool (8 Worker fuer maximale Parallelitaet)
        self._pool = ThreadPoolExecutor(max_workers=12)
        self._pending_future = None

        # Letzter Frame (für Snapshot)
        self._last_frame = None

        # Auto-Detect Cache
        self._detected_protocol = None

    def set_protocol(self, protocol: str):
        """Setzt das Protokoll (auto/tecmp/fpdlink/rtp_mjpeg/rtp_h264/avtp/gvsp/csi2)."""
        self._protocol = protocol
        self._detected_protocol = None

    def set_stream_isp_params(self, stream_id: int, r_fac: float = 1.0,
                               b_fac: float = 1.0, mode: str = 'auto'):
        """Setzt ISP-Parameter fuer einen bestimmten Video-Stream."""
        self._stream_isp_params[stream_id] = {
            'r_fac': r_fac, 'b_fac': b_fac, 'mode': mode
        }
        # ISP-Cache invalidieren, damit neue Parameter sofort wirken
        state = self._eth2090_streams.get(stream_id, {})
        isp_cache = state.get('_isp_cache', {})
        isp_cache.pop('wb_gains', None)
        isp_cache.pop('wb_luts', None)
        # Bei Mode-Wechsel auch LCG-Buffer und BL zuruecksetzen
        isp_cache.pop('lcg_persistent', None)
        isp_cache.pop('bl_lcg', None)
        isp_cache.pop('_bl_wp_lut8', None)

    def get_stream_isp_params(self, stream_id: int) -> dict:
        """Liest ISP-Parameter fuer einen Stream (oder Defaults)."""
        return self._stream_isp_params.get(stream_id, {
            'r_fac': 1.0, 'b_fac': 1.0, 'mode': 'auto'
        })

    def reset(self):
        """Setzt den Decoder-Zustand zurück."""
        self._rtp_fragments.clear()
        self._rtp_seq.clear()
        self._csi2_lines.clear()
        self._csi2_data_type = 0
        self._gvsp_buf.clear()
        self._gvsp_width = 0
        self._gvsp_height = 0
        self._gvsp_pixel_format = 0
        self._gvsp_detected = False
        self._eth2090_streams.clear()
        self._eth2090_stream_slots.clear()
        self._sensor_cache.clear()
        self._frame_count = 0
        self._fps_counter = 0
        self._current_fps = 0.0
        self._real_fps_last_time = 0.0
        self._real_fps_last_count = 0
        self._resolution = ""
        self._codec = ""
        self._last_frame = None
        self._detected_protocol = None
        if self._pending_future:
            self._pending_future = None

    def process_packet(self, pkt):
        """Wird für jedes empfangene Paket aufgerufen."""
        if self._paused or not CV2_AVAILABLE:
            return

        try:
            proto = self._resolve_protocol(pkt)
            if not proto:
                return

            if proto == 'tecmp':
                self._handle_tecmp(pkt, link_type='gmsl')
            elif proto == 'fpdlink':
                self._handle_tecmp(pkt, link_type='fpdlink')
            elif proto == 'tecmp_rtp':
                self._handle_tecmp_rtp(pkt)
            elif proto in ('rtp_mjpeg', 'rtp_h264'):
                self._handle_rtp(pkt)
            elif proto == 'avtp':
                self._handle_avtp(pkt)
            elif proto == 'gvsp':
                self._handle_gvsp(pkt)
            elif proto == 'csi2_0x2090':
                self._handle_csi2_0x2090(pkt)
        except Exception:
            pass  # Fehlerhafte Pakete still ignorieren

    def _resolve_protocol(self, pkt) -> Optional[str]:
        """Protokoll bestimmen (manuell oder Auto-Detect)."""
        if self._protocol != 'auto':
            return self._protocol
        return self._detect_protocol(pkt)

    def _detect_protocol(self, pkt) -> Optional[str]:
        """Automatische Protokollerkennung."""
        if not SCAPY_AVAILABLE:
            return None
        if not (Ether in pkt):
            return None

        # 1. TECMP (EtherType 0x99FE)
        if pkt[Ether].type == 0x99FE:
            if Raw in pkt:
                raw = bytes(pkt[Raw].load)
                if len(raw) >= 12:
                    data_type = int.from_bytes(raw[8:10], 'big')
                    # 0x0005 = Ethernet → innerer RTP
                    if data_type == 0x0005:
                        return 'tecmp_rtp'
                    # 0x0081 = GMSL/FPD-Link
                    return 'tecmp'
            return 'tecmp'

        # 2. UDP-basiert
        if UDP in pkt and Raw in pkt:
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            # TECMP über UDP (Port 50000)
            if sport == 50000 or dport == 50000:
                return 'tecmp'
            # GVCP Steuerkanal ignorieren (Port 3956)
            if sport == 3956 or dport == 3956:
                return None
            # GigE Vision (GVSP): Leader-Paket erkennen (Byte 4 == 0x01)
            raw = bytes(pkt[Raw].load)
            if len(raw) >= 32 and raw[4] == 0x01:
                # Leader: Payload-Type 0x0001 (Image) bei Byte 10-11
                pt_gvsp = int.from_bytes(raw[10:12], 'big')
                if pt_gvsp == 0x0001:
                    return 'gvsp'
            # Bereits als GVSP erkannt: Payload/Trailer ebenfalls zuordnen
            if self._gvsp_detected and len(raw) >= 8:
                if raw[4] in (0x02, 0x03):
                    return 'gvsp'
            # RTP-Erkennung
            if len(raw) > 12 and (raw[0] >> 6) == 2:
                pt = raw[1] & 0x7F
                if pt == 26:
                    return 'rtp_mjpeg'
                if 96 <= pt <= 127:
                    return 'rtp_h264'

        # 3. IEEE 1722 (EtherType 0x22F0)
        if pkt[Ether].type == 0x22F0:
            return 'avtp'

        # 4. Kundenspezifischer CSI-2 RAW Stream (EtherType 0x2090)
        if pkt[Ether].type == 0x2090:
            return 'csi2_0x2090'

        return None

    # ----- TECMP/GMSL/FPD-Link Handler -----

    def _handle_tecmp(self, pkt, link_type='gmsl'):
        """TECMP → GMSL/FPD-Link CSI-2 Extraktion."""
        if not DECODERS_AVAILABLE or not (Raw in pkt):
            return

        raw = bytes(pkt[Raw].load)
        if len(raw) < 16:
            return

        # TECMP innere Payload extrahieren
        inner = self._get_tecmp_inner_payload(raw)
        if not inner or len(inner) < 4:
            return

        try:
            if link_type == 'fpdlink':
                result = FPDLinkDecoder.decode(inner)
            else:
                result = GMSLDecoder.decode(inner)
        except Exception:
            return

        fields = {f.get('name', ''): f.get('value', '')
                  for f in result.get('fields', []) if isinstance(f, dict)}
        dt_str = fields.get('Data Type', '')

        # Data-Type-Code extrahieren
        dt_code = 0
        for f in result.get('fields', []):
            if isinstance(f, dict) and f.get('name') == 'Data Type':
                raw_val = f.get('raw_value', 0)
                if isinstance(raw_val, int):
                    dt_code = raw_val
                break

        payload = inner[4:]  # GMSL/FPD-Link Header ist 4 Bytes

        if 'Frame Start' in dt_str:
            self._csi2_lines = []
            self._csi2_data_type = dt_code
        elif 'Frame End' in dt_str:
            if self._csi2_lines:
                self._codec = f"CSI-2/{'FPD-Link' if link_type == 'fpdlink' else 'GMSL'}"
                frame = self._reconstruct_csi2_frame()
                if frame is not None:
                    self._emit_frame(frame)
                self._csi2_lines = []
        elif payload:
            self._csi2_lines.append(payload)

    def _handle_tecmp_rtp(self, pkt):
        """TECMP → innere Ethernet-Payload → RTP extrahieren."""
        if not (Raw in pkt):
            return

        raw = bytes(pkt[Raw].load)
        if len(raw) < 16:
            return

        inner = self._get_tecmp_inner_payload(raw)
        if inner and len(inner) > 42:
            try:
                inner_pkt = Ether(inner)
                self._handle_rtp(inner_pkt)
            except Exception:
                pass

    def _get_tecmp_inner_payload(self, raw: bytes) -> Optional[bytes]:
        """Extrahiert die innere Payload aus TECMP-Daten."""
        if len(raw) < 16:
            return None
        offset = 12
        if len(raw) < offset + 12:
            return None
        entry_len = int.from_bytes(raw[offset + 8:offset + 10], 'big')
        payload_start = offset + 12
        if len(raw) >= payload_start + entry_len:
            return raw[payload_start:payload_start + entry_len]
        return raw[payload_start:]

    # ----- RTP Handler -----

    def _handle_rtp(self, pkt):
        """RTP MJPEG/H.264 Frame-Reassembly."""
        if not (UDP in pkt) or not (Raw in pkt):
            return

        payload = bytes(pkt[Raw].load)
        if len(payload) < 12:
            return

        version = (payload[0] >> 6) & 0x03
        if version != 2:
            return

        pt = payload[1] & 0x7F
        marker = (payload[1] >> 7) & 0x01
        ssrc = int.from_bytes(payload[8:12], 'big')

        # Header-Länge berechnen (CC + Extension)
        cc = payload[0] & 0x0F
        header_len = 12 + cc * 4
        if (payload[0] >> 4) & 0x01:  # Extension-Bit
            if len(payload) > header_len + 4:
                ext_len = int.from_bytes(payload[header_len + 2:header_len + 4], 'big')
                header_len += 4 + ext_len * 4

        rtp_payload = payload[header_len:]
        if not rtp_payload:
            return

        if pt == 26:
            # MJPEG (PT=26)
            self._codec = "RTP/MJPEG"
            if ssrc not in self._rtp_fragments:
                self._rtp_fragments[ssrc] = bytearray()
            if len(rtp_payload) > 8:
                self._rtp_fragments[ssrc].extend(rtp_payload[8:])
            if marker:
                jpeg_data = bytes(self._rtp_fragments[ssrc])
                self._rtp_fragments[ssrc] = bytearray()
                if jpeg_data:
                    img = cv2.imdecode(np.frombuffer(jpeg_data, np.uint8), cv2.IMREAD_COLOR)
                    if img is not None:
                        self._emit_frame(img)

        elif 96 <= pt <= 127:
            # H.264 (dynamische Payload-Typen)
            self._codec = "RTP/H.264"
            nal_type = rtp_payload[0] & 0x1F
            if 1 <= nal_type <= 23:
                # Single NAL-Unit
                nal_data = b'\x00\x00\x00\x01' + bytes(rtp_payload)
                img = self._decode_h264_nal(nal_data)
                if img is not None:
                    self._emit_frame(img)
            elif nal_type == 28 and len(rtp_payload) >= 2:
                # FU-A Fragmentierung
                fu_header = rtp_payload[1]
                start_bit = (fu_header >> 7) & 1
                end_bit = (fu_header >> 6) & 1
                if ssrc not in self._rtp_fragments:
                    self._rtp_fragments[ssrc] = bytearray()
                if start_bit:
                    reconstructed = (rtp_payload[0] & 0xE0) | (fu_header & 0x1F)
                    self._rtp_fragments[ssrc] = bytearray([reconstructed])
                    self._rtp_fragments[ssrc].extend(rtp_payload[2:])
                else:
                    self._rtp_fragments[ssrc].extend(rtp_payload[2:])
                if end_bit and self._rtp_fragments[ssrc]:
                    nal_data = b'\x00\x00\x00\x01' + bytes(self._rtp_fragments[ssrc])
                    self._rtp_fragments[ssrc] = bytearray()
                    img = self._decode_h264_nal(nal_data)
                    if img is not None:
                        self._emit_frame(img)
        else:
            # Fallback: JPEG-Signatur
            if rtp_payload[:2] == b'\xFF\xD8':
                self._codec = "JPEG"
                img = cv2.imdecode(np.frombuffer(rtp_payload, np.uint8), cv2.IMREAD_COLOR)
                if img is not None:
                    self._emit_frame(img)

    def _decode_h264_nal(self, nal_data: bytes):
        """Dekodiert einen H.264 NAL-Unit."""
        try:
            return cv2.imdecode(np.frombuffer(nal_data, np.uint8), cv2.IMREAD_COLOR)
        except Exception:
            return None

    # ----- AVTP Handler -----

    def _handle_avtp(self, pkt):
        """IEEE 1722 AVTP/CVF: MJPEG/H.264 extrahieren."""
        if not DECODERS_AVAILABLE or not (Raw in pkt):
            return

        raw = bytes(pkt[Raw].load)
        if len(raw) < 24:
            return

        try:
            result = IEEE1722Decoder.decode(raw)
        except Exception:
            return

        fields = {f.get('name', ''): f.get('value', '')
                  for f in result.get('fields', []) if isinstance(f, dict)}
        subtype_str = fields.get('Subtype', '')
        if 'CVF' not in subtype_str and 'Compressed Video' not in subtype_str:
            return

        cvf_format = fields.get('Format', '')
        stream_id = fields.get('Stream ID', 0)
        avtp_payload = raw[24:]
        if not avtp_payload:
            return

        sid = stream_id if isinstance(stream_id, int) else hash(str(stream_id)) & 0xFFFFFFFF

        if 'MJPEG' in cvf_format or '0x02' in str(cvf_format):
            self._codec = "AVTP/MJPEG"
            marker = (raw[2] >> 4) & 0x01 if len(raw) > 2 else 0
            if sid not in self._rtp_fragments:
                self._rtp_fragments[sid] = bytearray()
            self._rtp_fragments[sid].extend(avtp_payload)
            if marker:
                jpeg_data = bytes(self._rtp_fragments[sid])
                self._rtp_fragments[sid] = bytearray()
                if jpeg_data:
                    img = cv2.imdecode(np.frombuffer(jpeg_data, np.uint8), cv2.IMREAD_COLOR)
                    if img is not None:
                        self._emit_frame(img)

        elif 'H.264' in cvf_format or '0x03' in str(cvf_format):
            self._codec = "AVTP/H.264"
            if avtp_payload:
                nal_data = b'\x00\x00\x00\x01' + bytes(avtp_payload)
                img = self._decode_h264_nal(nal_data)
                if img is not None:
                    self._emit_frame(img)

    # ----- 0x2090 Handler (kundenspezifischer CSI-2 RAW Stream) -----

    def _handle_csi2_0x2090(self, pkt):
        """EtherType 0x2090 — Kontinuierlicher CSI-2 RAW-Stream.

        Transport-Header (28 Bytes nach Ethernet):
          Bytes 0-3:   Sequenznummer (Big-Endian)
          Bytes 4-5:   Protokoll-Version (0x0203)
          Bytes 6-7:   Sub-Version (0x0101)
          Bytes 8-11:  Pakettyp: 4=Daten, 5=Frame-Ende, 6=Frame-Start
          Bytes 12-15: Stream-ID (z.B. 0x0064, 0x0065)
          Bytes 16-23: Zeitstempel (8 Bytes)
          Bytes 24-25: Datenlaenge (Big-Endian)
          Bytes 26-27: Reserviert
        Frame-Start (Typ 6): Zusaetzlich 32-Byte Sub-Header vor Pixeldaten.
        """
        if isinstance(pkt, (bytes, bytearray)):
            raw = pkt  # Schnellpfad: Raw-Bytes direkt
        elif Raw in pkt:
            raw = bytes(pkt[Raw].load)
        else:
            return
        if len(raw) < 28:
            return

        seq_num = int.from_bytes(raw[0:4], 'big')
        pkt_type = int.from_bytes(raw[8:12], 'big')
        stream_id = int.from_bytes(raw[12:16], 'big')
        data_len = int.from_bytes(raw[24:26], 'big')

        # Stream-State initialisieren (nur beim ersten Frame-Start)
        if stream_id not in self._eth2090_streams:
            if pkt_type != 0x06:
                return  # Warte auf Frame-Start fuer neuen Stream
            self._eth2090_streams[stream_id] = {
                'data': bytearray(), 'frame_started': False,
                'stride': 0, 'width': 0, 'line_stride': 0,
                'parse_buf': bytearray(), 'frame_lines': [],
            }
            # Nächsten freien Display-Slot zuweisen (max 4)
            if len(self._eth2090_stream_slots) < 4:
                slot = len(self._eth2090_stream_slots)
                self._eth2090_stream_slots[stream_id] = slot
                self.stream_detected.emit(stream_id, slot)

        # Nur Streams mit zugewiesenem Slot verarbeiten (CPU sparen)
        if stream_id not in self._eth2090_stream_slots:
            return

        state = self._eth2090_streams[stream_id]

        if pkt_type == 0x06:
            # Frame-Start: Sub-Header parsen (Stride + Datentyp)
            if len(raw) >= 60:
                sub_hdr = raw[28:60]
                stride_val = int.from_bytes(sub_hdr[18:20], 'big')
                if stride_val > 0 and state['width'] == 0:
                    # Jede Zeile: pixel_data (stride-16) + CSI-2 Header (16)
                    pixel_bpl = stride_val - 16
                    if pixel_bpl > 0 and pixel_bpl % 3 == 0:
                        w = pixel_bpl * 2 // 3
                        if w > 640:
                            state['stride'] = stride_val
                            state['width'] = w
                            state['line_stride'] = stride_val
                    # Fallback: voller Stride als Pixel-Bytes
                    if state['width'] == 0:
                        for pad in (0, 2, 4):
                            pix_bpl = stride_val - pad
                            if pix_bpl > 0 and pix_bpl % 3 == 0:
                                w = pix_bpl * 2 // 3
                                if w > 640:
                                    state['stride'] = stride_val
                                    state['width'] = w
                                    state['line_stride'] = stride_val
                                    break

            # Vorherige Daten verwerfen, neuen Frame beginnen
            state['data'] = bytearray()
            state['parse_buf'] = bytearray()
            state['frame_lines'] = []
            state['_last_line_ts'] = None
            state['frame_started'] = True
            # Transport-Timestamp speichern (= Sensorzeile 0 Referenz)
            state['_frame_start_ts'] = int.from_bytes(raw[16:24], 'big')
            # 32-Byte Sub-Header ueberspringen — nur puffern, NICHT extrahieren
            sub_hdr_len = 32
            pixel_data = raw[28 + sub_hdr_len:28 + data_len]
            if pixel_data:
                state['parse_buf'].extend(pixel_data)

        elif pkt_type == 0x04:
            # Daten-Paket: nur puffern (Extraktion bei Frame-Ende)
            if not state['frame_started']:
                return
            # Buffer begrenzen: max ~2 physische Frames
            # Verhindert Multi-Frame-Merge und spart CPU
            stride = state.get('stride', 6000)
            if len(state['parse_buf']) > stride * 4000:
                return  # Ueberlauf → Paket verwerfen
            state['parse_buf'].extend(raw[28:28 + data_len])

        elif pkt_type == 0x05:
            # Frame-Ende: puffern + ALLE Zeilen auf einmal extrahieren
            state['parse_buf'].extend(raw[28:28 + data_len])
            self._extract_0x2090_lines(state, force_last=True)

            # Mindestens 100 Zeilen + Frame-Rate-Begrenzung
            if state['frame_started'] and len(state['frame_lines']) >= 100:
                import time
                now = time.monotonic()
                last = state.get('_last_render', 0)
                if now - last >= 0.020:  # Max ~50 fps (Display-Limit in _emit_frame)
                    # ISP-Pipeline: Bis zu 4 parallele Tasks pro Stream
                    pending_list = state.setdefault('_pending_futures', [])
                    pending_list[:] = [f for f in pending_list if not f.done()]
                    if len(pending_list) < 4:
                        # ── Leichtgewichtiger Snapshot (~0.3ms) ──
                        # Assembly-Thread kopiert nur Referenzen,
                        # ALLES Schwere (RAW12 + ISP) geht an ThreadPool.
                        isp_cache = state.setdefault('_isp_cache', {})
                        frame_num = state.get('_frame_num', 0) + 1
                        state['_frame_num'] = frame_num
                        snapshot = {
                            'frame_lines': state['frame_lines'],
                            'stride': state.get('stride', 0),
                            'width': state.get('width', 0),
                            'isp_cache': isp_cache,
                            'frame_num': frame_num,
                            '_frame_start_ts': state.get('_frame_start_ts'),
                            'stream_id': stream_id,
                        }

                        slot = self._eth2090_stream_slots.get(stream_id, 0)

                        def _on_isp_done(fut, _slot=slot):
                            try:
                                result = fut.result()
                                if result is not None:
                                    bgr = result
                                    self._codec = 'CSI-2/0x2090'
                                    self._emit_frame(bgr, _slot)
                            except Exception as e:
                                try:
                                    import traceback
                                    with open('/tmp/0x2090_isp.log', 'a') as _f:
                                        _f.write(f"ISP-FEHLER: {e}\n")
                                        traceback.print_exc(file=_f)
                                except Exception:
                                    pass

                        # ── LCG-Update + ISP komplett im ThreadPool ──
                        # Assembly-Thread blockiert NIE (< 0.5ms pro Frame)
                        fut = self._pool.submit(
                            self._update_and_isp,
                            stream_id, snapshot
                        )
                        fut.add_done_callback(_on_isp_done)
                        pending_list.append(fut)
                        state['_last_render'] = now

            state['data'] = bytearray()
            state['parse_buf'] = bytearray()
            state['frame_lines'] = []
            state['frame_started'] = False

    def _update_and_isp(self, stream_id: int, snapshot: dict) -> 'Optional[np.ndarray]':
        """Kombinierte LCG-Update + ISP Pipeline fuer ThreadPool.

        Alles in einem Task: RAW12 Entpackung (nur neue Zeilen) →
        LCG-Buffer aktualisieren → Binning → Demosaic → Farbe → Resize.
        Lock schuetzt persistenten LCG-Buffer bei parallelen Tasks.
        """
        isp_cache = snapshot['isp_cache']
        frame_num = snapshot['frame_num']

        # ── Phase 1: LCG inkrementell aktualisieren (mit Lock) ──
        lcg_lock = isp_cache.setdefault('_lcg_lock', threading.Lock())
        with lcg_lock:
            lcg_snap = self._update_0x2090_lcg_from_snapshot(snapshot)
        if lcg_snap is None:
            return None

        # ── Phase 2: ISP (Binning + Demosaic + Farbe + Resize) ──
        return self._isp_from_lcg(stream_id, lcg_snap, isp_cache, frame_num)

    def _detect_bayer_parity_rccb(self, raw_lines, line_positions,
                                  pixel_bpl, n_groups):
        """Erkennt Bayer-Paritaet fuer RCCB-Sensor via absolute Regel.

        RCCB: Gerade Zeilen haben Clear-Filter (hoher LCG-Wert),
        ungerade Zeilen haben Blue-Filter (niedriger LCG-Wert).
        Clear >= Blue gilt IMMER (szenenunabhaengig), da der Clear-Filter
        ALLE Wellenlaengen durchlaesst.

        Keine gelernte Referenz noetig — rein physikalische Eigenschaft.

        Returns: 0 (pos[0] ist gerade → korrekt) oder
                 1 (pos[0] ist ungerade → alle Positionen um 1 verschieben)
        """
        import numpy as np

        # Zaehle: Wie oft ist die Zeile an gerader Position heller?
        n_even_brighter = 0
        n_odd_brighter = 0
        for i in range(min(len(raw_lines) - 1, 200)):
            if line_positions[i+1] - line_positions[i] != 1:
                continue
            data_a = raw_lines[i][1]
            data_b = raw_lines[i+1][1]
            if len(data_a) < n_groups * 3 or len(data_b) < n_groups * 3:
                continue
            arr_a = np.frombuffer(data_a[:n_groups * 3],
                                  dtype=np.uint8).reshape(n_groups, 3)
            arr_b = np.frombuffer(data_b[:n_groups * 3],
                                  dtype=np.uint8).reshape(n_groups, 3)
            m_a = float(np.mean((arr_a[:, 2].astype(np.uint16) << 4) |
                                (arr_a[:, 1] >> 4)))
            m_b = float(np.mean((arr_b[:, 2].astype(np.uint16) << 4) |
                                (arr_b[:, 1] >> 4)))
            # Regel: Zeile an GERADER Position soll HELLER sein (Clear > Blue)
            if line_positions[i] % 2 == 0:
                if m_a > m_b:
                    n_even_brighter += 1
                else:
                    n_odd_brighter += 1
            else:
                if m_b > m_a:
                    n_even_brighter += 1
                else:
                    n_odd_brighter += 1
            if n_even_brighter + n_odd_brighter >= 10:
                break

        if n_even_brighter + n_odd_brighter < 3:
            return 0  # Nicht genug Daten

        # RCCB: Gerade Positionen MUESSEN heller sein (Clear-Filter)
        if n_odd_brighter > n_even_brighter:
            return 1  # Paritaet falsch → verschieben
        return 0

    def _update_0x2090_lcg_from_snapshot(self, snapshot) -> 'Optional[np.ndarray]':
        """Wie _update_0x2090_lcg, aber liest aus snapshot statt state."""
        import numpy as np

        raw_lines = snapshot.get('frame_lines', [])
        stride = snapshot.get('stride', 0)
        width = snapshot.get('width', 0)
        isp_cache = snapshot.get('isp_cache', {})

        if stride <= 0 or width <= 0 or len(raw_lines) < 100:
            return None

        pixel_bpl = stride - 16
        if pixel_bpl <= 0 or pixel_bpl % 3 != 0:
            return None

        n_groups = pixel_bpl // 3
        valid_w = n_groups * 2
        lcg_w = valid_w // 2

        # ── Absolute Positionierung mit verriegeltem avg_dt ──
        # avg_dt verriegeln → gleiche Zeile bekommt in JEDEM Frame
        # die gleiche Position → persistenter Buffer stabil → keine Streifen.
        timestamps = [ts for ts, _ in raw_lines]
        deltas = sorted([timestamps[i+1] - timestamps[i]
                         for i in range(len(timestamps) - 1)
                         if 0 < timestamps[i+1] - timestamps[i] < 100000])
        if not deltas or deltas[len(deltas) // 2] <= 0:
            return None

        measured_dt = deltas[len(deltas) // 2]

        # avg_dt verriegeln: Nur beim ersten Frame setzen
        locked_dt = isp_cache.get('locked_avg_dt')
        if locked_dt is not None:
            if abs(measured_dt - locked_dt) / locked_dt > 0.10:
                isp_cache['locked_avg_dt'] = measured_dt
                avg_dt = measured_dt
            else:
                avg_dt = locked_dt
        else:
            isp_cache['locked_avg_dt'] = measured_dt
            avg_dt = measured_dt

        # ── Absolute Positionierung via Frame-Start-Timestamp ──
        # Frame-Start (0x06) markiert Sensorzeile 0. Dessen Transport-TS
        # dient als Anker → gleiche Sensorzeile = gleiche Bufferposition
        # ueber alle Frames hinweg (kein ts0-Drift mehr).
        fs_ts = snapshot.get('_frame_start_ts')
        if fs_ts is not None and fs_ts < timestamps[0]:
            ts0 = fs_ts
        else:
            ts0 = timestamps[0]  # Fallback wenn FS-TS fehlt

        line_positions = [max(0, round((ts - ts0) / avg_dt))
                          for ts in timestamps]

        max_pos = max(line_positions) if line_positions else 0
        frame_h = max_pos + 1

        # ── Multi-Frame-Erkennung ──
        expected_h_ref = isp_cache.get('expected_h', 2200)
        if frame_h > expected_h_ref * 1.3:
            frame_gap_thresh = 150 * avg_dt
            last_start = 0
            for i in range(len(timestamps) - 1):
                if timestamps[i+1] - timestamps[i] > frame_gap_thresh:
                    last_start = i + 1
            if last_start > 0:
                raw_lines = raw_lines[last_start:]
                timestamps = [ts for ts, _ in raw_lines]
                if len(raw_lines) < 100:
                    return None
                # Nach Multi-Frame-Split: Re-Positionierung mit FS-TS
                line_positions = [max(0, round((ts - ts0) / avg_dt))
                                  for ts in timestamps]
                max_pos = max(line_positions) if line_positions else 0
                frame_h = max_pos + 1

        # ── Diagnose-Log ──
        frame_num = snapshot.get('frame_num', 0)
        if frame_num <= 30 or frame_num % 100 == 0:
            try:
                with open('/tmp/0x2090_pos.log', 'a') as _f:
                    _f.write(f"F{frame_num}: lines={len(raw_lines)} "
                             f"dt={avg_dt} "
                             f"frame_h={frame_h} exp_h={isp_cache.get('expected_h',0)} "
                             f"fs_ts={'Y' if fs_ts else 'N'} "
                             f"pos[0:5]={line_positions[:5]} "
                             f"pos[-3:]={line_positions[-3:]}\n")
            except Exception:
                pass

        # ── Stabile Bildhoehe (Sensor: 2166 Zeilen) ──
        # Frueh auf Sensor-Hoehe konvergieren, Buffer nicht staendig
        # mit Nullen neu erstellen.
        prev_expected = isp_cache.get('expected_h', 0)
        if prev_expected >= 2000:
            expected_h = prev_expected  # Einmal gelernt → stabil bleiben
        elif 800 < frame_h < 2500:
            expected_h = max(prev_expected, frame_h)
        elif prev_expected > 0:
            expected_h = prev_expected
        else:
            expected_h = min(frame_h, 2200)
        expected_h = min(expected_h, 2200) & ~1
        if expected_h < 100:
            expected_h = max(len(raw_lines), 100) & ~1
        isp_cache['expected_h'] = expected_h

        lcg_buf = isp_cache.get('lcg_persistent')
        if lcg_buf is None or lcg_buf.shape != (expected_h, lcg_w):
            lcg_buf = np.zeros((expected_h, lcg_w), dtype=np.uint16)
            isp_cache['lcg_persistent'] = lcg_buf

        new_data = bytearray()
        new_indices = []
        for i, (ts, data) in enumerate(raw_lines):
            idx = line_positions[i]
            if 0 <= idx < expected_h:
                new_data.extend(data[:pixel_bpl])
                new_indices.append(idx)

        n_new = len(new_indices)
        if n_new < 50:
            return None

        # ── Kurzframe-Schutz: < 90% Coverage → alten Buffer behalten ──
        if expected_h > 100 and n_new < expected_h * 0.90:
            prev = isp_cache.get('lcg_persistent')
            if prev is not None:
                return prev.copy()
            return None

        expected_bytes = n_new * n_groups * 3
        raw_buf = np.frombuffer(bytes(new_data[:expected_bytes]),
                                dtype=np.uint8).reshape(n_new, n_groups, 3)
        b0 = raw_buf[:, :, 0].astype(np.uint16)
        b1 = raw_buf[:, :, 1].astype(np.uint16)
        b2 = raw_buf[:, :, 2].astype(np.uint16)

        image = np.empty((n_new, valid_w), dtype=np.uint16)
        image[:, 0::2] = (b0 << 4) | (b1 & 0x0F)   # HCG
        image[:, 1::2] = (b2 << 4) | (b1 >> 4)      # LCG

        # Gain-Modus: HCG oder LCG Kanal waehlen
        _sid = snapshot.get('stream_id', 0)
        _mode = self._stream_isp_params.get(_sid, {}).get('mode', 'auto')
        if _mode == 'hcg':
            new_data_ch = image[:, 0::2]
        else:
            new_data_ch = image[:, 1::2]
        idx_arr = np.array(new_indices, dtype=np.intp)
        lcg_buf[idx_arr] = new_data_ch

        del raw_buf, b0, b1, b2, image, new_data_ch, new_data
        return lcg_buf.copy()

    def _update_0x2090_lcg(self, state) -> 'Optional[np.ndarray]':
        """Inkrementelle LCG-Aktualisierung: RAW12 Entpackung nur fuer NEUE Zeilen.

        Laeuft im Assembly-Thread (synchron, ~3-5ms statt ~20ms fuer alle Zeilen).
        Haelt einen persistenten LCG-Buffer (uint16) pro Stream.
        Gibt eine thread-sichere Kopie zurueck fuer den ThreadPool-ISP.
        """
        import numpy as np

        raw_lines = state.get('frame_lines', [])
        stride = state.get('stride', 0)
        width = state.get('width', 0)
        isp_cache = state.setdefault('_isp_cache', {})

        if stride <= 0 or width <= 0 or len(raw_lines) < 100:
            return None

        pixel_bpl = stride - 16
        if pixel_bpl <= 0 or pixel_bpl % 3 != 0:
            return None

        n_groups = pixel_bpl // 3
        valid_w = n_groups * 2
        lcg_w = valid_w // 2  # LCG = ungerade Spalten

        # ── Sequenzielle Positionierung mit verriegeltem avg_dt ──
        timestamps = [ts for ts, _ in raw_lines]
        deltas = sorted([timestamps[i+1] - timestamps[i]
                         for i in range(len(timestamps) - 1)
                         if 0 < timestamps[i+1] - timestamps[i] < 100000])
        if not deltas or deltas[len(deltas) // 2] <= 0:
            return None

        measured_dt = deltas[len(deltas) // 2]

        locked_dt = isp_cache.get('locked_avg_dt')
        if locked_dt is not None:
            if abs(measured_dt - locked_dt) / locked_dt > 0.10:
                isp_cache['locked_avg_dt'] = measured_dt
                avg_dt = measured_dt
            else:
                avg_dt = locked_dt
        else:
            isp_cache['locked_avg_dt'] = measured_dt
            avg_dt = measured_dt

        # ── Absolute Positionierung via Frame-Start-Timestamp ──
        fs_ts = state.get('_frame_start_ts')
        if fs_ts is not None and fs_ts < timestamps[0]:
            ts0 = fs_ts
        else:
            ts0 = timestamps[0]

        line_positions = [max(0, round((ts - ts0) / avg_dt))
                          for ts in timestamps]

        max_pos = max(line_positions) if line_positions else 0
        frame_h = max_pos + 1

        # Multi-Frame-Erkennung (nur bei frame_h >> erwartet)
        expected_h_ref = isp_cache.get('expected_h', 2200)
        if frame_h > expected_h_ref * 1.3:
            frame_gap_thresh = 150 * avg_dt
            last_start = 0
            for i in range(len(timestamps) - 1):
                if timestamps[i+1] - timestamps[i] > frame_gap_thresh:
                    last_start = i + 1
            if last_start > 0:
                raw_lines = raw_lines[last_start:]
                timestamps = [ts for ts, _ in raw_lines]
                if len(raw_lines) < 100:
                    return None
                # Nach Multi-Frame-Split: Re-Positionierung mit FS-TS
                line_positions = [max(0, round((ts - ts0) / avg_dt))
                                  for ts in timestamps]
                max_pos = max(line_positions) if line_positions else 0
                frame_h = max_pos + 1

        # Erwartete Bildhoehe: einmal gelernt → stabil bleiben
        prev_expected = isp_cache.get('expected_h', 0)
        if prev_expected >= 2000:
            expected_h = prev_expected
        elif 800 < frame_h < 2500:
            expected_h = max(prev_expected, frame_h)
        elif prev_expected > 0:
            expected_h = prev_expected
        else:
            expected_h = min(frame_h, 2200)
        expected_h = min(expected_h, 2200) & ~1
        if expected_h < 100:
            expected_h = max(len(raw_lines), 100) & ~1
        isp_cache['expected_h'] = expected_h

        # ── Persistenten LCG-Buffer holen/erstellen ──
        lcg_buf = isp_cache.get('lcg_persistent')
        if lcg_buf is None or lcg_buf.shape != (expected_h, lcg_w):
            lcg_buf = np.zeros((expected_h, lcg_w), dtype=np.uint16)
            isp_cache['lcg_persistent'] = lcg_buf

        # ── Nur NEUE Zeilen sammeln (die in den Buffer passen) ──
        new_data = bytearray()
        new_indices = []
        for i, (ts, data) in enumerate(raw_lines):
            idx = line_positions[i]
            if 0 <= idx < expected_h:
                new_data.extend(data[:pixel_bpl])
                new_indices.append(idx)

        n_new = len(new_indices)
        if n_new < 50:
            return None

        # ── Kurzframe-Schutz: < 90% Coverage → alten Buffer behalten ──
        if expected_h > 100 and n_new < expected_h * 0.90:
            prev = isp_cache.get('lcg_persistent')
            if prev is not None:
                return prev.copy()
            return None

        # ── Batch RAW12 Entpackung (nur neue Zeilen) ──
        expected_bytes = n_new * n_groups * 3
        raw_buf = np.frombuffer(bytes(new_data[:expected_bytes]),
                                dtype=np.uint8).reshape(n_new, n_groups, 3)
        b0 = raw_buf[:, :, 0].astype(np.uint16)
        b1 = raw_buf[:, :, 1].astype(np.uint16)
        b2 = raw_buf[:, :, 2].astype(np.uint16)

        image = np.empty((n_new, valid_w), dtype=np.uint16)
        image[:, 0::2] = (b0 << 4) | (b1 & 0x0F)   # HCG
        image[:, 1::2] = (b2 << 4) | (b1 >> 4)      # LCG

        # Gain-Modus: HCG oder LCG Kanal waehlen
        _sid = state.get('_stream_id', 0)
        _mode = self._stream_isp_params.get(_sid, {}).get('mode', 'auto')
        if _mode == 'hcg':
            new_data_ch = image[:, 0::2]
        else:
            new_data_ch = image[:, 1::2]

        # ── Scatter-Write: Nur geaenderte Zeilen aktualisieren ──
        idx_arr = np.array(new_indices, dtype=np.intp)
        lcg_buf[idx_arr] = new_data_ch

        del raw_buf, b0, b1, b2, image, new_data_ch, new_data

        # Statistik fuer Logging
        state['_lcg_updated'] = n_new
        state['_lcg_gaps'] = expected_h - n_new

        return lcg_buf.copy()  # Thread-sichere Kopie

    def _isp_from_lcg(self, stream_id: int, lcg: 'np.ndarray',
                       isp_cache: dict, frame_num: int) -> 'Optional[np.ndarray]':
        """ISP-Pipeline ab LCG-Buffer: Binning → Demosaic → Farbe → Resize.

        Laeuft im ThreadPool (~20-30ms statt ~60ms mit RAW12-Entpackung).
        """
        import cv2
        import numpy as np
        import time as _time

        _isp_t0 = _time.monotonic()
        bh, bw = lcg.shape

        # ── 1. Bayer 2×2 Binning ──
        if bh >= 50 and bw >= 50:
            bh4 = (bh // 4) * 4
            bw4 = (bw // 4) * 4
            src = lcg[:bh4, :bw4]
            binned = np.empty((bh4 // 2, bw4 // 2), dtype=np.uint16)
            binned[0::2, 0::2] = (src[0::4, 0::4].astype(np.uint32) +
                                  src[0::4, 2::4] + src[2::4, 0::4] +
                                  src[2::4, 2::4]) >> 2
            binned[0::2, 1::2] = (src[0::4, 1::4].astype(np.uint32) +
                                  src[0::4, 3::4] + src[2::4, 1::4] +
                                  src[2::4, 3::4]) >> 2
            binned[1::2, 0::2] = (src[1::4, 0::4].astype(np.uint32) +
                                  src[1::4, 2::4] + src[3::4, 0::4] +
                                  src[3::4, 2::4]) >> 2
            binned[1::2, 1::2] = (src[1::4, 1::4].astype(np.uint32) +
                                  src[1::4, 3::4] + src[3::4, 1::4] +
                                  src[3::4, 3::4]) >> 2
            lcg = binned
            del binned, src

        # ── 2. Black-Level + White-Point ──
        ch = lcg.astype(np.float32)
        sub = lcg[::4, ::4]
        sub = sub[sub > 0]
        bl_new = float(np.percentile(sub, 1)) if len(sub) > 100 else 0.0
        bl_old = isp_cache.get('bl_lcg')
        if bl_old is not None:
            bl = bl_old * 0.8 + bl_new * 0.2
        else:
            bl = bl_new
        isp_cache['bl_lcg'] = bl
        ch = np.clip(ch - bl, 0, None)

        sub = ch[::4, ::4]
        pos = sub[sub > 0]
        wp = float(np.percentile(pos, 99.5)) if len(pos) > 100 else 1.0
        wp = max(wp, 1.0)
        ch *= (65535.0 / wp)
        np.clip(ch, 0, 65535, out=ch)
        ch_16 = ch.astype(np.uint16)
        del ch, lcg

        # ── 3. Bayer RG Demosaic (RCCB: R bei [0,0]) ──
        bgr_16 = cv2.cvtColor(ch_16, cv2.COLOR_BayerRG2BGR)
        del ch_16

        # ── 4. White Balance + Gamma (LUT-basiert) ──
        wb_sub = bgr_16[::4, ::4]
        gm = float(np.mean(wb_sub[:, :, 1]))
        bm = float(np.mean(wb_sub[:, :, 0]))
        rm = float(np.mean(wb_sub[:, :, 2]))
        gain_b = (gm / bm) if bm > 0 else 1.0
        gain_r = (gm / rm) if rm > 0 else 1.0

        # User-ISP-Parameter anwenden (R/B-Faktor als Multiplikator)
        user_isp = self._stream_isp_params.get(stream_id, {})
        gain_r *= user_isp.get('r_fac', 1.0)
        gain_b *= user_isp.get('b_fac', 1.0)

        prev = isp_cache.get('wb_gains')
        rebuild = True
        if prev is not None:
            if (abs(gain_b - prev[0]) / max(prev[0], 1e-6) < 0.05
                    and abs(gain_r - prev[1]) / max(prev[1], 1e-6) < 0.05):
                lut_b, lut_g, lut_r = isp_cache['wb_luts']
                rebuild = False
        if rebuild:
            def _make_lut(gain):
                x = np.arange(65536, dtype=np.float32) / 65535.0
                x = np.clip(x * gain, 0, 1)
                return (np.power(x, 1.0 / 2.2) * 255).astype(np.uint8)
            lut_b = _make_lut(gain_b)
            lut_g = _make_lut(1.0)
            lut_r = _make_lut(gain_r)
            isp_cache['wb_gains'] = (gain_b, gain_r)
            isp_cache['wb_luts'] = (lut_b, lut_g, lut_r)

        bgr = np.empty((*bgr_16.shape[:2], 3), dtype=np.uint8)
        bgr[:, :, 0] = lut_b[bgr_16[:, :, 0]]
        bgr[:, :, 1] = lut_g[bgr_16[:, :, 1]]
        bgr[:, :, 2] = lut_r[bgr_16[:, :, 2]]
        del bgr_16

        # ── 5. Feste Vorschaugroesse ──
        bgr = cv2.resize(bgr, (960, 540), interpolation=cv2.INTER_LINEAR)

        _isp_ms = (_time.monotonic() - _isp_t0) * 1000
        if frame_num <= 10 or frame_num % 50 == 0:
            try:
                # Farb-Diagnose: Mittelwerte nach WB+Gamma (BGR-Reihenfolge)
                _cs = bgr[::4, ::4]
                _bm_out = float(np.mean(_cs[:, :, 0]))
                _gm_out = float(np.mean(_cs[:, :, 1]))
                _rm_out = float(np.mean(_cs[:, :, 2]))
                with open('/tmp/0x2090_isp.log', 'a') as _f:
                    _f.write(f"frame {frame_num} stream 0x{stream_id:x}: "
                             f"LCG {bh}x{bw} → BGR 960x540, "
                             f"ISP {_isp_ms:.0f}ms, "
                             f"preWB B={bm:.0f} G={gm:.0f} R={rm:.0f}, "
                             f"gain_b={gain_b:.2f} gain_r={gain_r:.2f}, "
                             f"out B={_bm_out:.0f} G={_gm_out:.0f} R={_rm_out:.0f}\n")
            except Exception:
                pass

        # ── 帧抖动诊断 (帧间时间差检测) ──
        try:
            _jt_key = f'_jitter_{stream_id}'
            _jt = isp_cache.get(_jt_key)
            _now = _time.monotonic()
            if _jt is None:
                _jt = {'prev_time': _now, 'events': 0, 'total': 0,
                       'log_f': open('/tmp/0x2090_jitter.log', 'a')}
                isp_cache[_jt_key] = _jt
                _jt['log_f'].write(
                    f"\n=== Jitter-Diagnose gestartet S0x{stream_id:x} "
                    f"{_time.strftime('%H:%M:%S')} ===\n")
                _jt['log_f'].flush()
            else:
                _dt = (_now - _jt['prev_time']) * 1000  # ms
                _jt['total'] += 1
                # 正常帧间隔约 33ms (30fps) 或 66ms (15fps)
                # 异常: dt > 100ms (丢帧/卡顿) 或 dt < 10ms (突发)
                _is_anomaly = (_dt > 100) or (_dt < 10) or (_isp_ms > 80)
                if _is_anomaly:
                    _jt['events'] += 1
                    _jt['log_f'].write(
                        f"[JITTER] F{frame_num} S0x{stream_id:x} "
                        f"t={_time.strftime('%H:%M:%S')} "
                        f"dt={_dt:.0f}ms isp={_isp_ms:.0f}ms "
                        f"events={_jt['events']}/{_jt['total']}\n")
                    _jt['log_f'].flush()
                elif frame_num % 300 == 0:
                    _jt['log_f'].write(
                        f"[OK]     F{frame_num} S0x{stream_id:x} "
                        f"t={_time.strftime('%H:%M:%S')} "
                        f"dt={_dt:.0f}ms isp={_isp_ms:.0f}ms "
                        f"events={_jt['events']}/{_jt['total']}\n")
                    _jt['log_f'].flush()
            _jt['prev_time'] = _now
        except Exception:
            pass

        return bgr

    def _extract_0x2090_lines(self, state, force_last=False):
        """Extrahiert CSI-2 Zeilen inkrementell aus dem Parse-Buffer.

        Wird bei jedem Paket aufgerufen — Buffer bleibt klein (~8-15 KB).
        Speichert (timestamp, pixel_data) fuer Bayer-Padding in
        _reconstruct_0x2090_frame.
        """
        buf = state['parse_buf']
        wc = state.get('stride', 0)
        if wc <= 0:
            return

        magic = b'\x00\x00' + wc.to_bytes(2, 'big') + b'\x00\x2c'

        while len(buf) >= wc:
            idx = buf.find(magic)
            if idx < 0:
                if len(buf) > wc * 2:
                    del buf[:len(buf) - wc]
                break

            if idx > 0:
                del buf[:idx]

            if len(buf) < wc:
                break

            if len(buf) >= wc + len(magic):
                if buf[wc:wc + len(magic)] != magic:
                    del buf[:1]
                    continue
            elif force_last and len(buf) >= wc:
                pass
            else:
                break

            ts = int.from_bytes(buf[6:14], 'big')
            state['frame_lines'].append((ts, bytes(buf[16:wc])))
            # Diagnose: Bytes 14-15 loggen (potentieller Line-Counter?)
            _hdr14_n = state.get('_hdr14_total', 0)
            if _hdr14_n < 50:
                hdr14 = int.from_bytes(buf[14:16], 'big')
                try:
                    with open('/tmp/0x2090_hdr14.log', 'a') as _df:
                        _df.write(f"line#{len(state['frame_lines'])-1} "
                                  f"hdr14=0x{hdr14:04X} ({hdr14}) ts={ts}\n")
                except Exception:
                    pass
                state['_hdr14_total'] = _hdr14_n + 1
            del buf[:wc]

    def _reconstruct_0x2090_frame(self, stream_id: int,
                                   snapshot: dict = None) -> Optional['np.ndarray']:
        """Rekonstruiert ein BGR-Bild aus vorab extrahierten CSI-2 Zeilen.

        Bayer-Alignment wird via Timestamp-basiertes Padding sichergestellt:
        Bei Luecken mit ungerader Zeilenanzahl wird eine Duplikat-Zeile
        eingefuegt, damit die Bayer-Phase (gerade/ungerade Zeile) stimmt.

        snapshot: Falls gesetzt, werden Daten daraus statt aus state gelesen
                  (fuer async ISP im ThreadPool).
        """
        import cv2
        import numpy as np

        if snapshot is not None:
            raw_lines = snapshot['frame_lines']
            stride = snapshot['stride']
            width = snapshot['width']
            isp_cache = snapshot['isp_cache']
        else:
            state = self._eth2090_streams.get(stream_id)
            if not state:
                return None
            raw_lines = state.get('frame_lines', [])
            stride = state.get('stride', 0)
            width = state.get('width', 0)
            isp_cache = state.setdefault('_isp_cache', {})

        if stride <= 0 or width <= 0 or len(raw_lines) < 100:
            return None

        pixel_bpl = stride - 16
        if pixel_bpl <= 0 or pixel_bpl % 3 != 0:
            return None

        n_groups = pixel_bpl // 3
        valid_w = n_groups * 2

        # ── 1. Persistenter Frame-Buffer mit absoluter Positionierung ──
        # Jede empfangene Zeile wird via Timestamp an die korrekte
        # absolute Position geschrieben. Nicht empfangene Zeilen behalten
        # den Wert vom vorherigen Frame → stabiles, ruhiges Bild bei
        # statischer Kamera. Bayer-Alignment ist automatisch korrekt,
        # da Zeilen immer an der richtigen geraden/ungeraden Position sind.
        timestamps = [ts for ts, _ in raw_lines]
        deltas = sorted([timestamps[i+1] - timestamps[i]
                         for i in range(len(timestamps) - 1)
                         if 0 < timestamps[i+1] - timestamps[i] < 100000])

        gap_fills = 0

        if deltas and deltas[len(deltas) // 2] > 0:
            avg_dt = deltas[len(deltas) // 2]  # Median

            # Absolute Position jeder Zeile berechnen
            ts0 = timestamps[0]
            line_positions = [round((ts - ts0) / avg_dt) for ts in timestamps]
            max_pos = max(line_positions) if line_positions else 0
            frame_h = max_pos + 1

            # Erwartete Bildhoehe lernen (aus guten Frames)
            prev_expected = isp_cache.get('expected_h', 0)
            if frame_h > prev_expected * 0.8:
                expected_h = max(prev_expected, frame_h)
            elif prev_expected > 0:
                expected_h = prev_expected
            else:
                expected_h = frame_h
            expected_h = min(expected_h, 2000) & ~1  # Gerade, max 2000
            if expected_h < 100:
                expected_h = max(len(raw_lines), 100) & ~1
            isp_cache['expected_h'] = expected_h

            # Persistenten Buffer holen/erstellen
            persistent = isp_cache.get('persistent_lines')
            if persistent is None or len(persistent) != expected_h:
                persistent = [raw_lines[0][1]] * expected_h
                isp_cache['persistent_lines'] = persistent

            # Empfangene Zeilen an korrekte Positionen schreiben
            updated = 0
            for i, (ts, data) in enumerate(raw_lines):
                idx = line_positions[i]
                if 0 <= idx < expected_h:
                    persistent[idx] = data
                    updated += 1
            gap_fills = expected_h - updated

            frame_lines = list(persistent)  # Snapshot (bytes sind immutable)
        else:
            frame_lines = [row_data for ts, row_data in raw_lines]
            if len(frame_lines) > 2000:
                frame_lines = frame_lines[:2000]

        actual_h = len(frame_lines) & ~1  # Gerade Anzahl fuer Bayer
        if actual_h < 50:
            return None
        # ── Debug-Logging (Datei) ──
        if snapshot is not None:
            _frame_num = snapshot.get('frame_num', 0)
        else:
            _frame_num = state.get('_frame_num', 0) + 1
            state['_frame_num'] = _frame_num

        # ── 2. RAW12 entpacken (vektorisiert) ──
        line_data = bytearray()
        for row in range(actual_h):
            line_data.extend(frame_lines[row][:pixel_bpl])

        expected = actual_h * n_groups * 3
        buf = np.frombuffer(bytes(line_data[:expected]),
                            dtype=np.uint8).reshape(actual_h, n_groups, 3)
        b0 = buf[:, :, 0].astype(np.uint16)
        b1 = buf[:, :, 1].astype(np.uint16)
        b2 = buf[:, :, 2].astype(np.uint16)

        image = np.empty((actual_h, valid_w), dtype=np.uint16)
        image[:, 0::2] = (b0 << 4) | (b1 & 0x0F)
        image[:, 1::2] = (b2 << 4) | (b1 >> 4)
        del buf, b0, b1, b2, line_data

        # ── 3. LCG-Kanal extrahieren ──
        lcg = image[:, 1::2].copy()
        del image

        # ── 3b. Bayer 2×2 Binning (Vorschau-Beschleunigung) ──
        # Mittelt je 4 Pixel gleicher Bayer-Farbe (4×4 Block → 2×2 Block).
        # Reduziert Bildgroesse auf 1/4 → Demosaic + HSV ~4× schneller.
        bh, bw = lcg.shape
        import time as _time
        _isp_t0 = _time.monotonic()
        if bh >= 50 and bw >= 50:
            bh4 = (bh // 4) * 4
            bw4 = (bw // 4) * 4
            src = lcg[:bh4, :bw4]
            binned = np.empty((bh4 // 2, bw4 // 2), dtype=np.uint16)
            binned[0::2, 0::2] = (src[0::4, 0::4].astype(np.uint32) +
                                  src[0::4, 2::4] + src[2::4, 0::4] +
                                  src[2::4, 2::4]) >> 2
            binned[0::2, 1::2] = (src[0::4, 1::4].astype(np.uint32) +
                                  src[0::4, 3::4] + src[2::4, 1::4] +
                                  src[2::4, 3::4]) >> 2
            binned[1::2, 0::2] = (src[1::4, 0::4].astype(np.uint32) +
                                  src[1::4, 2::4] + src[3::4, 0::4] +
                                  src[3::4, 2::4]) >> 2
            binned[1::2, 1::2] = (src[1::4, 1::4].astype(np.uint32) +
                                  src[1::4, 3::4] + src[3::4, 1::4] +
                                  src[3::4, 3::4]) >> 2
            lcg = binned
            del binned, src

        # ── 4. ISP: Black-Level + White-Point → 16-Bit ──
        # isp_cache wurde bereits am Anfang gesetzt (aus state oder snapshot)
        ch = lcg.astype(np.float32)

        sub = lcg[::4, ::4]
        sub = sub[sub > 0]
        bl_new = float(np.percentile(sub, 1)) if len(sub) > 100 else 0.0
        bl_old = isp_cache.get('bl_lcg')
        if bl_old is not None:
            bl = bl_old * 0.8 + bl_new * 0.2  # Sanfte Anpassung
        else:
            bl = bl_new
        isp_cache['bl_lcg'] = bl
        ch = np.clip(ch - bl, 0, None)

        sub = ch[::4, ::4]
        pos = sub[sub > 0]
        wp = float(np.percentile(pos, 99.5)) if len(pos) > 100 else 1.0
        wp = max(wp, 1.0)
        ch *= (65535.0 / wp)
        np.clip(ch, 0, 65535, out=ch)
        ch_16 = ch.astype(np.uint16)
        del ch, lcg

        # ── 5. Bayer RG Demosaic (RCCB: R bei [0,0]) ──
        bgr_16 = cv2.cvtColor(ch_16, cv2.COLOR_BayerRG2BGR)
        del ch_16

        # ── 6. White Balance + Gamma (LUT-basiert, gecacht) ──
        wb_sub = bgr_16[::4, ::4]
        gm = float(np.mean(wb_sub[:, :, 1]))
        bm = float(np.mean(wb_sub[:, :, 0]))
        rm = float(np.mean(wb_sub[:, :, 2]))
        gain_b = (gm / bm) if bm > 0 else 1.0
        gain_r = (gm / rm) if rm > 0 else 1.0

        # User-ISP-Parameter anwenden (R/B-Faktor als Multiplikator)
        user_isp = self._stream_isp_params.get(stream_id, {})
        gain_r *= user_isp.get('r_fac', 1.0)
        gain_b *= user_isp.get('b_fac', 1.0)

        prev = isp_cache.get('wb_gains')
        rebuild = True
        if prev is not None:
            if (abs(gain_b - prev[0]) / max(prev[0], 1e-6) < 0.05
                    and abs(gain_r - prev[1]) / max(prev[1], 1e-6) < 0.05):
                lut_b, lut_g, lut_r = isp_cache['wb_luts']
                rebuild = False
        if rebuild:
            def _make_lut(gain):
                x = np.arange(65536, dtype=np.float32) / 65535.0
                x = np.clip(x * gain, 0, 1)
                return (np.power(x, 1.0 / 2.2) * 255).astype(np.uint8)
            lut_b = _make_lut(gain_b)
            lut_g = _make_lut(1.0)
            lut_r = _make_lut(gain_r)
            isp_cache['wb_gains'] = (gain_b, gain_r)
            isp_cache['wb_luts'] = (lut_b, lut_g, lut_r)

        bgr = np.empty((*bgr_16.shape[:2], 3), dtype=np.uint8)
        bgr[:, :, 0] = lut_b[bgr_16[:, :, 0]]
        bgr[:, :, 1] = lut_g[bgr_16[:, :, 1]]
        bgr[:, :, 2] = lut_r[bgr_16[:, :, 2]]
        del bgr_16

        # ── 7. Saettigungs-Boost DEAKTIVIERT fuer Live-Performance ──
        # HSV-Konvertierung (2× cvtColor) kostet ~30% der ISP-Zeit.
        # Fuer Live-Vorschau nicht noetig — Farben sind auch ohne OK.

        # ── 8. Auf feste Vorschaugroesse skalieren ──
        # Feste Ausgabe 960×540 verhindert Groessenschwankungen durch
        # variable Zeilenanzahl (Paketdrops). Aspect-Ratio wird ignoriert
        # da sich nur die Hoehe aendert — Breite ist immer ~962.
        bgr = cv2.resize(bgr, (960, 540),
                          interpolation=cv2.INTER_LINEAR)

        _isp_ms = (_time.monotonic() - _isp_t0) * 1000
        if _frame_num <= 10 or _frame_num % 20 == 0:
            try:
                _cs = bgr[::4, ::4]
                _bm_out = float(np.mean(_cs[:, :, 0]))
                _gm_out = float(np.mean(_cs[:, :, 1]))
                _rm_out = float(np.mean(_cs[:, :, 2]))
                with open('/tmp/0x2090_isp.log', 'a') as _f:
                    _f.write(f"[recon] F{_frame_num} S0x{stream_id:x}: "
                             f"raw={len(raw_lines)} gaps={gap_fills} h={actual_h}, "
                             f"LCG {bh}x{bw}→{bgr.shape[1]}x{bgr.shape[0]}, "
                             f"{_isp_ms:.0f}ms, "
                             f"preWB B={bm:.0f} G={gm:.0f} R={rm:.0f}, "
                             f"gain_b={gain_b:.2f} gain_r={gain_r:.2f}, "
                             f"out B={_bm_out:.0f} G={_gm_out:.0f} R={_rm_out:.0f}\n")
            except Exception:
                pass

        return bgr

    # ----- GigE Vision (GVSP) Handler -----

    def _handle_gvsp(self, pkt):
        """GigE Vision GVSP: Leader/Payload/Trailer Frame-Assembly."""
        if not (Raw in pkt):
            return

        raw = bytes(pkt[Raw].load)
        if len(raw) < 8:
            return

        import struct as _st
        from ui.bildvorschau_dialog import _gvsp_pixel_to_bgr, GVSP_PIXEL_FORMATS

        packet_format = raw[4]
        block_id = _st.unpack('>H', raw[2:4])[0]
        packet_id = _st.unpack('>I', b'\x00' + raw[5:8])[0]

        if packet_format == 0x01:
            # ── Leader: Bild-Parameter extrahieren ──
            if len(raw) < 8 + 24:
                return
            leader = raw[8:]
            payload_type = _st.unpack('>H', leader[2:4])[0]
            if payload_type != 0x0001:
                return  # Nur Image Leader

            pixel_fmt = _st.unpack('>I', leader[12:16])[0]
            size_x = _st.unpack('>I', leader[16:20])[0]
            size_y = _st.unpack('>I', leader[20:24])[0]

            if size_x == 0 or size_y == 0:
                return

            fmt_info = GVSP_PIXEL_FORMATS.get(pixel_fmt)
            fmt_name = fmt_info[0] if fmt_info else f'0x{pixel_fmt:08X}'

            self._gvsp_width = size_x
            self._gvsp_height = size_y
            self._gvsp_pixel_format = pixel_fmt
            self._gvsp_detected = True
            self._gvsp_buf[block_id] = {}
            self._codec = f"GVSP/{fmt_name}"

        elif packet_format == 0x03:
            # ── Payload: Bild-Chunk speichern ──
            if block_id in self._gvsp_buf:
                self._gvsp_buf[block_id][packet_id] = raw[8:]

        elif packet_format == 0x02:
            # ── Trailer: Frame zusammensetzen ──
            if block_id not in self._gvsp_buf or not self._gvsp_buf[block_id]:
                return

            chunks = self._gvsp_buf[block_id]
            raw_data = b''.join(chunks[pid] for pid in sorted(chunks))
            del self._gvsp_buf[block_id]

            bgr = _gvsp_pixel_to_bgr(
                raw_data,
                self._gvsp_width,
                self._gvsp_height,
                self._gvsp_pixel_format)
            if bgr is not None:
                self._emit_frame(bgr)

        # Speicher begrenzen: max 3 Block-IDs
        if len(self._gvsp_buf) > 3:
            oldest = min(self._gvsp_buf.keys())
            del self._gvsp_buf[oldest]

    # ----- CSI-2 Frame-Rekonstruktion -----

    def _reconstruct_csi2_frame(self) -> Optional['np.ndarray']:
        """Rekonstruiert ein Bild aus CSI-2 Zeilen."""
        if not self._csi2_lines:
            return None
        try:
            raw_data = b''.join(self._csi2_lines)
            dt = self._csi2_data_type

            if dt == 0x1E:
                # YUV422 8-bit (YUYV)
                line_len = len(self._csi2_lines[0])
                width = line_len // 2
                height = len(raw_data) // (width * 2)
                if width <= 0 or height <= 0:
                    return None
                total = width * height * 2
                yuv = np.frombuffer(raw_data[:total], np.uint8).reshape((height, width, 2))
                return cv2.cvtColor(yuv, cv2.COLOR_YUV2BGR_YUYV)

            elif dt == 0x24:
                # RGB888 → BGR konvertieren (Display erwartet BGR)
                line_len = len(self._csi2_lines[0])
                width = line_len // 3
                height = len(raw_data) // (width * 3)
                if width <= 0 or height <= 0:
                    return None
                total = width * height * 3
                rgb = np.frombuffer(raw_data[:total], np.uint8).reshape((height, width, 3))
                return cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)

            elif dt in (0x2D, 0x2C, 0x2B):
                # RAW12/RAW10/RAW8 → ISP-Pipeline
                return self._reconstruct_raw_frame(dt)

            else:
                # Fallback: als JPEG versuchen
                return cv2.imdecode(np.frombuffer(raw_data, np.uint8), cv2.IMREAD_COLOR)
        except Exception:
            return None

    def _reconstruct_raw_frame(self, dt: int) -> Optional['np.ndarray']:
        """RAW12/10/8 Zeilen → BGR Bild via ISP-Pipeline."""
        try:
            from ui.converter_panel import ConversionWorker
        except ImportError:
            return None

        lines = self._csi2_lines
        if not lines:
            return None

        line_len = len(lines[0])
        if dt == 0x2D:
            # RAW12: 3 Bytes → 2 Pixel
            width = (line_len // 3) * 2
        elif dt == 0x2C:
            # RAW10: 5 Bytes → 4 Pixel
            width = (line_len // 5) * 4
        else:
            # RAW8: 1 Byte = 1 Pixel
            width = line_len

        height = len(lines)
        if width <= 0 or height <= 0:
            return None

        if dt == 0x2D:
            return ConversionWorker._raw12_lines_to_bgr(
                lines, width, height, dual_gain_mode='auto',
                sensor_cache=self._sensor_cache)
        elif dt == 0x2C:
            return ConversionWorker._raw10_lines_to_bgr(lines, width, height)
        else:
            return ConversionWorker._raw8_lines_to_bgr(lines, width, height)

    # ----- Frame-Emission -----

    def _emit_frame(self, bgr: 'np.ndarray', display_index: int = 0):
        """Per-Display Frame-Rate-Limiting + Signal-Emission."""
        now = time.time()
        last = self._last_frame_times.get(display_index, 0.0)
        if now - last < self._min_frame_interval:
            return
        self._last_frame_times[display_index] = now
        self._last_frame = bgr
        self._frame_count += 1
        self._fps_counter += 1

        # FPS berechnen
        elapsed = now - self._fps_last_time
        if elapsed >= 1.0:
            self._current_fps = self._fps_counter / elapsed
            self._fps_counter = 0
            self._fps_last_time = now

        h, w = bgr.shape[:2]
        self._resolution = f"{w}\u00d7{h}"

        self.frame_ready.emit(bgr, display_index)

        # Info-Update alle 5 Frames
        if self._frame_count % 5 == 0:
            # Real FPS: 基于 frame_count 差值的实时帧率
            real_fps_val = 0.0
            real_elapsed = now - self._real_fps_last_time
            if real_elapsed >= 1.0:
                delta = self._frame_count - self._real_fps_last_count
                real_fps_val = delta / real_elapsed
                self._real_fps_last_count = self._frame_count
                self._real_fps_last_time = now
            self.info_updated.emit({
                'resolution': self._resolution,
                'fps': f"{self._current_fps:.1f}",
                'real_fps': f"{real_fps_val:.1f}" if real_fps_val > 0 else "",
                'codec': self._codec,
                'frames': self._frame_count,
            })

    def cleanup(self):
        """Ressourcen freigeben."""
        self._pool.shutdown(wait=False)


# =============================================================================
# Objekt-Erkennung: Detector + Thread
# =============================================================================

class ObjectDetector:
    """ORB Feature Matching mit Template-Matching-Fallback für texturarme Bilder."""

    def __init__(self):
        self.orb = cv2.ORB_create(nfeatures=1000)
        self.bf = cv2.BFMatcher(cv2.NORM_HAMMING)
        self.ref_kp = None
        self.ref_des = None
        self.ref_gray = None
        self.ref_shape = None
        self.use_template = False
        self.template_pyramid: list = []
        self.lowe_ratio = 0.75
        self.min_inliers = 15
        self.template_threshold = 0.70
        self.processing_width = 640
        self.keypoint_count = 0

    def set_reference(self, image: np.ndarray):
        """Referenzbild setzen. Wechselt automatisch zu Template-Matching bei wenigen Keypoints."""
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        self.ref_shape = gray.shape
        kp, des = self.orb.detectAndCompute(gray, None)
        self.keypoint_count = len(kp)
        if len(kp) >= self.min_inliers and des is not None:
            self.ref_kp, self.ref_des = kp, des
            self.use_template = False
        else:
            self.use_template = True
            self.template_pyramid = []
            for scale in [0.5, 0.75, 1.0, 1.25, 1.5]:
                h, w = gray.shape
                resized = cv2.resize(gray, (int(w * scale), int(h * scale)))
                self.template_pyramid.append(resized)
        self.ref_gray = gray

    def detect(self, frame: np.ndarray) -> dict:
        """Erkennung im Frame. Gibt {detected, confidence, bbox} zurück."""
        h, w = frame.shape[:2]
        scale = self.processing_width / w if w > self.processing_width else 1.0
        if scale < 1.0:
            frame = cv2.resize(frame, (self.processing_width, int(h * scale)))
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        if not self.use_template:
            return self._detect_orb(gray, scale)
        else:
            return self._detect_template(gray, scale)

    def _detect_orb(self, gray: np.ndarray, scale: float) -> dict:
        kp, des = self.orb.detectAndCompute(gray, None)
        if des is None or len(kp) < 5:
            return {'detected': False, 'confidence': 0.0, 'bbox': None}
        matches = self.bf.knnMatch(self.ref_des, des, k=2)
        good = []
        for m_n in matches:
            if len(m_n) == 2:
                m, n = m_n
                if m.distance < self.lowe_ratio * n.distance:
                    good.append(m)
        if len(good) < self.min_inliers:
            confidence = len(good) / max(self.min_inliers, 1)
            return {'detected': False, 'confidence': min(confidence, 0.99), 'bbox': None}
        src_pts = np.float32([self.ref_kp[m.queryIdx].pt for m in good]).reshape(-1, 1, 2)
        dst_pts = np.float32([kp[m.trainIdx].pt for m in good]).reshape(-1, 1, 2)
        M, mask = cv2.findHomography(src_pts, dst_pts, cv2.RANSAC, 5.0)
        if M is None:
            return {'detected': False, 'confidence': len(good) / max(self.min_inliers, 1), 'bbox': None}
        inliers = int(mask.sum())
        confidence = min(inliers / max(self.min_inliers, 1), 1.0)
        rh, rw = self.ref_shape
        corners = np.float32([[0, 0], [rw, 0], [rw, rh], [0, rh]]).reshape(-1, 1, 2)
        dst_corners = cv2.perspectiveTransform(corners, M)
        bbox = dst_corners.reshape(-1, 2).tolist()
        if scale < 1.0:
            bbox = [[x / scale, y / scale] for x, y in bbox]
        return {'detected': inliers >= self.min_inliers, 'confidence': confidence, 'bbox': bbox}

    def _detect_template(self, gray: np.ndarray, scale: float) -> dict:
        best_val = 0.0
        best_loc = None
        best_tw, best_th = 0, 0
        for tmpl in self.template_pyramid:
            th, tw = tmpl.shape
            if tw > gray.shape[1] or th > gray.shape[0]:
                continue
            result = cv2.matchTemplate(gray, tmpl, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, max_loc = cv2.minMaxLoc(result)
            if max_val > best_val:
                best_val = max_val
                best_loc = max_loc
                best_tw, best_th = tw, th
        if best_loc is None:
            return {'detected': False, 'confidence': 0.0, 'bbox': None}
        x, y = best_loc
        bbox = [[x, y], [x + best_tw, y], [x + best_tw, y + best_th], [x, y + best_th]]
        if scale < 1.0:
            bbox = [[bx / scale, by / scale] for bx, by in bbox]
        return {
            'detected': best_val >= self.template_threshold,
            'confidence': float(best_val),
            'bbox': bbox,
        }


class DetectionThread(QThread):
    """Verarbeitet Frames in separatem Thread mit Single-Slot-Queue."""

    detection_result = pyqtSignal(dict)

    def __init__(self, detector: ObjectDetector, parent=None):
        super().__init__(parent)
        self._detector = detector
        self._frame = None
        self._has_frame = False
        self._running = False
        import threading
        self._lock = threading.Lock()
        self._event = threading.Event()

    def submit_frame(self, bgr: np.ndarray):
        """Non-blocking: Ersetzt alten Frame (nur neuester wird verarbeitet)."""
        with self._lock:
            self._frame = bgr
            self._has_frame = True
        self._event.set()

    def run(self):
        self._running = True
        while self._running:
            self._event.wait(timeout=0.5)
            self._event.clear()
            frame = None
            with self._lock:
                if self._has_frame:
                    frame = self._frame
                    self._has_frame = False
            if frame is not None:
                try:
                    result = self._detector.detect(frame)
                    result['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                    self.detection_result.emit(result)
                except Exception:
                    pass

    def stop(self):
        self._running = False
        self._event.set()
        self.wait(3000)


class ObjectSelectionDialog(QDialog):
    """Dialog zur Auswahl eines erkannten Objekts aus einem Referenzbild."""

    _COLORS = [
        (0, 0, 255), (255, 0, 0), (0, 165, 255), (255, 0, 255),
        (0, 255, 255), (128, 0, 128), (0, 128, 255), (255, 255, 0),
    ]

    def __init__(self, image, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Objekt-Auswahl")
        self.setMinimumSize(700, 500)
        self.resize(900, 600)
        self._original = image.copy()
        self._bboxes = []  # Liste von (x, y, w, h)
        self._selected_idx = -1  # -1 = gesamtes Bild
        self._selected_image = image.copy()
        self._scale = 1.0
        self._offset_x = 0
        self._offset_y = 0
        self._detect_objects()
        self._annotated = self._draw_annotations()
        self._init_ui()
        self._update_image_display()
        self._select_full_image()

    # --- Konturen-Erkennung ---
    def _detect_objects(self):
        gray = cv2.cvtColor(self._original, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        thresh = cv2.adaptiveThreshold(
            blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
            cv2.THRESH_BINARY_INV, 11, 2
        )
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
        closed = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)
        contours, _ = cv2.findContours(closed, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        h, w = self._original.shape[:2]
        total_area = h * w
        min_area = total_area * 0.001
        max_area = total_area * 0.9
        rects = []
        for cnt in contours:
            area = cv2.contourArea(cnt)
            if min_area <= area <= max_area:
                rects.append(cv2.boundingRect(cnt))
        rects.sort(key=lambda r: r[2] * r[3], reverse=True)
        self._bboxes = rects[:20]

    # --- Bild-Annotation ---
    def _draw_annotations(self):
        img = self._original.copy()
        for i, (x, y, w, h) in enumerate(self._bboxes):
            color = self._COLORS[i % len(self._COLORS)]
            thickness = 4 if i == self._selected_idx else 2
            if i == self._selected_idx:
                color = (0, 255, 0)
            cv2.rectangle(img, (x, y), (x + w, y + h), color, thickness)
            label = str(i + 1)
            font = cv2.FONT_HERSHEY_SIMPLEX
            (tw, th), _ = cv2.getTextSize(label, font, 0.6, 2)
            cv2.rectangle(img, (x, y - th - 6), (x + tw + 6, y), color, -1)
            cv2.putText(img, label, (x + 3, y - 3), font, 0.6, (255, 255, 255), 2)
        return img

    # --- UI ---
    def _init_ui(self):
        layout = QVBoxLayout(self)

        n = len(self._bboxes)
        if n > 0:
            info_text = f"{n} Objekt(e) erkannt. Klicken Sie auf ein Objekt zur Auswahl."
        else:
            info_text = "Keine Objekte erkannt. Das gesamte Bild wird als Referenz verwendet."
        self._info_label = QLabel(info_text)
        self._info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._info_label.setStyleSheet("font-weight: bold; padding: 4px;")
        layout.addWidget(self._info_label)

        splitter = QHBoxLayout()

        # Linke Seite: Bild mit Bounding-Boxes
        self._image_label = QLabel()
        self._image_label.setMinimumSize(500, 400)
        self._image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._image_label.setStyleSheet("background: #222;")
        self._image_label.mousePressEvent = self._on_image_click
        splitter.addWidget(self._image_label, 3)

        # Rechte Seite: Vorschau + Controls
        right = QVBoxLayout()
        right.addWidget(QLabel("Vorschau:"))
        self._preview_label = QLabel()
        self._preview_label.setFixedSize(200, 200)
        self._preview_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._preview_label.setStyleSheet("background: #333; border: 1px solid #555;")
        right.addWidget(self._preview_label)

        self._crop_info_label = QLabel("Gesamtes Bild")
        self._crop_info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        right.addWidget(self._crop_info_label)

        full_btn = QPushButton("Gesamtes Bild")
        full_btn.clicked.connect(self._select_full_image)
        right.addWidget(full_btn)

        right.addStretch()
        splitter.addLayout(right, 1)
        layout.addLayout(splitter)

        # Button-Box
        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    # --- Bild-Anzeige ---
    def _update_image_display(self):
        img = self._annotated
        h, w = img.shape[:2]
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        qimg = QImage(rgb.data, w, h, 3 * w, QImage.Format.Format_RGB888)
        pixmap = QPixmap.fromImage(qimg)

        lw = self._image_label.width()
        lh = self._image_label.height()
        scaled = pixmap.scaled(lw, lh, Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation)
        self._image_label.setPixmap(scaled)

        self._scale = w / scaled.width() if scaled.width() > 0 else 1.0
        self._offset_x = (lw - scaled.width()) / 2
        self._offset_y = (lh - scaled.height()) / 2

    # --- Klick-Mapping ---
    def _on_image_click(self, event):
        if not self._bboxes:
            return
        x = (event.position().x() - self._offset_x) * self._scale
        y = (event.position().y() - self._offset_y) * self._scale
        if x < 0 or y < 0:
            return
        h, w = self._original.shape[:2]
        if x >= w or y >= h:
            return
        # Kleinste Box zuerst bei Überlappung
        candidates = []
        for i, (bx, by, bw, bh) in enumerate(self._bboxes):
            if bx <= x <= bx + bw and by <= y <= by + bh:
                candidates.append((bw * bh, i))
        if candidates:
            candidates.sort()
            self._select_object(candidates[0][1])

    def _select_object(self, index):
        self._selected_idx = index
        x, y, w, h = self._bboxes[index]
        self._selected_image = self._original[y:y+h, x:x+w].copy()
        self._annotated = self._draw_annotations()
        self._update_image_display()
        self._show_preview(self._selected_image)
        self._crop_info_label.setText(f"Objekt {index + 1}: {w}x{h}")

    def _select_full_image(self):
        self._selected_idx = -1
        self._selected_image = self._original.copy()
        self._annotated = self._draw_annotations()
        self._update_image_display()
        self._show_preview(self._original)
        h, w = self._original.shape[:2]
        self._crop_info_label.setText(f"Gesamtes Bild: {w}x{h}")

    def _show_preview(self, image):
        h, w = image.shape[:2]
        rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        qimg = QImage(rgb.data, w, h, 3 * w, QImage.Format.Format_RGB888)
        pixmap = QPixmap.fromImage(qimg)
        scaled = pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio,
                               Qt.TransformationMode.SmoothTransformation)
        self._preview_label.setPixmap(scaled)

    def get_selected_image(self):
        return self._selected_image

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_image_display()


# ════════════════════════════════════════════════════════════════
#  Video Render-Thread: QImage-Erstellung + Skalierung off-main-thread
# ════════════════════════════════════════════════════════════════

class _VideoRenderThread(QThread):
    """Bereitet Video-Frames in einem dedizierten Thread auf.

    Aufgaben (thread-sicher, kein GIL-Problem dank Qt C++):
      1. BGR numpy → QImage (Format_BGR888)
      2. QImage.scaled() auf Zielgroesse
    Nur setPixmap() muss im Hauptthread passieren (via Signal).
    """

    image_ready = pyqtSignal(QImage, int)  # (skaliertes QImage, display_index)

    def __init__(self, display_index: int, parent=None):
        super().__init__(parent)
        self._display_index = display_index
        self._queue: deque = deque(maxlen=2)  # Nur neueste Frames behalten
        self._running = True
        self._event = threading.Event()
        self._frame_count = 0
        self._fps = 0.0
        self._fps_time = 0.0
        self._fps_count = 0

    @property
    def display_fps(self) -> float:
        return self._fps

    def submit_frame(self, bgr: 'np.ndarray', target_w: int, target_h: int):
        """Frame einreichen (vom Hauptthread aufgerufen)."""
        self._queue.append((bgr, target_w, target_h))
        self._event.set()

    def stop(self):
        self._running = False
        self._event.set()
        self.wait(3000)

    def run(self):
        import time as _time
        _log_path = '/tmp/0x2090_render.log'
        self._fps_time = _time.time()

        try:
            with open(_log_path, 'a') as _f:
                _f.write(f"[RenderThread-{self._display_index}] gestartet\n")
        except Exception:
            pass

        while self._running:
            self._event.wait(timeout=0.5)
            self._event.clear()

            if not self._running:
                break

            # Nur neuesten Frame verarbeiten (aeltere verwerfen)
            item = None
            while self._queue:
                item = self._queue.popleft()
            if item is None:
                continue

            bgr, tw, th = item
            if tw <= 0 or th <= 0:
                continue

            try:
                h, w = bgr.shape[:2]
                # QImage aus BGR-Daten erstellen (referenziert bgr.data)
                qimg = QImage(bgr.data, w, h, 3 * w,
                              QImage.Format.Format_BGR888)
                # scaled() erzeugt eine NEUE QImage mit eigenen Daten →
                # bgr kann danach freigegeben werden
                from PyQt6.QtCore import QSize
                scaled = qimg.scaled(
                    QSize(tw, th),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.FastTransformation)

                self.image_ready.emit(scaled, self._display_index)
                self._frame_count += 1

                # Display-FPS berechnen
                self._fps_count += 1
                now = _time.time()
                elapsed = now - self._fps_time
                if elapsed >= 1.0:
                    self._fps = self._fps_count / elapsed
                    self._fps_count = 0
                    self._fps_time = now

                # Diagnose-Log (erste 5 Frames + jeder 200.)
                if self._frame_count <= 5 or self._frame_count % 200 == 0:
                    try:
                        with open(_log_path, 'a') as _f:
                            _f.write(f"[RT-{self._display_index}] "
                                     f"F{self._frame_count}: "
                                     f"{w}x{h}→{scaled.width()}x{scaled.height()}, "
                                     f"disp_fps={self._fps:.1f}\n")
                    except Exception:
                        pass

            except Exception as e:
                try:
                    with open(_log_path, 'a') as _f:
                        _f.write(f"[RT-{self._display_index}] FEHLER: {e}\n")
                except Exception:
                    pass

        try:
            with open('/tmp/0x2090_render.log', 'a') as _f:
                _f.write(f"[RenderThread-{self._display_index}] "
                         f"gestoppt, {self._frame_count} Frames verarbeitet\n")
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════
#  Frame-Dispatch-Thread: SHM-Lesen + Weiterleitung an RenderThreads
#  Umgeht den Qt Event-Loop komplett → kein Stau durch Paket-Tabelle
# ════════════════════════════════════════════════════════════════

class _FrameDispatchThread(QThread):
    """Liest Frames aus CaptureWorker SharedMemory via select().

    Vorher: QSocketNotifier → Hauptthread-Callback → RenderThread
    Nachher: select() im eigenen Thread → RenderThread → Hauptthread nur setPixmap()
    """

    stream_detected = pyqtSignal(int, int)   # (stream_id, display_slot)
    stream_worker = pyqtSignal(int, int)     # (stream_id, worker_index)
    fps_updated = pyqtSignal(int, str)       # (display_index, label_text)
    info_updated = pyqtSignal(str)           # globales Info-Label

    def __init__(self, conns, shms, render_threads, parent=None):
        super().__init__(parent)
        self._conns = conns
        self._shms = shms
        self._render_threads = render_threads
        self._running = True
        # Display-Groessen: main thread aktualisiert regelmaessig
        self._display_sizes = [(400, 400)] * 4
        self._display_sizes_lock = threading.Lock()
        # Per-Stream ISP-Parameter (Hauptthread schreibt, DispatchThread liest)
        self._isp_params: Dict[int, dict] = {}  # stream_id → {r_fac, b_fac}
        self._isp_params_lock = threading.Lock()
        # Gecachte R/B LUTs pro Stream (vermeidet wiederholte Berechnung)
        self._rb_luts: Dict[int, tuple] = {}  # stream_id → (r_fac, b_fac, lut_r, lut_b)

    def update_display_sizes(self, sizes: list):
        """Vom Hauptthread aufgerufen um aktuelle Widget-Groessen zu setzen."""
        with self._display_sizes_lock:
            self._display_sizes = sizes[:]

    def update_isp_params(self, stream_id: int, r_fac: float, b_fac: float):
        """Vom Hauptthread aufgerufen um ISP-Parameter zu aktualisieren."""
        with self._isp_params_lock:
            self._isp_params[stream_id] = {'r_fac': r_fac, 'b_fac': b_fac}

    def _apply_rb_correction(self, bgr, stream_id: int):
        """Wendet R/B-Faktor-Korrektur auf BGR-Frame an (nach CaptureWorker ISP)."""
        with self._isp_params_lock:
            params = self._isp_params.get(stream_id)
        if not params:
            return bgr
        r_fac = params.get('r_fac', 1.0)
        b_fac = params.get('b_fac', 1.0)
        if abs(r_fac - 1.0) < 0.01 and abs(b_fac - 1.0) < 0.01:
            return bgr
        # LUT-Cache pruefen / erstellen
        cached = self._rb_luts.get(stream_id)
        if cached and abs(cached[0] - r_fac) < 0.001 and abs(cached[1] - b_fac) < 0.001:
            lut_r, lut_b = cached[2], cached[3]
        else:
            x = np.arange(256, dtype=np.float32)
            lut_r = np.clip(x * r_fac, 0, 255).astype(np.uint8)
            lut_b = np.clip(x * b_fac, 0, 255).astype(np.uint8)
            self._rb_luts[stream_id] = (r_fac, b_fac, lut_r, lut_b)
        bgr = bgr.copy()
        bgr[:, :, 2] = lut_r[bgr[:, :, 2]]  # R-Kanal (BGR[2])
        bgr[:, :, 0] = lut_b[bgr[:, :, 0]]  # B-Kanal (BGR[0])
        return bgr

    def stop(self):
        self._running = False
        self.wait(3000)

    def run(self):
        import select as _sel
        import time as _time
        _log_path = '/tmp/0x2090_dispatch.log'

        try:
            with open(_log_path, 'a') as _f:
                _f.write(f"[Dispatch] gestartet, {len(self._conns)} Worker\n")
        except Exception:
            pass

        from core.capture_process import CaptureWorker as CW

        # File-Descriptor → (conn, shm, worker_index) Mapping
        fd_map: dict = {}
        for widx, (conn, shm) in enumerate(zip(self._conns, self._shms)):
            try:
                fd_map[conn.fileno()] = (conn, shm, widx)
            except Exception:
                pass
        fd_list = list(fd_map.keys())

        stream_slots: dict = {}   # stream_id → display_index
        fps_counters: dict = {}   # stream_id → last_frame_num
        fps_times: dict = {}      # stream_id → last_time
        frame_total = 0

        while self._running and fd_list:
            # select() mit Timeout — blockiert NICHT den Hauptthread
            try:
                readable, _, _ = _sel.select(fd_list, [], [], 0.1)
            except (ValueError, OSError):
                break

            for fd in readable:
                conn, shm, worker_idx = fd_map[fd]

                # Pipe leeren
                try:
                    while conn.poll():
                        conn.recv_bytes()
                except (EOFError, OSError):
                    continue

                try:
                    buf = shm.buf
                    active = struct.unpack_from('<I', buf, 0)[0]
                    off = CW.SHM_HEADER + active * CW.SLOT_SIZE
                    frame_num, h, w, stream_id = struct.unpack_from(
                        '<IIII', buf, off)

                    if h == 0 or w == 0 or h > 2000 or w > 2000:
                        continue
                    nbytes = h * w * 3
                    if nbytes > CW.MAX_BGR_BYTES:
                        continue

                    bgr = np.frombuffer(
                        bytes(buf[off + CW.SLOT_HEADER:
                                  off + CW.SLOT_HEADER + nbytes]),
                        dtype=np.uint8).reshape(h, w, 3)

                    # ── Stream-Slot zuweisen ──
                    if stream_id not in stream_slots:
                        slot = len(stream_slots)
                        if slot >= 4:
                            continue
                        stream_slots[stream_id] = slot
                        fps_counters[stream_id] = frame_num
                        fps_times[stream_id] = _time.time()
                        self.stream_detected.emit(stream_id, slot)
                        self.stream_worker.emit(stream_id, worker_idx)

                    display_index = stream_slots[stream_id]

                    # ── R/B-Faktor-Korrektur anwenden ──
                    bgr = self._apply_rb_correction(bgr, stream_id)

                    # ── An RenderThread weiterleiten ──
                    with self._display_sizes_lock:
                        sizes = self._display_sizes
                    if display_index < len(self._render_threads):
                        tw, th = sizes[display_index] \
                            if display_index < len(sizes) else (400, 400)
                        if tw > 0 and th > 0:
                            self._render_threads[display_index].submit_frame(
                                bgr, tw, th)

                    frame_total += 1

                    # ── Per-Stream FPS (Capture + Display) ──
                    now = _time.time()
                    last_t = fps_times.get(stream_id, now)
                    elapsed = now - last_t
                    if elapsed >= 1.0:
                        last_fn = fps_counters.get(stream_id, frame_num)
                        cap_fps = (frame_num - last_fn) / elapsed
                        fps_counters[stream_id] = frame_num
                        fps_times[stream_id] = now

                        disp_fps = 0.0
                        if display_index < len(self._render_threads):
                            disp_fps = \
                                self._render_threads[display_index].display_fps

                        label = (f"Stream 0x{stream_id:04X}   {w}×{h}   "
                                 f"{cap_fps:.1f} FPS "
                                 f"(disp:{disp_fps:.0f})   "
                                 f"#{frame_num}")
                        self.fps_updated.emit(display_index, label)
                        self.info_updated.emit(
                            f"Live Video [AF_PACKET/MMAP]   CSI-2/0x2090")

                    # Diagnose-Log
                    if frame_total <= 5 or frame_total % 500 == 0:
                        try:
                            with open(_log_path, 'a') as _f:
                                _f.write(
                                    f"[Dispatch] total={frame_total} "
                                    f"S0x{stream_id:04X} F{frame_num} "
                                    f"{w}x{h} → slot{display_index}\n")
                        except Exception:
                            pass

                except Exception as e:
                    try:
                        with open(_log_path, 'a') as _f:
                            _f.write(f"[Dispatch] FEHLER: {e}\n")
                    except Exception:
                        pass

        try:
            with open(_log_path, 'a') as _f:
                _f.write(f"[Dispatch] gestoppt, {frame_total} Frames total\n")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════════════
# Logger-Fernsteuerung — Hilfsklassen (Ping + REST API Worker)
# ═══════════════════════════════════════════════════════════════════════

class _PingThread(QThread):
    """Hintergrund-Thread für Ping-Prüfung mit Latenz-Messung."""

    result = pyqtSignal(bool, str, float)  # (erreichbar, ip, latenz_ms)

    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self._ip = ip

    def run(self):
        import subprocess as _sp
        import platform as _pf
        import re as _re
        param = '-n' if _pf.system().lower() == 'windows' else '-c'
        try:
            ret = _sp.run(
                ['ping', param, '1', '-W', '2', self._ip],
                capture_output=True, text=True, timeout=5,
            )
            if ret.returncode == 0:
                m = _re.search(r'[Tt]ime?=(\d+\.?\d*)\s*ms', ret.stdout)
                latency = float(m.group(1)) if m else 0.0
                self.result.emit(True, self._ip, latency)
            else:
                self.result.emit(False, self._ip, 0.0)
        except Exception:
            self.result.emit(False, self._ip, 0.0)


class _LoggerApiWorker(QThread):
    """Hintergrund-Thread für REST API Kommunikation mit dem CCA Logger."""

    data_loaded = pyqtSignal(dict)
    action_done = pyqtSignal(str)
    error = pyqtSignal(str)
    auth_expired = pyqtSignal(str, str, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._base_url = ''
        self._access_token: Optional[str] = None
        self._timeout = 5
        self._lock = threading.Lock()
        self._queue: list = []

    def set_base_url(self, url: str):
        self._base_url = url.rstrip('/')

    def set_access_token(self, token: Optional[str]):
        self._access_token = token

    def _auth_headers(self) -> Dict[str, str]:
        if self._access_token:
            return {'Authorization': f'Bearer {self._access_token}'}
        return {}

    def _enqueue(self, task: str, endpoint: str, payload: Dict[str, Any]):
        with self._lock:
            if task == 'load':
                self._queue = [
                    (t, e, p) for t, e, p in self._queue if t != task
                ]
            self._queue.append((task, endpoint, payload))
        if not self.isRunning():
            self.start()

    def load_properties(self, endpoint: str):
        self._enqueue('load', endpoint, {})

    def get_action(self, endpoint: str, action_name: str = ''):
        self._enqueue('get_action', endpoint, {'action': action_name})

    def run(self):
        try:
            import requests as req
        except ImportError:
            self.error.emit('Python-Paket "requests" nicht installiert.')
            return

        while True:
            with self._lock:
                if not self._queue:
                    break
                task, endpoint, payload = self._queue.pop(0)

            url = f'{self._base_url}{endpoint}'
            try:
                hdrs = self._auth_headers()
                if task == 'load':
                    resp = req.get(url, headers=hdrs, timeout=self._timeout)
                    resp.raise_for_status()
                    data = resp.json()
                    self.data_loaded.emit(data if isinstance(data, dict) else {'_raw': data})
                elif task == 'get_action':
                    resp = req.get(url, headers=hdrs, timeout=self._timeout)
                    resp.raise_for_status()
                    action = payload.get('action', endpoint)
                    self.action_done.emit(f'{action} — Erfolgreich')
            except req.ConnectionError:
                self.error.emit(
                    f'Verbindung zu {self._base_url} fehlgeschlagen.\n'
                    'Ist der Logger erreichbar?')
            except req.Timeout:
                self.error.emit(
                    f'Zeitüberschreitung bei {url}\n'
                    f'(Timeout: {self._timeout}s)')
            except req.HTTPError as e:
                if e.response is not None and e.response.status_code == 401 and self._access_token:
                    self.auth_expired.emit(task, endpoint, payload)
                else:
                    self.error.emit(f'HTTP-Fehler: {e}')
            except Exception as e:
                self.error.emit(f'Fehler: {e}')


class WiresharkPanel(QWidget):
    """Wireshark-ähnliches Panel für Paketanalyse."""

    # Signal für Time-Sync (Timestamp in Sekunden)
    packetTimestampSelected = pyqtSignal(float)
    # Signal wenn eine Datei erfolgreich geladen wurde
    file_opened = pyqtSignal(str)

    def __init__(self, parent=None, live_capture_mode: bool = False, default_capture_filter: str = ""):
        super().__init__(parent)

        self.packets = PacketStore()
        self.filtered_indices: List[int] = []
        self.current_file: Optional[str] = None

        # Roh-Bytes des aktuell ausgewählten Pakets (für Hex-Highlighting)
        self._current_pkt_bytes: bytes = b""
        self._current_is_dlt148: bool = False

        # Live-Capture Variablen
        self._live_capture_thread: Optional[LiveCaptureThread] = None
        self._is_capturing = False
        self._live_capture_mode = live_capture_mode
        self._default_capture_filter = default_capture_filter
        self._max_live_packets = 10000  # Limit um Abstürze zu verhindern
        self._total_trimmed = 0  # Zaehler fuer Ring-Buffer (fortlaufende Nr.-Spalte)
        self._packet_display_paused = True  # Paketanzeige standardmaessig pausiert

        # Live-Video-Decoder
        self._video_decoder: Optional[LiveVideoDecoder] = None
        self._video_decode_active = False

        # Objekt-Erkennung
        self._object_detector: Optional[ObjectDetector] = None
        self._detection_thread: Optional[DetectionThread] = None
        self._detection_active = False
        self._detection_ref_image = None        # BGR numpy
        self._detection_action_index = 0        # Ausgewählte Aktion
        self._detection_cooldown = False        # Verhindert Mehrfach-Auslösung
        self._detection_log_path: Optional[str] = None  # Log-Datei Pfad

        # Farbregeln-Manager
        self._color_rules_manager = ColorRulesManager()

        # ── Logger-Fernsteuerung (CCA REST API) ──
        self._logger_connected = False
        self._logger_recording_active = False
        self._logger_access_token: Optional[str] = None
        self._logger_refresh_token: Optional[str] = None
        self._logger_token_lifetime = 3600
        self._logger_token_acquired_at = 0.0
        self._logger_worker = _LoggerApiWorker(self)
        self._logger_worker.action_done.connect(self._logger_on_action_done)
        self._logger_worker.error.connect(self._logger_on_error)
        self._logger_worker.data_loaded.connect(self._logger_on_data_loaded)
        self._logger_worker.auth_expired.connect(self._logger_on_auth_expired)

        self._init_ui()

        # Wenn Live-Capture-Modus aktiviert, zeige die Live-Capture UI
        if live_capture_mode:
            self._show_live_capture_ui()

    def _init_ui(self):
        """Initialisiert die Benutzeroberfläche."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # Toolbar
        toolbar_layout = QHBoxLayout()

        # Öffnen-Button
        self.open_btn = QPushButton("📂 PCAP Öffnen")
        self.open_btn.clicked.connect(self._open_file)
        toolbar_layout.addWidget(self.open_btn)

        # Filter
        toolbar_layout.addWidget(QLabel("Filter:"))
        self.filter_entry = QLineEdit()
        self.filter_entry.setPlaceholderText("z.B. ip.src==192.168.1.1, tcp.port==13400, doip, someip, tecmp, udp")
        self.filter_entry.returnPressed.connect(self._apply_filter)
        toolbar_layout.addWidget(self.filter_entry, 1)

        self.filter_btn = QPushButton("▶ Anwenden")
        self.filter_btn.clicked.connect(self._apply_filter)
        toolbar_layout.addWidget(self.filter_btn)

        self.clear_filter_btn = QPushButton("✕ Löschen")
        self.clear_filter_btn.clicked.connect(self._clear_filter)
        toolbar_layout.addWidget(self.clear_filter_btn)

        # Statistiken-Button
        self.stats_btn = QPushButton("📊 Statistiken")
        self.stats_btn.clicked.connect(self._show_statistics)
        toolbar_layout.addWidget(self.stats_btn)

        # UDS Sequenz-Button
        self.uds_seq_btn = QPushButton("🔗 UDS Sequenz")
        self.uds_seq_btn.clicked.connect(self._show_uds_sequence_analysis)
        toolbar_layout.addWidget(self.uds_seq_btn)

        # Farbregeln-Button
        self.color_rules_btn = QPushButton("🎨 Farbregeln")
        self.color_rules_btn.clicked.connect(self._show_color_rules_dialog)
        toolbar_layout.addWidget(self.color_rules_btn)

        layout.addLayout(toolbar_layout)

        # Live-Capture Toolbar (zunächst versteckt)
        self.live_capture_widget = QWidget()
        live_capture_layout = QHBoxLayout(self.live_capture_widget)
        live_capture_layout.setContentsMargins(0, 4, 0, 4)

        # Interface-Auswahl (QPushButton + QMenu statt QComboBox — Wayland-kompatibel)
        live_capture_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QPushButton("Alle (Standard)")
        self.interface_combo.setMinimumWidth(250)
        self.interface_combo.setStyleSheet("text-align: left; padding: 3px 8px;")
        self._interface_menu = QMenu(self)
        self.interface_combo.setMenu(self._interface_menu)
        self._populate_interfaces()
        self._interface_items = []  # [(label, userData), ...]
        live_capture_layout.addWidget(self.interface_combo)
        self._selected_interfaces = []  # [(iface_name, type), ...] — Mehrfachauswahl
        self._selected_interface_type = "wsl"  # "wsl" oder "windows"
        self._wsl_interface_actions: Dict[str, QAction] = {}  # iface → QAction
        self._alle_action = None  # QAction fuer "Alle (Standard)"

        # Capture-Filter
        live_capture_layout.addWidget(QLabel("Capture Filter:"))
        self.capture_filter_entry = QLineEdit()
        self.capture_filter_entry.setPlaceholderText("z.B. host 192.168.1.10, port 13400, tcp and host 10.0.0.1")
        self.capture_filter_entry.setText(self._default_capture_filter)
        live_capture_layout.addWidget(self.capture_filter_entry, 1)

        # Paket-Limit
        live_capture_layout.addWidget(QLabel("Max Pakete:"))
        self.packet_limit_btn = QPushButton("10000")
        self.packet_limit_menu = QMenu(self)
        self.packet_limit_btn.setMenu(self.packet_limit_menu)
        self._selected_packet_limit = "10000"
        for limit in ["1000", "5000", "10000", "50000", "Unbegrenzt"]:
            action = self.packet_limit_menu.addAction(limit)
            action.triggered.connect(lambda checked, l=limit: self._on_packet_limit_selected(l))
        live_capture_layout.addWidget(self.packet_limit_btn)

        # Start/Stop Buttons
        self.start_capture_btn = QPushButton("▶ Start Capture")
        self.start_capture_btn.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        self.start_capture_btn.clicked.connect(self._start_live_capture)
        live_capture_layout.addWidget(self.start_capture_btn)

        self.stop_capture_btn = QPushButton("⬛ Stop")
        self.stop_capture_btn.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        self.stop_capture_btn.clicked.connect(self._stop_live_capture)
        self.stop_capture_btn.setEnabled(False)
        live_capture_layout.addWidget(self.stop_capture_btn)

        # Clear-Button für Live-Pakete
        self.clear_live_btn = QPushButton("🗑 Leeren")
        self.clear_live_btn.clicked.connect(self._clear_live_packets)
        live_capture_layout.addWidget(self.clear_live_btn)

        # Trennlinie
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        live_capture_layout.addWidget(sep)

        # Video-Decode Toggle-Button
        self._video_decode_btn = QPushButton("🎬 Video-Decode")
        self._video_decode_btn.setCheckable(True)
        self._video_decode_btn.setStyleSheet(
            "QPushButton:checked { background-color: #1976D2; color: white; font-weight: bold; }"
        )
        self._video_decode_btn.toggled.connect(self._toggle_video_decode)
        self._video_decode_btn.setEnabled(False)
        live_capture_layout.addWidget(self._video_decode_btn)

        # Protokoll-Dropdown (QPushButton + QMenu — Wayland-kompatibel)
        live_capture_layout.addWidget(QLabel("Protokoll:"))
        self._video_protocol_btn = QPushButton("Auto")
        self._video_protocol_btn.setMinimumWidth(100)
        self._video_protocol_btn.setStyleSheet("text-align: left; padding: 3px 8px;")
        self._video_protocol_menu = QMenu(self)
        self._video_protocol_btn.setMenu(self._video_protocol_menu)
        self._video_protocol_index = 0
        _proto_items = [
            "Auto", "PLP/TECMP (GMSL)", "PLP/TECMP (FPD-Link)",
            "PLP/TECMP \u2192 RTP",
            "RTP MJPEG", "RTP H.264", "IEEE 1722 AVTP", "GigE Vision (GVSP)",
            "CSI-2 (0x2090)"
        ]
        for i, label in enumerate(_proto_items):
            action = self._video_protocol_menu.addAction(label)
            action.triggered.connect(lambda checked, idx=i, lbl=label: self._on_video_protocol_selected(idx, lbl))
        live_capture_layout.addWidget(self._video_protocol_btn)

        # Daten-Anzeige Pause/Fortsetzen Button
        self._packet_display_btn = QPushButton("▶ Daten")
        self._packet_display_btn.setCheckable(True)
        self._packet_display_btn.setChecked(False)  # Standard: pausiert
        self._packet_display_btn.setToolTip("Paketanzeige starten/stoppen (spart CPU/RAM)")
        self._packet_display_btn.setStyleSheet(
            "QPushButton { background-color: #757575; color: white; padding: 3px 8px; }"
            "QPushButton:checked { background-color: #2E7D32; color: white; font-weight: bold; }"
        )
        self._packet_display_btn.toggled.connect(self._toggle_packet_display)
        live_capture_layout.addWidget(self._packet_display_btn)

        # Trennlinie
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        live_capture_layout.addWidget(sep2)

        # Ansicht-Umschalter: Paketanzeige / Video-Einstellungen
        live_capture_layout.addWidget(QLabel("Ansicht:"))
        self._view_mode_btn = QPushButton("Paketanzeige")
        self._view_mode_btn.setMinimumWidth(160)
        self._view_mode_btn.setStyleSheet("text-align: left; padding: 3px 8px;")
        self._view_mode_menu = QMenu(self)
        self._view_mode_btn.setMenu(self._view_mode_menu)
        self._view_mode_index = 0  # 0 = Paketanzeige, 1 = Video-Einstellungen
        _view_items = ["Paketanzeige", "Video-Einstellungen"]
        for i, label in enumerate(_view_items):
            action = self._view_mode_menu.addAction(label)
            action.triggered.connect(
                lambda checked, idx=i, lbl=label: self._on_view_mode_selected(idx, lbl))
        live_capture_layout.addWidget(self._view_mode_btn)

        self.live_capture_widget.hide()  # Zunächst versteckt
        layout.addWidget(self.live_capture_widget)

        # ── Logger-Fernsteuerung: Base-URL + OAuth2 ──
        self._create_logger_control_rows(layout)

        # Netzwerk-Speed Widget (ein-/ausklappbar)
        self.net_speed_widget = QWidget()
        net_speed_main_layout = QVBoxLayout(self.net_speed_widget)
        net_speed_main_layout.setContentsMargins(0, 0, 0, 0)
        net_speed_main_layout.setSpacing(2)

        self._net_speed_toggle_btn = QPushButton("📊 Netzwerk-Durchsatz ▼")
        self._net_speed_toggle_btn.setStyleSheet(
            "text-align: left; padding: 4px 8px; font-weight: bold;"
        )
        self._net_speed_toggle_btn.setFlat(True)
        self._net_speed_toggle_btn.clicked.connect(self._toggle_net_speed)
        net_speed_main_layout.addWidget(self._net_speed_toggle_btn)

        self._net_speed_content = QGroupBox()
        self._net_speed_content.setStyleSheet("QGroupBox { padding: 4px; margin: 0px; }")
        self._net_speed_content_layout = QVBoxLayout(self._net_speed_content)
        self._net_speed_content_layout.setContentsMargins(8, 4, 8, 4)
        self._net_speed_content_layout.setSpacing(2)

        # Gesamt-Zeile
        total_row = QHBoxLayout()
        total_name = QLabel("Gesamt:")
        total_name.setFixedWidth(72)
        total_name.setFont(QFont("Consolas", 9))
        self._net_speed_total_rx = QLabel("↓ 0 B/s")
        self._net_speed_total_rx.setFont(QFont("Consolas", 9))
        self._net_speed_total_rx.setStyleSheet("color: #2e7d32;")
        self._net_speed_total_rx.setFixedWidth(84)
        self._net_speed_total_tx = QLabel("↑ 0 B/s")
        self._net_speed_total_tx.setFont(QFont("Consolas", 9))
        self._net_speed_total_tx.setStyleSheet("color: #1565c0;")
        self._net_speed_total_tx.setFixedWidth(84)
        total_row.addWidget(total_name)
        total_row.addWidget(self._net_speed_total_rx)
        total_row.addWidget(self._net_speed_total_tx)
        total_row.addStretch()
        self._net_speed_content_layout.addLayout(total_row)

        # Container für dynamische Interface-Zeilen
        self._net_speed_iface_container = QVBoxLayout()
        self._net_speed_content_layout.addLayout(self._net_speed_iface_container)

        net_speed_main_layout.addWidget(self._net_speed_content)
        net_speed_main_layout.addStretch(1)

        self._net_speed_expanded = True
        self._net_speed_labels: Dict[str, Tuple[QLabel, QLabel, QLabel]] = {}
        self._prev_net_stats: Dict[str, Tuple[int, int]] = {}

        self._net_speed_timer = QTimer()
        self._net_speed_timer.timeout.connect(self._update_net_speed)

        self.net_speed_widget.hide()
        # Wird im top_splitter neben der Paketliste platziert

        # Fortschrittsbalken
        self.progress_bar = QProgressBar()
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Haupt-Splitter (vertikal)
        main_splitter = QSplitter(Qt.Orientation.Vertical)

        # Oberer Bereich: Paketliste (Model/View)
        self.packet_model = PacketTableModel(self)
        self.packet_table = QTableView()
        self.packet_table.setModel(self.packet_model)
        self.packet_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.packet_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.packet_table.selectionModel().selectionChanged.connect(self._on_packet_selected)
        self.packet_table.setAlternatingRowColors(True)
        self.packet_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self._show_packet_context_menu)

        # Spaltenbreiten
        header = self.packet_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        header.resizeSection(6, 180)  # Info-Spalte schmaler

        # ── Video-Einstellungen-Panel (umschaltbar mit Paketliste) ──
        self._video_settings_widget = QWidget()
        vs_layout = QVBoxLayout(self._video_settings_widget)
        vs_layout.setContentsMargins(0, 0, 0, 0)
        vs_layout.setSpacing(0)

        # QTabWidget fuer per-Stream Tabs (wie Bildvorschau)
        self._vs_tabs = QTabWidget()
        self._vs_tabs.setStyleSheet(
            "QTabBar::tab { min-width: 100px; padding: 6px 12px; }"
        )

        # Platzhalter-Tab wenn keine Streams erkannt
        self._vs_placeholder = QLabel(
            "Keine Video-Streams erkannt.\n"
            "Starten Sie Video-Decode, um Streams zu erkennen."
        )
        self._vs_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._vs_placeholder.setStyleSheet("color: #888; font-size: 12px; padding: 20px;")
        self._vs_tabs.addTab(self._vs_placeholder, "Video-Einstellungen")

        vs_layout.addWidget(self._vs_tabs)

        # Datenstruktur fuer Stream-Controls
        self._vs_stream_controls: Dict[int, dict] = {}  # stream_id → {tab, r_slider, b_slider, mode_btn}

        self._video_settings_widget.hide()  # Initial versteckt

        # ── PLP Counter Monitor Panel ──
        self._counter_widget = QWidget()
        counter_main_layout = QVBoxLayout(self._counter_widget)
        counter_main_layout.setContentsMargins(0, 0, 0, 0)
        counter_main_layout.setSpacing(2)

        self._counter_toggle_btn = QPushButton("🔢 PLP Counter ▼")
        self._counter_toggle_btn.setStyleSheet(
            "text-align: left; padding: 4px 8px; font-weight: bold;"
        )
        self._counter_toggle_btn.setFlat(True)
        self._counter_toggle_btn.clicked.connect(self._toggle_counter_panel)
        counter_main_layout.addWidget(self._counter_toggle_btn)

        self._counter_content = QGroupBox()
        self._counter_content.setStyleSheet("QGroupBox { padding: 4px; margin: 0px; }")
        self._counter_content_layout = QVBoxLayout(self._counter_content)
        self._counter_content_layout.setContentsMargins(4, 4, 4, 4)
        self._counter_content_layout.setSpacing(3)

        # Dynamisch erzeugte Interface-Zeilen (werden bei stats_updated befuellt)
        self._counter_labels: Dict[str, Tuple[QLabel, QLabel]] = {}  # iface → (header, value)
        self._counter_iface_container = QVBoxLayout()
        self._counter_content_layout.addLayout(self._counter_iface_container)

        # Seit-Zeile
        self._counter_since_label = QLabel("Seit: —")
        self._counter_since_label.setFont(QFont("Consolas", 8))
        self._counter_since_label.setStyleSheet("color: #666;")
        self._counter_content_layout.addWidget(self._counter_since_label)

        # Gap-Analyse Anzeige (Einzelkamera-Modus, step=1)
        self._counter_gap_label = QLabel("")
        self._counter_gap_label.setFont(QFont("Consolas", 8))
        self._counter_gap_label.setWordWrap(True)
        self._counter_gap_label.setTextFormat(Qt.TextFormat.RichText)
        self._counter_gap_label.setStyleSheet("padding-left: 4px;")
        self._counter_gap_label.hide()  # nur bei step=1 sichtbar
        self._counter_content_layout.addWidget(self._counter_gap_label)

        # Gap-Datei Polling Timer (alle 2s)
        self._gap_poll_timer = QTimer(self)
        self._gap_poll_timer.timeout.connect(self._poll_gap_files)
        self._gap_poll_timer.setInterval(2000)

        # Reset-Button
        self._counter_reset_btn = QPushButton("↺ Zurücksetzen")
        self._counter_reset_btn.setFixedHeight(24)
        self._counter_reset_btn.setFont(QFont("Consolas", 8))
        self._counter_reset_btn.clicked.connect(self._reset_counter_monitor)
        self._counter_content_layout.addWidget(self._counter_reset_btn)

        # Stop/Start-Button
        self._counter_stop_btn = QPushButton("⏹ Counter pausieren")
        self._counter_stop_btn.setFixedHeight(24)
        self._counter_stop_btn.setFont(QFont("Consolas", 8))
        self._counter_stop_btn.setCheckable(True)
        self._counter_stop_btn.setStyleSheet(
            "QPushButton:checked { background-color: #d32f2f; color: white; }"
        )
        self._counter_stop_btn.toggled.connect(self._toggle_counter_monitor_running)
        self._counter_content_layout.addWidget(self._counter_stop_btn)

        # ScrollArea fuer Counter-Inhalt (Gap-Analyse kann lang werden)
        self._counter_scroll = QScrollArea()
        self._counter_scroll.setWidgetResizable(True)
        self._counter_scroll.setWidget(self._counter_content)
        self._counter_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        counter_main_layout.addWidget(self._counter_scroll, 1)

        self._counter_expanded = True
        self._cm_process = None
        self._cm_timer = None
        self._counter_widget.hide()

        # ── Loss Monitor Panel (ECharts WebEngine) ──
        self._loss_monitor_widget = QWidget()
        loss_main_layout = QVBoxLayout(self._loss_monitor_widget)
        loss_main_layout.setContentsMargins(0, 0, 0, 0)
        loss_main_layout.setSpacing(2)

        # Toggle-Button (wie PLP Counter)
        self._loss_toggle_btn = QPushButton("📉 Loss Monitor ▼")
        self._loss_toggle_btn.setStyleSheet(
            "text-align: left; padding: 4px 8px; font-weight: bold;")
        self._loss_toggle_btn.setFlat(True)
        self._loss_toggle_btn.clicked.connect(self._toggle_loss_monitor)
        loss_main_layout.addWidget(self._loss_toggle_btn)

        self._loss_content = QWidget()
        loss_content_layout = QVBoxLayout(self._loss_content)
        loss_content_layout.setContentsMargins(0, 0, 0, 0)
        loss_content_layout.setSpacing(0)

        if WEBENGINE_AVAILABLE:
            self._loss_webview = QWebEngineView()
            self._loss_webview.setContextMenuPolicy(
                Qt.ContextMenuPolicy.NoContextMenu)
            html_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'resources', 'loss_monitor.html')
            if os.path.exists(html_path):
                self._loss_webview.load(QUrl.fromLocalFile(html_path))
            else:
                self._loss_webview.setHtml(
                    '<body style="background:#1e1e1e;color:#e00;">'
                    'loss_monitor.html nicht gefunden</body>')
            loss_content_layout.addWidget(self._loss_webview)
        else:
            _fb = QLabel("WebEngine nicht verfügbar")
            _fb.setAlignment(Qt.AlignmentFlag.AlignCenter)
            _fb.setStyleSheet("color: #888;")
            loss_content_layout.addWidget(_fb)
            self._loss_webview = None

        loss_main_layout.addWidget(self._loss_content, 1)

        # Loss Monitor Daten-State
        self._loss_expanded = True
        self._loss_prev_rx_missed: Dict[str, int] = {}
        self._loss_prev_rx_dropped: Dict[str, int] = {}
        self._loss_prev_rx_errors: Dict[str, int] = {}
        self._loss_prev_rx_crc: Dict[str, int] = {}
        self._loss_prev_rx_packets: Dict[str, int] = {}
        self._loss_prev_rx_bytes: Dict[str, int] = {}
        self._loss_prev_kern_drops: Dict[int, int] = {}  # worker_idx → prev
        self._loss_prev_plp_gaps: Dict[int, int] = {}    # worker_idx → prev
        self._loss_monitor_timer = QTimer()
        self._loss_monitor_timer.timeout.connect(self._update_loss_monitor)
        self._loss_monitor_timer.setInterval(2000)
        self._loss_config_sent = False

        self._loss_monitor_widget.hide()

        # Oberer Bereich: Horizontaler Splitter (Durchsatz | Counter | LossMonitor | Paketliste/Video)
        top_splitter = QSplitter(Qt.Orientation.Horizontal)
        top_splitter.addWidget(self.net_speed_widget)
        top_splitter.addWidget(self._counter_widget)
        top_splitter.addWidget(self._loss_monitor_widget)
        top_splitter.addWidget(self.packet_table)
        top_splitter.addWidget(self._video_settings_widget)

        # Video-Anzeigebereich (initial hidden, rechts neben Paketliste)
        self._video_container = QWidget()
        self._video_container.setMinimumWidth(300)
        video_layout = QVBoxLayout(self._video_container)
        video_layout.setContentsMargins(0, 0, 0, 0)
        video_layout.setSpacing(0)

        # ── Tab-Leiste: Live Video | Live CAN | Live LIN | Live Eth | Live FlexRay ──
        tab_bar_widget = QWidget()
        tab_bar_widget.setStyleSheet('background-color: #1a1a2e;')
        tab_bar_layout = QHBoxLayout(tab_bar_widget)
        tab_bar_layout.setContentsMargins(4, 2, 4, 0)
        tab_bar_layout.setSpacing(2)

        _TAB_STYLE_INACTIVE = (
            'QPushButton { background: #2a2a3e; color: #8888aa;'
            '  border: 1px solid #3a3a5e; border-bottom: none;'
            '  border-radius: 4px 4px 0 0; padding: 4px 12px; font-size: 11px; }'
            'QPushButton:hover { background: #3a3a5e; color: #bbbbdd; }'
        )
        _TAB_STYLE_ACTIVE = (
            'QPushButton { background: #0d47a1; color: #ffffff;'
            '  border: 1px solid #1565c0; border-bottom: none;'
            '  border-radius: 4px 4px 0 0; padding: 4px 12px;'
            '  font-size: 11px; font-weight: bold; }'
        )

        self._live_tab_buttons: List[QPushButton] = []
        self._live_tab_active_style = _TAB_STYLE_ACTIVE
        self._live_tab_inactive_style = _TAB_STYLE_INACTIVE
        _tab_defs = [
            ('🎬 Live Video', '#1976D2'),
            ('🚗 Live CAN', '#4CAF50'),
            ('🔗 Live LIN', '#FF9800'),
            ('🌐 Live Eth', '#9C27B0'),
            ('⚡ Live FlexRay', '#F44336'),
        ]
        for i, (label, _color) in enumerate(_tab_defs):
            btn = QPushButton(label)
            btn.setStyleSheet(_TAB_STYLE_ACTIVE if i == 0 else _TAB_STYLE_INACTIVE)
            btn.clicked.connect(lambda checked, idx=i: self._switch_live_tab(idx))
            tab_bar_layout.addWidget(btn)
            self._live_tab_buttons.append(btn)

        tab_bar_layout.addStretch()
        video_layout.addWidget(tab_bar_widget)

        # ── Toolbar-Stack: jeder Tab hat seine eigene Toolbar ──
        self._live_toolbar_stack = QStackedWidget()
        self._live_toolbar_stack.setFixedHeight(30)

        # --- Toolbar 0: Live Video ---
        video_toolbar = QWidget()
        video_toolbar.setStyleSheet(
            'QWidget { background-color: #1a1a2e; }'
            'QLabel { color: #bbbbdd; background: transparent; border: none; }')
        video_header = QHBoxLayout(video_toolbar)
        video_header.setContentsMargins(4, 0, 4, 2)
        video_header.setSpacing(4)

        self._video_info_label = QLabel("🎬 Live Video")
        self._video_info_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._video_info_label.setFont(QFont("Consolas", 9))
        self._video_info_label.setStyleSheet("color: #1976D2; font-weight: bold; background: transparent;")
        video_header.addWidget(self._video_info_label)
        video_header.addStretch()

        self._video_stream_count = 0

        self._video_pause_btn = QPushButton("⏸ Pause")
        self._video_pause_btn.setCheckable(True)
        self._video_pause_btn.setFixedWidth(80)
        self._video_pause_btn.toggled.connect(self._toggle_video_pause)
        video_header.addWidget(self._video_pause_btn)

        self._video_snapshot_btn = QPushButton("📷 Snapshot")
        self._video_snapshot_btn.setFixedWidth(110)
        self._video_snapshot_btn.clicked.connect(self._save_video_snapshot)
        video_header.addWidget(self._video_snapshot_btn)

        _vsep = QFrame()
        _vsep.setFrameShape(QFrame.Shape.VLine)
        _vsep.setFrameShadow(QFrame.Shadow.Sunken)
        video_header.addWidget(_vsep)

        self._detect_ref_btn = QPushButton("🔍 Referenzbild")
        self._detect_ref_btn.setFixedWidth(130)
        self._detect_ref_btn.clicked.connect(self._load_detection_reference)
        video_header.addWidget(self._detect_ref_btn)

        self._detect_action_btn = QPushButton("Aktion: Zeitstempel loggen")
        self._detect_action_btn.setMinimumWidth(180)
        self._detect_action_menu = QMenu(self)
        self._detect_action_btn.setMenu(self._detect_action_menu)
        _actions = [
            "Zeitstempel loggen",
            "Capture stoppen",
            "Video-Snapshot speichern",
            "Nur Markierung (kein Stopp)",
        ]
        for i, label in enumerate(_actions):
            action = self._detect_action_menu.addAction(label)
            action.triggered.connect(
                lambda checked, idx=i, lbl=label: self._on_detect_action_selected(idx, lbl)
            )
        video_header.addWidget(self._detect_action_btn)

        self._detect_toggle_btn = QPushButton("▶ Erkennung")
        self._detect_toggle_btn.setCheckable(True)
        self._detect_toggle_btn.setFixedWidth(110)
        self._detect_toggle_btn.setEnabled(False)
        self._detect_toggle_btn.setStyleSheet(
            "QPushButton:checked { background-color: #E65100; color: white; font-weight: bold; }"
        )
        self._detect_toggle_btn.toggled.connect(self._toggle_detection)
        video_header.addWidget(self._detect_toggle_btn)

        self._detect_status_label = QLabel("")
        self._detect_status_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._detect_status_label.setFont(QFont("Consolas", 8))
        self._detect_status_label.setMinimumWidth(60)
        video_header.addWidget(self._detect_status_label)

        self._live_toolbar_stack.addWidget(video_toolbar)  # Index 0

        # --- Toolbars 1-4: Bus-Ansichten (CAN, LIN, Eth, FlexRay) ---
        _bus_defs = [
            ('CAN', '#4CAF50', '🚗'),
            ('LIN', '#FF9800', '🔗'),
            ('Ethernet', '#9C27B0', '🌐'),
            ('FlexRay', '#F44336', '⚡'),
        ]
        self._bus_pause_btns: List[QPushButton] = []
        for bus_name, bus_color, bus_icon in _bus_defs:
            bus_tb = QWidget()
            bus_tb.setStyleSheet(
                'QWidget { background-color: #1a1a2e; }'
                'QLabel { color: #bbbbdd; background: transparent; border: none; }')
            bus_h = QHBoxLayout(bus_tb)
            bus_h.setContentsMargins(4, 0, 4, 2)
            bus_h.setSpacing(4)

            bus_lbl = QLabel(f"{bus_icon} Live {bus_name}")
            bus_lbl.setFont(QFont("Consolas", 9))
            bus_lbl.setStyleSheet(
                f"color: {bus_color}; font-weight: bold; background: transparent;")
            bus_h.addWidget(bus_lbl)
            bus_h.addStretch()

            bus_pause = QPushButton("⏸ Pause")
            bus_pause.setCheckable(True)
            bus_pause.setFixedWidth(100)
            bus_pause.setStyleSheet(
                "QPushButton { background: #2a2a3e; color: #ddd; border: 1px solid #444;"
                "  border-radius: 3px; padding: 3px 8px; }"
                "QPushButton:checked { background: #2E7D32; color: white; font-weight: bold; }")
            self._bus_pause_btns.append(bus_pause)
            bus_h.addWidget(bus_pause)

            self._live_toolbar_stack.addWidget(bus_tb)  # Index 1-4

        video_layout.addWidget(self._live_toolbar_stack)

        # ── Content-Stack: jeder Tab hat seinen eigenen Inhaltsbereich ──
        self._live_content_stack = QStackedWidget()

        # --- Page 0: Live Video (Video-Grid) ---
        self._video_grid_widget = QWidget()
        self._video_grid_layout = QGridLayout(self._video_grid_widget)
        self._video_grid_layout.setContentsMargins(0, 0, 0, 0)
        self._video_grid_layout.setSpacing(2)

        self._video_displays: list = []
        self._video_id_labels: list = []
        self._video_panels: list = []
        for _i in range(4):
            panel = QWidget()
            panel_layout = QVBoxLayout(panel)
            panel_layout.setContentsMargins(0, 0, 0, 0)
            panel_layout.setSpacing(0)

            id_lbl = QLabel("")
            id_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            id_lbl.setFixedHeight(20)
            id_lbl.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
            id_lbl.setStyleSheet(
                "background-color: #1a1a2e; color: #4FC3F7; padding: 2px;")
            panel_layout.addWidget(id_lbl)

            vid_lbl = QLabel()
            vid_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            vid_lbl.setMinimumHeight(100)
            vid_lbl.setStyleSheet(
                "background-color: #000000; color: #555555; font-size: 14px;")
            vid_lbl.setFont(QFont("Consolas", 12))
            panel_layout.addWidget(vid_lbl, 1)

            panel.setVisible(False)
            self._video_displays.append(vid_lbl)
            self._video_id_labels.append(id_lbl)
            self._video_panels.append(panel)

        self._video_panels[0].setVisible(True)
        self._video_displays[0].setText("Kein Video-Signal")
        self._video_display = self._video_displays[0]

        self._video_grid_layout.addWidget(self._video_panels[0], 0, 0, 2, 2)
        self._live_content_stack.addWidget(self._video_grid_widget)  # Index 0

        # --- Pages 1-4: Bus-Ansichten (CAN, LIN, Eth, FlexRay) ---
        self._bus_tables: List[QTableWidget] = []
        _bus_columns = {
            'CAN':      ['Zeit', 'Kanal', 'ID', 'Name', 'DLC', 'Daten', 'Info'],
            'LIN':      ['Zeit', 'Kanal', 'ID', 'Name', 'DLC', 'Daten', 'Prüfsumme'],
            'Ethernet': ['Zeit', 'Src MAC', 'Dst MAC', 'EtherType', 'Protokoll', 'Länge', 'Info'],
            'FlexRay':  ['Zeit', 'Kanal', 'Slot', 'Zyklus', 'DLC', 'Daten', 'Info'],
        }
        for bus_name, _color, _icon in _bus_defs:
            bus_table = QTableWidget()
            bus_table.setColumnCount(7)
            bus_table.setHorizontalHeaderLabels(_bus_columns[bus_name])
            bus_table.setAlternatingRowColors(True)
            bus_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
            bus_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
            bus_table.setFont(QFont("Consolas", 9))
            bus_table.setStyleSheet(
                "QTableWidget { background-color: #0a0a1a; color: #e0e0e0;"
                "  gridline-color: #2a2a3e; }"
                "QTableWidget::item:selected { background-color: #1565c0; }"
                "QHeaderView::section { background: #1a1a2e; color: #8888aa;"
                "  border: 1px solid #2a2a3e; padding: 3px; font-weight: bold; }")
            header = bus_table.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            for col in range(1, 6):
                header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
            bus_table.verticalHeader().setVisible(False)
            bus_table.verticalHeader().setDefaultSectionSize(22)

            self._bus_tables.append(bus_table)
            self._live_content_stack.addWidget(bus_table)  # Index 1-4

        self._current_live_tab = 0
        video_layout.addWidget(self._live_content_stack, 1)

        # Video-Container initial sichtbar (schwarzer Hintergrund)

        self._top_splitter = top_splitter
        main_splitter.addWidget(top_splitter)
        main_splitter.addWidget(self._video_container)

        # Unterer Bereich: Splitter für Details und Hex (initial versteckt)
        self._bottom_splitter = bottom_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Paketdetails (Tree)
        self.detail_tree = QTreeWidget()
        self.detail_tree.setHeaderLabels(["Feld", "Wert"])
        self.detail_tree.setColumnWidth(0, 200)
        self.detail_tree.currentItemChanged.connect(self._on_detail_item_selected)
        bottom_splitter.addWidget(self.detail_tree)

        # Hex-Dump
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)
        self.hex_view.setFont(QFont("Consolas", 10))
        bottom_splitter.addWidget(self.hex_view)

        bottom_splitter.setSizes([400, 400])
        main_splitter.addWidget(bottom_splitter)
        self._bottom_splitter.hide()
        self._main_splitter = main_splitter

        main_splitter.setSizes([105, 595, 0])
        layout.addWidget(main_splitter)

        # Statusleiste
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Bereit")
        status_layout.addWidget(self.status_label)
        self.packet_count_label = QLabel("Pakete: 0")
        status_layout.addWidget(self.packet_count_label, 0, Qt.AlignmentFlag.AlignRight)
        layout.addLayout(status_layout)

    def _open_file(self):
        """Öffnet eine PCAP-Datei."""
        if not SCAPY_AVAILABLE:
            QMessageBox.critical(self, "Fehler", "Scapy ist nicht installiert.\nBitte installieren Sie es mit: pip install scapy")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "PCAP-Datei öffnen",
            "",
            "PCAP-Dateien (*.pcap *.pcapng *.cap);;Alle Dateien (*.*)"
        )

        if file_path:
            self._load_file(file_path)

    def _load_file(self, file_path: str):
        """Lädt eine PCAP-Datei."""
        self.current_file = file_path
        self.packets = PacketStore()
        self.filtered_indices = []
        self._base_time = None
        self.packet_model.clear()
        self.status_label.setText(f"Lade: {os.path.basename(file_path)}...")
        self.progress_bar.show()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)

        self.loader_thread = PacketLoaderThread(file_path)
        self.loader_thread.progress.connect(self._on_load_progress)
        self.loader_thread.file_info_ready.connect(self._on_file_info)
        self.loader_thread.batch_ready.connect(self._on_batch_ready)
        self.loader_thread.finished.connect(self._on_load_finished)
        self.loader_thread.error.connect(self._on_load_error)
        self.loader_thread.start()
        self.file_opened.emit(file_path)

    def _on_load_progress(self, percent: int):
        """Aktualisiert den Fortschrittsbalken."""
        self.progress_bar.setValue(percent)
        self.status_label.setText(f"Lade: {os.path.basename(self.current_file)}... {percent}%")

    def _on_file_info(self, info: dict):
        """Empfaengt Datei-Metadaten vom Loader-Thread."""
        self.packets._file_path = self.current_file
        self.packets._link_type = info.get('link_type', 1)
        self.packets._is_pcapng = info.get('is_pcapng', False)

    def _on_batch_ready(self, batch_data):
        """Wird aufgerufen, wenn ein Batch von Paket-Metadaten bereit ist."""
        start_idx = len(self.packets)
        summaries = batch_data['summaries']
        color_extras = batch_data['color_extras']
        timestamps = batch_data['timestamps']

        if batch_data.get('pcapng'):
            self.packets.add_batch_pcapng(
                batch_data['raw_list'], timestamps, summaries, color_extras)
        else:
            self.packets.add_batch(
                batch_data['offsets'], batch_data['cap_lens'],
                timestamps, summaries, color_extras)

        batch_len = len(summaries)
        filter_text = self.filter_entry.text().strip().lower() if hasattr(self, 'filter_entry') else ""
        if filter_text:
            new_indices = [start_idx + i for i in range(batch_len)
                          if self._packet_matches_filter_fast(summaries[i], filter_text)]
        else:
            new_indices = list(range(start_idx, start_idx + batch_len))
        self.filtered_indices.extend(new_indices)
        self._append_packets_to_table(new_indices)
        self.packet_count_label.setText(f"Pakete: {len(self.packets)}")
        self.status_label.setText(
            f"Lade: {os.path.basename(self.current_file)}... {len(self.packets)} Pakete"
        )

    def _append_packets_to_table(self, new_indices: list):
        """Hängt neue Pakete an die Tabelle an (Model/View)."""
        if not new_indices:
            return
        # base_time aus dem allerersten Paket bestimmen
        if self._base_time is None and len(self.packets) > 0:
            self._base_time = self.packets.get_timestamp(0)

        display_start = self.packet_model.rowCount()
        row_tuples = []
        color_tuples = []

        for display_row, pkt_idx in enumerate(new_indices, start=display_start):
            if self.packets.is_live:
                pkt = self.packets[pkt_idx]
                zeit = ""
                if hasattr(pkt, 'time') and self._base_time is not None:
                    rel_time = pkt.time - self._base_time
                    zeit = f"{rel_time:.6f}"
                src, dst, proto, info = self._get_packet_info(pkt)
                pkt_len = str(len(pkt))
                packet_data = self._extract_packet_color_data(pkt, proto, info)
            else:
                summary = self.packets.get_summary(pkt_idx)
                src, dst, proto, info, raw_len = summary
                pkt_len = str(raw_len)
                ts = self.packets.get_timestamp(pkt_idx)
                zeit = f"{ts - self._base_time:.6f}" if self._base_time is not None else ""
                color_extra = self.packets.get_color_extra(pkt_idx)
                packet_data = self._extract_packet_color_data_fast(src, dst, proto, info, color_extra)

            row_tuples.append((str(display_row + 1), zeit, src, dst, proto, pkt_len, info))
            fg, bg = self._color_rules_manager.evaluate(packet_data)
            color_tuples.append((fg, bg))

        self.packet_model.append_rows(row_tuples, color_tuples)

    def _on_load_finished(self):
        """Wird aufgerufen, wenn das Laden abgeschlossen ist."""
        self.progress_bar.hide()
        self.status_label.setText(f"Geladen: {os.path.basename(self.current_file)}")
        self.packet_count_label.setText(f"Pakete: {len(self.packets)}")

    def _on_load_error(self, error: str):
        """Wird aufgerufen, wenn ein Fehler auftritt."""
        self.progress_bar.hide()
        self.status_label.setText("Fehler beim Laden")
        QMessageBox.critical(self, "Fehler", f"Fehler beim Laden der Datei:\n{error}")

    def _update_packet_table(self):
        """Aktualisiert die Paketliste (für Filter)."""
        base_time = None
        row_tuples = []
        color_tuples = []

        for i, pkt_idx in enumerate(self.filtered_indices):
            if self.packets.is_live:
                pkt = self.packets[pkt_idx]
                zeit = ""
                if hasattr(pkt, 'time'):
                    if base_time is None:
                        base_time = pkt.time
                    rel_time = pkt.time - base_time
                    zeit = f"{rel_time:.6f}"
                src, dst, proto, info = self._get_packet_info(pkt)
                pkt_len = str(len(pkt))
                packet_data = self._extract_packet_color_data(pkt, proto, info)
            else:
                summary = self.packets.get_summary(pkt_idx)
                src, dst, proto, info, raw_len = summary
                pkt_len = str(raw_len)
                ts = self.packets.get_timestamp(pkt_idx)
                if base_time is None:
                    base_time = ts
                zeit = f"{ts - base_time:.6f}"
                color_extra = self.packets.get_color_extra(pkt_idx)
                packet_data = self._extract_packet_color_data_fast(src, dst, proto, info, color_extra)

            row_tuples.append((str(self._total_trimmed + pkt_idx + 1), zeit, src, dst, proto, pkt_len, info))
            fg, bg = self._color_rules_manager.evaluate(packet_data)
            color_tuples.append((fg, bg))

        self.packet_model.reset_with_data(row_tuples, color_tuples)

    def _extract_packet_color_data(self, pkt, proto: str, info: str) -> Dict[str, Any]:
        """Extrahiert Paketdaten fuer die Farbregeln-Auswertung."""
        data = {
            'protocol': proto,
            'info': info,
            'src': '',
            'dst': '',
            'uds_sid': None,
            'uds_nrc': None,
            'uds_positive_response': False,
            'doip_type': None,
            'someip_message_type': None,
            'someip_return_code': None,
        }

        if not SCAPY_AVAILABLE:
            return data

        # DLT 148: effektives Paket verwenden
        pkt = self._get_effective_pkt(pkt)

        # IP-Adressen
        if IP in pkt:
            data['src'] = pkt[IP].src
            data['dst'] = pkt[IP].dst

        # DoIP-Daten extrahieren
        if TCP in pkt and Raw in pkt:
            tcp = pkt[TCP]
            if tcp.sport == 13400 or tcp.dport == 13400:
                raw_data = bytes(pkt[Raw].load)
                if len(raw_data) >= 8:
                    payload_type = int.from_bytes(raw_data[2:4], 'big')
                    data['doip_type'] = payload_type

                    # UDS-Daten aus DoIP Diagnostic Message extrahieren
                    if payload_type == 0x8001 and len(raw_data) > 12:
                        uds_data = raw_data[12:]
                        if uds_data:
                            sid = uds_data[0]
                            data['uds_sid'] = sid

                            # Negative Response (0x7F)
                            if sid == 0x7F and len(uds_data) >= 3:
                                data['uds_nrc'] = uds_data[2]

                            # Positive Response (SID | 0x40)
                            elif sid & 0x40:
                                data['uds_positive_response'] = True

        # SOME/IP-Daten extrahieren
        if UDP in pkt and Raw in pkt:
            udp = pkt[UDP]
            if udp.sport == 30490 or udp.dport == 30490 or \
               (udp.sport >= 30000 and udp.sport <= 32000) or \
               (udp.dport >= 30000 and udp.dport <= 32000):
                raw_data = bytes(pkt[Raw].load)
                if len(raw_data) >= 16:
                    message_type = raw_data[14]
                    return_code = raw_data[15]
                    data['someip_message_type'] = message_type
                    data['someip_return_code'] = return_code

        return data

    def _extract_packet_color_data_fast(self, src: str, dst: str, proto: str, info: str, color_extra: dict) -> Dict[str, Any]:
        """Extrahiert Paketdaten fuer Farbregeln aus Summary-Daten (ohne Scapy)."""
        return {
            'protocol': proto,
            'info': info,
            'src': src.split(':')[0] if ':' in src else src,
            'dst': dst.split(':')[0] if ':' in dst else dst,
            'uds_sid': None,
            'uds_nrc': color_extra.get('uds_nrc'),
            'uds_positive_response': color_extra.get('uds_positive_response', False),
            'doip_type': color_extra.get('doip_type'),
            'someip_message_type': color_extra.get('someip_message_type'),
            'someip_return_code': color_extra.get('someip_return_code'),
        }

    def _show_color_rules_dialog(self):
        """Oeffnet den Farbregeln-Dialog."""
        dialog = ColorRulesDialog(self._color_rules_manager, self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Tabelle mit neuen Farben aktualisieren
            self._update_packet_table()

    def _parse_dlt148_ethernet(self, raw_data: bytes):
        """Versucht eingebetteten Ethernet-Frame in DLT 148 (TECMP) Paketen zu finden.

        DLT 148 Pakete haben einen 12-Byte-Header gefolgt von einem Ethernet-Frame.
        Gibt (offset, Ether-Paket) zurück oder (None, None) wenn kein Ethernet gefunden.
        """
        if not SCAPY_AVAILABLE or len(raw_data) < 26:
            return None, None
        # Prüfe ob bei Offset 12 ein gültiger EtherType liegt
        ethertype = int.from_bytes(raw_data[24:26], 'big')
        if ethertype in (0x0800, 0x86DD, 0x0806, 0x8100, 0x99FE):
            try:
                eth_pkt = Ether(raw_data[12:])
                return 12, eth_pkt
            except Exception:
                pass
        return None, None

    def _get_packet_info(self, pkt: Packet) -> tuple:
        """Extrahiert Paketinformationen."""
        src = ""
        dst = ""
        proto = "Unknown"
        info = ""

        # DLT 148 (TECMP): Raw-Pakete mit eingebettetem Ethernet bei Offset 12
        if not (Ether in pkt or IP in pkt) and Raw in pkt:
            raw_data = bytes(pkt)
            offset, eth_pkt = self._parse_dlt148_ethernet(raw_data)
            if eth_pkt is not None:
                # Rekursiv die eingebetteten Schichten auswerten
                src, dst, proto, info = self._get_packet_info(eth_pkt)
                # TECMP-Header-Info voranstellen
                if len(raw_data) >= 12:
                    device_id = int.from_bytes(raw_data[0:2], 'big')
                    if not info:
                        info = f"[TECMP Dev:0x{device_id:04X}]"
                return src, dst, proto, info

        if Ether in pkt:
            src = pkt[Ether].src
            dst = pkt[Ether].dst
            proto = "Ethernet"

            # PLP/TECMP via EtherType
            if pkt[Ether].type == TECMPDecoder.TECMP_ETHERTYPE:
                proto = "PLP/TECMP"
                if Raw in pkt:
                    tecmp_info = self._get_tecmp_info(bytes(pkt[Raw].load))
                    if tecmp_info:
                        info = tecmp_info
                return src, dst, proto, info

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "IP"

        if TCP in pkt:
            tcp = pkt[TCP]
            src = f"{src}:{tcp.sport}"
            dst = f"{dst}:{tcp.dport}"
            proto = "TCP"
            info = f"{tcp.sport} → {tcp.dport} [{self._get_tcp_flags(tcp)}]"

            # DoIP Erkennung
            if tcp.sport == 13400 or tcp.dport == 13400:
                proto = "DoIP"
                if Raw in pkt:
                    doip_info = self._get_doip_info(bytes(pkt[Raw].load))
                    if doip_info:
                        info = doip_info

            # Bekannte TCP-Applikationsprotokolle (Port-basiert)
            elif tcp.sport == 80 or tcp.dport == 80:
                proto = "HTTP"
            elif tcp.sport == 443 or tcp.dport == 443:
                proto = "TLS"
            elif tcp.sport == 53 or tcp.dport == 53:
                proto = "DNS"
            elif tcp.sport == 22 or tcp.dport == 22:
                proto = "SSH"
            elif tcp.sport == 445 or tcp.dport == 445:
                proto = "SMB"
            elif tcp.sport == 139 or tcp.dport == 139:
                proto = "NetBIOS-SSN"
            elif tcp.sport == 3389 or tcp.dport == 3389:
                proto = "RDP"

        elif UDP in pkt:
            udp = pkt[UDP]
            src = f"{src}:{udp.sport}"
            dst = f"{dst}:{udp.dport}"
            proto = "UDP"
            info = f"{udp.sport} → {udp.dport}"
            sports_dports = {udp.sport, udp.dport}

            # SOME/IP Erkennung (typische Ports: 30490-30501)
            if 30490 <= udp.sport <= 30510 or 30490 <= udp.dport <= 30510:
                proto = "SOME/IP"
                if Raw in pkt:
                    someip_info = self._get_someip_info(bytes(pkt[Raw].load))
                    if someip_info:
                        info = someip_info

            # PLP/TECMP via UDP
            elif udp.sport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT or udp.dport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT:
                proto = "PLP/TECMP"
                if Raw in pkt:
                    tecmp_info = self._get_tecmp_info(bytes(pkt[Raw].load))
                    if tecmp_info:
                        info = tecmp_info

            # Bekannte UDP-Applikationsprotokolle (Port-basiert)
            elif sports_dports & {67, 68}:
                proto = "DHCP"
                info = "DHCP Discover/Offer/Request/ACK"
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if len(payload) > 0:
                        op = payload[0]
                        info = "DHCP Request (Boot Request)" if op == 1 else "DHCP Reply (Boot Reply)" if op == 2 else info
            elif sports_dports & {137}:
                proto = "NBNS"
                info = f"NBNS Name Query {udp.sport} → {udp.dport}"
            elif sports_dports & {138}:
                proto = "BROWSER"
                info = f"Browser Protocol {udp.sport} → {udp.dport}"
            elif sports_dports & {53}:
                proto = "DNS"
                info = f"DNS Query/Response {udp.sport} → {udp.dport}"
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    if len(payload) >= 4:
                        flags = (payload[2] << 8) | payload[3]
                        info = "DNS Response" if flags & 0x8000 else "DNS Query"
            elif sports_dports & {5353}:
                proto = "mDNS"
                info = f"Multicast DNS {udp.sport} → {udp.dport}"
            elif sports_dports & {1900}:
                proto = "SSDP"
                info = f"SSDP {udp.sport} → {udp.dport}"
                if Raw in pkt:
                    try:
                        first_line = bytes(pkt[Raw].load).split(b"\r\n")[0].decode("utf-8", errors="replace")
                        info = first_line
                    except Exception:
                        pass
            elif sports_dports & {5355}:
                proto = "LLMNR"
                info = f"Link-Local Multicast Name Resolution {udp.sport} → {udp.dport}"
            elif sports_dports & {161, 162}:
                proto = "SNMP"
                info = f"SNMP {udp.sport} → {udp.dport}"
            elif sports_dports & {123}:
                proto = "NTP"
                info = f"Network Time Protocol {udp.sport} → {udp.dport}"
            elif sports_dports & {514}:
                proto = "Syslog"
                info = f"Syslog {udp.sport} → {udp.dport}"

        elif ICMP in pkt:
            proto = "ICMP"
            icmp = pkt[ICMP]
            info = f"Type: {icmp.type}, Code: {icmp.code}"

        return src, dst, proto, info

    def _get_tcp_flags(self, tcp) -> str:
        """Gibt TCP-Flags als String zurück."""
        flags = []
        if tcp.flags.S:
            flags.append("SYN")
        if tcp.flags.A:
            flags.append("ACK")
        if tcp.flags.F:
            flags.append("FIN")
        if tcp.flags.R:
            flags.append("RST")
        if tcp.flags.P:
            flags.append("PSH")
        return ", ".join(flags) if flags else ""

    def _get_doip_info(self, data: bytes) -> str:
        """Extrahiert DoIP-Info."""
        if len(data) < 8:
            return ""
        payload_type = int.from_bytes(data[2:4], 'big')
        return DoIPDecoder.PAYLOAD_TYPES.get(payload_type, f"Type: 0x{payload_type:04X}")

    def _get_someip_info(self, data: bytes) -> str:
        """Extrahiert SOME/IP-Info."""
        if len(data) < 16:
            return ""
        service_id = int.from_bytes(data[0:2], 'big')
        method_id = int.from_bytes(data[2:4], 'big')
        message_type = data[14]
        msg_type_str = SOMEIPDecoder.MESSAGE_TYPES.get(message_type, "")
        return f"Service: 0x{service_id:04X}, Method: 0x{method_id:04X} [{msg_type_str}]"

    def _get_tecmp_info(self, data: bytes) -> str:
        """Extrahiert PLP/TECMP-Info."""
        if len(data) < 12:
            return ""
        device_id = int.from_bytes(data[0:2], 'big')
        msg_type = data[5]
        data_type = int.from_bytes(data[6:8], 'big')
        msg_type_str = TECMPDecoder.MESSAGE_TYPES.get(msg_type, f"0x{msg_type:02X}")
        data_type_str = TECMPDecoder.DATA_TYPES.get(data_type, f"0x{data_type:04X}")
        info = f"Device: 0x{device_id:04X}, {msg_type_str}, {data_type_str}"
        # CAN-ID aus erstem Payload Entry extrahieren
        if data_type in (0x0001, 0x0002, 0x0003) and len(data) > 12 + 16 + 4:
            can_id_raw = int.from_bytes(data[28:32], 'big')
            can_id = can_id_raw & 0x1FFFFFFF
            info += f" [ID: 0x{can_id:03X}]"
        return info

    def _on_packet_selected(self):
        """Wird aufgerufen, wenn ein Paket ausgewählt wird."""
        indexes = self.packet_table.selectionModel().selectedRows()
        if not indexes:
            return

        row = indexes[0].row()
        if row < len(self.filtered_indices):
            pkt_idx = self.filtered_indices[row]
            pkt = self.packets[pkt_idx]  # Lazy Load von Disk bei File-Mode
            self._current_pkt_bytes = bytes(pkt)
            self._current_is_dlt148 = not (Ether in pkt or IP in pkt) and Raw in pkt
            self._show_packet_details(pkt)
            self._show_hex_dump(pkt)

            # Timestamp für Time-Sync extrahieren und Signal emittieren
            ts = self.packets.get_timestamp(pkt_idx)
            if ts > 0:
                self.packetTimestampSelected.emit(ts)

    def scroll_to_timestamp(self, timestamp: float, emit_signal: bool = True):
        """Scrollt zum Paket mit dem nächsten Timestamp (für Time-Sync).

        Args:
            timestamp: Unix-Timestamp in Sekunden
            emit_signal: Ob packetTimestampSelected emittiert werden soll
        """
        if not self.filtered_indices:
            return

        # Nächstes Paket zum Timestamp finden
        best_row = 0
        best_diff = float('inf')

        for i, pkt_idx in enumerate(self.filtered_indices):
            ts = self.packets.get_timestamp(pkt_idx)
            diff = abs(ts - timestamp)
            if diff < best_diff:
                best_diff = diff
                best_row = i

        # Zur Zeile scrollen und auswählen
        if not emit_signal:
            self.packet_table.blockSignals(True)

        self.packet_table.selectRow(best_row)
        self.packet_table.scrollTo(
            self.packet_model.index(best_row, 0),
            QTableView.ScrollHint.PositionAtCenter
        )

        if not emit_signal:
            self.packet_table.blockSignals(False)
            # Details trotzdem anzeigen
            if best_row < len(self.filtered_indices):
                pkt_idx = self.filtered_indices[best_row]
                pkt = self.packets[pkt_idx]
                self._current_pkt_bytes = bytes(pkt)
                self._current_is_dlt148 = not (Ether in pkt or IP in pkt) and Raw in pkt
                self._show_packet_details(pkt)
                self._show_hex_dump(pkt)

    # ── Hilfs-Methoden für Detail-Tree mit Byte-Ranges ──────────────────

    def _field_item(self, name: str, value: str, byte_start: int, byte_end: int) -> QTreeWidgetItem:
        """Erzeugt ein QTreeWidgetItem mit gespeicherter Byte-Range (für Hex-Highlighting)."""
        item = QTreeWidgetItem([name, value])
        item.setData(0, Qt.ItemDataRole.UserRole, (byte_start, byte_end))
        return item

    def _on_detail_item_selected(self, current, previous):
        """Wird aufgerufen wenn ein Feld im Detail-Tree angeklickt wird → Hex-Highlight."""
        if current is None or not self._current_pkt_bytes:
            return
        byte_range = current.data(0, Qt.ItemDataRole.UserRole)
        if byte_range and isinstance(byte_range, tuple) and len(byte_range) == 2:
            self._show_hex_dump_html(self._current_pkt_bytes, byte_range)
        else:
            self._show_hex_dump_html(self._current_pkt_bytes, None)

    def _add_decoder_fields(self, parent: QTreeWidgetItem, fields: list,
                            field_map: dict, payload_offset: int):
        """Mappt Decoder-Felder auf Byte-Offsets und fügt sie als Kinder hinzu.

        Args:
            parent: Eltern-TreeWidgetItem
            fields: Liste von (field_name, value) Tupeln
            field_map: Dict {field_name: (rel_start, rel_end)} relative Byte-Offsets
            payload_offset: Absoluter Offset des Payload-Beginns im Paket
        """
        for field_name, value in fields:
            if field_name in field_map:
                rs, re = field_map[field_name]
                parent.addChild(self._field_item(field_name, value, payload_offset + rs, payload_offset + re))
            else:
                parent.addChild(QTreeWidgetItem([field_name, value]))

    # ── Paketdetails anzeigen ─────────────────────────────────────────────

    def _show_packet_details(self, pkt: Packet):
        """Zeigt Paketdetails im Tree an."""
        self.detail_tree.clear()

        # DLT 148 (TECMP): Raw-Pakete mit 12-Byte-Header + eingebettetem Ethernet
        if not (Ether in pkt or IP in pkt) and Raw in pkt:
            raw_data = bytes(pkt)
            offset, eth_pkt = self._parse_dlt148_ethernet(raw_data)
            if offset is not None and len(raw_data) >= 12:
                device_id = int.from_bytes(raw_data[0:2], 'big')
                counter = int.from_bytes(raw_data[2:4], 'big')
                version = raw_data[4]
                msg_type = raw_data[5]
                data_type = int.from_bytes(raw_data[6:8], 'big')
                flags = raw_data[8:12].hex().upper()
                tecmp_item = QTreeWidgetItem(["TECMP / DLT 148 Header", "12 bytes"])
                tecmp_item.setData(0, Qt.ItemDataRole.UserRole, (0, 12))
                tecmp_item.addChild(self._field_item("Device ID", f"0x{device_id:04X}", 0, 2))
                tecmp_item.addChild(self._field_item("Counter", f"0x{counter:04X}", 2, 4))
                tecmp_item.addChild(self._field_item("Version", f"{version}", 4, 5))
                tecmp_item.addChild(self._field_item("Message Type", f"0x{msg_type:02X}", 5, 6))
                tecmp_item.addChild(self._field_item("Data Type", f"0x{data_type:04X}", 6, 8))
                tecmp_item.addChild(self._field_item("Flags", f"0x{flags}", 8, 12))
                self.detail_tree.addTopLevelItem(tecmp_item)
                tecmp_item.setExpanded(True)
                self._show_packet_details_inner(eth_pkt, base_offset=12)
                return
            elif len(raw_data) >= 12:
                device_id = int.from_bytes(raw_data[0:2], 'big')
                tecmp_item = QTreeWidgetItem(["TECMP / DLT 148 Header", ""])
                tecmp_item.setData(0, Qt.ItemDataRole.UserRole, (0, 12))
                tecmp_item.addChild(self._field_item("Device ID", f"0x{device_id:04X}", 0, 2))
                tecmp_item.addChild(self._field_item("Raw Data", raw_data[12:].hex().upper(), 12, len(raw_data)))
                self.detail_tree.addTopLevelItem(tecmp_item)
                tecmp_item.setExpanded(True)
                return

        self._show_packet_details_inner(pkt, base_offset=0)

    def _show_packet_details_inner(self, pkt, base_offset: int = 0):
        """Zeigt Paketdetails für ein (ggf. eingebettetes) Paket mit Byte-Offsets."""
        off = base_offset  # laufender Offset

        # ── Ethernet II ──────────────────────────────────────────────────
        if Ether in pkt:
            eth_off = off
            eth_item = QTreeWidgetItem(["Ethernet II", f"{pkt[Ether].dst} → {pkt[Ether].src}"])
            eth_item.setData(0, Qt.ItemDataRole.UserRole, (eth_off, eth_off + 14))
            eth_item.addChild(self._field_item("Destination", pkt[Ether].dst, eth_off, eth_off + 6))
            eth_item.addChild(self._field_item("Source", pkt[Ether].src, eth_off + 6, eth_off + 12))
            eth_item.addChild(self._field_item("Type", f"0x{pkt[Ether].type:04X}", eth_off + 12, eth_off + 14))
            self.detail_tree.addTopLevelItem(eth_item)
            eth_item.setExpanded(True)
            off = eth_off + 14

            # PLP/TECMP via EtherType
            if pkt[Ether].type == TECMPDecoder.TECMP_ETHERTYPE and Raw in pkt:
                tecmp_data = bytes(pkt[Raw].load)
                tecmp_result = TECMPDecoder.decode(tecmp_data)
                tecmp_item = QTreeWidgetItem(["PLP/TECMP (Technically Enhanced Capture Module Protocol)", ""])
                tecmp_item.setData(0, Qt.ItemDataRole.UserRole, (off, off + len(tecmp_data)))
                self._add_decoder_fields(tecmp_item, tecmp_result.get("fields", []),
                                         TECMPDecoder.FIELD_MAP if hasattr(TECMPDecoder, 'FIELD_MAP') else {}, off)

                for i, entry in enumerate(tecmp_result.get("entries", [])):
                    entry_item = QTreeWidgetItem([f"Payload Entry {i+1}", ""])
                    for field, value in entry.get("fields", []):
                        entry_item.addChild(QTreeWidgetItem([field, value]))
                    bus_data = entry.get("bus_data")
                    if bus_data:
                        bus_item = QTreeWidgetItem([bus_data["protocol"], ""])
                        for field, value in bus_data.get("fields", []):
                            bus_item.addChild(QTreeWidgetItem([field, value]))
                        entry_item.addChild(bus_item)
                        bus_item.setExpanded(True)
                    if entry.get("payload"):
                        entry_item.addChild(QTreeWidgetItem(["Raw Payload", entry["payload"]]))
                    tecmp_item.addChild(entry_item)
                    entry_item.setExpanded(True)

                self.detail_tree.addTopLevelItem(tecmp_item)
                tecmp_item.setExpanded(True)

        # ── ARP ──────────────────────────────────────────────────────────
        if ARP in pkt:
            arp = pkt[ARP]
            arp_off = off
            opcode_str = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"op={arp.op}"
            arp_item = QTreeWidgetItem(["Address Resolution Protocol", f"({opcode_str})"])
            arp_item.setData(0, Qt.ItemDataRole.UserRole, (arp_off, arp_off + 28))
            arp_item.addChild(self._field_item("Hardware Type", f"0x{arp.hwtype:04X}", arp_off, arp_off + 2))
            arp_item.addChild(self._field_item("Protocol Type", f"0x{arp.ptype:04X}", arp_off + 2, arp_off + 4))
            arp_item.addChild(self._field_item("Hardware Size", str(arp.hwlen), arp_off + 4, arp_off + 5))
            arp_item.addChild(self._field_item("Protocol Size", str(arp.plen), arp_off + 5, arp_off + 6))
            arp_item.addChild(self._field_item("Opcode", f"{arp.op} ({opcode_str})", arp_off + 6, arp_off + 8))
            arp_item.addChild(self._field_item("Sender MAC", str(arp.hwsrc), arp_off + 8, arp_off + 14))
            arp_item.addChild(self._field_item("Sender IP", str(arp.psrc), arp_off + 14, arp_off + 18))
            arp_item.addChild(self._field_item("Target MAC", str(arp.hwdst), arp_off + 18, arp_off + 24))
            arp_item.addChild(self._field_item("Target IP", str(arp.pdst), arp_off + 24, arp_off + 28))
            self.detail_tree.addTopLevelItem(arp_item)
            arp_item.setExpanded(True)
            return  # ARP hat kein IP/TCP/UDP

        # ── IPv4 ─────────────────────────────────────────────────────────
        if IP in pkt:
            ip = pkt[IP]
            ip_off = off
            ihl_bytes = ip.ihl * 4
            proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
            proto_name = proto_map.get(ip.proto, str(ip.proto))
            flags_str = ""
            if ip.flags.DF:
                flags_str += "DF "
            if ip.flags.MF:
                flags_str += "MF "
            flags_str = flags_str.strip() if flags_str else "None"

            ip_item = QTreeWidgetItem(["Internet Protocol Version 4", f"{ip.src} → {ip.dst}"])
            ip_item.setData(0, Qt.ItemDataRole.UserRole, (ip_off, ip_off + ihl_bytes))
            ip_item.addChild(self._field_item("Version", str(ip.version), ip_off, ip_off + 1))
            ip_item.addChild(self._field_item("Header Length", f"{ihl_bytes} bytes ({ip.ihl})", ip_off, ip_off + 1))
            ip_item.addChild(self._field_item("Differentiated Services", f"0x{ip.tos:02X}", ip_off + 1, ip_off + 2))
            ip_item.addChild(self._field_item("Total Length", str(ip.len), ip_off + 2, ip_off + 4))
            ip_item.addChild(self._field_item("Identification", f"0x{ip.id:04X} ({ip.id})", ip_off + 4, ip_off + 6))
            ip_item.addChild(self._field_item("Flags", flags_str, ip_off + 6, ip_off + 8))
            ip_item.addChild(self._field_item("Fragment Offset", str(ip.frag), ip_off + 6, ip_off + 8))
            ip_item.addChild(self._field_item("Time to Live", str(ip.ttl), ip_off + 8, ip_off + 9))
            ip_item.addChild(self._field_item("Protocol", f"{ip.proto} ({proto_name})", ip_off + 9, ip_off + 10))
            ip_item.addChild(self._field_item("Header Checksum", f"0x{ip.chksum:04X}", ip_off + 10, ip_off + 12))
            ip_item.addChild(self._field_item("Source Address", ip.src, ip_off + 12, ip_off + 16))
            ip_item.addChild(self._field_item("Destination Address", ip.dst, ip_off + 16, ip_off + 20))
            self.detail_tree.addTopLevelItem(ip_item)
            ip_item.setExpanded(True)
            off = ip_off + ihl_bytes

        # ── ICMP ─────────────────────────────────────────────────────────
        if ICMP in pkt:
            icmp = pkt[ICMP]
            icmp_off = off
            icmp_type_names = {0: "Echo Reply", 3: "Destination Unreachable",
                               8: "Echo Request", 11: "Time Exceeded"}
            type_name = icmp_type_names.get(icmp.type, f"Type {icmp.type}")
            icmp_item = QTreeWidgetItem(["Internet Control Message Protocol", type_name])
            icmp_item.setData(0, Qt.ItemDataRole.UserRole, (icmp_off, icmp_off + 8))
            icmp_item.addChild(self._field_item("Type", f"{icmp.type} ({type_name})", icmp_off, icmp_off + 1))
            icmp_item.addChild(self._field_item("Code", str(icmp.code), icmp_off + 1, icmp_off + 2))
            icmp_item.addChild(self._field_item("Checksum", f"0x{icmp.chksum:04X}", icmp_off + 2, icmp_off + 4))
            if icmp.type in (0, 8):
                icmp_item.addChild(self._field_item("Identifier", f"0x{icmp.id:04X}", icmp_off + 4, icmp_off + 6))
                icmp_item.addChild(self._field_item("Sequence Number", str(icmp.seq), icmp_off + 6, icmp_off + 8))
            self.detail_tree.addTopLevelItem(icmp_item)
            icmp_item.setExpanded(True)

        # ── TCP ──────────────────────────────────────────────────────────
        if TCP in pkt:
            tcp = pkt[TCP]
            tcp_off = off
            data_offset_bytes = tcp.dataofs * 4 if tcp.dataofs else 20
            tcp_item = QTreeWidgetItem(["Transmission Control Protocol",
                                        f"{tcp.sport} → {tcp.dport} [{self._get_tcp_flags(tcp)}]"])
            tcp_item.setData(0, Qt.ItemDataRole.UserRole, (tcp_off, tcp_off + data_offset_bytes))
            tcp_item.addChild(self._field_item("Source Port", str(tcp.sport), tcp_off, tcp_off + 2))
            tcp_item.addChild(self._field_item("Destination Port", str(tcp.dport), tcp_off + 2, tcp_off + 4))
            tcp_item.addChild(self._field_item("Sequence Number", str(tcp.seq), tcp_off + 4, tcp_off + 8))
            tcp_item.addChild(self._field_item("Acknowledgment Number", str(tcp.ack), tcp_off + 8, tcp_off + 12))
            tcp_item.addChild(self._field_item("Data Offset", f"{data_offset_bytes} bytes ({tcp.dataofs})", tcp_off + 12, tcp_off + 13))
            # Flags als Untergruppe
            flags_item = self._field_item("Flags", f"0x{int(tcp.flags):03X} ({self._get_tcp_flags(tcp)})", tcp_off + 12, tcp_off + 14)
            flag_names = [("URG", tcp.flags.U), ("ACK", tcp.flags.A), ("PSH", tcp.flags.P),
                          ("RST", tcp.flags.R), ("SYN", tcp.flags.S), ("FIN", tcp.flags.F)]
            for fname, fval in flag_names:
                flags_item.addChild(QTreeWidgetItem([f"  {fname}", "Set" if fval else "Not set"]))
            tcp_item.addChild(flags_item)
            tcp_item.addChild(self._field_item("Window Size", str(tcp.window), tcp_off + 14, tcp_off + 16))
            tcp_item.addChild(self._field_item("Checksum", f"0x{tcp.chksum:04X}", tcp_off + 16, tcp_off + 18))
            tcp_item.addChild(self._field_item("Urgent Pointer", str(tcp.urgptr), tcp_off + 18, tcp_off + 20))
            self.detail_tree.addTopLevelItem(tcp_item)
            tcp_item.setExpanded(True)
            off = tcp_off + data_offset_bytes

            # DoIP
            if (tcp.sport == 13400 or tcp.dport == 13400) and Raw in pkt:
                doip_data = bytes(pkt[Raw].load)
                doip_result = DoIPDecoder.decode(doip_data)
                doip_off = off
                doip_item = QTreeWidgetItem(["DoIP (Diagnostics over IP)", ""])
                doip_item.setData(0, Qt.ItemDataRole.UserRole, (doip_off, doip_off + len(doip_data)))
                doip_item.addChild(self._field_item("Version", doip_result.get("fields", [("","")])[0][1] if doip_result.get("fields") else "", doip_off, doip_off + 1))
                doip_item.addChild(self._field_item("Inverse Version", f"0x{doip_data[1]:02X}" if len(doip_data) > 1 else "", doip_off + 1, doip_off + 2))
                if len(doip_data) >= 8:
                    pt = int.from_bytes(doip_data[2:4], 'big')
                    pl = int.from_bytes(doip_data[4:8], 'big')
                    pt_name = DoIPDecoder.PAYLOAD_TYPES.get(pt, f"0x{pt:04X}")
                    doip_item.addChild(self._field_item("Payload Type", f"0x{pt:04X} ({pt_name})", doip_off + 2, doip_off + 4))
                    doip_item.addChild(self._field_item("Payload Length", str(pl), doip_off + 4, doip_off + 8))
                    if pt == 0x8001 and len(doip_data) >= 12:
                        sa = int.from_bytes(doip_data[8:10], 'big')
                        ta = int.from_bytes(doip_data[10:12], 'big')
                        doip_item.addChild(self._field_item("Source Address", f"0x{sa:04X}", doip_off + 8, doip_off + 10))
                        doip_item.addChild(self._field_item("Target Address", f"0x{ta:04X}", doip_off + 10, doip_off + 12))
                # restliche Decoder-Felder (die nicht manuell gemappt wurden)
                for field, value in doip_result.get("fields", [])[4:]:
                    doip_item.addChild(QTreeWidgetItem([field, value]))

                if "uds" in doip_result:
                    uds_item = QTreeWidgetItem(["UDS (Unified Diagnostic Services)", ""])
                    uds_off = doip_off + 12 if len(doip_data) >= 13 else doip_off + 8
                    uds_item.setData(0, Qt.ItemDataRole.UserRole, (uds_off, doip_off + len(doip_data)))
                    for field, value in doip_result["uds"].get("fields", []):
                        uds_item.addChild(QTreeWidgetItem([field, value]))
                    doip_item.addChild(uds_item)
                    uds_item.setExpanded(True)

                self.detail_tree.addTopLevelItem(doip_item)
                doip_item.setExpanded(True)

        # ── UDP ──────────────────────────────────────────────────────────
        elif UDP in pkt:
            udp = pkt[UDP]
            udp_off = off
            udp_item = QTreeWidgetItem(["User Datagram Protocol", f"{udp.sport} → {udp.dport}"])
            udp_item.setData(0, Qt.ItemDataRole.UserRole, (udp_off, udp_off + 8))
            udp_item.addChild(self._field_item("Source Port", str(udp.sport), udp_off, udp_off + 2))
            udp_item.addChild(self._field_item("Destination Port", str(udp.dport), udp_off + 2, udp_off + 4))
            udp_item.addChild(self._field_item("Length", str(udp.len), udp_off + 4, udp_off + 6))
            udp_item.addChild(self._field_item("Checksum", f"0x{udp.chksum:04X}", udp_off + 6, udp_off + 8))
            self.detail_tree.addTopLevelItem(udp_item)
            udp_item.setExpanded(True)
            off = udp_off + 8

            # SOME/IP
            if (30490 <= udp.sport <= 30510 or 30490 <= udp.dport <= 30510) and Raw in pkt:
                someip_data = bytes(pkt[Raw].load)
                someip_off = off
                if len(someip_data) >= 16:
                    sid = int.from_bytes(someip_data[0:2], 'big')
                    mid = int.from_bytes(someip_data[2:4], 'big')
                    slen = int.from_bytes(someip_data[4:8], 'big')
                    cid = int.from_bytes(someip_data[8:10], 'big')
                    sessid = int.from_bytes(someip_data[10:12], 'big')
                    pver = someip_data[12]
                    iver = someip_data[13]
                    mtype = someip_data[14]
                    rcode = someip_data[15]
                    mtype_str = SOMEIPDecoder.MESSAGE_TYPES.get(mtype, f"0x{mtype:02X}")
                    rcode_str = SOMEIPDecoder.RETURN_CODES.get(rcode, f"0x{rcode:02X}") if hasattr(SOMEIPDecoder, 'RETURN_CODES') else f"0x{rcode:02X}"
                    someip_item = QTreeWidgetItem(["SOME/IP", f"Service: 0x{sid:04X}, Method: 0x{mid:04X}"])
                    someip_item.setData(0, Qt.ItemDataRole.UserRole, (someip_off, someip_off + len(someip_data)))
                    someip_item.addChild(self._field_item("Service ID", f"0x{sid:04X}", someip_off, someip_off + 2))
                    someip_item.addChild(self._field_item("Method ID", f"0x{mid:04X}", someip_off + 2, someip_off + 4))
                    someip_item.addChild(self._field_item("Length", str(slen), someip_off + 4, someip_off + 8))
                    someip_item.addChild(self._field_item("Client ID", f"0x{cid:04X}", someip_off + 8, someip_off + 10))
                    someip_item.addChild(self._field_item("Session ID", f"0x{sessid:04X}", someip_off + 10, someip_off + 12))
                    someip_item.addChild(self._field_item("Protocol Version", str(pver), someip_off + 12, someip_off + 13))
                    someip_item.addChild(self._field_item("Interface Version", str(iver), someip_off + 13, someip_off + 14))
                    someip_item.addChild(self._field_item("Message Type", f"0x{mtype:02X} ({mtype_str})", someip_off + 14, someip_off + 15))
                    someip_item.addChild(self._field_item("Return Code", f"0x{rcode:02X} ({rcode_str})", someip_off + 15, someip_off + 16))
                else:
                    someip_result = SOMEIPDecoder.decode(someip_data)
                    someip_item = QTreeWidgetItem(["SOME/IP", ""])
                    for field, value in someip_result.get("fields", []):
                        someip_item.addChild(QTreeWidgetItem([field, value]))
                self.detail_tree.addTopLevelItem(someip_item)
                someip_item.setExpanded(True)

            # PLP/TECMP via UDP
            elif (udp.sport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT or udp.dport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT) and Raw in pkt:
                tecmp_data = bytes(pkt[Raw].load)
                tecmp_result = TECMPDecoder.decode(tecmp_data)
                tecmp_item = QTreeWidgetItem(["PLP/TECMP (Technically Enhanced Capture Module Protocol)", ""])
                tecmp_item.setData(0, Qt.ItemDataRole.UserRole, (off, off + len(tecmp_data)))
                self._add_decoder_fields(tecmp_item, tecmp_result.get("fields", []),
                                         TECMPDecoder.FIELD_MAP if hasattr(TECMPDecoder, 'FIELD_MAP') else {}, off)

                for i, entry in enumerate(tecmp_result.get("entries", [])):
                    entry_item = QTreeWidgetItem([f"Payload Entry {i+1}", ""])
                    for field, value in entry.get("fields", []):
                        entry_item.addChild(QTreeWidgetItem([field, value]))
                    bus_data = entry.get("bus_data")
                    if bus_data:
                        bus_item = QTreeWidgetItem([bus_data["protocol"], ""])
                        for field, value in bus_data.get("fields", []):
                            bus_item.addChild(QTreeWidgetItem([field, value]))
                        entry_item.addChild(bus_item)
                        bus_item.setExpanded(True)
                    if entry.get("payload"):
                        entry_item.addChild(QTreeWidgetItem(["Raw Payload", entry["payload"]]))
                    tecmp_item.addChild(entry_item)
                    entry_item.setExpanded(True)

                self.detail_tree.addTopLevelItem(tecmp_item)
                tecmp_item.setExpanded(True)

        # ── Raw Data ─────────────────────────────────────────────────────
        if Raw in pkt:
            raw_len = len(pkt[Raw].load)
            total_len = len(self._current_pkt_bytes) if self._current_pkt_bytes else off + raw_len
            raw_item = self._field_item("Data", f"{raw_len} bytes", total_len - raw_len, total_len)
            self.detail_tree.addTopLevelItem(raw_item)

    # ── Hex-Dump (HTML-basiert mit Highlighting) ──────────────────────────

    def _show_hex_dump(self, pkt: Packet):
        """Zeigt Hex-Dump des Pakets (Wrapper)."""
        self._show_hex_dump_html(bytes(pkt), None)

    def _show_hex_dump_html(self, data: bytes, highlight_range):
        """Rendert Hex-Dump als HTML mit optionalem Byte-Highlighting.

        Args:
            data: Roh-Bytes des Pakets
            highlight_range: (start, end) Byte-Indizes zum Hervorheben, oder None
        """
        # Theme-Farben
        try:
            from ui.theme import ThemeManager
            p = ThemeManager.instance().get_palette()
            is_dark = p.bg_primary == '#1e1e2e'
        except Exception:
            is_dark = True
        if is_dark:
            bg_color = "#1e1e1e"
            text_color = "#d4d4d4"
            offset_color = "#569cd6"
            hl_color = "#264f78"
        else:
            bg_color = "#ffffff"
            text_color = "#1e1e1e"
            offset_color = "#0550ae"
            hl_color = "#add6ff"

        hl_start = highlight_range[0] if highlight_range else -1
        hl_end = highlight_range[1] if highlight_range else -1

        # DLT 148 Erkennung
        is_dlt148 = self._current_is_dlt148 and len(data) >= 26
        if is_dlt148:
            ethertype = int.from_bytes(data[24:26], 'big')
            is_dlt148 = ethertype in (0x0800, 0x86DD, 0x0806, 0x8100, 0x99FE)

        lines = []
        start = 0

        if is_dlt148:
            # TECMP Header (12 Bytes) als eigene Zeile
            line = self._hex_line_html(data, 0, 12, offset_color, text_color, hl_color, hl_start, hl_end)
            lines.append(line)
            sep = (f'<span style="color:{offset_color}">{"─" * 10}</span>  '
                   f'<span style="color:#666">{"─" * 48}  {"─" * 16}</span>'
                   f'  <span style="color:#888">◄ TECMP Header</span>')
            lines.append(sep)
            start = 12

        for i in range(start, len(data), 16):
            line = self._hex_line_html(data, i, min(i + 16, len(data)), offset_color, text_color, hl_color, hl_start, hl_end)
            lines.append(line)

        html = (f'<pre style="background-color:{bg_color}; color:{text_color}; '
                f'font-family:Consolas,monospace; font-size:10pt; margin:0; padding:4px; '
                f'line-height:1.4;">'
                + "\n".join(lines)
                + '</pre>')
        self.hex_view.setHtml(html)

    def _hex_line_html(self, data: bytes, row_start: int, row_end: int,
                       offset_color: str, text_color: str, hl_color: str,
                       hl_start: int, hl_end: int) -> str:
        """Rendert eine einzelne Hex-Dump-Zeile als HTML mit Byte-Level-Highlighting."""
        # Offset
        parts = [f'<span style="color:{offset_color}">{row_start:08X}</span>  ']

        # Hex-Bytes
        hex_parts = []
        for idx in range(row_start, row_start + 16):
            if idx < row_end:
                b = data[idx]
                if hl_start <= idx < hl_end:
                    hex_parts.append(f'<span style="background-color:{hl_color}">{b:02X}</span>')
                else:
                    hex_parts.append(f'{b:02X}')
            else:
                hex_parts.append('  ')
        parts.append(' '.join(hex_parts))

        # ASCII
        parts.append('  ')
        ascii_parts = []
        for idx in range(row_start, row_start + 16):
            if idx < row_end:
                b = data[idx]
                c = chr(b) if 32 <= b < 127 else '.'
                # HTML-Escape
                if c == '<':
                    c = '&lt;'
                elif c == '>':
                    c = '&gt;'
                elif c == '&':
                    c = '&amp;'
                if hl_start <= idx < hl_end:
                    ascii_parts.append(f'<span style="background-color:{hl_color}">{c}</span>')
                else:
                    ascii_parts.append(c)
        parts.append(''.join(ascii_parts))

        return ''.join(parts)

    def _apply_filter(self):
        """Wendet den Filter an."""
        filter_text = self.filter_entry.text().strip().lower()

        if not filter_text:
            self.filtered_indices = list(range(len(self.packets)))
        elif self.packets.is_live:
            self.filtered_indices = [
                i for i in range(len(self.packets))
                if self._packet_matches_filter(self.packets[i], filter_text)
            ]
        else:
            self.filtered_indices = [
                i for i in range(len(self.packets))
                if self._packet_matches_filter_fast(self.packets.get_summary(i), filter_text)
            ]

        self._update_packet_table()
        self.packet_count_label.setText(f"Pakete: {len(self.filtered_indices)} / {len(self.packets)}")

    def _get_effective_pkt(self, pkt: Packet):
        """Gibt das effektive Paket zurück (ggf. eingebettetes Ethernet aus DLT 148)."""
        if not (Ether in pkt or IP in pkt) and Raw in pkt:
            _, eth_pkt = self._parse_dlt148_ethernet(bytes(pkt))
            if eth_pkt is not None:
                return eth_pkt
        return pkt

    def _packet_matches_filter(self, pkt: Packet, filter_text: str) -> bool:
        """Prüft, ob ein Paket dem Filter entspricht."""
        # Für DLT 148 das eingebettete Paket verwenden
        eff = self._get_effective_pkt(pkt)

        # Protokoll-Filter
        if filter_text == "tcp":
            return TCP in eff
        elif filter_text == "udp":
            return UDP in eff
        elif filter_text == "icmp":
            return ICMP in eff
        elif filter_text == "doip":
            if TCP in eff:
                return eff[TCP].sport == 13400 or eff[TCP].dport == 13400
            return False
        elif filter_text == "someip" or filter_text == "some/ip":
            if UDP in eff:
                return 30490 <= eff[UDP].sport <= 30510 or 30490 <= eff[UDP].dport <= 30510
            return False
        elif filter_text in ("plp", "tecmp", "plp/tecmp"):
            if Ether in eff and eff[Ether].type == TECMPDecoder.TECMP_ETHERTYPE:
                return True
            if UDP in eff:
                return eff[UDP].sport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT or eff[UDP].dport == TECMPDecoder.TECMP_DEFAULT_UDP_PORT
            return False

        # IP-Filter (ip.src==x.x.x.x oder ip.dst==x.x.x.x)
        if filter_text.startswith("ip.src=="):
            ip_addr = filter_text.split("==")[1]
            return IP in eff and eff[IP].src == ip_addr
        elif filter_text.startswith("ip.dst=="):
            ip_addr = filter_text.split("==")[1]
            return IP in eff and eff[IP].dst == ip_addr

        # Port-Filter (tcp.port==x oder udp.port==x)
        if filter_text.startswith("tcp.port=="):
            port = int(filter_text.split("==")[1])
            return TCP in eff and (eff[TCP].sport == port or eff[TCP].dport == port)
        elif filter_text.startswith("udp.port=="):
            port = int(filter_text.split("==")[1])
            return UDP in eff and (eff[UDP].sport == port or eff[UDP].dport == port)

        # Allgemeine Textsuche in Paketinfo
        src, dst, proto, info = self._get_packet_info(pkt)
        search_text = f"{src} {dst} {proto} {info}".lower()
        return filter_text in search_text

    def _packet_matches_filter_fast(self, summary: tuple, filter_text: str) -> bool:
        """Prueft ob ein Paket dem Filter entspricht (aus Summary-Daten, ohne Scapy)."""
        src, dst, proto, info, raw_len = summary
        proto_lower = proto.lower()

        # Protokoll-Filter
        TCP_PROTOS = {"tcp", "doip", "http", "tls", "ssh", "smb", "netbios-ssn", "rdp"}
        UDP_PROTOS = {"udp", "some/ip", "dhcp", "nbns", "browser", "dns", "mdns",
                      "ssdp", "llmnr", "snmp", "ntp", "syslog", "plp/tecmp"}

        if filter_text == "tcp":
            return proto_lower in TCP_PROTOS
        elif filter_text == "udp":
            return proto_lower in UDP_PROTOS
        elif filter_text == "icmp":
            return proto_lower == "icmp"
        elif filter_text == "doip":
            return proto_lower == "doip"
        elif filter_text in ("someip", "some/ip"):
            return proto_lower == "some/ip"
        elif filter_text in ("plp", "tecmp", "plp/tecmp"):
            return proto_lower == "plp/tecmp" or "[tecmp" in info.lower()

        # IP-Filter (ip.src==x.x.x.x oder ip.dst==x.x.x.x)
        if filter_text.startswith("ip.src=="):
            ip_addr = filter_text.split("==")[1]
            src_ip = src.split(':')[0] if ':' in src else src
            return src_ip == ip_addr
        elif filter_text.startswith("ip.dst=="):
            ip_addr = filter_text.split("==")[1]
            dst_ip = dst.split(':')[0] if ':' in dst else dst
            return dst_ip == ip_addr

        # Port-Filter
        if filter_text.startswith("tcp.port=="):
            if proto_lower not in TCP_PROTOS:
                return False
            port = filter_text.split("==")[1]
            src_port = src.split(':')[1] if ':' in src else ""
            dst_port = dst.split(':')[1] if ':' in dst else ""
            return src_port == port or dst_port == port
        elif filter_text.startswith("udp.port=="):
            if proto_lower not in UDP_PROTOS:
                return False
            port = filter_text.split("==")[1]
            src_port = src.split(':')[1] if ':' in src else ""
            dst_port = dst.split(':')[1] if ':' in dst else ""
            return src_port == port or dst_port == port

        # Allgemeine Textsuche
        search_text = f"{src} {dst} {proto} {info}".lower()
        return filter_text in search_text

    def _clear_filter(self):
        """Löscht den Filter."""
        self.filter_entry.clear()
        self.filtered_indices = list(range(len(self.packets)))
        self._update_packet_table()
        self.packet_count_label.setText(f"Pakete: {len(self.packets)}")

    def _show_statistics(self):
        """Zeigt Statistiken an."""
        if len(self.packets) == 0:
            QMessageBox.warning(self, "Warnung", "Keine Pakete geladen")
            return

        # Statistiken sammeln
        protocols = {}
        conversations = {}
        endpoints = {}

        if self.packets.is_live:
            for pkt in self.packets:
                _, _, proto, _ = self._get_packet_info(pkt)
                protocols[proto] = protocols.get(proto, 0) + 1
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    conv = tuple(sorted([src, dst]))
                    conversations[conv] = conversations.get(conv, 0) + 1
                    endpoints[src] = endpoints.get(src, 0) + 1
                    endpoints[dst] = endpoints.get(dst, 0) + 1
        else:
            for i in range(len(self.packets)):
                summary = self.packets.get_summary(i)
                src, dst, proto, info, raw_len = summary
                protocols[proto] = protocols.get(proto, 0) + 1
                # IP extrahieren (ohne Port)
                src_ip = src.split(':')[0] if ':' in src else src
                dst_ip = dst.split(':')[0] if ':' in dst else dst
                if src_ip and dst_ip and src_ip != dst_ip:
                    conv = tuple(sorted([src_ip, dst_ip]))
                    conversations[conv] = conversations.get(conv, 0) + 1
                    endpoints[src_ip] = endpoints.get(src_ip, 0) + 1
                    endpoints[dst_ip] = endpoints.get(dst_ip, 0) + 1

        # Dialog erstellen
        stats_dialog = QMessageBox(self)
        stats_dialog.setWindowTitle("Statistiken")
        stats_dialog.setIcon(QMessageBox.Icon.Information)

        text = f"<b>Gesamtpakete:</b> {len(self.packets)}<br><br>"

        text += "<b>Protokollhierarchie:</b><br>"
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            percent = count / len(self.packets) * 100
            text += f"  {proto}: {count} ({percent:.1f}%)<br>"

        text += "<br><b>Top 5 Konversationen:</b><br>"
        for (src, dst), count in sorted(conversations.items(), key=lambda x: -x[1])[:5]:
            text += f"  {src} ↔ {dst}: {count}<br>"

        text += "<br><b>Top 5 Endpoints:</b><br>"
        for ip, count in sorted(endpoints.items(), key=lambda x: -x[1])[:5]:
            text += f"  {ip}: {count}<br>"

        stats_dialog.setText(text)
        stats_dialog.exec()

    def _show_packet_context_menu(self, pos):
        """Zeigt Kontextmenü für ein Paket."""
        index = self.packet_table.indexAt(pos)
        if not index.isValid():
            return
        row = index.row()
        if row < 0 or row >= len(self.filtered_indices):
            return

        pkt_idx = self.filtered_indices[row]
        menu = QMenu(self)

        # Prüfen ob DoIP-Paket (aus Summary oder Scapy)
        is_doip = False
        if self.packets.is_live:
            pkt = self.packets[pkt_idx]
            if TCP in pkt:
                tcp = pkt[TCP]
                if tcp.sport == 13400 or tcp.dport == 13400:
                    is_doip = True
        else:
            summary = self.packets.get_summary(pkt_idx)
            if summary[2] == "DoIP":
                is_doip = True

        if is_doip:
            follow_action = menu.addAction("Follow DoIP Stream")
            follow_action.triggered.connect(lambda: self._follow_doip_stream(row))

            uds_stream_action = menu.addAction("UDS Sequenz dieses Streams")
            uds_stream_action.triggered.connect(lambda: self._show_uds_sequence_analysis())
            menu.addSeparator()

        filter_action = menu.addAction("Als Filter anwenden")
        filter_action.triggered.connect(lambda: self._apply_filter_from_packet(pkt_idx))

        menu.exec(self.packet_table.viewport().mapToGlobal(pos))

    def _apply_filter_from_packet(self, pkt_idx: int):
        """Wendet einen Filter basierend auf dem ausgewählten Paket an."""
        if self.packets.is_live:
            pkt = self.packets[pkt_idx]
            if IP in pkt:
                self.filter_entry.setText(f"ip.src=={pkt[IP].src}")
                self._apply_filter()
        else:
            summary = self.packets.get_summary(pkt_idx)
            src = summary[0]
            src_ip = src.split(':')[0] if ':' in src else src
            if src_ip:
                self.filter_entry.setText(f"ip.src=={src_ip}")
                self._apply_filter()

    def _follow_doip_stream(self, row: int):
        """Zeigt alle Pakete der gleichen TCP-Verbindung (DoIP Stream)."""
        if row >= len(self.filtered_indices):
            return

        pkt_idx = self.filtered_indices[row]

        # Stream-Key aus Summary oder Scapy extrahieren
        if self.packets.is_live:
            pkt = self.packets[pkt_idx]
            if TCP not in pkt or IP not in pkt:
                return
            src_str = f"{pkt[IP].src}:{pkt[TCP].sport}"
            dst_str = f"{pkt[IP].dst}:{pkt[TCP].dport}"
        else:
            summary = self.packets.get_summary(pkt_idx)
            src_str = summary[0]  # z.B. "192.168.1.10:54321"
            dst_str = summary[1]  # z.B. "192.168.1.20:13400"

        norm_key = tuple(sorted([src_str, dst_str]))

        # Alle Pakete mit gleichem Stream-Key sammeln
        # Vorab-Filter ueber Summaries (nur TCP-basierte Protokolle)
        TCP_PROTOS = {"TCP", "DoIP", "HTTP", "TLS", "SSH", "SMB", "NetBIOS-SSN", "RDP"}
        stream_packets = []

        for idx in range(len(self.packets)):
            if self.packets.is_live:
                p = self.packets[idx]
                if TCP not in p or IP not in p:
                    continue
                p_src = f"{p[IP].src}:{p[TCP].sport}"
                p_dst = f"{p[IP].dst}:{p[TCP].dport}"
            else:
                s = self.packets.get_summary(idx)
                if s[2] not in TCP_PROTOS:
                    continue
                p_src = s[0]
                p_dst = s[1]

            p_key = tuple(sorted([p_src, p_dst]))
            if p_key == norm_key:
                p = self.packets[idx]  # Lazy Load fuer Dialog
                stream_packets.append((idx, p))

        stream_key = f"{norm_key[0]} \u2194 {norm_key[1]}"
        dialog = DoIPStreamDialog(stream_packets, stream_key, self)
        dialog.exec()

    def _show_uds_sequence_analysis(self):
        """Zeigt die UDS-Sequenz-Analyse."""
        if len(self.packets) == 0:
            QMessageBox.warning(self, "Warnung", "Keine Pakete geladen")
            return

        if self.packets.is_live:
            # Live-Mode: alle Pakete direkt verfuegbar
            dialog = UDSSequenzDialog(list(self.packets), parent_panel=self, parent=self)
        else:
            # File-Mode: nur DoIP-Pakete lazy laden (spart viel Zeit)
            doip_indices = self.packets.get_indices_by_proto("DoIP")
            doip_packets = [self.packets[idx] for idx in doip_indices]
            dialog = UDSSequenzDialog(doip_packets, parent_panel=self, parent=self)
        dialog.exec()

    def _jump_to_packet(self, original_index: int):
        """Springt zu einem Paket in der Haupttabelle.
        Hinweis: Bei File-Mode mit UDS-Analyse koennen die Indices abweichen."""
        if original_index >= len(self.packets):
            return

        # Index in filtered_indices suchen
        try:
            row = self.filtered_indices.index(original_index)
        except ValueError:
            QMessageBox.information(
                self, "Hinweis",
                f"Paket Nr. {original_index + 1} ist durch den aktuellen Filter ausgeblendet."
            )
            return

        self.packet_table.selectRow(row)
        self.packet_table.scrollTo(
            self.packet_model.index(row, 0),
            QTableView.ScrollHint.PositionAtCenter
        )

    def _get_windows_interfaces(self) -> list:
        """Ermittelt verfuegbare Windows-Netzwerkschnittstellen ueber dumpcap.exe.

        Returns:
            Liste von (device_name, friendly_name, vendor_description) Tupeln.
        """
        if not os.path.exists(DUMPCAP_PATH):
            return []

        try:
            result = subprocess.run(
                [DUMPCAP_PATH, "-D", "-M"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                return []

            # -M gibt JSON aus: Liste von Objekten mit Device-Pfad als Key
            data = json.loads(result.stdout)
            interfaces = []

            for entry in data:
                for device_name, info in entry.items():
                    friendly_name = info.get("friendly_name", "") or ""
                    vendor_desc = info.get("vendor_description", "") or ""
                    is_loopback = info.get("loopback", False)

                    # Nutzlose Adapter herausfiltern
                    combined = (friendly_name + " " + vendor_desc).lower()
                    if any(skip in combined for skip in [
                        "wan miniport", "wi-fi direct",
                    ]):
                        continue

                    # Loopback ueberspringen (Windows hat eigenen)
                    if is_loopback:
                        continue

                    interfaces.append((device_name, friendly_name, vendor_desc))

            return interfaces
        except Exception:
            return []

    def _populate_interfaces(self):
        """Füllt die Interface-Auswahl mit verfügbaren Netzwerkschnittstellen.

        WSL-Interfaces sind per Checkbox mehrfach auswaehlbar.
        Windows-Interfaces bleiben Einzelauswahl.
        """
        self._interface_menu.clear()
        self._interface_items = []
        self._wsl_interface_actions = {}
        self._alle_action = None

        # Windows-Interfaces via dumpcap.exe (oben, da primaer gewuenscht)
        win_interfaces = self._get_windows_interfaces()
        if win_interfaces:
            for device_name, friendly_name, vendor_desc in win_interfaces:
                display = friendly_name if friendly_name else vendor_desc
                if friendly_name and vendor_desc:
                    display = f"{friendly_name} ({vendor_desc})"
                elif not display:
                    display = device_name
                label = f"[Win] {display}"
                user_data = (device_name, "windows")
                self._interface_items.append((label, user_data))
                action = self._interface_menu.addAction(label)
                action.triggered.connect(
                    lambda checked, lbl=label, ud=user_data: self._on_interface_selected(lbl, ud))

            self._interface_menu.addSeparator()

        # WSL-Interfaces — Checkboxen fuer Mehrfachauswahl
        alle_action = self._interface_menu.addAction("Alle (Standard)")
        alle_action.setCheckable(True)
        alle_action.setChecked(True)
        alle_action.triggered.connect(
            lambda checked: self._on_wsl_interface_toggled("", checked))
        self._alle_action = alle_action
        self._interface_items.append(("Alle (Standard)", ("", "wsl")))

        wsl_ifaces = []
        if SCAPY_AVAILABLE:
            try:
                interfaces = get_if_list()
                for iface in sorted(interfaces):
                    if iface and iface != "lo":
                        wsl_ifaces.append(iface)
                if "lo" in interfaces:
                    wsl_ifaces.append("lo")
            except Exception:
                wsl_ifaces = ["eth0", "lo"]

        for iface in wsl_ifaces:
            display = f"{iface} (Loopback)" if iface == "lo" else iface
            action = self._interface_menu.addAction(display)
            action.setCheckable(True)
            action.setChecked(False)
            action.triggered.connect(
                lambda checked, n=iface: self._on_wsl_interface_toggled(n, checked))
            self._wsl_interface_actions[iface] = action
            self._interface_items.append((display, (iface, "wsl")))

        # Standardauswahl: "Alle"
        self._selected_interfaces = [("", "wsl")]
        self._selected_interface_type = "wsl"
        self.interface_combo.setText("Alle (Standard)")

    def _on_wsl_interface_toggled(self, iface_name: str, checked: bool):
        """Callback wenn eine WSL-Interface-Checkbox umgeschaltet wird."""
        if iface_name == "":
            # "Alle (Standard)" gewaehlt → alle Einzel-Checkboxen abwaehlen
            if self._alle_action:
                self._alle_action.setChecked(True)
            for act in self._wsl_interface_actions.values():
                act.setChecked(False)
            self._selected_interfaces = [("", "wsl")]
            self._selected_interface_type = "wsl"
            self.interface_combo.setText("Alle (Standard)")
            return

        # Einzel-Interface getoggelt → "Alle" abwaehlen
        if self._alle_action:
            self._alle_action.setChecked(False)

        # Aktuelle Auswahl aus den Checkboxen lesen
        selected = []
        for name, act in self._wsl_interface_actions.items():
            if act.isChecked():
                selected.append((name, "wsl"))

        if not selected:
            # Nichts ausgewaehlt → zurueck auf "Alle"
            if self._alle_action:
                self._alle_action.setChecked(True)
            self._selected_interfaces = [("", "wsl")]
            self._selected_interface_type = "wsl"
            self.interface_combo.setText("Alle (Standard)")
        else:
            self._selected_interfaces = selected
            self._selected_interface_type = "wsl"
            names = [n for n, _ in selected]
            self.interface_combo.setText(", ".join(names))

    def _on_interface_selected(self, label: str, user_data: tuple):
        """Wird aufgerufen, wenn ein Windows-Interface ausgewaehlt wird (Einzelauswahl)."""
        # Alle WSL-Checkboxen abwaehlen
        if self._alle_action:
            self._alle_action.setChecked(False)
        for act in self._wsl_interface_actions.values():
            act.setChecked(False)

        self.interface_combo.setText(label)
        iface, itype = user_data
        self._selected_interfaces = [(iface, itype)]
        self._selected_interface_type = itype

    def _on_interface_combo_changed(self, index: int):
        """Kompatibilität: Wird nicht mehr direkt benötigt (QPushButton+QMenu)."""
        if index < len(self._interface_items):
            label, data = self._interface_items[index]
            self._on_interface_selected(label, data)

    def _on_packet_limit_selected(self, limit: str):
        """Wird aufgerufen, wenn ein Paket-Limit ausgewählt wird."""
        self._selected_packet_limit = limit
        self.packet_limit_btn.setText(limit)

    def _show_live_capture_ui(self):
        """Zeigt die Live-Capture UI an."""
        self.live_capture_widget.show()
        self._logger_control_widget.show()
        self.open_btn.setEnabled(False)  # PCAP-Öffnen deaktivieren im Live-Modus
        self.net_speed_widget.show()
        self._counter_widget.show()
        self._loss_monitor_widget.show()
        self._top_splitter.setSizes([140, 420, 250, 430])
        # Vertikale Aufteilung: Panels oben ~50%, Video unten ~50%
        # (gleich wie nach Video-Decode, damit Layout stabil bleibt)
        self._main_splitter.setSizes([450, 450, 0])
        self._prev_net_stats = self._read_net_dev()
        self._net_speed_timer.start(1000)
        self._loss_monitor_timer.start(2000)

    def _start_live_capture(self):
        """Startet die Live-Capture."""
        use_windows = self._selected_interface_type == "windows"

        if not use_windows and not SCAPY_AVAILABLE:
            QMessageBox.critical(
                self, "Fehler",
                "Scapy ist nicht installiert.\nBitte installieren Sie es mit: pip install scapy"
            )
            return

        if self._is_capturing:
            return

        # Interface(s) und Filter abrufen
        wsl_ifaces = [n for n, t in self._selected_interfaces if t == "wsl" and n]
        # Einzelner Interface-String fuer Abwaertskompatibilitaet
        interface = wsl_ifaces[0] if len(wsl_ifaces) == 1 else (
            self._selected_interfaces[0][0] if self._selected_interfaces else "")
        capture_filter = self.capture_filter_entry.text().strip()

        # Ring-Buffer Schwellwert aus Paket-Limit
        limit_text = self._selected_packet_limit
        if limit_text == "Unbegrenzt":
            self._max_live_packets = 100000  # Sicherheitslimit
        else:
            self._max_live_packets = int(limit_text)
        self._total_trimmed = 0

        # Vorhandene Pakete leeren
        self.packets = PacketStore()
        self.filtered_indices = []
        self.packet_model.clear()

        # Capture-Thread starten
        # Prioritaet: 1. Windows dumpcap.exe  2. Linux dumpcap  3. Scapy
        # packet_limit=0: Thread laeuft unbegrenzt, Ring-Buffer uebernimmt Begrenzung
        linux_dumpcap = None
        if not use_windows:
            # Linux dumpcap suchen (wesentlich schneller als Scapy)
            for dp in ["/usr/bin/dumpcap", "/usr/local/bin/dumpcap",
                       "/usr/sbin/dumpcap"]:
                if os.path.exists(dp):
                    linux_dumpcap = dp
                    break
        # Interface-Argument: Liste fuer multi-interface, String fuer single
        capture_iface = wsl_ifaces if len(wsl_ifaces) > 1 else interface
        if use_windows:
            self._live_capture_thread = WindowsCaptureThread(interface, capture_filter, 0)
            backend = "dumpcap.exe"
        elif linux_dumpcap:
            self._live_capture_thread = WindowsCaptureThread(capture_iface, capture_filter, 0)
            self._live_capture_thread._dumpcap_path = linux_dumpcap
            backend = "dumpcap"
        else:
            self._live_capture_thread = LiveCaptureThread(capture_iface, capture_filter, 0)
            backend = "Scapy"
        self._live_capture_thread.packet_received.connect(self._on_packet_received)
        # ── 0x2090 Video Assembly-Thread starten ──
        # Entkoppelt Capture (Pipe-Lesen) von Frame-Assembly (CPU-intensiv)
        self._video_assembly_thread = None
        if hasattr(self._live_capture_thread, '_video_queue'):
            self._video_assembly_thread = threading.Thread(
                target=self._video_assembly_worker,
                args=(self._live_capture_thread,),
                daemon=True, name='VideoAssembly')
            self._video_assembly_running = True
            self._video_assembly_thread.start()
        self._live_capture_thread.error.connect(self._on_capture_error)
        self._live_capture_thread.started_capture.connect(self._on_capture_started)
        self._live_capture_thread.finished.connect(self._on_capture_finished)
        self._live_capture_thread.start()

        self._is_capturing = True
        self.start_capture_btn.setEnabled(False)
        self.stop_capture_btn.setEnabled(True)
        self.interface_combo.setEnabled(False)
        self.capture_filter_entry.setEnabled(False)
        self.packet_limit_btn.setEnabled(False)
        self._video_decode_btn.setEnabled(True)
        filter_info = f" (Filter: {capture_filter})" if capture_filter else ""
        iface_info = f" auf {', '.join(wsl_ifaces)}" if len(wsl_ifaces) > 1 else ""
        self.status_label.setText(f"Live-Capture läuft [{backend}]{iface_info}...{filter_info}")

        # ── PLP Counter Monitor starten ──
        # Auto-Erkennung wenn "Alle" gewaehlt (wsl_ifaces leer)
        counter_ifaces = list(wsl_ifaces)
        if not counter_ifaces:
            _virtual_pfx = ('lo', 'docker', 'veth', 'br-', 'virbr')
            try:
                for entry in os.listdir('/sys/class/net'):
                    if any(entry.startswith(p) for p in _virtual_pfx):
                        continue
                    try:
                        with open(f'/sys/class/net/{entry}/carrier') as f:
                            if f.read().strip() != '1':
                                continue
                        with open(f'/sys/class/net/{entry}/speed') as f:
                            if int(f.read().strip()) < 5000:
                                continue
                    except (OSError, ValueError):
                        continue
                    counter_ifaces.append(entry)
            except Exception:
                pass
        # Counter Monitor wird NACH _start_afpacket_workers gestartet,
        # weil _inline_counter_stats erst dort erstellt wird.
        self._pending_counter_ifaces = counter_ifaces if counter_ifaces else None

    def _stop_live_capture(self):
        """Stoppt die Live-Capture."""
        self._is_capturing = False
        self.progress_bar.hide()

        # ── PLP Counter Monitor + Loss Monitor stoppen ──
        self._stop_counter_monitor()
        self._stop_loss_monitor()

        # ── Assembly-Thread stoppen ──
        self._video_assembly_running = False
        if getattr(self, '_video_assembly_thread', None):
            self._video_assembly_thread.join(timeout=2)
            self._video_assembly_thread = None

        if self._live_capture_thread:
            self._live_capture_thread.stop()
            self._live_capture_thread.wait(3000)  # Max 3 Sekunden warten
            self._live_capture_thread = None

        self.start_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.interface_combo.setEnabled(True)
        self.capture_filter_entry.setEnabled(True)
        self.packet_limit_btn.setEnabled(True)

        # Video-Decode: Backend stoppen, aber Anzeige beibehalten
        # (letzter Frame + Layout bleiben stehen)
        self._video_decode_btn.setEnabled(False)
        if self._video_decode_active:
            self._video_decode_active = False
            # Render-Threads stoppen (kein neues Bild mehr)
            for rt in getattr(self, '_render_threads', []):
                try:
                    rt.stop()
                except Exception:
                    pass
            self._render_threads = []
            # AF_PACKET Worker stoppen
            self._cleanup_afpacket()
            # Decoder aufräumen
            if self._video_decoder:
                self._video_decoder.cleanup()
                self._video_decoder.deleteLater()
                self._video_decoder = None
            # Toggle-Button zuruecksetzen OHNE _stop_video_decode
            self._video_decode_btn.blockSignals(True)
            self._video_decode_btn.setChecked(False)
            self._video_decode_btn.blockSignals(False)

        self.status_label.setText(f"Live-Capture gestoppt. {len(self.packets)} Pakete erfasst.")

    def _video_assembly_worker(self, capture_thread):
        """Einzelner Assembly-Thread: Liest 0x2090-Pakete aus Queue.

        Ein Thread ist optimal wegen Python GIL — mehrere Threads
        konkurrieren nur um den GIL und sind LANGSAMER.
        ISP laeuft trotzdem parallel (NumPy/OpenCV geben GIL frei).
        """
        queue = capture_thread._video_queue
        popleft = queue.popleft
        batch = []
        last_count_update = 0

        while getattr(self, '_video_assembly_running', False):
            # ── Batch: Bis zu 500 Pakete auf einmal ──
            batch.clear()
            try:
                for _ in range(500):
                    batch.append(popleft())
            except IndexError:
                pass

            if not batch:
                time.sleep(0.0001)  # 0.1ms wenn Queue leer
                continue

            if not (self._video_decode_active and self._video_decoder):
                continue

            decoder = self._video_decoder
            for pkt_data in batch:
                try:
                    decoder._handle_csi2_0x2090(pkt_data[14:])
                except Exception:
                    pass

            # Paketzaehler
            total_vid = capture_thread._video_pkt_count
            if total_vid - last_count_update >= 5000:
                last_count_update = total_vid
                try:
                    total = self._total_trimmed + len(self.packets)
                    self.packet_count_label.setText(
                        f"Pakete: {total + total_vid}")
                except Exception:
                    pass

    def _on_raw_video_packet(self, pkt_data: bytes):
        """Legacy-Fallback: 0x2090-Pakete als Raw-Bytes (nur wenn Queue nicht verfuegbar)."""
        if self._video_decode_active and self._video_decoder:
            self._video_decoder._handle_csi2_0x2090(pkt_data[14:])

    def _on_packet_received(self, pkt):
        """Verarbeitet ein empfangenes Live-Paket."""
        # ── Video-Schnellpfad: 0x2090-Pakete direkt an Decoder, ──
        # ── NICHT in Tabelle/Ring-Buffer (Performance-kritisch).  ──
        if self._video_decode_active and self._video_decoder:
            try:
                if Ether in pkt and pkt[Ether].type == 0x2090:
                    self._video_decoder.process_packet(pkt)
                    # Nur Paketzaehler aktualisieren (alle 500 Pakete)
                    self._live_video_pkt_count = getattr(
                        self, '_live_video_pkt_count', 0) + 1
                    if self._live_video_pkt_count % 500 == 0:
                        total = self._total_trimmed + len(self.packets)
                        self.packet_count_label.setText(
                            f"Pakete: {total + self._live_video_pkt_count}")
                    return  # Tabelle ueberspringen!
            except Exception:
                pass

        # Ring-Buffer: Aelteste 25% entfernen wenn Limit erreicht
        if len(self.packets) >= self._max_live_packets:
            self._trim_live_packets()

        self.packets.append_live(pkt)
        pkt_idx = len(self.packets) - 1
        self.filtered_indices.append(pkt_idx)  # Im Live-Modus keine Filterung

        # Tabelle aktualisieren (nur neue Zeile hinzufügen für Performance)
        self._add_packet_to_table(pkt, pkt_idx)

        # Video-Dekodierung: Nicht-0x2090 Protokolle (GVSP, RTP, etc.)
        if self._video_decode_active and self._video_decoder:
            self._video_decoder.process_packet(pkt)

        # Status aktualisieren
        total = self._total_trimmed + len(self.packets)
        if self._total_trimmed > 0:
            self.packet_count_label.setText(f"Pakete: {len(self.packets)} (gesamt: {total})")
        else:
            self.packet_count_label.setText(f"Pakete: {len(self.packets)}")

    def _trim_live_packets(self):
        """Ring-Buffer: Entfernt die aeltesten 25% der Pakete."""
        trim_count = len(self.packets) // 4
        if trim_count == 0:
            return
        self.packets.trim_oldest(trim_count)
        self._total_trimmed += trim_count
        # filtered_indices neu aufbauen
        filter_text = self.filter_entry.text().strip().lower()
        if not filter_text:
            self.filtered_indices = list(range(len(self.packets)))
        else:
            self.filtered_indices = [
                i for i in range(len(self.packets))
                if self._packet_matches_filter(self.packets[i], filter_text)
            ]
        # _base_time auf erstes verbleibendes Paket aktualisieren
        if len(self.packets) > 0 and hasattr(self.packets[0], 'time'):
            self._base_time = self.packets[0].time
        self._update_packet_table()

    # ----- Live-Video-Dekodierung Steuerung -----

    def _toggle_video_decode(self, checked: bool):
        """Video-Dekodierung ein-/ausschalten."""
        if checked:
            self._start_video_decode()
        else:
            self._stop_video_decode()

    def _start_video_decode(self):
        """Startet die Video-Dekodierung."""
        if not CV2_AVAILABLE:
            QMessageBox.warning(self, "Fehler",
                                "OpenCV (cv2) ist nicht installiert.\n"
                                "pip install opencv-python")
            self._video_decode_btn.setChecked(False)
            return

        # Protokoll-Mapping
        proto_map = {
            0: 'auto',
            1: 'tecmp',
            2: 'fpdlink',
            3: 'tecmp_rtp',
            4: 'rtp_mjpeg',
            5: 'rtp_h264',
            6: 'avtp',
            7: 'gvsp',
            8: 'csi2_0x2090',
        }
        proto = proto_map.get(self._video_protocol_index, 'auto')

        # ── AF_PACKET Schnellpfad: 0x2090 auf Linux ──
        # CaptureWorker-Prozesse mit AF_PACKET+MMAP → Zero-Copy, kein GIL
        self._afpacket_workers = []
        self._afpacket_shms = []
        self._afpacket_notifiers = []
        self._afpacket_conns = []
        self._afpacket_stop = None
        self._frame_dispatch = None

        # AF_PACKET Interface-Liste ermitteln
        afp_ifaces = [n for n, t in self._selected_interfaces if t == "wsl" and n]
        if not afp_ifaces:
            # "Alle" gewaehlt → nur physische Interfaces mit Link (carrier=1)
            # Virtuelle Interfaces (docker0, veth, br-) ausschliessen
            _virtual_prefixes = ('lo', 'docker', 'veth', 'br-', 'virbr')
            try:
                candidates = get_if_list() if SCAPY_AVAILABLE else []
                for iface in candidates:
                    if not iface or any(iface.startswith(p) for p in _virtual_prefixes):
                        continue
                    # Nur Interfaces mit Link (carrier=1) und Speed >= 5 Gbps
                    try:
                        with open(f'/sys/class/net/{iface}/carrier') as f:
                            if f.read().strip() != '1':
                                continue
                        with open(f'/sys/class/net/{iface}/speed') as f:
                            speed = int(f.read().strip())
                            if speed < 5000:  # < 5 Gbps → kein Video-Interface
                                continue
                    except (OSError, ValueError):
                        continue
                    afp_ifaces.append(iface)
            except Exception:
                afp_ifaces = []
            logging.getLogger(__name__).info(
                f"AF_PACKET Auto-Interfaces: {afp_ifaces}")

        if (proto in ('csi2_0x2090', 'auto')
                and hasattr(socket, 'AF_PACKET')
                and self._is_capturing
                and afp_ifaces):
            try:
                self._start_afpacket_workers(afp_ifaces)
            except Exception as e:
                logging.getLogger(__name__).warning(
                    f"AF_PACKET fehlgeschlagen ({e}), Fallback auf LiveVideoDecoder")
                self._cleanup_afpacket()

        # ── PLP Counter Monitor starten (NACH Worker-Start) ──
        _pci = getattr(self, '_pending_counter_ifaces', None)
        if _pci:
            self._start_counter_monitor(_pci)
            self._pending_counter_ifaces = None

        # ── Render-Threads starten (4 Slots, je 1 Thread) ──
        self._render_threads: list = []
        for idx in range(4):
            rt = _VideoRenderThread(idx, parent=self)
            rt.image_ready.connect(self._on_render_ready)
            rt.start()
            self._render_threads.append(rt)

        # ── FrameDispatchThread starten (ersetzt QSocketNotifier) ──
        if self._afpacket_workers and self._afpacket_conns:
            self._frame_dispatch = _FrameDispatchThread(
                self._afpacket_conns, self._afpacket_shms,
                self._render_threads, parent=self)
            self._frame_dispatch.stream_detected.connect(
                self._on_stream_detected)
            self._frame_dispatch.stream_worker.connect(
                self._on_stream_worker_mapped)
            self._frame_dispatch.fps_updated.connect(
                lambda idx, txt: self._video_id_labels[idx].setText(txt)
                if idx < len(self._video_id_labels) else None)
            self._frame_dispatch.info_updated.connect(
                self._video_info_label.setText)
            self._frame_dispatch.start()
            # QSocketNotifier deaktivieren (Dispatch-Thread uebernimmt)
            for n in self._afpacket_notifiers:
                try:
                    n.setEnabled(False)
                except Exception:
                    pass
            # Timer fuer Display-Size-Updates (alle 500ms)
            self._display_size_timer = QTimer(self)
            self._display_size_timer.timeout.connect(
                self._update_dispatch_display_sizes)
            self._display_size_timer.start(500)

        # Fallback: LiveVideoDecoder (fuer nicht-0x2090 oder wenn AF_PACKET fehlschlaegt)
        if not self._afpacket_workers:
            self._video_decoder = LiveVideoDecoder(protocol=proto, parent=self)
            self._video_decoder.frame_ready.connect(self._on_video_frame_ready)
            self._video_decoder.stream_detected.connect(self._on_stream_detected)
            self._video_decoder.info_updated.connect(self._on_video_info_updated)
        else:
            self._video_decoder = None

        self._video_decode_active = True

        # Video-Container anzeigen (volle Breite unterhalb)
        self._video_container.show()
        self._bottom_splitter.hide()
        self._main_splitter.setSizes([450, 450, 0])
        self._video_display.setText("Warte auf Video-Signal...")
        backend = "AF_PACKET/MMAP" if self._afpacket_workers else "Software"
        self._video_info_label.setText(f"Live Video [{backend}]  —  Warte auf Signal...")

    def _kill_stale_capture_workers(self):
        """Toetet verwaiste CaptureWorker-Prozesse aus vorherigen Sitzungen.

        Ohne dies halten alte Worker AF_PACKET-Sockets offen → Kernel
        muss jedes Paket an ALLE Sockets liefern → Durchsatz sinkt drastisch.

        Strategie: Alle 'run.py'-Kindprozesse finden, deren Elternprozess
        nicht mehr existiert oder nicht der aktuelle Hauptprozess ist.
        """
        import subprocess
        import signal
        logger = logging.getLogger(__name__)
        try:
            # Alle python-Prozesse finden die run.py ausfuehren
            result = subprocess.run(
                ['pgrep', '-a', '-f', 'run.py'],
                capture_output=True, text=True, timeout=3)
            own_pid = os.getpid()
            stale = []
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                pid_str = line.split()[0]
                pid = int(pid_str)
                if pid == own_pid:
                    continue
                # Elternprozess pruefen: Wenn ppid=1 (init) → verwaist
                try:
                    with open(f'/proc/{pid}/stat') as f:
                        ppid = int(f.read().split(')')[1].split()[1])
                    if ppid == 1 or ppid != own_pid:
                        stale.append(pid)
                except (FileNotFoundError, ValueError, IndexError):
                    pass
            if stale:
                for pid in stale:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                logger.warning(
                    f"Killed {len(stale)} stale capture workers: {stale}")
        except Exception:
            pass

    def _start_afpacket_workers(self, interfaces):
        """Startet CaptureWorker-Prozesse mit AF_PACKET+MMAP.

        Args:
            interfaces: str (einzelnes Interface) oder list[str] (mehrere).
                        Pro Interface werden 2 Worker erstellt, jeder erkennt
                        automatisch einen Stream (z.B. 0x0066/0x0067).
        """
        import multiprocessing
        from multiprocessing.shared_memory import SharedMemory
        from core.capture_process import CaptureWorker, capture_worker_entry

        # Abwaertskompatibilitaet: str → Liste
        if isinstance(interfaces, str):
            interfaces = [interfaces]

        logger = logging.getLogger(__name__)
        logger.info(f"AF_PACKET: {len(interfaces)} Interfaces → "
                    f"{', '.join(interfaces)}")

        # Verwaiste Worker aus vorherigen Sitzungen beenden
        self._kill_stale_capture_workers()

        WORKERS_PER_IFACE = 2
        total_workers = WORKERS_PER_IFACE * len(interfaces)
        stop_event = multiprocessing.Event()
        self._afpacket_stop = stop_event

        # Shared Array fuer Stream-Duplikat-Erkennung (ueber alle Worker)
        claimed = multiprocessing.Array('i', total_workers, lock=True)
        for i in range(total_workers):
            claimed[i] = 0

        # Per-Worker Gain-Mode Shared Value (0=Auto/LCG, 1=HCG)
        self._afpacket_gain_modes = []
        # stream_id → worker_index Mapping (fuer Mode-Updates)
        self._afpacket_stream_worker_map: Dict[int, int] = {}

        # ── Inline Counter Stats (alle Worker teilen ein Array) ──
        self._inline_counter_stats = multiprocessing.Array(
            'l', total_workers * _ICT_FIELDS, lock=False)
        self._inline_counter_workers = total_workers
        self._inline_counter_ifaces = list(interfaces)
        self._inline_counter_pause = multiprocessing.Event()
        self._inline_counter_reset = multiprocessing.Value('i', 0)

        global_idx = 0
        for iface in interfaces:
            for local_i in range(WORKERS_PER_IFACE):
                shm_name = f"lc_vid_{os.getpid()}_{global_idx}"
                shm = SharedMemory(name=shm_name, create=True,
                                   size=CaptureWorker.SHM_SIZE)

                # Pipe fuer Frame-Benachrichtigung
                reader_conn, writer_conn = multiprocessing.Pipe(duplex=False)

                # Shared Value fuer Gain-Mode
                gain_mode = multiprocessing.Value('i', 0)
                self._afpacket_gain_modes.append(gain_mode)

                proc = multiprocessing.Process(
                    target=capture_worker_entry,
                    args=(iface, shm_name, writer_conn, stop_event,
                          global_idx, total_workers, claimed, gain_mode,
                          self._inline_counter_stats,
                          self._inline_counter_pause,
                          self._inline_counter_reset),
                    daemon=True,
                    name=f"CaptureWorker-{iface}-{local_i}")
                proc.start()
                writer_conn.close()  # Writer-Ende im Hauptprozess schliessen

                # QSocketNotifier fuer Zero-Latency Benachrichtigung
                fd = reader_conn.fileno()
                notifier = QSocketNotifier(fd, QSocketNotifier.Type.Read, self)
                notifier.activated.connect(
                    lambda _fd, _idx=global_idx, _conn=reader_conn, _shm=shm:
                        self._on_afpacket_frame(_idx, _conn, _shm))
                notifier.setEnabled(True)

                self._afpacket_workers.append(proc)
                self._afpacket_shms.append(shm)
                self._afpacket_notifiers.append(notifier)
                self._afpacket_conns.append(reader_conn)

                global_idx += 1

    def _on_afpacket_frame(self, worker_idx: int, conn, shm):
        """Callback wenn CaptureWorker einen neuen Frame geschrieben hat."""
        try:
            # Pipe leeren (kann mehrere Bytes enthalten)
            while conn.poll():
                conn.recv_bytes()
        except (EOFError, OSError):
            return

        if not self._video_decode_active:
            return

        try:
            buf = shm.buf
            active = struct.unpack_from('<I', buf, 0)[0]
            from core.capture_process import CaptureWorker as CW
            off = CW.SHM_HEADER + active * CW.SLOT_SIZE

            frame_num, h, w, stream_id = struct.unpack_from('<IIII', buf, off)
            if h == 0 or w == 0 or h > 2000 or w > 2000:
                return

            nbytes = h * w * 3
            if nbytes > CW.MAX_BGR_BYTES:
                return

            bgr = np.frombuffer(
                bytes(buf[off + CW.SLOT_HEADER:off + CW.SLOT_HEADER + nbytes]),
                dtype=np.uint8).reshape(h, w, 3)

            # Stream-Slot bestimmen (automatisch zuweisen)
            if stream_id not in self._afpacket_frame_counts:
                slot = len(self._afpacket_frame_counts)
                if slot < 4:
                    self._afpacket_frame_counts[stream_id] = frame_num
                    self._afpacket_fps_counters[stream_id] = frame_num
                    self._afpacket_fps_times[stream_id] = time.time()
                    self._on_stream_detected(stream_id, slot)

            slots = list(self._afpacket_frame_counts.keys())
            if stream_id not in slots:
                return
            display_index = slots.index(stream_id)
            self._afpacket_frame_counts[stream_id] = frame_num

            # Per-Stream FPS aus frame_num-Differenz berechnen (= echte Capture-FPS)
            now = time.time()
            last_t = self._afpacket_fps_times.get(stream_id, now)
            elapsed = now - last_t
            if elapsed >= 1.0:
                last_fn = self._afpacket_fps_counters.get(stream_id, frame_num)
                cap_fps = (frame_num - last_fn) / elapsed
                self._afpacket_fps_counters[stream_id] = frame_num
                self._afpacket_fps_times[stream_id] = now
                # Display-FPS vom RenderThread lesen
                rts = getattr(self, '_render_threads', [])
                disp_fps = rts[display_index].display_fps \
                    if display_index < len(rts) else 0.0
                # Per-Stream Label: Capture-FPS + Display-FPS
                if display_index < len(self._video_id_labels):
                    self._video_id_labels[display_index].setText(
                        f"Stream 0x{stream_id:04X}   {w}×{h}   "
                        f"{cap_fps:.1f} FPS (disp:{disp_fps:.0f})   "
                        f"#{frame_num}")
                # Globales Info-Label: nur Backend-Info
                self._video_info_label.setText(
                    f"Live Video [AF_PACKET/MMAP]   CSI-2/0x2090")

            self._on_video_frame_ready(bgr, display_index)

        except Exception:
            pass

    def _update_dispatch_display_sizes(self):
        """Timer-Callback: Aktuelle Display-Groessen an DispatchThread senden."""
        dispatch = getattr(self, '_frame_dispatch', None)
        if dispatch:
            sizes = [(d.size().width(), d.size().height())
                     for d in self._video_displays]
            dispatch.update_display_sizes(sizes)

    def _cleanup_afpacket(self):
        """AF_PACKET Worker und Ressourcen aufraeumen."""
        # Display-Size-Timer stoppen
        timer = getattr(self, '_display_size_timer', None)
        if timer:
            timer.stop()
            self._display_size_timer = None

        # FrameDispatchThread stoppen (VOR Connections schliessen!)
        dispatch = getattr(self, '_frame_dispatch', None)
        if dispatch:
            dispatch.stop()
            self._frame_dispatch = None

        # Notifier deaktivieren
        for n in getattr(self, '_afpacket_notifiers', []):
            try:
                n.setEnabled(False)
            except Exception:
                pass
        self._afpacket_notifiers = []

        # Stop-Event setzen
        if getattr(self, '_afpacket_stop', None):
            self._afpacket_stop.set()

        # Connections schliessen
        for conn in getattr(self, '_afpacket_conns', []):
            try:
                conn.close()
            except Exception:
                pass
        self._afpacket_conns = []

        # Worker-Prozesse beenden
        for proc in getattr(self, '_afpacket_workers', []):
            try:
                proc.join(timeout=2)
                if proc.is_alive():
                    proc.kill()
            except Exception:
                pass
        self._afpacket_workers = []

        # SharedMemory aufraeumen
        for shm in getattr(self, '_afpacket_shms', []):
            try:
                shm.close()
                shm.unlink()
            except Exception:
                pass
        self._afpacket_shms = []

        self._afpacket_stop = None

    def _stop_video_decode(self):
        """Stoppt die Video-Dekodierung."""
        self._video_decode_active = False

        # Erkennung deaktivieren
        if self._detection_active:
            self._detect_toggle_btn.setChecked(False)

        # Render-Threads stoppen
        for rt in getattr(self, '_render_threads', []):
            try:
                rt.stop()
            except Exception:
                pass
        self._render_threads = []

        # AF_PACKET Worker stoppen
        self._cleanup_afpacket()

        if self._video_decoder:
            self._video_decoder.cleanup()
            self._video_decoder.deleteLater()
            self._video_decoder = None

        # Video-Panels zurücksetzen
        self._video_stream_count = 0
        self._per_stream_fps = {}
        for i in range(4):
            self._video_displays[i].clear()
            self._video_id_labels[i].setText("")
            self._video_panels[i].setVisible(i == 0)
        self._video_displays[0].setText("Kein Video-Signal")
        self._rearrange_video_grid(1)

        # Video-Container ausblenden, Details wieder anzeigen
        self._video_container.hide()
        self._bottom_splitter.show()
        self._main_splitter.setSizes([400, 0, 300])

        # Video-Einstellungen zuruecksetzen und Paketanzeige wiederherstellen
        self._clear_video_settings_streams()
        if self._view_mode_index != 0:
            self._on_view_mode_selected(0, "Paketanzeige")

    def _on_video_protocol_selected(self, index: int, label: str):
        """Protokoll-Auswahl im Menü geändert."""
        self._video_protocol_index = index
        self._video_protocol_btn.setText(label)
        if self._video_decoder:
            proto_map = {
                0: 'auto', 1: 'tecmp', 2: 'fpdlink', 3: 'tecmp_rtp',
                4: 'rtp_mjpeg', 5: 'rtp_h264', 6: 'avtp', 7: 'gvsp',
                8: 'csi2_0x2090',
            }
            self._video_decoder.set_protocol(proto_map.get(index, 'auto'))

    # ── Ansicht-Umschalter: Paketanzeige / Video-Einstellungen ──

    def _on_view_mode_selected(self, index: int, label: str):
        """Wechselt zwischen Paketanzeige und Video-Einstellungen."""
        self._view_mode_index = index
        self._view_mode_btn.setText(label)
        if index == 0:
            # Paketanzeige anzeigen
            self._video_settings_widget.hide()
            self.packet_table.show()
            # Splitter: [net_speed, counter, loss_monitor, packet_table, vs_widget]
            sizes = self._top_splitter.sizes()
            total = sum(sizes)
            rest = total - sizes[0] - sizes[1] - sizes[2]
            self._top_splitter.setSizes([sizes[0], sizes[1], sizes[2], rest, 0])
        else:
            # Video-Einstellungen anzeigen
            self.packet_table.hide()
            self._video_settings_widget.show()
            # Splitter: Video-Einstellungen bekommt Paketlisten-Platz
            sizes = self._top_splitter.sizes()
            total = sum(sizes)
            rest = total - sizes[0] - sizes[1] - sizes[2]
            self._top_splitter.setSizes([sizes[0], sizes[1], sizes[2], 0, rest])

    def _add_video_settings_stream(self, stream_id: int):
        """Fuegt einen Tab fuer einen neuen Video-Stream hinzu."""
        if stream_id in self._vs_stream_controls:
            return

        # Platzhalter-Tab entfernen wenn erster echter Stream
        if self._vs_placeholder.parent() is not None:
            idx = self._vs_tabs.indexOf(self._vs_placeholder)
            if idx >= 0:
                self._vs_tabs.removeTab(idx)

        # ── Tab-Inhalt: ScrollArea mit Controls ──
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        lay = QVBoxLayout(content)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(4)

        # ── Stream-Info ──
        info_group = QGroupBox(f"Stream 0x{stream_id:04X}")
        info_group.setStyleSheet(
            "QGroupBox { font-weight: bold; border: 1px solid #bbb; "
            "border-radius: 4px; margin-top: 6px; padding: 6px 8px; padding-top: 16px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }"
        )
        info_lay = QVBoxLayout(info_group)
        info_lay.setContentsMargins(8, 8, 8, 4)
        info_label = QLabel("Format:      RAW12\nAuflösung:  —")
        info_label.setFont(QFont("Consolas", 9))
        info_lay.addWidget(info_label)
        lay.addWidget(info_group)

        # ── Dual-Gain Modus ──
        mode_group = QGroupBox("Dual-Gain Modus")
        mode_group.setStyleSheet(
            "QGroupBox { font-weight: bold; border: 1px solid #bbb; "
            "border-radius: 4px; margin-top: 6px; padding: 6px 8px; padding-top: 16px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }"
        )
        mode_lay = QVBoxLayout(mode_group)
        mode_lay.setContentsMargins(8, 8, 8, 8)

        mode_btn = QPushButton("Auto")
        mode_btn.setStyleSheet(
            "text-align: left; padding: 6px 10px; border: 1px solid #aaa; "
            "border-radius: 3px; background: white; font-size: 12px;"
        )
        mode_menu = QMenu(self)
        _modes = [
            ("Auto", "auto"),
            ("HCG (High Conversion Gain)", "hcg"),
            ("LCG (Low Conversion Gain)", "lcg"),
        ]
        for mlabel, mval in _modes:
            action = mode_menu.addAction(mlabel)
            action.triggered.connect(
                lambda checked, sid=stream_id, v=mval, l=mlabel:
                    self._on_vs_mode_changed(sid, v, l))
        mode_btn.setMenu(mode_menu)
        mode_lay.addWidget(mode_btn)
        lay.addWidget(mode_group)

        # ── Bildparameter ──
        param_group = QGroupBox("Bildparameter")
        param_group.setStyleSheet(
            "QGroupBox { font-weight: bold; border: 1px solid #bbb; "
            "border-radius: 4px; margin-top: 6px; padding: 6px 8px; padding-top: 16px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }"
        )
        param_lay = QVBoxLayout(param_group)
        param_lay.setContentsMargins(8, 8, 8, 8)
        param_lay.setSpacing(2)

        r_slider = self._create_param_slider("R-Faktor", 0.1, 5.0, 1.0, 0.05)
        r_slider.on_change(lambda sid=stream_id: self._on_vs_param_changed(sid))
        param_lay.addWidget(r_slider)

        b_slider = self._create_param_slider("B-Faktor", 0.1, 5.0, 1.0, 0.05)
        b_slider.on_change(lambda sid=stream_id: self._on_vs_param_changed(sid))
        param_lay.addWidget(b_slider)

        # Zuruecksetzen
        reset_btn = QPushButton("Zurücksetzen")
        reset_btn.setStyleSheet(
            "background-color: #5a9bd5; color: white; padding: 6px 16px; "
            "border-radius: 3px; font-weight: bold;"
        )
        reset_btn.clicked.connect(
            lambda checked, sid=stream_id: self._on_vs_reset(sid))
        param_lay.addWidget(reset_btn)

        lay.addWidget(param_group)
        lay.addStretch()

        scroll.setWidget(content)

        # Tab hinzufuegen
        tab_label = f"Stream 0x{stream_id:02X}"
        if stream_id > 0xFF:
            tab_label = f"Stream 0x{stream_id:04X}"
        self._vs_tabs.addTab(scroll, tab_label)

        self._vs_stream_controls[stream_id] = {
            'tab': scroll,
            'r_slider': r_slider,
            'b_slider': b_slider,
            'mode_btn': mode_btn,
            'info_label': info_label,
        }

    def _create_param_slider(self, label: str, min_val: float, max_val: float,
                              default: float, step: float) -> QWidget:
        """Erstellt einen ParamSlider inline (analog zu parameter_tuner_dialog)."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(4, 2, 4, 2)

        # Header: Label + Wert
        header = QHBoxLayout()
        header.addWidget(QLabel(label))
        ticks = round((max_val - min_val) / step)
        fmt_str = "{:.2f}" if step < 0.1 else "{:.1f}"
        value_label = QLabel(fmt_str.format(default))
        value_label.setStyleSheet("font-weight: bold;")
        header.addStretch()
        header.addWidget(value_label)
        layout.addLayout(header)

        # Slider mit Pfeil-Buttons
        _arrow_style = (
            "QPushButton { border: none; border-radius: 3px;"
            "  background: #4a90d9; color: white; font-size: 11px;"
            "  font-weight: bold; padding: 0; }"
            "QPushButton:hover { background: #357abd; }"
            "QPushButton:pressed { background: #2a6099; }"
        )
        slider_row = QHBoxLayout()
        slider_row.setSpacing(2)

        left_btn = QPushButton("\u25C0")
        left_btn.setFixedSize(22, 22)
        left_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        left_btn.setStyleSheet(_arrow_style)
        left_btn.setAutoRepeat(True)
        left_btn.setAutoRepeatDelay(400)
        left_btn.setAutoRepeatInterval(80)
        slider_row.addWidget(left_btn)

        slider = QSlider(Qt.Orientation.Horizontal)
        slider.setMinimum(0)
        slider.setMaximum(ticks)
        slider.setValue(round((default - min_val) / step))
        slider_row.addWidget(slider)

        right_btn = QPushButton("\u25B6")
        right_btn.setFixedSize(22, 22)
        right_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        right_btn.setStyleSheet(_arrow_style)
        right_btn.setAutoRepeat(True)
        right_btn.setAutoRepeatDelay(400)
        right_btn.setAutoRepeatInterval(80)
        slider_row.addWidget(right_btn)

        layout.addLayout(slider_row)

        # State am Widget speichern
        widget._slider = slider
        widget._min = min_val
        widget._step = step
        widget._default = default
        widget._value_label = value_label
        widget._fmt_str = fmt_str
        widget._callback = None

        def _on_changed(tick):
            val = min_val + tick * step
            value_label.setText(fmt_str.format(val))
            if widget._callback:
                widget._callback()

        slider.valueChanged.connect(_on_changed)
        left_btn.clicked.connect(lambda: slider.setValue(max(0, slider.value() - 1)))
        right_btn.clicked.connect(lambda: slider.setValue(min(ticks, slider.value() + 1)))

        def _value():
            return min_val + slider.value() * step
        widget.value = _value

        def _set_value(val):
            slider.setValue(round((val - min_val) / step))
        widget.set_value = _set_value

        def _reset():
            slider.setValue(round((default - min_val) / step))
        widget.reset = _reset

        def _on_change(callback):
            widget._callback = callback
        widget.on_change = _on_change

        return widget

    def _on_vs_mode_changed(self, stream_id: int, mode: str, label: str):
        """Dual-Gain Modus fuer einen Stream geaendert."""
        controls = self._vs_stream_controls.get(stream_id)
        if controls:
            controls['mode_btn'].setText(label)
        # R/B-Faktoren aus aktuellen Slidern lesen
        r_fac = controls['r_slider'].value() if controls else 1.0
        b_fac = controls['b_slider'].value() if controls else 1.0
        self._apply_isp_to_backends(stream_id, r_fac, b_fac, mode)

    def _on_vs_param_changed(self, stream_id: int):
        """R/B-Faktor Slider fuer einen Stream geaendert."""
        controls = self._vs_stream_controls.get(stream_id)
        if not controls:
            return
        r_fac = controls['r_slider'].value()
        b_fac = controls['b_slider'].value()
        mode_text = controls['mode_btn'].text().lower()
        mode = 'auto'
        if 'hcg' in mode_text:
            mode = 'hcg'
        elif 'lcg' in mode_text:
            mode = 'lcg'
        self._apply_isp_to_backends(stream_id, r_fac, b_fac, mode)

    def _on_vs_reset(self, stream_id: int):
        """Alle Parameter fuer einen Stream zuruecksetzen."""
        controls = self._vs_stream_controls.get(stream_id)
        if not controls:
            return
        controls['r_slider'].reset()
        controls['b_slider'].reset()
        controls['mode_btn'].setText("Auto")
        self._apply_isp_to_backends(stream_id, 1.0, 1.0, 'auto')

    def _on_stream_worker_mapped(self, stream_id: int, worker_index: int):
        """Speichert stream_id → worker_index Mapping (fuer Gain-Mode Updates)."""
        swm = getattr(self, '_afpacket_stream_worker_map', {})
        swm[stream_id] = worker_index
        self._afpacket_stream_worker_map = swm

    def _apply_isp_to_backends(self, stream_id: int, r_fac: float,
                                b_fac: float, mode: str):
        """Leitet ISP-Parameter an alle aktiven Backends weiter."""
        # LiveVideoDecoder (Software-Pfad)
        decoder = self._video_decoder
        if decoder:
            decoder.set_stream_isp_params(stream_id, r_fac, b_fac, mode)
        # FrameDispatchThread (AF_PACKET-Pfad): R/B-Faktor
        dispatch = getattr(self, '_frame_dispatch', None)
        if dispatch:
            dispatch.update_isp_params(stream_id, r_fac, b_fac)
        # CaptureWorker (AF_PACKET-Pfad): Gain-Mode via SharedMemory
        swm = getattr(self, '_afpacket_stream_worker_map', {})
        gm_list = getattr(self, '_afpacket_gain_modes', [])
        widx = swm.get(stream_id)
        if widx is not None and widx < len(gm_list):
            mode_val = 1 if mode == 'hcg' else 0  # 0=auto/lcg, 1=hcg
            gm_list[widx].value = mode_val

    def _clear_video_settings_streams(self):
        """Entfernt alle Stream-Tabs aus dem Video-Einstellungen-Panel."""
        self._vs_tabs.clear()
        self._vs_stream_controls.clear()
        # Platzhalter-Tab wiederherstellen
        self._vs_tabs.addTab(self._vs_placeholder, "Video-Einstellungen")

    def _on_video_frame_ready(self, bgr, display_index: int = 0):
        """Empfaengt BGR-Frame und leitet an RenderThread weiter."""
        try:
            if display_index < 0 or display_index >= len(self._video_displays):
                display_index = 0
            target = self._video_displays[display_index]
            if not target.isVisible():
                return

            # An RenderThread uebergeben (QImage + Skalierung im Thread)
            rts = getattr(self, '_render_threads', [])
            if display_index < len(rts):
                ds = target.size()
                rts[display_index].submit_frame(bgr, ds.width(), ds.height())
            else:
                # Fallback: direkt im Hauptthread rendern
                self._render_frame_direct(bgr, target)

            # Objekt-Erkennung: nur für Display 0
            if display_index == 0 and self._detection_active and self._detection_thread:
                self._detection_thread.submit_frame(bgr)
        except Exception:
            pass

    def _render_frame_direct(self, bgr, target):
        """Fallback: Frame direkt im Hauptthread rendern (ohne RenderThread)."""
        h, w = bgr.shape[:2]
        qimg = QImage(bgr.data, w, h, 3 * w, QImage.Format.Format_BGR888)
        pixmap = QPixmap.fromImage(qimg)
        display_size = target.size()
        scaled = pixmap.scaled(
            display_size,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.FastTransformation)
        target.setPixmap(scaled)

    def _on_render_ready(self, qimg: QImage, display_index: int):
        """Slot: Empfaengt fertig skaliertes QImage vom RenderThread."""
        try:
            if display_index >= len(self._video_displays):
                return
            target = self._video_displays[display_index]
            if not target.isVisible():
                return
            target.setPixmap(QPixmap.fromImage(qimg))
        except Exception:
            pass

    def _on_video_info_updated(self, info: dict):
        """Aktualisiert die Video-Info-Anzeige."""
        res = info.get('resolution', '?')
        fps = info.get('fps', '?')
        codec = info.get('codec', '?')
        frames = info.get('frames', 0)
        real_fps = info.get('real_fps', '')
        real_part = f"  (real:{real_fps})" if real_fps else ""
        self._video_info_label.setText(
            f"Live Video   {res}   {fps} FPS{real_part}   {codec}   #{frames}"
        )

    def _toggle_video_pause(self, paused: bool):
        """Video-Dekodierung pausieren/fortsetzen."""
        if self._video_decoder:
            self._video_decoder._paused = paused
        self._video_pause_btn.setText("▶ Resume" if paused else "⏸ Pause")

    def _on_stream_detected(self, stream_id: int, display_index: int):
        """Neuer Video-Stream erkannt — Grid automatisch anpassen."""
        if display_index >= 4:
            return
        # Stream-ID-Label setzen
        self._video_id_labels[display_index].setText(f"Stream 0x{stream_id:04X}")

        new_count = display_index + 1
        if new_count > self._video_stream_count:
            self._video_stream_count = new_count
            self._rearrange_video_grid(new_count)

        # Video-Einstellungen-Controls fuer neuen Stream hinzufuegen
        self._add_video_settings_stream(stream_id)

    def _rearrange_video_grid(self, count: int):
        """Video-Panels im Grid neu anordnen."""
        # Alle Panels aus Grid entfernen
        for panel in self._video_panels:
            self._video_grid_layout.removeWidget(panel)
            panel.setVisible(False)

        # Immer 1×N horizontal nebeneinander (eine Zeile)
        for i in range(min(count, len(self._video_panels))):
            self._video_grid_layout.addWidget(
                self._video_panels[i], 0, i)
            self._video_panels[i].setVisible(True)

    def _save_video_snapshot(self):
        """Speichert den aktuellen Video-Frame als PNG."""
        if not self._video_decoder or self._video_decoder._last_frame is None:
            QMessageBox.information(self, "Snapshot", "Kein Video-Frame vorhanden.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Video-Snapshot speichern", "snapshot.png",
            "PNG-Dateien (*.png);;JPEG-Dateien (*.jpg)"
        )
        if path:
            try:
                cv2.imwrite(path, self._video_decoder._last_frame)
                self.status_label.setText(f"Snapshot gespeichert: {path}")
            except Exception as e:
                QMessageBox.critical(self, "Fehler", f"Snapshot konnte nicht gespeichert werden:\n{e}")

    # ----- Objekt-Erkennung Methoden -----

    def _load_detection_reference(self):
        """Lädt ein Referenzbild für die Objekt-Erkennung."""
        if not CV2_AVAILABLE:
            QMessageBox.warning(self, "Fehler", "OpenCV ist nicht verfügbar.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Referenzbild laden", "",
            "Bilddateien (*.png *.jpg *.jpeg *.bmp *.tif *.tiff)"
        )
        if not path:
            return
        img = cv2.imread(path)
        if img is None:
            QMessageBox.warning(self, "Fehler", f"Bild konnte nicht geladen werden:\n{path}")
            return
        # Objekt-Auswahl-Dialog
        dialog = ObjectSelectionDialog(img, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        ref_image = dialog.get_selected_image()
        if ref_image is None:
            return
        self._detection_ref_image = ref_image
        self._object_detector = ObjectDetector()
        self._object_detector.set_reference(ref_image)
        h, w = ref_image.shape[:2]
        method = "Template" if self._object_detector.use_template else "ORB"
        kp = self._object_detector.keypoint_count
        self._detect_ref_btn.setToolTip(
            f"Referenz: {os.path.basename(path)}\n{w}x{h}, {kp} Keypoints, Methode: {method}"
        )
        self._detect_status_label.setText(f"Ref: {w}x{h} {method}")
        self._detect_status_label.setStyleSheet("color: #1976D2;")
        self._detect_toggle_btn.setEnabled(True)

    def _on_detect_action_selected(self, index: int, label: str):
        """Aktions-Auswahl im Menü geändert."""
        self._detection_action_index = index
        self._detect_action_btn.setText(f"Aktion: {label}")

    def _toggle_detection(self, checked: bool):
        """Erkennung ein-/ausschalten."""
        if checked:
            if self._object_detector is None:
                self._detect_toggle_btn.setChecked(False)
                return
            self._detection_thread = DetectionThread(self._object_detector)
            self._detection_thread.detection_result.connect(self._on_detection_result)
            self._detection_thread.start()
            self._detection_active = True
            self._detect_toggle_btn.setText("■ Erkennung")
            self._detect_status_label.setText("Aktiv")
            self._detect_status_label.setStyleSheet("color: #E65100; font-weight: bold;")
        else:
            self._detection_active = False
            if self._detection_thread:
                self._detection_thread.stop()
                self._detection_thread.deleteLater()
                self._detection_thread = None
            self._detect_toggle_btn.setText("▶ Erkennung")
            self._detect_status_label.setText("")
            self._detect_status_label.setStyleSheet("")
            self._detection_cooldown = False

    def _on_detection_result(self, result: dict):
        """Callback für Erkennungsergebnis aus dem Detection-Thread."""
        conf = result.get('confidence', 0.0)
        detected = result.get('detected', False)
        pct = int(conf * 100)
        if detected:
            self._detect_status_label.setText(f"{pct}% ✓")
            self._detect_status_label.setStyleSheet("color: #2E7D32; font-weight: bold;")
        else:
            self._detect_status_label.setText(f"{pct}%")
            self._detect_status_label.setStyleSheet("color: #9E9E9E;")
        if detected and not self._detection_cooldown:
            self._detection_cooldown = True
            QTimer.singleShot(3000, self._reset_detection_cooldown)
            self._execute_detection_action(result)

    def _reset_detection_cooldown(self):
        """Setzt den Detection-Cooldown zurück."""
        self._detection_cooldown = False

    def _execute_detection_action(self, result: dict):
        """Führt die konfigurierte Aktion bei Erkennung aus."""
        conf = result.get('confidence', 0.0)
        ts = result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])

        if self._detection_action_index == 0:
            # Zeitstempel loggen
            if self._detection_log_path is None:
                path, _ = QFileDialog.getSaveFileName(
                    self, "Detection-Log speichern", "detection_log.txt",
                    "Textdateien (*.txt);;Alle Dateien (*)"
                )
                if not path:
                    return
                self._detection_log_path = path
            try:
                with open(self._detection_log_path, 'a', encoding='utf-8') as f:
                    f.write(f"{ts} — Objekt erkannt (Confidence: {conf:.2f})\n")
                self.status_label.setText(f"Detection Log: {ts} (Confidence: {conf:.2f})")
            except Exception as e:
                self.status_label.setText(f"Log-Fehler: {e}")

        elif self._detection_action_index == 1:
            # Capture stoppen
            self.status_label.setText(f"Objekt erkannt ({conf:.0%}) — Capture wird gestoppt")
            self._stop_live_capture()

        elif self._detection_action_index == 2:
            # Video-Snapshot automatisch speichern
            if self._video_decoder and self._video_decoder._last_frame is not None:
                snap_name = f"detection_{ts.replace(':', '-').replace(' ', '_')}.png"
                snap_dir = os.path.dirname(self._detection_log_path) if self._detection_log_path else "."
                snap_path = os.path.join(snap_dir, snap_name)
                try:
                    cv2.imwrite(snap_path, self._video_decoder._last_frame)
                    self.status_label.setText(f"Detection-Snapshot: {snap_path}")
                except Exception as e:
                    self.status_label.setText(f"Snapshot-Fehler: {e}")

        elif self._detection_action_index == 3:
            # Nur Markierung — Label blinkt orange
            self._detect_status_label.setStyleSheet(
                "color: #E65100; font-weight: bold; background-color: #FFF3E0;"
            )
            self.status_label.setText(f"Objekt erkannt ({conf:.0%}) — {ts}")
            QTimer.singleShot(1500, lambda: self._detect_status_label.setStyleSheet(
                "color: #2E7D32; font-weight: bold;" if self._detection_active else ""
            ))

    def _toggle_packet_display(self, checked: bool):
        """Paketanzeige ein-/ausschalten."""
        self._packet_display_paused = not checked
        if checked:
            self._packet_display_btn.setText("⏸ Daten")
        else:
            self._packet_display_btn.setText("▶ Daten")

    def _add_packet_to_table(self, pkt, index: int):
        """Fügt ein einzelnes Paket zur Tabelle hinzu (für Live-Capture Performance)."""
        if self._packet_display_paused:
            return
        # Zeit (relative Zeit seit erstem Paket)
        zeit = ""
        if hasattr(pkt, 'time'):
            if len(self.packets) == 1:
                self._base_time = pkt.time
            rel_time = pkt.time - getattr(self, '_base_time', pkt.time)
            zeit = f"{rel_time:.6f}"

        src, dst, proto, info = self._get_packet_info(pkt)
        row_tuple = (str(self._total_trimmed + index + 1), zeit, src, dst, proto, str(len(pkt)), info)

        # Farbkodierung
        packet_data = self._extract_packet_color_data(pkt, proto, info)
        fg, bg = self._color_rules_manager.evaluate(packet_data)
        color_tuple = (fg, bg)

        self.packet_model.append_rows([row_tuple], [color_tuple])

        # Zur letzten Zeile scrollen (Auto-Scroll)
        self.packet_table.scrollToBottom()

    def _on_capture_error(self, error: str):
        """Wird bei Capture-Fehlern aufgerufen."""
        self._stop_live_capture()

        # Prüfen ob es ein Berechtigungsfehler ist
        if "Operation not permitted" in error or "Errno 1" in error:
            reply = QMessageBox.question(
                self, "Berechtigungsfehler",
                "Live-Capture erfordert Administrator-Rechte.\n\n"
                "Möchten Sie jetzt die Berechtigung einrichten?\n"
                "(Erfordert einmalig Ihr Administrator-Passwort)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                self._setup_capture_permissions()
        else:
            QMessageBox.critical(
                self, "Capture-Fehler",
                f"Fehler beim Live-Capture:\n{error}"
            )

    def _on_capture_started(self):
        """Wird aufgerufen, wenn die Capture gestartet wurde."""
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_bar.show()

    def _on_capture_finished(self):
        """Wird aufgerufen, wenn die Capture beendet wurde."""
        self.progress_bar.hide()
        if self._is_capturing:  # Nur wenn nicht manuell gestoppt
            self._stop_live_capture()

    def _clear_live_packets(self):
        """Leert die Liste der Live-Pakete."""
        self.packets = PacketStore()
        self.filtered_indices = []
        self._total_trimmed = 0
        self.packet_model.clear()
        self.detail_tree.clear()
        self.hex_view.clear()
        self.packet_count_label.setText("Pakete: 0")
        self.status_label.setText("Paketliste geleert")

    def _setup_capture_permissions(self):
        """Richtet die Capture-Berechtigungen mit Administrator-Passwort ein."""
        from core.platform import IS_WINDOWS, setup_capture_permissions_command

        if IS_WINDOWS:
            QMessageBox.information(
                self,
                "Windows: Npcap erforderlich",
                "Unter Windows wird Npcap fuer Live-Capture benoetigt.\n\n"
                "Bitte laden Sie Npcap von https://npcap.com herunter\n"
                "und installieren Sie es mit der Option\n"
                "'Install Npcap in WinPcap API-compatible Mode'."
            )
            return

        # Linux: setcap-basierte Berechtigung
        python_path = os.path.realpath(sys.executable)
        setcap_cmd = setup_capture_permissions_command()

        # Passwort-Dialog anzeigen
        password, ok = QInputDialog.getText(
            self,
            "Administrator-Passwort",
            f"Bitte geben Sie Ihr Administrator-Passwort ein,\n"
            f"um die Capture-Berechtigung für Python einzurichten:\n\n"
            f"Python-Pfad: {python_path}",
            QLineEdit.EchoMode.Password
        )

        if not ok or not password:
            return

        cmd = f"echo '{password}' | sudo -S {setcap_cmd}"

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                QMessageBox.information(
                    self,
                    "Erfolg",
                    "Die Capture-Berechtigung wurde erfolgreich eingerichtet!\n\n"
                    "Sie können die Live-Capture jetzt starten.\n"
                    "(Diese Einrichtung ist dauerhaft und muss nicht wiederholt werden)"
                )
                self.status_label.setText("Berechtigung eingerichtet - Bereit für Live-Capture")
            else:
                error_msg = result.stderr.strip()
                if "incorrect password" in error_msg.lower() or "sorry" in error_msg.lower():
                    QMessageBox.warning(
                        self,
                        "Falsches Passwort",
                        "Das eingegebene Passwort ist falsch.\n"
                        "Bitte versuchen Sie es erneut."
                    )
                else:
                    QMessageBox.critical(
                        self,
                        "Fehler",
                        f"Fehler beim Einrichten der Berechtigung:\n{error_msg}"
                    )
        except subprocess.TimeoutExpired:
            QMessageBox.critical(
                self,
                "Zeitüberschreitung",
                "Die Passwort-Überprüfung hat zu lange gedauert."
            )
        except Exception as e:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Unerwarteter Fehler:\n{str(e)}"
            )

    def _read_net_dev(self) -> Dict[str, Tuple[int, int]]:
        """Gibt pro Interface (rx_bytes, tx_bytes) zurueck."""
        from core.platform import get_net_io_counters
        return get_net_io_counters()

    def _format_speed(self, bytes_per_sec: int) -> str:
        """Formatiert Geschwindigkeit in lesbare Einheiten."""
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec} B/s"
        elif bytes_per_sec < 1024 * 1024:
            return f"{bytes_per_sec / 1024:.1f} KB/s"
        elif bytes_per_sec < 1024 * 1024 * 1024:
            return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
        else:
            return f"{bytes_per_sec / (1024 * 1024 * 1024):.1f} GB/s"

    def _update_net_speed(self):
        """Aktualisiert die Netzwerk-Geschwindigkeitsanzeige (jede Sekunde)."""
        current = self._read_net_dev()
        if not current:
            return

        if self._prev_net_stats:
            total_rx = 0
            total_tx = 0
            active_ifaces = set()

            for iface, (rx, tx) in current.items():
                prev = self._prev_net_stats.get(iface)
                if prev is None:
                    continue
                delta_rx = max(0, rx - prev[0])
                delta_tx = max(0, tx - prev[1])
                total_rx += delta_rx
                total_tx += delta_tx
                active_ifaces.add(iface)

                # Interface-Labels erstellen oder aktualisieren
                if iface not in self._net_speed_labels:
                    row_layout = QHBoxLayout()
                    name_label = QLabel(f"{iface}:")
                    name_label.setFixedWidth(72)
                    name_label.setFont(QFont("Consolas", 9))
                    rx_label = QLabel("↓ 0 B/s")
                    rx_label.setFont(QFont("Consolas", 9))
                    rx_label.setStyleSheet("color: #2e7d32;")
                    rx_label.setFixedWidth(84)
                    tx_label = QLabel("↑ 0 B/s")
                    tx_label.setFont(QFont("Consolas", 9))
                    tx_label.setStyleSheet("color: #1565c0;")
                    tx_label.setFixedWidth(84)
                    row_layout.addWidget(name_label)
                    row_layout.addWidget(rx_label)
                    row_layout.addWidget(tx_label)
                    row_layout.addStretch()
                    self._net_speed_iface_container.addLayout(row_layout)
                    self._net_speed_labels[iface] = (name_label, rx_label, tx_label)

                _, rx_label, tx_label = self._net_speed_labels[iface]
                rx_label.setText(f"↓ {self._format_speed(delta_rx)}")
                tx_label.setText(f"↑ {self._format_speed(delta_tx)}")

            # Verschwundene Interfaces ausblenden
            for iface in list(self._net_speed_labels.keys()):
                if iface not in active_ifaces:
                    name_l, rx_l, tx_l = self._net_speed_labels[iface]
                    name_l.hide()
                    rx_l.hide()
                    tx_l.hide()

            # Gesamt aktualisieren
            self._net_speed_total_rx.setText(f"↓ {self._format_speed(total_rx)}")
            self._net_speed_total_tx.setText(f"↑ {self._format_speed(total_tx)}")

        self._prev_net_stats = current

    def _toggle_net_speed(self):
        """Klappt den Netzwerk-Durchsatz-Bereich ein/aus."""
        self._net_speed_expanded = not self._net_speed_expanded
        if self._net_speed_expanded:
            self._net_speed_content.show()
            self._net_speed_toggle_btn.setText("📊 Netzwerk-Durchsatz ▼")
        else:
            self._net_speed_content.hide()
            self._net_speed_toggle_btn.setText("📊 Netzwerk-Durchsatz ▶")

    # ── Loss Monitor (ECharts WebEngine) ──

    def _read_nic_stats(self) -> Dict[str, Dict[str, int]]:
        """Liest NIC-Statistiken pro Interface aus sysfs (~5µs Overhead).

        Returns: {iface: {missed, dropped, errors, crc, packets, bytes}}
        """
        result = {}
        ifaces = getattr(self, '_inline_counter_ifaces', [])
        stats_names = ['rx_missed_errors', 'rx_dropped', 'rx_errors',
                       'rx_crc_errors', 'rx_packets', 'rx_bytes']
        keys = ['missed', 'dropped', 'errors', 'crc', 'packets', 'bytes']
        for iface in ifaces:
            d = {}
            for sname, key in zip(stats_names, keys):
                try:
                    with open(f'/sys/class/net/{iface}/statistics/{sname}') as f:
                        d[key] = int(f.read().strip())
                except (OSError, ValueError):
                    d[key] = 0
            result[iface] = d
        return result

    def _toggle_loss_monitor(self):
        """Klappt das Loss-Monitor Panel ein/aus."""
        self._loss_expanded = not self._loss_expanded
        if self._loss_expanded:
            self._loss_content.show()
            self._loss_toggle_btn.setText("📉 Loss Monitor ▼")
        else:
            self._loss_content.hide()
            self._loss_toggle_btn.setText("📉 Loss Monitor ▶")

    def _update_loss_monitor(self):
        """Aktualisiert das Loss-Monitor Panel (alle 2 Sekunden).

        Sammelt Daten aus 3 Ebenen und pusht per-Interface JSON an ECharts:
          1. NIC-Level: rx_missed, rx_dropped, rx_errors, rx_crc (sysfs)
          2. Kernel-Level: kern_drops (AF_PACKET PACKET_STATISTICS, Shared Array)
          3. PLP-Level: Counter Gaps (Shared Array)
        """
        if self._loss_webview is None:
            return

        # ── 1. NIC Stats pro Interface (sysfs) ──
        curr = self._read_nic_stats()
        iface_data = {}
        nic_total_delta = 0
        total_pps = 0

        for iface, stats in curr.items():
            prev_missed = self._loss_prev_rx_missed.get(iface, stats['missed'])
            prev_dropped = self._loss_prev_rx_dropped.get(iface, stats['dropped'])
            prev_errors = self._loss_prev_rx_errors.get(iface, stats['errors'])
            prev_crc = self._loss_prev_rx_crc.get(iface, stats['crc'])
            prev_pkts = self._loss_prev_rx_packets.get(iface, stats['packets'])
            prev_bytes = self._loss_prev_rx_bytes.get(iface, stats['bytes'])

            d_missed = max(0, stats['missed'] - prev_missed)
            d_dropped = max(0, stats['dropped'] - prev_dropped)
            d_errors = max(0, stats['errors'] - prev_errors)
            d_crc = max(0, stats['crc'] - prev_crc)
            d_pkts = max(0, stats['packets'] - prev_pkts)
            d_bytes = max(0, stats['bytes'] - prev_bytes)
            pps = d_pkts // 2  # 2s Intervall
            bps = d_bytes // 2

            nic_total_delta += d_missed
            total_pps += pps

            iface_data[iface] = {
                'missed': d_missed,
                'dropped': d_dropped,
                'errors': d_errors,
                'crc': d_crc,
                'pps': pps,
                'bps': bps,
                # Kumulative Werte (Σ)
                'missed_sum': stats['missed'],
                'dropped_sum': stats['dropped'],
                'errors_sum': stats['errors'],
                'crc_sum': stats['crc'],
            }

            self._loss_prev_rx_missed[iface] = stats['missed']
            self._loss_prev_rx_dropped[iface] = stats['dropped']
            self._loss_prev_rx_errors[iface] = stats['errors']
            self._loss_prev_rx_crc[iface] = stats['crc']
            self._loss_prev_rx_packets[iface] = stats['packets']
            self._loss_prev_rx_bytes[iface] = stats['bytes']

        # ── 2+3. kern_drops + plp_gaps aus Shared Array ──
        kern_delta = 0
        kern_sum = 0
        plp_delta = 0
        plp_sum = 0
        ict = getattr(self, '_inline_counter_stats', None)
        n_workers = getattr(self, '_inline_counter_workers', 0)
        if ict and n_workers > 0:
            for widx in range(n_workers):
                base = widx * _ICT_FIELDS
                try:
                    w_gaps = ict[base + _ICT_GAPS]
                    w_kern = ict[base + _ICT_KERN_DROPS]
                except (IndexError, Exception):
                    continue

                kern_sum += w_kern
                plp_sum += w_gaps

                prev_k = self._loss_prev_kern_drops.get(widx, w_kern)
                kern_delta += max(0, w_kern - prev_k)
                self._loss_prev_kern_drops[widx] = w_kern

                prev_g = self._loss_prev_plp_gaps.get(widx, w_gaps)
                plp_delta += max(0, w_gaps - prev_g)
                self._loss_prev_plp_gaps[widx] = w_gaps

        # ── JSON zusammenbauen und an ECharts pushen ──
        import json
        payload = json.dumps({
            'ifaces': iface_data,
            'kern': kern_delta,
            'kern_sum': kern_sum,
            'plp': plp_delta,
            'plp_sum': plp_sum,
            'total_pps': total_pps,
            'nic_total': nic_total_delta,
        }, separators=(',', ':'))

        js = f"window.pushData('{payload}');"
        try:
            self._loss_webview.page().runJavaScript(js)
        except Exception:
            pass

        # ── NIC-Konfiguration einmalig senden ──
        if not self._loss_config_sent and curr:
            iface0 = list(curr.keys())[0]
            try:
                import subprocess
                r = subprocess.run(
                    ['ethtool', '-c', iface0],
                    capture_output=True, text=True, timeout=2)
                adaptive = 'on'
                usecs = '50'
                for line in r.stdout.splitlines():
                    if 'Adaptive RX:' in line:
                        adaptive = line.split()[-3]
                    if line.startswith('rx-usecs:'):
                        usecs = line.split()[-1]
                cfg = f"adaptive-rx {adaptive} | rx-usecs {usecs}"
            except Exception:
                cfg = "—"
            js_cfg = f"window.setConfig('{cfg}');"
            try:
                self._loss_webview.page().runJavaScript(js_cfg)
            except Exception:
                pass
            self._loss_config_sent = True

    def _stop_loss_monitor(self):
        """Stoppt den Loss-Monitor Timer."""
        self._loss_monitor_timer.stop()
        self._loss_prev_rx_missed.clear()
        self._loss_prev_rx_dropped.clear()
        self._loss_prev_rx_errors.clear()
        self._loss_prev_rx_crc.clear()
        self._loss_prev_rx_packets.clear()
        self._loss_prev_rx_bytes.clear()
        self._loss_prev_kern_drops.clear()
        self._loss_prev_plp_gaps.clear()
        self._loss_config_sent = False

    # ── PLP Counter Monitor Methoden ──

    def _toggle_counter_panel(self):
        """Klappt das PLP Counter Panel ein/aus."""
        self._counter_expanded = not self._counter_expanded
        if self._counter_expanded:
            self._counter_content.show()
            self._counter_toggle_btn.setText("🔢 PLP Counter ▼")
        else:
            self._counter_content.hide()
            self._counter_toggle_btn.setText("🔢 PLP Counter ▶")

    def _start_counter_monitor(self, interfaces: list):
        """Startet den PLP Counter Monitor (Inline-Modus).

        Kein separater Prozess mehr — Counter werden direkt in den
        CaptureWorker-Prozessen extrahiert (gleicher AF_PACKET Socket).
        Vorteile: kein zweiter Socket → kein NAPI-Doubling → kein Jitter.
        """
        self._stop_counter_monitor()
        logger = logging.getLogger(__name__)

        # Inline-Modus: CaptureWorker schreiben direkt in
        # self._inline_counter_stats (bereits beim Worker-Start erstellt)
        ict = getattr(self, '_inline_counter_stats', None)
        if ict is None:
            logger.warning("Counter Monitor: kein inline_counter_stats, "
                           "CaptureWorker noch nicht gestartet?")
            return

        self._cm_interfaces = list(interfaces)[:_CM_MAX_IFACES]
        self._cm_inline_mode = True
        self._cm_start_time = time.time()

        logger.info(f"PLP Counter Monitor (INLINE): {interfaces}")

        # QTimer liest jede Sekunde die Shared-Daten
        self._cm_timer = QTimer()
        self._cm_timer.timeout.connect(self._poll_counter_stats)
        self._cm_timer.start(1000)

        # Gap-Analyse Timer starten
        self._gap_poll_timer.start()

    def _stop_counter_monitor(self):
        """Stoppt den PLP Counter Monitor."""
        if hasattr(self, '_cm_timer') and self._cm_timer:
            self._cm_timer.stop()
            self._cm_timer = None
        if hasattr(self, '_gap_poll_timer'):
            self._gap_poll_timer.stop()
            self._counter_gap_label.hide()
        # Legacy-Modus: separaten Prozess stoppen
        if hasattr(self, '_cm_stop') and self._cm_stop:
            self._cm_stop.set()
        if hasattr(self, '_cm_process') and self._cm_process:
            self._cm_process.join(timeout=2)
            if self._cm_process.is_alive():
                self._cm_process.terminate()
            self._cm_process = None

    def _toggle_counter_monitor_running(self, paused: bool):
        """Pausiert oder setzt den Counter Monitor fort (Diagnose-Modus)."""
        try:
            if paused:
                # Inline-Modus: CaptureWorker Counter-Extraktion stoppen
                icp = getattr(self, '_inline_counter_pause', None)
                if icp is not None:
                    icp.set()
                # Legacy-Modus
                if hasattr(self, '_cm_pause'):
                    self._cm_pause.set()
                self._counter_stop_btn.setText("▶ Counter fortsetzen")
                for *_, val in [v[:2] for v in self._counter_labels.values()]:
                    val.setText("—  (pausiert)")
                self._counter_since_label.setText("Counter Monitor pausiert")
                # Jitter-Log Marker
                try:
                    import time as _t
                    with open('/tmp/0x2090_jitter.log', 'a') as _f:
                        _f.write(f"\n{'='*60}\n"
                                 f">>> COUNTER MONITOR PAUSIERT  {_t.strftime('%H:%M:%S')}\n"
                                 f"{'='*60}\n")
                except Exception:
                    pass
            else:
                # Inline-Modus: Counter-Extraktion wieder aktivieren
                icp = getattr(self, '_inline_counter_pause', None)
                if icp is not None:
                    icp.clear()
                # Legacy-Modus
                if hasattr(self, '_cm_reset'):
                    self._cm_reset.set()
                if hasattr(self, '_cm_pause'):
                    self._cm_pause.clear()
                self._counter_stop_btn.setText("⏹ Counter pausieren")
                # Jitter-Log Marker
                try:
                    import time as _t
                    with open('/tmp/0x2090_jitter.log', 'a') as _f:
                        _f.write(f"\n{'='*60}\n"
                                 f">>> COUNTER MONITOR FORTGESETZT  {_t.strftime('%H:%M:%S')}\n"
                                 f"{'='*60}\n")
                except Exception:
                    pass
                print("[DIAG] DONE (resumed)", flush=True)
        except Exception as e:
            print(f"[DIAG] EXCEPTION: {e}", flush=True)
            traceback.print_exc()

    def _reset_counter_monitor(self):
        """Setzt Counter-Statistiken zurueck.

        Inline-Modus: Snapshot der aktuellen Werte speichern,
        danach werden nur die Differenzen angezeigt.
        """
        # Legacy-Modus
        if hasattr(self, '_cm_reset') and self._cm_reset:
            self._cm_reset.set()
        # Inline-Modus: Snapshot speichern
        ict = getattr(self, '_inline_counter_stats', None)
        if ict is not None:
            n_workers = getattr(self, '_inline_counter_workers', 0)
            snap = {}
            for widx in range(n_workers):
                base = widx * _ICT_FIELDS
                try:
                    snap[widx] = (ict[base + _ICT_TOTAL],
                                  ict[base + _ICT_GAPS],
                                  ict[base + _ICT_LOST])
                except (IndexError, Exception):
                    snap[widx] = (0, 0, 0)
            self._inline_counter_snapshot = snap
        # Worker-Prozesse anweisen, Gap/OOO-Daten zurueckzusetzen
        icr = getattr(self, '_inline_counter_reset', None)
        if icr is not None:
            icr.value += 1
        for entry in self._counter_labels.values():
            entry[1].setText("—  (zurückgesetzt)")
            # OOO Label zuruecksetzen
            if len(entry) > 2:
                entry[2].setText(
                    '<span style="color:#2e7d32">'
                    'Out-of-Order: 0</span>')
            # Gap Label zuruecksetzen
            if len(entry) > 3:
                entry[3].setText("")
                entry[3].hide()
        self._counter_gap_label.hide()
        self._cm_start_time = time.time()
        self._counter_since_label.setText(
            f"Seit: {time.strftime('%H:%M:%S')}")

    def _poll_counter_stats(self):
        """Liest Counter-Statistiken aus Shared Array (QTimer, 1x/s)."""
        inline = getattr(self, '_cm_inline_mode', False)
        if inline:
            return self._poll_counter_stats_inline()
        # Legacy-Modus (separater Prozess)
        if not hasattr(self, '_cm_stats') or not self._cm_stats:
            return
        ifaces = getattr(self, '_cm_interfaces', [])
        since_h = self._cm_since[0]
        since_m = self._cm_since[1]
        since_s = self._cm_since[2]
        since_str = f"{since_h:02d}:{since_m:02d}:{since_s:02d}"

        stats = {}
        for i, iface in enumerate(ifaces):
            base = i * _CM_FIELDS
            total = self._cm_stats[base + _CM_TOTAL]
            gaps = self._cm_stats[base + _CM_GAPS]
            lost = self._cm_stats[base + _CM_LOST]
            sids = []
            for si in range(8):
                v = self._cm_stats[base + _CM_STREAMS_START + si]
                if v != 0:
                    sids.append(v)
            total_exp = total + lost
            rate = lost / total_exp if total_exp > 0 else 0.0
            stats[iface] = {
                'total': total, 'gaps': gaps, 'lost': lost,
                'rate': rate, 'since': since_str, 'streams': sids,
            }
        self._on_counter_stats_updated(stats)

    def _poll_counter_stats_inline(self):
        """Liest Counter-Statistiken aus CaptureWorker Inline-Array."""
        ict = getattr(self, '_inline_counter_stats', None)
        if ict is None:
            return
        n_workers = getattr(self, '_inline_counter_workers', 0)
        ifaces = getattr(self, '_inline_counter_ifaces', [])
        start_time = getattr(self, '_cm_start_time', time.time())
        snap = getattr(self, '_inline_counter_snapshot', None)

        # 启动时间 → "Seit" 格式
        t = time.localtime(start_time)
        since_str = f"{t.tm_hour:02d}:{t.tm_min:02d}:{t.tm_sec:02d}"

        # 每个 interface 有 2 个 worker — 合并它们的统计
        WORKERS_PER_IFACE = 2
        stats = {}
        for iface_idx, iface in enumerate(ifaces):
            total = 0
            gaps = 0
            lost = 0
            all_sids = set()
            for w in range(WORKERS_PER_IFACE):
                widx = iface_idx * WORKERS_PER_IFACE + w
                if widx >= n_workers:
                    break
                base = widx * _ICT_FIELDS
                try:
                    w_total = ict[base + _ICT_TOTAL]
                    w_gaps = ict[base + _ICT_GAPS]
                    w_lost = ict[base + _ICT_LOST]
                    # Snapshot abziehen (Reset-Funktion)
                    if snap and widx in snap:
                        s_total, s_gaps, s_lost = snap[widx]
                        w_total -= s_total
                        w_gaps -= s_gaps
                        w_lost -= s_lost
                    total += w_total
                    gaps += w_gaps
                    lost += w_lost
                    for si in range(8):
                        v = ict[base + _ICT_STREAMS_START + si]
                        if v != 0:
                            all_sids.add(v)
                except (IndexError, Exception):
                    pass

            total_exp = total + lost
            rate = lost / total_exp if total_exp > 0 else 0.0
            stats[iface] = {
                'total': total, 'gaps': gaps, 'lost': lost,
                'rate': rate, 'since': since_str,
                'streams': sorted(all_sids),
            }
        self._on_counter_stats_updated(stats)

    def _on_counter_stats_updated(self, stats: dict):
        """Aktualisiert die Counter-Anzeige mit neuen Statistiken."""
        since_str = "—"
        for iface, st in stats.items():
            since_str = st['since']
            rate = st['rate']
            gaps = st['gaps']
            lost = st['lost']
            total = st['total']
            streams = st.get('streams', [])

            # Dynamisch Label erstellen falls noch nicht vorhanden
            if iface not in self._counter_labels:
                row = QVBoxLayout()
                streams_str = "/".join(f"0x{s:02X}" for s in streams) if streams else "..."
                hdr = QLabel(f"{iface} ({streams_str}):")
                hdr.setFont(QFont("Consolas", 9, QFont.Weight.Bold))
                row.addWidget(hdr)
                val = QLabel("—  (wartend)")
                val.setFont(QFont("Consolas", 9))
                val.setWordWrap(True)
                val.setTextFormat(Qt.TextFormat.RichText)
                val.setStyleSheet("padding-left: 4px;")
                row.addWidget(val)
                ooo = QLabel("")
                ooo.setFont(QFont("Consolas", 9))
                ooo.setWordWrap(True)
                ooo.setTextFormat(Qt.TextFormat.RichText)
                ooo.setStyleSheet("padding-left: 4px;")
                row.addWidget(ooo)
                gap = QLabel("")
                gap.setFont(QFont("Consolas", 9))
                gap.setWordWrap(True)
                gap.setTextFormat(Qt.TextFormat.RichText)
                gap.setStyleSheet("padding-left: 4px;")
                gap.hide()
                row.addWidget(gap)
                self._counter_iface_container.addLayout(row)
                self._counter_labels[iface] = (hdr, val, ooo, gap)

            hdr, val = self._counter_labels[iface][:2]

            # Header mit erkannten Stream-IDs aktualisieren
            if streams:
                streams_str = "/".join(f"0x{s:02X}" for s in streams)
                hdr.setText(f"{iface} ({streams_str}):")

            # Farben: Verlustrate/Verlust=rot, Empfangen=gruen, Luecken=orange
            if gaps == 0:
                val.setText(
                    f'<span style="color:#2e7d32">Verlust 0%</span>, '
                    f'<span style="color:#2e7d32">{total}</span> Pakete empfangen')
            else:
                val.setText(
                    f'Verlust <span style="color:#d32f2f">{rate:.4%}</span>, '
                    f'<span style="color:#d32f2f">{lost}</span> verloren, '
                    f'<span style="color:#e6a117">{gaps}</span> Lücken, '
                    f'<span style="color:#2e7d32">{total}</span> empfangen')

        self._counter_since_label.setText(f"Seit: {since_str}")

    def _get_iface_stream_label(self, widx, ifaces, workers_per_iface):
        """Gibt Stream-ID-Label fuer einen Worker-Index zurueck (z.B. '0x64')."""
        iface_idx = widx // workers_per_iface
        if iface_idx < len(ifaces):
            iface = ifaces[iface_idx]
            if iface in self._counter_labels:
                hdr = self._counter_labels[iface][0]
                txt = hdr.text()  # z.B. "eno8np3 (0x64):"
                start = txt.find('(')
                end = txt.find(')')
                if start != -1 and end != -1:
                    return txt[start + 1:end]
            return iface
        return f"w{widx}"

    def _poll_gap_files(self):
        """Liest Gap-Analyse-Dateien der Worker und zeigt Details an (per Interface)."""
        n_workers = getattr(self, '_inline_counter_workers', 0)
        if n_workers == 0:
            return
        ifaces = getattr(self, '_inline_counter_ifaces', [])
        WORKERS_PER_IFACE = 2
        has_data = False

        # Per-Interface Datenstrukturen
        gaps_per_iface = {}
        buckets_per_iface = {}
        det_per_iface = {}
        ooo_per_iface = {}
        ooo_events = {}

        for widx in range(n_workers):
            iface_idx = widx // WORKERS_PER_IFACE
            iface_name = ifaces[iface_idx] if iface_idx < len(ifaces) else f"w{widx}"

            path = f'/tmp/plp_gaps_w{widx}.dat'
            try:
                with open(path, 'r') as f:
                    file_lines = f.readlines()
            except (FileNotFoundError, OSError):
                continue
            section = 'meta'
            for line in file_lines:
                line = line.strip()
                if not line:
                    continue
                if line == '---':
                    section = 'buckets'
                    continue
                if line == '===':
                    section = 'ooo'
                    continue
                if line.startswith('S:'):
                    parts = line.split(',')
                    for p in parts:
                        if p.startswith('T:'):
                            try:
                                det_per_iface[iface_name] = det_per_iface.get(iface_name, 0) + int(p[2:])
                            except ValueError:
                                pass
                        if p.startswith('O:'):
                            try:
                                ooo_per_iface[iface_name] = ooo_per_iface.get(iface_name, 0) + int(p[2:])
                            except (ValueError, IndexError):
                                pass
                    has_data = True
                elif line.startswith('G:') and section != 'buckets':
                    try:
                        parts = line[2:].split(',')
                        prev = int(parts[0])
                        curr = int(parts[1])
                        nmiss = int(parts[2])
                        gaps_per_iface.setdefault(iface_name, []).append((prev, curr, nmiss))
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('B:'):
                    try:
                        parts = line[2:].split(',')
                        bi = int(parts[0])
                        cnt = int(parts[1])
                        bkt = buckets_per_iface.setdefault(iface_name, {})
                        bkt[bi] = bkt.get(bi, 0) + cnt
                    except (ValueError, IndexError):
                        pass
                elif line.startswith('OOO:'):
                    try:
                        parts = line[4:].split(',')
                        prev = int(parts[0])
                        curr = int(parts[1])
                        ooo_events.setdefault(iface_name, []).append((prev, curr))
                    except (ValueError, IndexError):
                        pass

        if not has_data:
            self._counter_gap_label.hide()
            for iface_name in ifaces:
                if iface_name in self._counter_labels and len(self._counter_labels[iface_name]) > 3:
                    self._counter_labels[iface_name][3].hide()
            return

        # OOO per Interface Label aktualisieren
        for iface_name in (ifaces if ifaces else list(ooo_per_iface.keys())):
            if iface_name not in self._counter_labels:
                continue
            entry = self._counter_labels[iface_name]
            ooo_label = entry[2] if len(entry) > 2 else None
            if ooo_label is None:
                continue
            ooo_count = ooo_per_iface.get(iface_name, 0)
            if ooo_count == 0:
                ooo_label.setText(
                    '<span style="color:#2e7d32">'
                    'Out-of-Order: 0</span>')
            else:
                ooo_parts = [
                    f'<b style="color:#d32f2f">'
                    f'Out-of-Order: {ooo_count}</b>']
                for prev, curr in reversed(ooo_events.get(iface_name, [])[-5:]):
                    ooo_parts.append(
                        f'<br>&nbsp;&nbsp;{prev}\u2192{curr} '
                        f'<span style="color:#d32f2f">'
                        f'(R\u00fcckw\u00e4rts)</span>')
                ooo_label.setText(''.join(ooo_parts))

        # Gap-Analyse per Interface Label aktualisieren
        for iface_name in ifaces:
            if iface_name not in self._counter_labels:
                continue
            entry = self._counter_labels[iface_name]
            gap_label = entry[3] if len(entry) > 3 else None
            if gap_label is None:
                continue

            iface_det = det_per_iface.get(iface_name, 0)
            iface_gaps = gaps_per_iface.get(iface_name, [])
            iface_bkt = buckets_per_iface.get(iface_name, {})
            # Stream-ID Label fuer diese Interface bestimmen
            if iface_name in self._counter_labels:
                _hdr_txt = self._counter_labels[iface_name][0].text()
                _s = _hdr_txt.find('(')
                _e = _hdr_txt.find(')')
                iface_stream = _hdr_txt[_s+1:_e] if _s != -1 and _e != -1 else iface_name
            else:
                iface_stream = iface_name

            if iface_det == 0 and not iface_gaps:
                gap_label.hide()
                continue

            html = []
            html.append(
                f'Fehlende Counter gesamt: '
                f'<b>{iface_det}</b><br>')

            recent = iface_gaps[-8:]
            if recent:
                html.append(
                    '<span style="color:#888">'
                    'Letzte L\u00fccken:</span><br>')
                for prev, curr, nmiss in reversed(recent):
                    miss_start = (prev + 1) & 0xFFFF
                    if nmiss <= 8:
                        miss_vals = ", ".join(
                            str((miss_start + i) & 0xFFFF)
                            for i in range(nmiss))
                    else:
                        miss_vals = (
                            ", ".join(
                                str((miss_start + i) & 0xFFFF)
                                for i in range(4))
                            + " ... "
                            + ", ".join(
                                str((miss_start + nmiss - 2 + i)
                                    & 0xFFFF)
                                for i in range(2)))
                    html.append(
                        f'&nbsp;&nbsp;{iface_stream}: {prev}\u2192{curr} '
                        f'<span style="color:#d32f2f">'
                        f'fehlt [{miss_vals}]</span> '
                        f'({nmiss})<br>')

            if iface_bkt:
                top = sorted(iface_bkt.items(),
                             key=lambda x: -x[1])[:5]
                html.append(
                    '<span style="color:#888">'
                    'H\u00e4ufigste Bereiche:</span><br>')
                for bi, cnt in top:
                    r_start = bi * 256
                    r_end = r_start + 255
                    html.append(
                        f'&nbsp;&nbsp;Counter '
                        f'{r_start}-{r_end}: '
                        f'<b>{cnt}</b>\u00d7<br>')

            gap_label.setText(''.join(html))
            gap_label.show()

        # Globales gap_label nicht mehr benoetigt
        self._counter_gap_label.hide()

    # ═══════════════════════════════════════════════════════════════════════
    # Logger-Fernsteuerung (CCA REST API) — UI-Aufbau
    # ═══════════════════════════════════════════════════════════════════════

    def _create_logger_control_rows(self, parent_layout: QVBoxLayout):
        """Erstellt Base-URL + OAuth2 Zeilen für Logger-Fernsteuerung."""
        self._logger_control_widget = QWidget()
        container = QVBoxLayout(self._logger_control_widget)
        container.setContentsMargins(0, 0, 0, 0)
        container.setSpacing(0)

        # ── Zeile 1: Base-URL ──
        url_row = QWidget()
        url_row.setFixedHeight(30)
        url_row.setStyleSheet(
            'QWidget { background-color: #ffffff; border-bottom: 1px solid #e0e0e0; }'
            'QLabel { color: #636e72; background: transparent; border: none; }'
            'QLineEdit, QComboBox { background-color: #ffffff; color: #2d3436;'
            '  border: 1px solid #d0d4dc; border-radius: 3px;'
            '  padding: 2px 4px; font-size: 11px; }'
            'QLineEdit:focus, QComboBox:focus { border: 1px solid #0984e3; }'
        )
        r1 = QHBoxLayout(url_row)
        r1.setContentsMargins(8, 2, 8, 2)
        r1.setSpacing(4)

        lbl = QLabel('Logger:')
        lbl.setStyleSheet('font-weight: bold; font-size: 11px;')
        r1.addWidget(lbl)

        self._logger_protocol_combo = NativeComboBox()
        self._logger_protocol_combo.addItems(['http://', 'https://'])
        self._logger_protocol_combo.setFixedWidth(78)
        r1.addWidget(self._logger_protocol_combo)

        self._logger_ip_input = IpHistoryCombo(
            settings_key='LiveCapture/logger_ip_history',
            default_value='192.168.178.254',
            placeholder='Logger-IP',
        )
        self._logger_ip_input.setFixedWidth(180)
        r1.addWidget(self._logger_ip_input)

        self._logger_ping_label = QLabel('\u2298 Getrennt')
        self._logger_ping_label.setFixedWidth(110)
        self._logger_ping_label.setStyleSheet('font-size: 11px; color: #888;')
        r1.addWidget(self._logger_ping_label)

        self._logger_ping_timer = QTimer(self)
        self._logger_ping_timer.setSingleShot(True)
        self._logger_ping_timer.timeout.connect(self._logger_start_ping)
        self._logger_ip_input.lineEdit().textChanged.connect(
            self._logger_on_ip_changed_ping)

        self._logger_connect_btn = QPushButton('Verbinden')
        self._logger_connect_btn.setStyleSheet(
            'QPushButton { background: #F44336; color: white; border: none;'
            '  padding: 3px 10px; border-radius: 3px; font-size: 11px; }'
            'QPushButton:hover { background: #E53935; }')
        self._logger_connect_btn.clicked.connect(self._logger_on_connect)
        r1.addWidget(self._logger_connect_btn)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        sep.setFixedHeight(18)
        r1.addWidget(sep)

        _tb_style = (
            'QPushButton { background: #ffffff; color: #2d3436;'
            '  border: 1px solid #d0d4dc; border-radius: 3px;'
            '  padding: 3px 10px; font-size: 11px; }'
            'QPushButton:hover { background: #f0f4ff; color: #1565c0; }'
            'QPushButton:disabled { background: #f5f5f5; color: #b0b0b0; }'
        )

        self._logger_rec_start_btn = QPushButton('\u25B6 Aufzeichnung starten')
        self._logger_rec_start_btn.setStyleSheet(_tb_style)
        self._logger_rec_start_btn.clicked.connect(self._logger_on_rec_start)
        r1.addWidget(self._logger_rec_start_btn)

        self._logger_rec_stop_btn = QPushButton('\u23F9 Stoppen')
        self._logger_rec_stop_btn.setStyleSheet(_tb_style)
        self._logger_rec_stop_btn.clicked.connect(self._logger_on_rec_stop)
        r1.addWidget(self._logger_rec_stop_btn)

        # Recording-LED + Timer
        self._logger_rec_led = QLabel('\u25CF')
        self._logger_rec_led.setStyleSheet('color: #888888; font-size: 12px;')
        r1.addWidget(self._logger_rec_led)

        self._logger_rec_timer_label = QLabel('')
        self._logger_rec_timer_label.setStyleSheet(
            'font-size: 11px; font-weight: bold; color: #F44336;')
        self._logger_rec_timer_label.hide()
        r1.addWidget(self._logger_rec_timer_label)

        # Status
        self._logger_status_label = QLabel('')
        self._logger_status_label.setStyleSheet('font-size: 11px; color: #666;')
        r1.addWidget(self._logger_status_label)

        r1.addStretch()
        container.addWidget(url_row)

        # ── Zeile 2: OAuth2 ──
        auth_row = QWidget()
        auth_row.setFixedHeight(30)
        auth_row.setStyleSheet(
            'QWidget { background-color: #fafbfc; border-bottom: 1px solid #e0e0e0; }'
            'QLabel { color: #636e72; background: transparent; border: none; }')
        r2 = QHBoxLayout(auth_row)
        r2.setContentsMargins(8, 0, 8, 2)
        r2.setSpacing(6)

        lbl_auth = QLabel('OAuth2:')
        lbl_auth.setStyleSheet(
            'font-size: 11px; font-weight: bold; color: #0984e3;'
            ' background: transparent; border: none;')
        r2.addWidget(lbl_auth)

        _input_style = (
            'font-size: 11px; color: #2d3436; background: #ffffff;'
            ' border: 1px solid #d0d4dc; border-radius: 3px; padding: 2px 6px;')

        self._logger_auth_user = QLineEdit()
        self._logger_auth_user.setFixedWidth(120)
        self._logger_auth_user.setPlaceholderText('Benutzername')
        self._logger_auth_user.setStyleSheet(_input_style)
        r2.addWidget(self._logger_auth_user)

        self._logger_auth_pass = QLineEdit()
        self._logger_auth_pass.setFixedWidth(120)
        self._logger_auth_pass.setPlaceholderText('Passwort')
        self._logger_auth_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._logger_auth_pass.setStyleSheet(_input_style)
        r2.addWidget(self._logger_auth_pass)

        self._logger_login_btn = QPushButton('Anmelden')
        self._logger_login_btn.setStyleSheet(
            'QPushButton { background: #0277BD; color: white; font-weight: bold;'
            '  border: none; padding: 5px 10px; border-radius: 6px; font-size: 11px; }'
            'QPushButton:hover { background: #0288D1; }'
            'QPushButton:disabled { background: #555; }')
        self._logger_login_btn.clicked.connect(self._logger_oauth2_login)
        r2.addWidget(self._logger_login_btn)

        self._logger_logout_btn = QPushButton('Abmelden')
        self._logger_logout_btn.setStyleSheet(
            'QPushButton { background: #6D4C41; color: white; font-weight: bold;'
            '  border: none; padding: 5px 10px; border-radius: 6px; font-size: 11px; }'
            'QPushButton:hover { background: #9B8076; }')
        self._logger_logout_btn.setEnabled(False)
        self._logger_logout_btn.clicked.connect(self._logger_oauth2_logout)
        r2.addWidget(self._logger_logout_btn)

        self._logger_auth_status = QLabel('Nicht angemeldet')
        self._logger_auth_status.setStyleSheet(
            'font-size: 11px; color: #999; padding-left: 4px;'
            ' background: transparent; border: none;')
        r2.addWidget(self._logger_auth_status)

        self._logger_token_bar = QProgressBar()
        self._logger_token_bar.setFixedWidth(160)
        self._logger_token_bar.setFixedHeight(18)
        self._logger_token_bar.setRange(0, 3600)
        self._logger_token_bar.setValue(0)
        self._logger_token_bar.setFormat('%v min')
        self._logger_token_bar.setVisible(False)
        self._logger_token_bar.setStyleSheet('''
            QProgressBar {
                border: 1px solid #555; border-radius: 4px;
                background: #2b2b2b; font-size: 10px; color: #ddd;
                text-align: center;
            }
            QProgressBar::chunk {
                border-radius: 3px;
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #43A047,stop:1 #66BB6A);
            }
        ''')
        r2.addWidget(self._logger_token_bar)

        self._logger_token_timer = QTimer(self)
        self._logger_token_timer.setInterval(60_000)
        self._logger_token_timer.timeout.connect(self._logger_update_token_bar)

        r2.addStretch()
        container.addWidget(auth_row)

        # Timer
        self._logger_heartbeat_timer = QTimer(self)
        self._logger_heartbeat_timer.setInterval(30_000)
        self._logger_heartbeat_timer.timeout.connect(self._logger_on_heartbeat)

        self._logger_rec_blink_timer = QTimer(self)
        self._logger_rec_blink_timer.setInterval(50)
        self._logger_rec_blink_timer.timeout.connect(self._logger_on_rec_blink)
        self._logger_rec_start_time = 0.0

        self._logger_control_widget.hide()
        parent_layout.addWidget(self._logger_control_widget)

    # ═══════════════════════════════════════════════════════════════════════
    # Logger-Fernsteuerung — Verbindung & Ping
    # ═══════════════════════════════════════════════════════════════════════

    def _logger_get_base_url(self) -> str:
        """Gibt die aktuelle Logger Base-URL zurück."""
        return f'{self._logger_protocol_combo.currentText()}{self._logger_ip_input.currentText()}'.rstrip('/')

    def _logger_on_ip_changed_ping(self, text: str):
        """IP geändert — Ping mit 800ms Debounce starten."""
        if self._logger_connected:
            return
        self._logger_ping_timer.stop()
        ip = text.strip()
        if not ip:
            self._logger_ping_label.setText('\u2298 Getrennt')
            self._logger_ping_label.setStyleSheet('font-size: 11px; color: #888;')
            return
        self._logger_ping_label.setText('\u25CB Ping...')
        self._logger_ping_label.setStyleSheet('font-size: 11px; color: #FFB74D;')
        self._logger_ping_timer.start(800)

    def _logger_start_ping(self):
        """Startet den Ping in einem Hintergrund-Thread."""
        if self._logger_connected:
            return
        ip = self._logger_ip_input.currentText().strip()
        if not ip:
            return
        thread = _PingThread(ip, self)
        thread.result.connect(self._logger_on_ping_result)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    def _logger_on_ping_result(self, ok: bool, ip: str, latency_ms: float):
        """Ping-Ergebnis anzeigen."""
        if self._logger_connected:
            return
        current_ip = self._logger_ip_input.currentText().strip()
        if ip != current_ip:
            return
        if ok:
            ms = f'{latency_ms:.0f}' if latency_ms >= 1 else f'{latency_ms:.1f}'
            self._logger_ping_label.setText(f'\u25CF Ping OK ({ms}ms)')
            self._logger_ping_label.setStyleSheet(
                'font-size: 11px; color: #4CAF50; font-weight: bold;')
        else:
            self._logger_ping_label.setText('\u25CF Ping NOK')
            self._logger_ping_label.setStyleSheet(
                'font-size: 11px; color: #F44336; font-weight: bold;')

    def _logger_on_connect(self):
        """Verbindung zum Logger herstellen / trennen."""
        if self._logger_connected:
            if self._logger_access_token:
                self._logger_oauth2_logout()
            self._logger_connected = False
            self._logger_recording_active = False
            self._logger_heartbeat_timer.stop()
            self._logger_rec_blink_timer.stop()
            self._logger_connect_btn.setText('Verbinden')
            self._logger_connect_btn.setStyleSheet(
                'QPushButton { background: #F44336; color: white; border: none;'
                '  padding: 3px 10px; border-radius: 3px; font-size: 11px; }'
                'QPushButton:hover { background: #E53935; }')
            self._logger_rec_start_btn.setEnabled(True)
            self._logger_rec_stop_btn.setEnabled(True)
            self._logger_status_label.setText('')
            self._logger_ping_label.setText('\u2298 Getrennt')
            self._logger_ping_label.setStyleSheet('font-size: 11px; color: #888;')
            self._logger_rec_led.setStyleSheet('color: #888888; font-size: 12px;')
            self._logger_rec_timer_label.setText('')
            self._logger_rec_timer_label.hide()
            self._logger_on_ip_changed_ping(self._logger_ip_input.currentText())
            logging.getLogger(__name__).info('Logger-Verbindung getrennt')
            return

        ip = self._logger_ip_input.currentText().strip()
        if not ip:
            return

        # IP in Historie speichern (persistiert in QSettings)
        self._logger_ip_input.save_current()

        protocol = self._logger_protocol_combo.currentText()
        base_url = f'{protocol}{ip}'
        self._logger_worker.set_base_url(base_url)
        self._logger_worker.load_properties('/api/v1/system/cca_basic_info')

        self._logger_connected = True
        self._logger_connect_btn.setText('Trennen')
        self._logger_connect_btn.setStyleSheet(
            'QPushButton { background: #4CAF50; color: white; border: none;'
            '  padding: 3px 10px; border-radius: 3px; font-size: 11px; }'
            'QPushButton:hover { background: #388E3C; }')
        self._logger_status_label.setText(f'Verbunden mit {ip}')
        self._logger_status_label.setStyleSheet('font-size: 11px; color: #4CAF50;')
        self._logger_ping_label.setText('\u25CF Verbunden')
        self._logger_ping_label.setStyleSheet(
            'font-size: 11px; color: #4CAF50; font-weight: bold;')
        self._logger_heartbeat_timer.start()
        self._logger_ping_timer.stop()

        if not self._logger_access_token:
            self._logger_auth_status.setText('Bitte anmelden \u2192')
            self._logger_auth_status.setStyleSheet(
                'font-size: 11px; color: #FFB74D; font-weight: bold;'
                ' background: transparent; border: none;')
        logging.getLogger(__name__).info('Verbinde mit Logger: %s', base_url)

    def _logger_on_heartbeat(self):
        """Heartbeat: Prüft ob der Logger noch erreichbar ist."""
        if not self._logger_connected:
            return
        self._logger_worker.load_properties('/api/v1/system/cca_basic_info')

    # ═══════════════════════════════════════════════════════════════════════
    # Logger-Fernsteuerung — OAuth2
    # ═══════════════════════════════════════════════════════════════════════

    def _logger_oauth2_login(self):
        """Meldet sich am CCA-Gerät an und speichert Access/Refresh-Token."""
        import traceback
        _log = logging.getLogger(__name__)
        try:
            base = self._logger_get_base_url()
            user = self._logger_auth_user.text().strip()
            pwd = self._logger_auth_pass.text()
            if not base or not user or not pwd:
                QMessageBox.warning(
                    self, 'Anmeldung',
                    'Bitte Base-URL, Benutzername und Passwort eingeben.')
                return

            self._logger_login_btn.setEnabled(False)
            self._logger_auth_status.setText('Anmeldung läuft \u2026')
            self._logger_auth_status.setStyleSheet(
                'font-size: 11px; color: #FFB74D; padding-left: 6px;'
                ' background: transparent; border: none;')

            _log.info('Logger OAuth2 Login: %s user=%s', base, user)

            import requests as _req
            resp = _req.post(
                f'{base}/api/v1/oauth2/token',
                json={'username': user, 'password': pwd},
                headers={'Content-Type': 'application/json'},
                timeout=10,
                verify=False,
            )
            _log.info('Logger OAuth2 Response: %s', resp.status_code)

            if resp.status_code == 200:
                data = resp.json()
                self._logger_access_token = data.get('access_token')
                self._logger_refresh_token = data.get('refresh_token')
                self._logger_auth_status.setText(f'Angemeldet als {user}')
                self._logger_auth_status.setStyleSheet(
                    'font-size: 11px; color: #4CBB17; font-weight: bold;'
                    ' padding-left: 6px; background: transparent; border: none;')
                self._logger_logout_btn.setEnabled(True)
                self._logger_auth_pass.clear()
                self._logger_token_acquired_at = time.time()
                self._logger_worker.set_access_token(self._logger_access_token)
                self._logger_start_token_bar()
            else:
                try:
                    detail = resp.json().get('msg', resp.text[:200])
                except Exception:
                    detail = resp.text[:200]
                self._logger_auth_status.setText(f'Fehler ({resp.status_code})')
                self._logger_auth_status.setStyleSheet(
                    'font-size: 11px; color: #FF6680; padding-left: 6px;'
                    ' background: transparent; border: none;')
                QMessageBox.warning(
                    self, 'Anmeldung fehlgeschlagen',
                    f'Status {resp.status_code}: {detail}')
        except Exception as exc:
            _log.error('Logger OAuth2 Login Fehler:\n%s', traceback.format_exc())
            self._logger_auth_status.setText('Verbindungsfehler')
            self._logger_auth_status.setStyleSheet(
                'font-size: 11px; color: #FF6680; padding-left: 6px;'
                ' background: transparent; border: none;')
            try:
                QMessageBox.warning(self, 'Verbindungsfehler', str(exc))
            except Exception:
                pass
        finally:
            self._logger_login_btn.setEnabled(True)

    def _logger_oauth2_logout(self):
        """Meldet sich ab und löscht die Tokens."""
        base = self._logger_get_base_url()
        import requests
        if base and self._logger_access_token:
            try:
                requests.delete(
                    f'{base}/api/v1/oauth2/token',
                    headers={
                        'Authorization': f'Bearer {self._logger_access_token}',
                        'Content-Type': 'application/json',
                    },
                    timeout=5,
                )
            except Exception:
                pass

        self._logger_access_token = None
        self._logger_refresh_token = None
        self._logger_worker.set_access_token(None)
        self._logger_token_timer.stop()
        self._logger_token_bar.setVisible(False)
        self._logger_auth_status.setText('Nicht angemeldet')
        self._logger_auth_status.setStyleSheet(
            'font-size: 11px; color: #999; padding-left: 6px;'
            ' background: transparent; border: none;')
        self._logger_logout_btn.setEnabled(False)

    def _logger_oauth2_refresh(self) -> bool:
        """Erneuert den Access-Token mit dem Refresh-Token."""
        base = self._logger_get_base_url()
        if not base or not self._logger_refresh_token:
            return False
        import requests
        try:
            resp = requests.post(
                f'{base}/api/v1/oauth2/refresh',
                json={'refresh_token': self._logger_refresh_token},
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                self._logger_access_token = data.get('access_token')
                new_refresh = data.get('refresh_token')
                if new_refresh:
                    self._logger_refresh_token = new_refresh
                self._logger_token_acquired_at = time.time()
                self._logger_worker.set_access_token(self._logger_access_token)
                self._logger_start_token_bar()
                return True
        except Exception:
            pass
        return False

    def _logger_on_auth_expired(self, task: str, endpoint: str,
                                payload: Dict[str, Any]):
        """401 erhalten — Token automatisch erneuern."""
        log = logging.getLogger(__name__)
        log.warning('Logger-Token abgelaufen (401), versuche Refresh …')
        if self._logger_oauth2_refresh():
            log.info('Logger-Token erneuert, Anfrage wird wiederholt')
            self._logger_worker._enqueue(task, endpoint, payload)
        else:
            self._logger_auth_status.setText('Token abgelaufen — bitte neu anmelden')
            self._logger_auth_status.setStyleSheet(
                'font-size: 11px; color: #FF6680; padding-left: 6px;'
                ' background: transparent; border: none;')

    def _logger_start_token_bar(self):
        """Zeigt den Token-Fortschrittsbalken und startet den Timer."""
        self._logger_token_bar.setRange(0, self._logger_token_lifetime)
        self._logger_token_bar.setValue(self._logger_token_lifetime)
        self._logger_update_token_bar()
        self._logger_token_bar.setVisible(True)
        self._logger_token_timer.start()

    def _logger_update_token_bar(self):
        """Aktualisiert den Token-Fortschrittsbalken (jede Minute)."""
        elapsed = time.time() - self._logger_token_acquired_at
        remaining = max(0, self._logger_token_lifetime - int(elapsed))
        self._logger_token_bar.setValue(remaining)
        mins = remaining // 60
        self._logger_token_bar.setFormat(f'Token: {mins} min')

        if remaining > 600:
            chunk_bg = ('background: qlineargradient(x1:0,y1:0,x2:1,y2:0,'
                        'stop:0 #43A047,stop:1 #66BB6A);')
        elif remaining > 180:
            chunk_bg = ('background: qlineargradient(x1:0,y1:0,x2:1,y2:0,'
                        'stop:0 #F9A825,stop:1 #FDD835);')
        else:
            chunk_bg = ('background: qlineargradient(x1:0,y1:0,x2:1,y2:0,'
                        'stop:0 #E53935,stop:1 #EF5350);')

        self._logger_token_bar.setStyleSheet(f'''
            QProgressBar {{
                border: 1px solid #555; border-radius: 4px;
                background: #2b2b2b; font-size: 10px; color: #ddd;
                text-align: center;
            }}
            QProgressBar::chunk {{
                border-radius: 3px;
                {chunk_bg}
            }}
        ''')

        if remaining == 0 and self._logger_refresh_token:
            self._logger_token_timer.stop()
            if self._logger_oauth2_refresh():
                self._logger_auth_status.setText(
                    self._logger_auth_status.text().replace(
                        'Angemeldet', 'Erneuert'))
            else:
                self._logger_auth_status.setText('Token abgelaufen')
                self._logger_auth_status.setStyleSheet(
                    'font-size: 11px; color: #FF6680; padding-left: 4px;'
                    ' background: transparent; border: none;')
                self._logger_token_bar.setFormat('Abgelaufen!')

    # ═══════════════════════════════════════════════════════════════════════
    # Logger-Fernsteuerung — Aufzeichnung Start / Stop
    # ═══════════════════════════════════════════════════════════════════════

    def _logger_on_rec_start(self):
        """Aufzeichnung auf dem Logger starten."""
        if not self._logger_connected:
            QMessageBox.warning(self, 'Logger', 'Bitte zuerst mit dem Logger verbinden.')
            return
        if not self._logger_access_token:
            QMessageBox.warning(self, 'Logger', 'Bitte zuerst anmelden (OAuth2).')
            return
        self._logger_worker.get_action('/api/v1/recording/start',
                                       'Aufzeichnung starten')
        self._logger_recording_active = True
        self._logger_rec_start_btn.setEnabled(False)
        self._logger_rec_start_btn.setStyleSheet(
            'QPushButton { background: #4CAF50; color: white; }'
            'QPushButton:disabled { background: #4CAF50; color: #cccccc; }')
        self._logger_rec_stop_btn.setEnabled(True)
        self._logger_rec_stop_btn.setStyleSheet(
            'QPushButton { background: #F44336; color: white; border: none; }'
            'QPushButton:hover { background: #E53935; }')
        self._logger_rec_start_time = time.monotonic()
        self._logger_rec_led.setStyleSheet('color: #F44336; font-size: 12px;')
        self._logger_rec_timer_label.setText('REC 00:00')
        self._logger_rec_timer_label.show()
        self._logger_rec_blink_timer.start()

    def _logger_on_rec_stop(self):
        """Aufzeichnung auf dem Logger stoppen."""
        if not self._logger_connected:
            QMessageBox.warning(self, 'Logger', 'Bitte zuerst mit dem Logger verbinden.')
            return
        self._logger_worker.get_action('/api/v1/recording/stop',
                                       'Aufzeichnung stoppen')
        self._logger_recording_active = False
        self._logger_rec_start_btn.setEnabled(True)
        _tb_style = (
            'QPushButton { background: #ffffff; color: #2d3436;'
            '  border: 1px solid #d0d4dc; border-radius: 3px;'
            '  padding: 3px 10px; font-size: 11px; }'
            'QPushButton:hover { background: #f0f4ff; color: #1565c0; }'
            'QPushButton:disabled { background: #f5f5f5; color: #b0b0b0; }'
        )
        self._logger_rec_start_btn.setStyleSheet(_tb_style)
        self._logger_rec_stop_btn.setEnabled(False)
        self._logger_rec_stop_btn.setStyleSheet(
            'QPushButton { background: #a04040; color: white; }'
            'QPushButton:disabled { background: #a04040; color: #cccccc; }')
        self._logger_rec_blink_timer.stop()
        self._logger_rec_led.setStyleSheet('color: #888888; font-size: 12px;')
        self._logger_rec_timer_label.setText('')
        self._logger_rec_timer_label.hide()

    def _logger_on_rec_blink(self):
        """Pulsiert die Recording-LED und aktualisiert den Timer."""
        import math
        elapsed_blink = time.monotonic() - self._logger_rec_start_time
        brightness = 0.4 + 0.6 * (0.5 + 0.5 * math.sin(
            2 * math.pi * elapsed_blink / 1.5))
        r = int(244 * brightness)
        g = int(67 * brightness * 0.3)
        b = int(54 * brightness * 0.3)
        self._logger_rec_led.setStyleSheet(
            f'color: rgb({r},{g},{b}); font-size: 12px;'
            ' background: transparent; border: none;')
        secs = int(elapsed_blink)
        m, s = divmod(secs, 60)
        self._logger_rec_timer_label.setText(f'REC {m:02d}:{s:02d}')

    # ═══════════════════════════════════════════════════════════════════════
    # Logger-Fernsteuerung — Worker-Callbacks
    # ═══════════════════════════════════════════════════════════════════════

    def _logger_on_action_done(self, message: str):
        """Erfolgsmeldung vom Logger-Worker."""
        self._logger_status_label.setText(message)
        self._logger_status_label.setStyleSheet('font-size: 11px; color: #4CAF50;')
        QTimer.singleShot(5000, self._logger_restore_status)

    def _logger_on_error(self, message: str):
        """Fehlermeldung vom Logger-Worker."""
        short = message.split('\n')[0][:60]
        self._logger_status_label.setText(f'Fehler: {short}')
        self._logger_status_label.setStyleSheet('font-size: 11px; color: #E53935;')
        logging.getLogger(__name__).warning('Logger-API-Fehler: %s', message)

        if 'fehlgeschlagen' in message or 'Zeitüberschreitung' in message:
            if self._logger_connected:
                self._logger_connected = False
                self._logger_recording_active = False
                self._logger_heartbeat_timer.stop()
                self._logger_rec_blink_timer.stop()
                self._logger_connect_btn.setText('Verbinden')
                self._logger_connect_btn.setStyleSheet(
                    'QPushButton { background: #F44336; color: white; border: none;'
                    '  padding: 3px 10px; border-radius: 3px; font-size: 11px; }'
                    'QPushButton:hover { background: #E53935; }')
                self._logger_status_label.setText('Verbindung verloren')
                self._logger_status_label.setStyleSheet(
                    'font-size: 11px; color: #E53935;')
                logging.getLogger(__name__).warning('Logger-Verbindung verloren')

    def _logger_on_data_loaded(self, data: Dict[str, Any]):
        """Daten vom Logger empfangen (z.B. Geräte-Info bei Heartbeat)."""
        if not self._logger_connected:
            return
        model = data.get('model', '')
        sn = data.get('serial_number', '')
        fw = data.get('firmware_version', '')
        if model or sn or fw:
            parts = []
            if model:
                parts.append(model)
            if sn:
                parts.append(f'SN:{sn}')
            if fw:
                parts.append(f'FW:{fw}')
            ip = self._logger_ip_input.currentText().strip()
            self._logger_status_label.setText(
                f'Verbunden mit {ip} — {" | ".join(parts)}')
            self._logger_status_label.setStyleSheet(
                'font-size: 11px; color: #4CAF50;')

    def _logger_restore_status(self):
        """Setzt Logger-Statusleiste auf Normalzustand zurück."""
        if self._logger_connected:
            ip = self._logger_ip_input.currentText().strip()
            self._logger_status_label.setText(f'Verbunden mit {ip}')
            self._logger_status_label.setStyleSheet(
                'font-size: 11px; color: #4CAF50;')
        else:
            self._logger_status_label.setText('')
            self._logger_status_label.setStyleSheet(
                'font-size: 11px; color: #666;')

    # ═══════════════════════════════════════════════════════════════════════
    # Live-Tab Umschaltung (Video / CAN / LIN / Eth / FlexRay)
    # ═══════════════════════════════════════════════════════════════════════

    def _switch_live_tab(self, index: int):
        """Wechselt zwischen Live-Ansichten (Video, CAN, LIN, Eth, FlexRay)."""
        if index == self._current_live_tab:
            return
        self._current_live_tab = index

        # Tab-Buttons aktualisieren
        for i, btn in enumerate(self._live_tab_buttons):
            btn.setStyleSheet(
                self._live_tab_active_style if i == index
                else self._live_tab_inactive_style)

        # Toolbar + Content umschalten
        self._live_toolbar_stack.setCurrentIndex(index)
        self._live_content_stack.setCurrentIndex(index)

