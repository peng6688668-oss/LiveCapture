"""Gateway Engine — Cross-Bus Frame-Routing.

Unterstuetzt:
  - CAN → CAN (ID-Mapping)
  - LIN → CAN (ID-Mapping)
  - TECMP/PLP → CAN (Extraction + Injection)
  - Beliebige Kombinationen via Routing-Regeln

Routing-Regeln sind JSON-serialisierbar fuer Persistenz.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

_log = logging.getLogger(__name__)


@dataclass
class RoutingRule:
    """Eine Routing-Regel: Source → Target mit optionalem ID-Mapping."""
    name: str = ''
    enabled: bool = True
    source_bus: str = ''     # 'CAN', 'LIN', 'Ethernet', 'FlexRay'
    target_bus: str = ''     # 'CAN', 'LIN'
    source_id_filter: int = -1   # -1 = alle IDs
    target_id_map: int = -1      # -1 = gleiche ID beibehalten
    data_transform: str = 'none'  # 'none', 'swap_bytes', 'truncate'

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'enabled': self.enabled,
            'source_bus': self.source_bus,
            'target_bus': self.target_bus,
            'source_id_filter': self.source_id_filter,
            'target_id_map': self.target_id_map,
            'data_transform': self.data_transform,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'RoutingRule':
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class GatewayEngine(QObject):
    """Routing-Engine die Frames zwischen Bussen weiterleitet.

    Nutzung:
      1. add_rule() zum Hinzufuegen von Regeln
      2. register_sender() zum Registrieren von Bus-Sendern
      3. on_frame_received() aufrufen wenn ein Frame empfangen wird
    """

    frame_routed = pyqtSignal(str, str, int)  # (source_bus, target_bus, frame_id)
    error_occurred = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules: List[RoutingRule] = []
        self._senders: Dict[str, Callable] = {}  # bus_name → send_function
        self._routed_count = 0
        self._error_count = 0

    # ── Regelverwaltung ──

    def add_rule(self, rule: RoutingRule) -> int:
        """Fuegt eine Routing-Regel hinzu. Gibt den Index zurueck."""
        self._rules = self._rules + [rule]
        return len(self._rules) - 1

    def remove_rule(self, index: int):
        """Entfernt eine Regel."""
        self._rules = [r for i, r in enumerate(self._rules) if i != index]

    def get_rules(self) -> List[RoutingRule]:
        return list(self._rules)

    def clear_rules(self):
        self._rules = []

    # ── Bus-Sender registrieren ──

    def register_sender(self, bus_name: str, send_func: Callable):
        """Registriert eine Sende-Funktion fuer einen Bus.

        send_func(frame_id: int, data: bytes, dlc: int) -> bool
        """
        self._senders[bus_name] = send_func

    # ── Frame-Verarbeitung ──

    def on_frame_received(self, source_bus: str, frame_id: int,
                          data: bytes, dlc: int = 0):
        """Wird aufgerufen wenn ein Frame empfangen wird. Routet gemaess Regeln."""
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.source_bus != source_bus:
                continue
            if rule.source_id_filter >= 0 and rule.source_id_filter != frame_id:
                continue

            target_id = frame_id if rule.target_id_map < 0 else rule.target_id_map
            target_data = self._transform_data(data, rule.data_transform)
            target_dlc = dlc if dlc > 0 else len(target_data)

            sender = self._senders.get(rule.target_bus)
            if sender is None:
                continue

            try:
                sender(target_id, target_data, target_dlc)
                self._routed_count += 1
                self.frame_routed.emit(source_bus, rule.target_bus, target_id)
            except Exception as e:
                self._error_count += 1
                self.error_occurred.emit(
                    f"Gateway {source_bus}→{rule.target_bus}: {e}")

    @staticmethod
    def _transform_data(data: bytes, transform: str) -> bytes:
        if transform == 'swap_bytes':
            return bytes(reversed(data))
        elif transform == 'truncate':
            return data[:8]
        return data

    # ── Statistik ──

    @property
    def routed_count(self) -> int:
        return self._routed_count

    @property
    def error_count(self) -> int:
        return self._error_count

    def reset_counters(self):
        self._routed_count = 0
        self._error_count = 0

    # ── Persistenz ──

    def save_rules(self, path: str):
        """Speichert Regeln als JSON."""
        data = [r.to_dict() for r in self._rules]
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

    def load_rules(self, path: str):
        """Laedt Regeln aus JSON."""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self._rules = [RoutingRule.from_dict(d) for d in data]
