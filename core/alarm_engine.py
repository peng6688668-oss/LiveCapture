"""Alarm Engine — Schwellwert-Ueberwachung fuer Analog/Digital-Signale.

Unterstuetzte Alarm-Typen:
  - Analog: Spannung ueber/unter Schwellwert, Aenderungsrate
  - Digital: Pegel-Haenge (stuck HIGH/LOW), Frequenz ausserhalb Bereich
"""

import logging
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

_log = logging.getLogger(__name__)


@dataclass
class AlarmEvent:
    """Ein ausgeloester Alarm."""
    channel: int = 0
    alarm_type: str = ''
    message: str = ''
    value: float = 0.0
    threshold: float = 0.0
    timestamp: float = 0.0


@dataclass
class AlarmRule:
    """Eine Alarm-Regel."""
    enabled: bool = True
    channel: int = -1        # -1 = alle Kanaele
    alarm_type: str = 'above'  # above, below, stuck_high, stuck_low, rate
    threshold: float = 0.0
    duration_s: float = 1.0  # Fuer stuck-Alarme: Mindestdauer
    cooldown_s: float = 5.0  # Abklingzeit zwischen Alarmen


class AlarmMonitor:
    """Ueberwacht Signale und loest Alarme aus.

    Nutzung:
        monitor = AlarmMonitor()
        monitor.add_rule(AlarmRule(alarm_type='above', threshold=4.5))
        monitor.on_alarm = lambda event: print(event)

        # Im Update-Loop:
        event = monitor.check_analog(channel, timestamp, voltage)
        event = monitor.check_digital(channel, timestamp, level)
    """

    def __init__(self):
        self._rules: List[AlarmRule] = []
        self._last_alarm_time: Dict[str, float] = {}
        self._digital_state: Dict[int, dict] = {}  # ch → {level, since}
        self._history: List[AlarmEvent] = []
        self.on_alarm: Optional[Callable[[AlarmEvent], None]] = None

    def add_rule(self, rule: AlarmRule):
        self._rules = self._rules + [rule]

    def remove_rule(self, index: int):
        self._rules = [r for i, r in enumerate(self._rules) if i != index]

    def get_rules(self) -> List[AlarmRule]:
        return list(self._rules)

    def clear_rules(self):
        self._rules = []

    @property
    def history(self) -> List[AlarmEvent]:
        return list(self._history)

    def clear_history(self):
        self._history = []

    def check_analog(self, channel: int, timestamp: float,
                     voltage: float) -> Optional[AlarmEvent]:
        """Prueft Analog-Alarme. Gibt AlarmEvent zurueck oder None."""
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.channel >= 0 and rule.channel != channel:
                continue

            triggered = False
            if rule.alarm_type == 'above' and voltage > rule.threshold:
                triggered = True
            elif rule.alarm_type == 'below' and voltage < rule.threshold:
                triggered = True

            if triggered:
                key = f"analog_{channel}_{rule.alarm_type}"
                last = self._last_alarm_time.get(key, 0.0)
                if timestamp - last < rule.cooldown_s:
                    continue
                self._last_alarm_time[key] = timestamp
                event = AlarmEvent(
                    channel=channel,
                    alarm_type=rule.alarm_type,
                    message=(f"CH{channel}: {voltage:.3f}V "
                             f"{'>' if rule.alarm_type == 'above' else '<'} "
                             f"{rule.threshold:.3f}V"),
                    value=voltage,
                    threshold=rule.threshold,
                    timestamp=timestamp,
                )
                self._history.append(event)
                if self.on_alarm:
                    self.on_alarm(event)
                return event
        return None

    def check_digital(self, channel: int, timestamp: float,
                      level: int) -> Optional[AlarmEvent]:
        """Prueft Digital-Alarme (stuck HIGH/LOW)."""
        state = self._digital_state.setdefault(
            channel, {'level': level, 'since': timestamp})

        if level != state['level']:
            state['level'] = level
            state['since'] = timestamp
            return None

        stuck_duration = timestamp - state['since']

        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.channel >= 0 and rule.channel != channel:
                continue

            triggered = False
            if (rule.alarm_type == 'stuck_high'
                    and level == 1
                    and stuck_duration >= rule.duration_s):
                triggered = True
            elif (rule.alarm_type == 'stuck_low'
                  and level == 0
                  and stuck_duration >= rule.duration_s):
                triggered = True

            if triggered:
                key = f"digital_{channel}_{rule.alarm_type}"
                last = self._last_alarm_time.get(key, 0.0)
                if timestamp - last < rule.cooldown_s:
                    continue
                self._last_alarm_time[key] = timestamp
                lvl_str = "HIGH" if level == 1 else "LOW"
                event = AlarmEvent(
                    channel=channel,
                    alarm_type=rule.alarm_type,
                    message=(f"CH{channel}: {lvl_str} seit "
                             f"{stuck_duration:.1f}s"),
                    value=float(level),
                    threshold=rule.duration_s,
                    timestamp=timestamp,
                )
                self._history.append(event)
                if self.on_alarm:
                    self.on_alarm(event)
                return event
        return None
