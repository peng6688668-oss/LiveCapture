"""Trigger Engine — Oszilloskop-Style Trigger fuer Analog/Digital.

Trigger-Typen:
  - Edge (Rising/Falling/Either)
  - Level (Above/Below threshold)
  - Window (Inside/Outside band)

Zustandsmaschine: IDLE → ARMED → TRIGGERED → CAPTURING_POST → DONE
"""

import logging
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Deque, List, Optional, Tuple

_log = logging.getLogger(__name__)


class TriggerState(Enum):
    IDLE = 'idle'
    ARMED = 'armed'
    TRIGGERED = 'triggered'
    CAPTURING_POST = 'capturing_post'
    DONE = 'done'


class TriggerType(Enum):
    EDGE_RISING = 'edge_rising'
    EDGE_FALLING = 'edge_falling'
    EDGE_EITHER = 'edge_either'
    LEVEL_ABOVE = 'level_above'
    LEVEL_BELOW = 'level_below'
    WINDOW_INSIDE = 'window_inside'
    WINDOW_OUTSIDE = 'window_outside'


@dataclass
class TriggerConfig:
    """Trigger-Konfiguration."""
    trigger_type: TriggerType = TriggerType.EDGE_RISING
    channel: int = 0
    threshold: float = 2.5
    threshold_upper: float = 4.0   # Fuer Window-Trigger
    threshold_lower: float = 1.0
    pre_samples: int = 500
    post_samples: int = 1000
    auto_rearm: bool = False       # Normal-Modus (auto-rearm) vs Single-Shot


class TriggerEngine:
    """Oszilloskop-Trigger mit Pre/Post-Buffer.

    Nutzung:
        engine = TriggerEngine()
        engine.configure(TriggerConfig(trigger_type=TriggerType.EDGE_RISING))
        engine.arm()

        # Im Sample-Loop:
        result = engine.feed(timestamp, value)
        if result is not None:
            pre_samples, trigger_point, post_samples = result
    """

    def __init__(self):
        self._config = TriggerConfig()
        self._state = TriggerState.IDLE
        self._pre_buffer: Deque[Tuple[float, float]] = deque(maxlen=500)
        self._post_buffer: List[Tuple[float, float]] = []
        self._trigger_point: Optional[Tuple[float, float]] = None
        self._post_count = 0
        self._prev_value: Optional[float] = None

    @property
    def state(self) -> TriggerState:
        return self._state

    def configure(self, config: TriggerConfig):
        """Setzt die Trigger-Konfiguration."""
        self._config = config
        self._pre_buffer = deque(maxlen=max(1, config.pre_samples))

    def arm(self):
        """Scharfschalten des Triggers."""
        self._state = TriggerState.ARMED
        self._pre_buffer.clear()
        self._post_buffer = []
        self._trigger_point = None
        self._post_count = 0
        self._prev_value = None

    def reset(self):
        """Zuruecksetzen auf IDLE."""
        self._state = TriggerState.IDLE
        self._pre_buffer.clear()
        self._post_buffer = []
        self._trigger_point = None

    def feed(self, timestamp: float, value: float
             ) -> Optional[Tuple[list, Tuple[float, float], list]]:
        """Fuettert einen Sample. Gibt Capture-Ergebnis zurueck wenn fertig.

        Returns:
            None — noch nicht ausgeloest oder noch am Sammeln
            (pre_samples, trigger_point, post_samples) — fertige Aufnahme
        """
        if self._state == TriggerState.IDLE or self._state == TriggerState.DONE:
            return None

        if self._state == TriggerState.ARMED:
            self._pre_buffer.append((timestamp, value))

            if self._check_trigger(value):
                self._state = TriggerState.CAPTURING_POST
                self._trigger_point = (timestamp, value)
                self._post_count = 0

            self._prev_value = value
            return None

        if self._state == TriggerState.CAPTURING_POST:
            self._post_buffer.append((timestamp, value))
            self._post_count += 1

            if self._post_count >= self._config.post_samples:
                self._state = TriggerState.DONE
                result = (
                    list(self._pre_buffer),
                    self._trigger_point,
                    list(self._post_buffer),
                )
                if self._config.auto_rearm:
                    self.arm()
                return result

            self._prev_value = value
            return None

        return None

    def _check_trigger(self, value: float) -> bool:
        """Prueft ob der Trigger ausgeloest wird."""
        cfg = self._config
        prev = self._prev_value

        if cfg.trigger_type == TriggerType.EDGE_RISING:
            return (prev is not None
                    and prev <= cfg.threshold < value)

        elif cfg.trigger_type == TriggerType.EDGE_FALLING:
            return (prev is not None
                    and prev >= cfg.threshold > value)

        elif cfg.trigger_type == TriggerType.EDGE_EITHER:
            if prev is None:
                return False
            return ((prev <= cfg.threshold < value)
                    or (prev >= cfg.threshold > value))

        elif cfg.trigger_type == TriggerType.LEVEL_ABOVE:
            return value > cfg.threshold

        elif cfg.trigger_type == TriggerType.LEVEL_BELOW:
            return value < cfg.threshold

        elif cfg.trigger_type == TriggerType.WINDOW_INSIDE:
            return cfg.threshold_lower <= value <= cfg.threshold_upper

        elif cfg.trigger_type == TriggerType.WINDOW_OUTSIDE:
            return value < cfg.threshold_lower or value > cfg.threshold_upper

        return False
