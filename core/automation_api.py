"""Automation API — Python-Scripting-Fassade fuer LiveCapture.

Bietet eine einfache API fuer automatisierte Tests:
  - CAN/LIN Frames senden und empfangen
  - UDS Diagnose-Requests
  - Warten auf bestimmte Frames (wait_for)
  - Assertions (assert_frame, assert_did)
  - Ergebnis-Protokoll (Report)

Thread-sicher: API-Calls aus Script-Thread werden per QueuedConnection
an den UI-Thread delegiert.
"""

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger(__name__)


@dataclass
class FrameEvent:
    """Ein empfangener Frame."""
    bus: str = ''
    frame_id: int = 0
    data: bytes = b''
    dlc: int = 0
    timestamp: float = 0.0
    channel: str = ''


@dataclass
class TestResult:
    """Ergebnis eines Test-Schritts."""
    step: str = ''
    passed: bool = True
    message: str = ''
    timestamp: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


class AutomationAPI:
    """Fassade fuer Script-Automatisierung.

    Nutzung in Scripts:
        api = AutomationAPI()
        api.set_can_sender(can_page._send_raw)
        api.set_lin_sender(lin_page._send_raw)

        # CAN senden
        api.can_send(0x123, bytes([0x01, 0x02, 0x03]))

        # Auf Antwort warten
        frame = api.wait_for(bus='CAN', frame_id=0x456, timeout=2.0)

        # UDS Request
        resp = api.uds_request(0x22, did=0xF190)

        # Assertion
        api.assert_frame('CAN', 0x456, expected_data=b'\\x01\\x02')

        # Report generieren
        api.save_report('/tmp/test_report.txt')
    """

    def __init__(self):
        self._can_sender: Optional[Callable] = None
        self._lin_sender: Optional[Callable] = None
        self._uds_sender: Optional[Callable] = None
        self._analog_page = None
        self._digital_page = None
        self._rx_buffer: deque = deque(maxlen=10000)
        self._rx_lock = threading.Lock()
        self._rx_event = threading.Event()
        self._results: List[TestResult] = []
        self._test_name = 'Unnamed Test'
        self._start_time = time.time()

    # ── Sender registrieren ──

    def set_can_sender(self, func: Callable):
        """Registriert CAN-Sende-Funktion: func(frame_id, data) -> bool"""
        self._can_sender = func

    def set_lin_sender(self, func: Callable):
        """Registriert LIN-Sende-Funktion: func(frame_id, data) -> bool"""
        self._lin_sender = func

    def set_uds_sender(self, func: Callable):
        """Registriert UDS-Sende-Funktion: func(tx_id, data_bytes)"""
        self._uds_sender = func

    # ── Frame-Empfang (wird von Bus-Seiten aufgerufen) ──

    def on_frame_received(self, bus: str, frame_id: int,
                          data: bytes, dlc: int = 0,
                          channel: str = ''):
        """Wird vom UI-Thread aufgerufen wenn ein Frame empfangen wird."""
        event = FrameEvent(
            bus=bus, frame_id=frame_id, data=bytes(data),
            dlc=dlc or len(data), timestamp=time.time(),
            channel=channel,
        )
        with self._rx_lock:
            self._rx_buffer.append(event)
        self._rx_event.set()

    # ── Senden ──

    def can_send(self, frame_id: int, data: bytes) -> bool:
        """Sendet einen CAN-Frame."""
        if self._can_sender is None:
            _log.error("Kein CAN-Sender registriert")
            return False
        try:
            return self._can_sender(frame_id, data)
        except Exception as e:
            _log.error("CAN-Senden fehlgeschlagen: %s", e)
            return False

    def lin_send(self, frame_id: int, data: bytes) -> bool:
        """Sendet einen LIN-Frame."""
        if self._lin_sender is None:
            _log.error("Kein LIN-Sender registriert")
            return False
        try:
            return self._lin_sender(frame_id, data)
        except Exception as e:
            _log.error("LIN-Senden fehlgeschlagen: %s", e)
            return False

    def uds_request(self, sid: int, sub_function: int = None,
                    did: int = None, data: bytes = b'',
                    tx_id: int = 0x7DF) -> Optional[bytes]:
        """Sendet einen UDS-Request und wartet auf die Antwort."""
        from core.uds_codec import build_request, ISOTPReassembler
        req = build_request(sid, sub_function, did, data)
        reassembler = ISOTPReassembler()
        frames = reassembler.segment_request(req)

        if self._uds_sender is None and self._can_sender is not None:
            for f in frames:
                self._can_sender(tx_id, f)
        elif self._uds_sender is not None:
            for f in frames:
                self._uds_sender(tx_id, f)
        else:
            _log.error("Kein UDS/CAN-Sender registriert")
            return None

        # Auf Antwort warten (ISO-TP Reassembly)
        rx_id = tx_id + 8 if tx_id < 0x7F0 else 0x7E8
        deadline = time.time() + 2.0
        while time.time() < deadline:
            frame = self.wait_for(bus='CAN', frame_id=rx_id, timeout=0.5)
            if frame is not None:
                result = reassembler.feed(frame.frame_id, frame.data)
                if result is not None:
                    return result
        return None

    # ── Empfang / Warten ──

    def wait_for(self, bus: str = '', frame_id: int = -1,
                 timeout: float = 5.0) -> Optional[FrameEvent]:
        """Wartet auf einen bestimmten Frame. Gibt None bei Timeout zurueck."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._rx_event.wait(timeout=0.1)
            self._rx_event.clear()
            with self._rx_lock:
                for event in self._rx_buffer:
                    if bus and event.bus != bus:
                        continue
                    if frame_id >= 0 and event.frame_id != frame_id:
                        continue
                    return event
        return None

    def get_last_frame(self, bus: str = '', frame_id: int = -1
                       ) -> Optional[FrameEvent]:
        """Gibt den letzten passenden Frame zurueck (non-blocking)."""
        with self._rx_lock:
            for event in reversed(self._rx_buffer):
                if bus and event.bus != bus:
                    continue
                if frame_id >= 0 and event.frame_id != frame_id:
                    continue
                return event
        return None

    def clear_rx_buffer(self):
        """Leert den Empfangspuffer."""
        with self._rx_lock:
            self._rx_buffer.clear()

    # ── Assertions ──

    def assert_frame(self, bus: str, frame_id: int,
                     expected_data: bytes = None,
                     timeout: float = 5.0,
                     step_name: str = '') -> bool:
        """Prueft ob ein bestimmter Frame empfangen wird."""
        frame = self.wait_for(bus=bus, frame_id=frame_id, timeout=timeout)
        if frame is None:
            self._add_result(step_name or f"assert_frame 0x{frame_id:03X}",
                             False, f"Timeout: kein Frame 0x{frame_id:03X} auf {bus}")
            return False
        if expected_data is not None and frame.data[:len(expected_data)] != expected_data:
            self._add_result(
                step_name or f"assert_frame 0x{frame_id:03X}",
                False,
                f"Daten-Mismatch: erwartet={expected_data.hex()}"
                f" empfangen={frame.data.hex()}")
            return False
        self._add_result(step_name or f"assert_frame 0x{frame_id:03X}",
                         True, f"Frame empfangen: {frame.data.hex()}")
        return True

    def assert_did(self, did: int, expected_contains: str = '',
                   timeout: float = 5.0,
                   step_name: str = '') -> bool:
        """Liest einen DID und prueft den Inhalt."""
        resp = self.uds_request(0x22, did=did)
        if resp is None:
            self._add_result(step_name or f"assert_did 0x{did:04X}",
                             False, "Timeout: keine UDS-Antwort")
            return False
        from core.uds_codec import parse_response
        parsed = parse_response(resp)
        if not parsed.is_positive:
            self._add_result(step_name or f"assert_did 0x{did:04X}",
                             False, f"NRC: {parsed.nrc_name}")
            return False
        if expected_contains:
            data_str = parsed.data.hex().upper()
            if expected_contains.upper() not in data_str:
                self._add_result(
                    step_name or f"assert_did 0x{did:04X}",
                    False,
                    f"Inhalt '{expected_contains}' nicht in '{data_str}'")
                return False
        self._add_result(step_name or f"assert_did 0x{did:04X}",
                         True, f"DID OK: {parsed.data.hex().upper()}")
        return True

    # ── Test-Verwaltung ──

    def set_test_name(self, name: str):
        self._test_name = name
        self._start_time = time.time()

    def _add_result(self, step: str, passed: bool, message: str):
        self._results.append(TestResult(
            step=step, passed=passed, message=message,
            timestamp=time.time(),
        ))
        status = "PASS" if passed else "FAIL"
        _log.info("[%s] %s: %s", status, step, message)

    def get_results(self) -> List[TestResult]:
        return list(self._results)

    def clear_results(self):
        self._results = []

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self._results)

    @property
    def summary(self) -> str:
        total = len(self._results)
        passed = sum(1 for r in self._results if r.passed)
        failed = total - passed
        elapsed = time.time() - self._start_time
        return (f"Test: {self._test_name}\n"
                f"Ergebnis: {passed}/{total} bestanden, "
                f"{failed} fehlgeschlagen\n"
                f"Dauer: {elapsed:.1f}s")

    # ── Report ──

    def save_report(self, path: str):
        """Speichert einen Test-Report als Textdatei."""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(f"{'=' * 60}\n")
            f.write(f"  LiveCapture Test-Report\n")
            f.write(f"  {self._test_name}\n")
            f.write(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'=' * 60}\n\n")

            for i, r in enumerate(self._results, 1):
                status = "PASS" if r.passed else "FAIL"
                ts = time.strftime('%H:%M:%S',
                                   time.localtime(r.timestamp))
                f.write(f"  [{status}] {i}. {r.step}\n")
                f.write(f"         {r.message}\n")
                f.write(f"         ({ts})\n\n")

            f.write(f"{'=' * 60}\n")
            f.write(f"  {self.summary}\n")
            f.write(f"{'=' * 60}\n")

        _log.info("Report gespeichert: %s", path)

    # ── Analog/Digital API ──

    def set_analog_page(self, page):
        """Registriert die Analog-Live-Seite fuer Messwert-Zugriff."""
        self._analog_page = page

    def set_digital_page(self, page):
        """Registriert die Digital-Live-Seite fuer Messwert-Zugriff."""
        self._digital_page = page

    def analog_read(self, channel: int) -> Optional[float]:
        """Gibt den letzten Spannungswert eines Analog-Kanals zurueck."""
        if self._analog_page is None:
            return None
        bufs = getattr(self._analog_page, '_channel_buffers', {})
        buf = bufs.get(channel)
        if buf is None or not buf.voltages:
            return None
        return buf.voltages[-1]

    def analog_stats(self, channel: int) -> Dict[str, Any]:
        """Gibt Min/Max/Mean/RMS eines Analog-Kanals zurueck."""
        if self._analog_page is None:
            return {}
        bufs = getattr(self._analog_page, '_channel_buffers', {})
        buf = bufs.get(channel)
        if buf is None:
            return {}
        return buf.stats()

    def digital_read(self, channel: int) -> Optional[int]:
        """Gibt den letzten Pegel (0/1) eines Digital-Kanals zurueck."""
        if self._digital_page is None:
            return None
        bufs = getattr(self._digital_page, '_channel_buffers', {})
        buf = bufs.get(channel)
        if buf is None or not buf.levels:
            return None
        return int(buf.levels[-1])

    def digital_stats(self, channel: int) -> Dict[str, Any]:
        """Gibt Frequenz/Duty/Edges/Pulsbreite eines Digital-Kanals zurueck."""
        if self._digital_page is None:
            return {}
        bufs = getattr(self._digital_page, '_channel_buffers', {})
        buf = bufs.get(channel)
        if buf is None:
            return {}
        return buf.stats()

    def wait_for_analog(self, channel: int, threshold: float,
                        condition: str = 'above',
                        timeout: float = 5.0) -> bool:
        """Wartet bis Analog-Kanal den Schwellwert ueber/unterschreitet."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            val = self.analog_read(channel)
            if val is not None:
                if condition == 'above' and val > threshold:
                    return True
                elif condition == 'below' and val < threshold:
                    return True
            time.sleep(0.05)
        return False

    def wait_for_digital(self, channel: int, level: int,
                         timeout: float = 5.0) -> bool:
        """Wartet bis Digital-Kanal den angegebenen Pegel erreicht."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            val = self.digital_read(channel)
            if val is not None and val == level:
                return True
            time.sleep(0.05)
        return False
