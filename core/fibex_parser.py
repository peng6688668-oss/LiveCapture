"""Minimaler FIBEX-Parser fuer FlexRay Frame-Namen und Signal-Dekodierung.

Unterstuetzt FIBEX 3.x/4.x (ASAM MCD-2 NET).
Namespace: http://www.asam.net/xml/fbx
"""

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_log = logging.getLogger(__name__)

# FIBEX Namespaces (haeufigste Varianten)
_NS_CANDIDATES = [
    'http://www.asam.net/xml/fbx',
    'http://www.asam.net/xml',
    'http://www.asam.net/xml/fbx/filelevel',
]


@dataclass
class FibexSignal:
    """Ein FlexRay-Signal innerhalb eines Frames."""
    name: str = ''
    bit_position: int = 0
    bit_size: int = 0
    factor: float = 1.0
    offset: float = 0.0
    unit: str = ''
    min_val: float = 0.0
    max_val: float = 0.0


@dataclass
class FibexFrame:
    """Ein FlexRay-Frame mit Slot-ID und Signalen."""
    name: str = ''
    slot_id: int = 0
    byte_length: int = 0
    cycle: int = 0
    signals: List[FibexSignal] = field(default_factory=list)


class FibexDatabase:
    """Laedt und verwaltet FIBEX-Frames fuer FlexRay Slot-ID → Name Lookup."""

    def __init__(self):
        self._frames_by_slot: Dict[int, FibexFrame] = {}
        self._frames_by_name: Dict[str, FibexFrame] = {}
        self._file_path: str = ''

    @property
    def frames(self) -> List[FibexFrame]:
        return list(self._frames_by_slot.values())

    def load_file(self, path: str):
        """Parst eine FIBEX-XML-Datei."""
        self._file_path = path
        tree = ET.parse(path)
        root = tree.getroot()

        # Namespace auto-detect
        ns = self._detect_namespace(root)
        nsmap = {'fx': ns} if ns else {}

        # Frames extrahieren
        self._parse_frames(root, nsmap)
        _log.info("FIBEX geladen: %s (%d Frames)", path, len(self._frames_by_slot))

    def _detect_namespace(self, root) -> str:
        """Erkennt den FIBEX-Namespace aus dem Root-Element."""
        tag = root.tag
        if '{' in tag:
            ns = tag.split('}')[0].lstrip('{')
            return ns
        # Fallback: bekannte Namespaces pruefen
        for ns in _NS_CANDIDATES:
            if root.find(f'{{{ns}}}ELEMENTS') is not None:
                return ns
        return ''

    def _parse_frames(self, root, nsmap: dict):
        """Extrahiert Frame-Definitionen aus FIBEX."""
        ns = nsmap.get('fx', '')
        prefix = f'{{{ns}}}' if ns else ''

        # Methode 1: Standard FIBEX 3.x/4.x Pfad
        for frame_el in root.iter(f'{prefix}FRAME'):
            frame = FibexFrame()

            # Frame-Name
            short_name = frame_el.find(f'{prefix}SHORT-NAME')
            if short_name is None:
                short_name = frame_el.find(f'{prefix}FRAME-NAME')
            if short_name is not None and short_name.text:
                frame.name = short_name.text

            # Byte-Laenge
            byte_len = frame_el.find(f'{prefix}BYTE-LENGTH')
            if byte_len is not None and byte_len.text:
                try:
                    frame.byte_length = int(byte_len.text)
                except ValueError:
                    pass

            # Frame-ID aus Attribut oder Sub-Element
            frame_id = frame_el.get('ID', '')

            # Signale
            for sig_el in frame_el.iter(f'{prefix}SIGNAL-INSTANCE'):
                sig = self._parse_signal(sig_el, prefix)
                if sig:
                    frame.signals.append(sig)

            if frame.name:
                self._frames_by_name[frame.name] = frame

        # Slot-Zuordnung aus FRAME-TRIGGERING
        for ft in root.iter(f'{prefix}FRAME-TRIGGERING'):
            slot_el = ft.find(f'.//{prefix}SLOT-ID')
            frame_ref = ft.find(f'{prefix}FRAME-REF')
            if frame_ref is None:
                frame_ref = ft.find(f'.//{prefix}FRAME-REF')

            if slot_el is not None and slot_el.text:
                try:
                    slot_id = int(slot_el.text)
                except ValueError:
                    continue

                # Frame-Ref: ID-REF Attribut oder Text
                ref_id = ''
                if frame_ref is not None:
                    ref_id = frame_ref.get('ID-REF', '') or frame_ref.text or ''

                # Frame-Name aus Ref suchen
                frame_name = ''
                if ref_id:
                    # Suche Frame mit passendem ID-Attribut
                    for f_el in root.iter(f'{prefix}FRAME'):
                        if f_el.get('ID', '') == ref_id:
                            sn = f_el.find(f'{prefix}SHORT-NAME')
                            if sn is not None:
                                frame_name = sn.text or ''
                            break

                if frame_name and frame_name in self._frames_by_name:
                    frame = self._frames_by_name[frame_name]
                    frame.slot_id = slot_id
                    self._frames_by_slot[slot_id] = frame

        # Fallback: Frames ohne Slot-Zuordnung mit Name registrieren
        if not self._frames_by_slot and self._frames_by_name:
            _log.warning("Keine Slot-Zuordnung gefunden, %d Frames nur per Name",
                         len(self._frames_by_name))

    def _parse_signal(self, sig_el, prefix: str) -> Optional[FibexSignal]:
        """Parst ein SIGNAL-INSTANCE Element."""
        sig = FibexSignal()
        sn = sig_el.find(f'{prefix}SHORT-NAME')
        if sn is not None and sn.text:
            sig.name = sn.text

        bp = sig_el.find(f'{prefix}BIT-POSITION')
        if bp is not None and bp.text:
            try:
                sig.bit_position = int(bp.text)
            except ValueError:
                pass

        bl = sig_el.find(f'{prefix}BIT-SIZE')
        if bl is not None and bl.text:
            try:
                sig.bit_size = int(bl.text)
            except ValueError:
                pass

        return sig if sig.name else None

    def get_frame_by_slot(self, slot_id: int) -> FibexFrame:
        """Gibt den Frame fuer eine Slot-ID zurueck (KeyError wenn nicht gefunden)."""
        return self._frames_by_slot[slot_id]

    def get_frame_by_name(self, name: str) -> FibexFrame:
        """Gibt den Frame fuer einen Namen zurueck."""
        return self._frames_by_name[name]
