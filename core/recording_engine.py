"""Recording Engine — BLF/ASC/CSV Export fuer Bus-Daten.

Unterstuetzte Formate:
  - BLF (Vector Binary Log Format) — CAN/LIN via python-can
  - ASC (ASCII Trace) — CAN/LIN/FlexRay
  - CSV (Komma-separiert) — alle Bus-Typen
  - PCAP (Packet Capture) — Ethernet
"""

import csv
import logging
import os
import struct
import time
from datetime import datetime
from typing import List, Optional

_log = logging.getLogger(__name__)

# python-can BLF/ASC Writer
try:
    import can
    CAN_IO_AVAILABLE = True
except ImportError:
    CAN_IO_AVAILABLE = False


def get_export_filter(bus_name: str) -> str:
    """Gibt den Dateidialog-Filter fuer einen Bus-Typ zurueck."""
    if bus_name in ('CAN', 'LIN'):
        return (
            "BLF (*.blf);;ASC (*.asc);;CSV (*.csv);;Alle (*)"
        )
    elif bus_name == 'Ethernet':
        return "CSV (*.csv);;Alle (*)"
    elif bus_name == 'FlexRay':
        return "ASC (*.asc);;CSV (*.csv);;Alle (*)"
    return "CSV (*.csv);;Alle (*)"


def get_default_filename(bus_name: str, ext: str = 'blf') -> str:
    """Erzeugt einen Standard-Dateinamen mit Zeitstempel."""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{bus_name}_record_{ts}.{ext}"


def export_bus_data(path: str, bus_name: str, headers: list,
                    rows: List[tuple]) -> int:
    """Exportiert Bus-Daten im Format je nach Dateiendung.

    Returns: Anzahl geschriebener Zeilen
    """
    ext = os.path.splitext(path)[1].lower()
    if ext == '.blf' and bus_name in ('CAN', 'LIN'):
        return _export_blf(path, bus_name, headers, rows)
    elif ext == '.asc':
        return _export_asc(path, bus_name, headers, rows)
    else:
        return _export_csv(path, headers, rows)


def _export_csv(path: str, headers: list, rows: List[tuple]) -> int:
    """CSV-Export (Semikolon-getrennt, UTF-8)."""
    with open(path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow(headers)
        for row in rows:
            writer.writerow(row)
    return len(rows)


def _export_blf(path: str, bus_name: str, headers: list,
                rows: List[tuple]) -> int:
    """BLF-Export via python-can fuer CAN/LIN."""
    if not CAN_IO_AVAILABLE:
        _log.warning("python-can nicht installiert, Fallback auf CSV")
        return _export_csv(path.replace('.blf', '.csv'), headers, rows)

    count = 0
    with can.BLFWriter(path) as writer:
        for row in rows:
            msg = _row_to_can_message(bus_name, headers, row)
            if msg is not None:
                writer.on_message_received(msg)
                count += 1
    return count


def _export_asc(path: str, bus_name: str, headers: list,
                rows: List[tuple]) -> int:
    """ASC-Export (ASCII Trace Format)."""
    count = 0
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f"date {datetime.now().strftime('%a %b %d %I:%M:%S %p %Y')}\n")
        f.write(f"base hex  timestamps absolute\n")
        f.write(f"internal events logged\n")
        f.write(f"Begin Triggerblock\n")

        for row in rows:
            line = _row_to_asc_line(bus_name, headers, row)
            if line:
                f.write(line + '\n')
                count += 1

        f.write(f"End Triggerblock\n")
    return count


def _row_to_can_message(bus_name: str, headers: list,
                        row: tuple) -> Optional['can.Message']:
    """Konvertiert eine Tabellenzeile in ein can.Message-Objekt."""
    if not CAN_IO_AVAILABLE:
        return None
    try:
        col = {h: i for i, h in enumerate(headers)}

        # Zeitstempel
        zeit_str = row[col.get('Zeit', 1)]
        try:
            timestamp = float(zeit_str)
        except (ValueError, TypeError):
            timestamp = 0.0

        # ID
        id_str = row[col.get('ID', 3)]
        if isinstance(id_str, str):
            id_str = id_str.strip().rstrip('.')
            arb_id = int(id_str, 16) if id_str.startswith('0x') else int(id_str)
        else:
            arb_id = int(id_str)

        # Fuer LIN: ID in untere 6 Bits
        if bus_name == 'LIN':
            arb_id = arb_id & 0x3F

        # DLC
        dlc_str = row[col.get('DLC', 5)]
        dlc = int(dlc_str) if dlc_str else 0

        # Daten
        data_str = row[col.get('Daten', 6)]
        if isinstance(data_str, str) and data_str.strip():
            data = bytes.fromhex(data_str.replace(' ', ''))
        else:
            data = b''

        # Kanal
        channel_str = row[col.get('Kanal', 2)]
        channel = str(channel_str) if channel_str else '0'

        return can.Message(
            timestamp=timestamp,
            arbitration_id=arb_id,
            data=data[:dlc] if dlc > 0 else data,
            channel=channel,
            is_extended_id=arb_id > 0x7FF,
        )
    except Exception as e:
        _log.debug("Zeile nicht konvertierbar: %s", e)
        return None


def _row_to_asc_line(bus_name: str, headers: list, row: tuple) -> str:
    """Konvertiert eine Tabellenzeile in eine ASC-Zeile."""
    try:
        col = {h: i for i, h in enumerate(headers)}

        zeit_str = row[col.get('Zeit', 1)]
        try:
            timestamp = float(zeit_str)
        except (ValueError, TypeError):
            timestamp = 0.0

        if bus_name in ('CAN', 'LIN'):
            id_str = row[col.get('ID', 3)]
            if isinstance(id_str, str):
                id_str = id_str.strip().rstrip('.')
            dlc_str = row[col.get('DLC', 5)]
            data_str = row[col.get('Daten', 6)]
            kanal = row[col.get('Kanal', 2)]
            dlc = int(dlc_str) if dlc_str else 0
            data_hex = data_str if isinstance(data_str, str) else ''
            direction = 'Rx'
            info_str = row[col.get('Info', 7)] if len(row) > 7 else ''
            if isinstance(info_str, str) and 'TX' in info_str.upper():
                direction = 'Tx'
            return (f"   {timestamp:.6f} 1  "
                    f"{id_str}             {direction}   d {dlc}  {data_hex}")

        elif bus_name == 'FlexRay':
            slot = row[col.get('Slot', 3)]
            cycle = row[col.get('Zyklus', 4)]
            dlc_str = row[col.get('DLC', 5)]
            data_str = row[col.get('Daten', 6)]
            kanal = row[col.get('Kanal', 2)]
            dlc = int(dlc_str) if dlc_str else 0
            return (f"   {timestamp:.6f} FR  {kanal}  "
                    f"Slot={slot} Cycle={cycle} DLC={dlc}  {data_str}")

        elif bus_name == 'Ethernet':
            return (f"   {timestamp:.6f}  "
                    + '  '.join(str(v) for v in row[1:]))

    except Exception as e:
        _log.debug("ASC-Zeile nicht erzeugbar: %s", e)
    return ''
