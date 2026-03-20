"""PLP (Probe-Logger-Protocol) Dissector — EtherType 0x2090.

Portiert aus 10-dissector_plp.lua und allen PLP Sub-Dissektoren (ViGEM GmbH).
Unterstützt UserEvent, Status Probe/Bus, Logging Stream, Config Probe,
CounterEvent, TimeSyncEvent, GenericEvent mit CAN, CAN-FD, LIN, FlexRay,
Ethernet, Ethernet 10BASE T1S, UDP und weiteren Bus-Typen.

Verwendet dasselbe DissectField wie cca_dissector.py.
"""

import struct
import logging
from dataclasses import dataclass, field as dc_field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Ergebnis-Datenstruktur (identisch mit cca_dissector) ─────────────────


@dataclass
class DissectField:
    """Ein Feld im Dissect-Ergebnis (für Tree-Darstellung)."""
    name: str
    value: str
    start: int = 0
    end: int = 0
    children: List['DissectField'] = dc_field(default_factory=list)


# ── Konstanten ───────────────────────────────────────────────────────────

PLP_HEADER_LEN = 12
PLP_BUS_HDR_LEN = 16

PLP_TYPE_NAMES = {
    0x00: "UserEvent",
    0x01: "Status Probe",
    0x02: "Status Bus",
    0x03: "Logging Stream",
    0x04: "Config Probe",
    0x0A: "Replay Data",
    0x0B: "CounterEvent",
    0x0C: "TimeSyncEvent",
    0x0D: "GenericEvent",
}

MSG_TYPE_NAMES = {
    0x0000: "None (Undefined)",
    0x0001: "CAN (-FD) Raw",
    0x0002: "CAN Data",
    0x0003: "CAN-FD Data",
    0x0004: "LIN",
    0x0007: "FlexRay Raw",
    0x0008: "FlexRay Data",
    0x000A: "GPIO",
    0x000E: "ILaS",
    0x0010: "UART/RS232_ASCII",
    0x0011: "UART/RS232_RAW",
    0x0012: "UART/RS232_SLA",
    0x0020: "Analog",
    0x0021: "Analog_SLA",
    0x0028: "Analog Alternative",
    0x0080: "Ethernet II (FZG-Kommunikation)",
    0x0082: "Ethernet 10BASE T1S",
    0x0090: "DLT TCP",
    0x00A0: "XCP",
    0x0100: "SerDes",
    0x0101: "MIPI-CSI2 Video",
    0x0102: "MIPI-CSI2 Lidar",
    0x0103: "SPI",
    0x0104: "I2C 7 BIT",
    0x0105: "I2C 10 BIT",
    0x0106: "I2C 7 BIT Event",
    0x0107: "I2C 10 BIT Event",
    0x0200: "TAPI",
    0x0201: "TAPI Initial State",
    0x0202: "TAPI Core Dump",
    0x0400: "Radar",
    0xA000: "PLP_Raw",
    0xB000: "Pre-Label",
}

LOGGER_SYNC_TYPES = {
    1: "Measurement Start",
    2: "Mode Change",
    3: "Label",
    4: "Mode",
    5: "User Event + Trigger",
}


# ── Erkennung ────────────────────────────────────────────────────────────

def is_plp_packet(ethertype: int) -> bool:
    """Prüft ob der EtherType dem PLP-Protokoll entspricht (0x2090)."""
    return ethertype == 0x2090


# ── Haupt-Dissector ──────────────────────────────────────────────────────

def dissect(raw: bytes, base_offset: int = 0) -> List[DissectField]:
    """Dissectiert ein PLP-Paket und gibt eine Liste von DissectField zurück.

    Args:
        raw: Rohe PLP-Payload (nach Ethernet-Header, ab PLP Header)
        base_offset: Absoluter Byte-Offset im Gesamtpaket
    """
    fields = []
    length = len(raw)

    if length < PLP_HEADER_LEN:
        fields.append(DissectField("PLP", f"[Fehler: Zu kurz ({length} Bytes)]",
                                   base_offset, base_offset + length))
        return fields

    # ── PLP Header (12 Bytes) ──
    o = base_offset
    probe_id = struct.unpack('!H', raw[0:2])[0]
    counter = struct.unpack('!H', raw[2:4])[0]
    version = raw[4]
    plp_type = raw[5]
    msg_type = struct.unpack('!H', raw[6:8])[0]
    reserved = struct.unpack('!H', raw[8:10])[0]
    probe_flags = struct.unpack('!H', raw[10:12])[0]

    plp_type_name = PLP_TYPE_NAMES.get(plp_type, f"Unknown (0x{plp_type:02X})")
    msg_type_name = MSG_TYPE_NAMES.get(msg_type, f"Unknown (0x{msg_type:04X})")

    hdr = DissectField(
        "Probe-Logger-Protocol (PLP)",
        f"PLP {plp_type_name}",
        o, o + PLP_HEADER_LEN
    )
    hdr.children = [
        DissectField("ProbeID", str(probe_id), o, o + 2),
        DissectField("Counter", str(counter), o + 2, o + 4),
        DissectField("Version", str(version), o + 4, o + 5),
        DissectField("PlpType", f"0x{plp_type:02X} [{plp_type_name}]", o + 5, o + 6),
        DissectField("MsgType", f"0x{msg_type:04X} [{msg_type_name}]", o + 6, o + 8),
        DissectField("Reserved", f"0x{reserved:04X}", o + 8, o + 10),
    ]

    # ProbeFlags aufschlüsseln
    pf = DissectField("ProbeFlags", f"0x{probe_flags:04X}", o + 10, o + 12)
    pf.children = [
        DissectField("End of Segment (EOS)", str(probe_flags & 0x0001), o + 10, o + 12),
        DissectField("Start of Segment (SOS)", str((probe_flags >> 1) & 0x01),
                     o + 10, o + 12),
        DissectField("Spy", str((probe_flags >> 2) & 0x01), o + 10, o + 12),
        DissectField("Multi Frame", str((probe_flags >> 3) & 0x01), o + 10, o + 12),
        DissectField("Probe Overflow", str((probe_flags >> 15) & 0x01), o + 10, o + 12),
    ]
    hdr.children.append(pf)
    fields.append(hdr)

    # ── PlpType-spezifische Payload ──
    payload = raw[PLP_HEADER_LEN:]
    po = o + PLP_HEADER_LEN  # Payload absoluter Offset

    if plp_type == 0x00:
        _dissect_user_event(payload, po, fields)
    elif plp_type == 0x01:
        if version == 0x01:
            _dissect_status_probe_v1(payload, po, fields)
        else:
            _dissect_status_probe_v2(payload, po, fields)
    elif plp_type == 0x02:
        if version == 0x01:
            _dissect_status_bus_v1(payload, po, fields)
        else:
            _dissect_status_bus_v2(payload, po, fields)
    elif plp_type == 0x03:
        _dissect_logging_stream(payload, po, msg_type, fields)
    elif plp_type == 0x04:
        if version == 0x01:
            _dissect_config_probe_v1(payload, po, fields)
        else:
            _dissect_config_probe_v2(payload, po, fields)
    elif plp_type == 0x0B:
        _dissect_counter_event(payload, po, fields)
    elif plp_type == 0x0C:
        _dissect_timesync_event(payload, po, fields)
    elif plp_type == 0x0D:
        _dissect_generic_v2(payload, po, fields)
    elif len(payload) > 0:
        fields.append(DissectField("Payload", payload.hex().upper(),
                                   po, po + len(payload)))

    return fields


# ── Bus Message Header ──────────────────────────────────────────────────

def _dissect_bus_header(data: bytes, base: int, parent: DissectField) -> int:
    """Dissectiert den 16-Byte Bus Message Header und gibt data_length zurück."""
    if len(data) < PLP_BUS_HDR_LEN:
        parent.value = "[Decoding Error: Zu kurz]"
        return 0

    o = base
    busspec_id = struct.unpack('!I', data[0:4])[0]
    ts_ns = struct.unpack('!Q', data[4:12])[0]
    data_length = struct.unpack('!H', data[12:14])[0]
    data_flags = struct.unpack('!H', data[14:16])[0]

    ts_sec = ts_ns / 1_000_000_000
    ts_str = f"{ts_sec:.9f} s"

    parent.children.extend([
        DissectField("BusspecID", str(busspec_id), o, o + 4),
        DissectField("Timestamp", ts_str, o + 4, o + 12),
        DissectField("Length", str(data_length), o + 12, o + 14),
    ])

    df = DissectField("DataFlags", f"0x{data_flags:04X}", o + 14, o + 16)
    df.children = [
        DissectField("CRC Error", str(int(bool(data_flags & 0x2000))), o + 14, o + 16),
        DissectField("Tx Message", str(int(bool(data_flags & 0x4000))), o + 14, o + 16),
        DissectField("Bus Overflow", str(int(bool(data_flags & 0x8000))), o + 14, o + 16),
    ]
    parent.children.append(df)

    return data_length


# ── UserEvent (0x00) ─────────────────────────────────────────────────────

def _dissect_user_event(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x00 — UserEvent."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP User Event", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    if length >= 4 and len(data) >= PLP_BUS_HDR_LEN + 4:
        o = base + PLP_BUS_HDR_LEN
        ue_probe_id = struct.unpack('!H', data[PLP_BUS_HDR_LEN:PLP_BUS_HDR_LEN + 2])[0]
        ue_id = struct.unpack('!H', data[PLP_BUS_HDR_LEN + 2:PLP_BUS_HDR_LEN + 4])[0]
        root.children.extend([
            DissectField("Userevent ProbeID", str(ue_probe_id), o, o + 2),
            DissectField("Userevent ID", str(ue_id), o + 2, o + 4),
        ])

    fields.append(root)


# ── Status Probe V1 (0x01, version=1) ───────────────────────────────────

def _dissect_status_probe_v1(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x01, Version 1 — Status Probe."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Status Probe", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length > 0 and len(data) >= p + 16:
        root.children.extend([
            DissectField("Vendor ID", f"0x{data[p]:02X}", o, o + 1),
            DissectField("Version", f"0x{data[p+1]:02X}", o + 1, o + 2),
            DissectField("Reserved", f"0x{data[p+2]:02X}", o + 2, o + 3),
        ])
        vsd_len = data[p + 3]
        root.children.extend([
            DissectField("VSD Length", str(vsd_len), o + 3, o + 4),
            DissectField("Probe Serial", f"0x{struct.unpack('!I', data[p+4:p+8])[0]:08X}",
                         o + 4, o + 8),
            DissectField("PLP Total", str(struct.unpack('!I', data[p+8:p+12])[0]),
                         o + 8, o + 12),
            DissectField("Error Total", str(struct.unpack('!I', data[p+12:p+16])[0]),
                         o + 12, o + 16),
        ])
        if vsd_len > 0 and len(data) >= p + 16 + vsd_len:
            root.children.append(DissectField(
                "Vendor Specific Data", data[p + 16:p + 16 + vsd_len].hex().upper(),
                o + 16, o + 16 + vsd_len))

    fields.append(root)


# ── Status Probe V2 (0x01, version≠1) ───────────────────────────────────

def _dissect_status_probe_v2(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x01, Version ≥ 2 — Status Probe V2."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Status Probe", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length > 0 and len(data) >= p + 12:
        root.children.extend([
            DissectField("Vendor ID", f"0x{data[p]:02X}", o, o + 1),
            DissectField("Version", f"0x{data[p+1]:02X}", o + 1, o + 2),
            DissectField("Type", f"0x{data[p+2]:02X}", o + 2, o + 3),
            DissectField("Reserved", f"0x{data[p+3]:02X}", o + 3, o + 4),
        ])
        vsd_len = struct.unpack('!H', data[p + 4:p + 6])[0]
        root.children.extend([
            DissectField("VSD Length", str(vsd_len), o + 4, o + 6),
            DissectField("ProbeID", str(struct.unpack('!H', data[p+6:p+8])[0]),
                         o + 6, o + 8),
            DissectField("Probe Serial", f"0x{struct.unpack('!I', data[p+8:p+12])[0]:08X}",
                         o + 8, o + 12),
        ])
        if vsd_len > 0 and len(data) >= p + 12 + vsd_len:
            root.children.append(DissectField(
                "Vendor Specific Data", data[p + 12:p + 12 + vsd_len].hex().upper(),
                o + 12, o + 12 + vsd_len))

    fields.append(root)


# ── Status Bus V1 (0x02, version=1) ─────────────────────────────────────

def _dissect_status_bus_v1(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x02, Version 1 — Status Bus."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Status Bus", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length > 0 and len(data) >= p + 16:
        root.children.extend([
            DissectField("Vendor ID", f"0x{data[p]:02X}", o, o + 1),
            DissectField("Version", f"0x{data[p+1]:02X}", o + 1, o + 2),
            DissectField("Reserved", f"0x{data[p+2]:02X}", o + 2, o + 3),
        ])
        vsd_len = data[p + 3]
        root.children.extend([
            DissectField("VSD Length", str(vsd_len), o + 3, o + 4),
            DissectField("Probe Serial", f"0x{struct.unpack('!I', data[p+4:p+8])[0]:08X}",
                         o + 4, o + 8),
            DissectField("PLP Total", str(struct.unpack('!I', data[p+8:p+12])[0]),
                         o + 8, o + 12),
            DissectField("Error Total", str(struct.unpack('!I', data[p+12:p+16])[0]),
                         o + 12, o + 16),
        ])
        if vsd_len > 0 and len(data) >= p + 16 + vsd_len:
            root.children.append(DissectField(
                "Vendor Specific Data", data[p + 16:p + 16 + vsd_len].hex().upper(),
                o + 16, o + 16 + vsd_len))

    fields.append(root)


# ── Status Bus V2 (0x02, version≠1) ─────────────────────────────────────

def _dissect_status_bus_v2(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x02, Version ≥ 2 — Status Bus V2 mit Bus-Entries."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Status Bus", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length > 0 and len(data) >= p + 12:
        root.children.extend([
            DissectField("Vendor ID", f"0x{data[p]:02X}", o, o + 1),
            DissectField("Version", f"0x{data[p+1]:02X}", o + 1, o + 2),
            DissectField("Type", f"0x{data[p+2]:02X}", o + 2, o + 3),
            DissectField("Reserved", f"0x{data[p+3]:02X}", o + 3, o + 4),
        ])
        vsd_len = struct.unpack('!H', data[p + 4:p + 6])[0]
        root.children.extend([
            DissectField("VSD Length", str(vsd_len), o + 4, o + 6),
            DissectField("ProbeID", str(struct.unpack('!H', data[p+6:p+8])[0]),
                         o + 6, o + 8),
            DissectField("Probe Serial", f"0x{struct.unpack('!I', data[p+8:p+12])[0]:08X}",
                         o + 8, o + 12),
        ])

        # Bus-Entries
        entry_len = 12 + vsd_len
        rem_off = p + 12
        entry_idx = 1
        while rem_off + entry_len <= len(data):
            eo = base + rem_off
            entry = DissectField(f"Bus Entry #{entry_idx}", "", eo, eo + entry_len)
            entry.children = [
                DissectField("BusspecID",
                             str(struct.unpack('!I', data[rem_off:rem_off + 4])[0]),
                             eo, eo + 4),
                DissectField("PLP Total",
                             str(struct.unpack('!I', data[rem_off + 4:rem_off + 8])[0]),
                             eo + 4, eo + 8),
                DissectField("Error Total",
                             str(struct.unpack('!I', data[rem_off + 8:rem_off + 12])[0]),
                             eo + 8, eo + 12),
            ]
            if vsd_len > 0:
                entry.children.append(DissectField(
                    "Vendor Specific Data",
                    data[rem_off + 12:rem_off + 12 + vsd_len].hex().upper(),
                    eo + 12, eo + 12 + vsd_len))
            root.children.append(entry)
            rem_off += entry_len
            entry_idx += 1

    fields.append(root)


# ── Logging Stream (0x03) ───────────────────────────────────────────────

def _dissect_logging_stream(data: bytes, base: int, msg_type: int,
                            fields: List[DissectField]):
    """PlpType 0x03 — Logging Stream (rekursiv für mehrere Bus Messages)."""
    cur = 0
    msg_idx = 1

    while cur + PLP_BUS_HDR_LEN <= len(data):
        o = base + cur
        root = DissectField(f"PLP Bus Message #{msg_idx}", "", o, o)
        length = _dissect_bus_header(data[cur:], o, root)

        # Sub-Dissektor aufrufen
        payload_start = cur + PLP_BUS_HDR_LEN
        if length > 0 and payload_start + length <= len(data):
            # DataFlags (2 Bytes vor Payload) werden mit übergeben
            df_start = cur + PLP_BUS_HDR_LEN - 2
            sub_data = data[df_start:payload_start + length]
            po = base + df_start

            sub_field = _dispatch_bus_payload(msg_type, sub_data, po)
            if sub_field:
                root.children.append(sub_field)
        elif length > 0 and payload_start < len(data):
            root.children.append(DissectField(
                "Data", data[payload_start:min(payload_start + length, len(data))].hex().upper(),
                base + payload_start, base + min(payload_start + length, len(data))))

        root.end = o + PLP_BUS_HDR_LEN + length
        fields.append(root)

        cur += PLP_BUS_HDR_LEN + length
        msg_idx += 1


# ── Config Probe V1 (0x04, version=1) ───────────────────────────────────

def _dissect_config_probe_v1(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x04, Version 1 — Config Probe."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Config Probe", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length > 0 and len(data) >= p + 8:
        root.children.extend([
            DissectField("Vendor ID", f"0x{data[p]:02X}", o, o + 1),
            DissectField("Version", f"0x{data[p+1]:02X}", o + 1, o + 2),
            DissectField("Type", f"0x{data[p+2]:02X}", o + 2, o + 3),
        ])
        vsd_len = data[p + 3]
        root.children.extend([
            DissectField("VSD Length", str(vsd_len), o + 3, o + 4),
            DissectField("Probe Serial", f"0x{struct.unpack('!I', data[p+4:p+8])[0]:08X}",
                         o + 4, o + 8),
        ])
        if vsd_len > 0 and len(data) >= p + 8 + vsd_len:
            root.children.append(DissectField(
                "Vendor Specific Data", data[p + 8:p + 8 + vsd_len].hex().upper(),
                o + 8, o + 8 + vsd_len))

    fields.append(root)


# ── Config Probe V2 (0x04, version≠1) ───────────────────────────────────

def _dissect_config_probe_v2(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x04, Version ≥ 2 — Config Probe V2."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Config Probe", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length > 0 and len(data) >= p + 12:
        root.children.extend([
            DissectField("Vendor ID", f"0x{data[p]:02X}", o, o + 1),
            DissectField("Version", f"0x{data[p+1]:02X}", o + 1, o + 2),
            DissectField("Type", f"0x{data[p+2]:02X}", o + 2, o + 3),
            DissectField("Reserved", f"0x{data[p+3]:02X}", o + 3, o + 4),
        ])
        vsd_len = struct.unpack('!H', data[p + 4:p + 6])[0]
        root.children.extend([
            DissectField("VSD Length", str(vsd_len), o + 4, o + 6),
            DissectField("ProbeID", str(struct.unpack('!H', data[p+6:p+8])[0]),
                         o + 6, o + 8),
            DissectField("Probe Serial", f"0x{struct.unpack('!I', data[p+8:p+12])[0]:08X}",
                         o + 8, o + 12),
        ])
        if vsd_len > 0 and len(data) >= p + 12 + vsd_len:
            root.children.append(DissectField(
                "Vendor Specific Data", data[p + 12:p + 12 + vsd_len].hex().upper(),
                o + 12, o + 12 + vsd_len))

    fields.append(root)


# ── CounterEvent (0x0B) ─────────────────────────────────────────────────

def _dissect_counter_event(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x0B — Counter Event."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Counter Event", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length >= 8 and len(data) >= p + 8:
        root.children.extend([
            DissectField("Counterevent ProbeID",
                         str(struct.unpack('!H', data[p:p + 2])[0]), o, o + 2),
            DissectField("Interface ID",
                         str(struct.unpack('!H', data[p + 2:p + 4])[0]), o + 2, o + 4),
            DissectField("Previous Counter",
                         str(struct.unpack('!H', data[p + 4:p + 6])[0]), o + 4, o + 6),
            DissectField("Current Counter",
                         str(struct.unpack('!H', data[p + 6:p + 8])[0]), o + 6, o + 8),
        ])

    fields.append(root)


# ── TimeSyncEvent (0x0C) ────────────────────────────────────────────────

def _dissect_timesync_event(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x0C — TimeSync Event."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP TimeSync Event", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p
    if length >= 8 and len(data) >= p + 8:
        root.children.extend([
            DissectField("TimeSync ProbeID",
                         str(struct.unpack('!H', data[p:p + 2])[0]), o, o + 2),
            DissectField("Interface ID",
                         str(struct.unpack('!H', data[p + 2:p + 4])[0]), o + 2, o + 4),
            DissectField("Reserved",
                         str(struct.unpack('!H', data[p + 4:p + 6])[0]), o + 4, o + 6),
            DissectField("Async", str(data[p + 6]), o + 6, o + 7),
            DissectField("Delta", str(data[p + 7]), o + 7, o + 8),
        ])

    fields.append(root)


# ── GenericEvent (0x0D) ─────────────────────────────────────────────────

def _dissect_generic_v2(data: bytes, base: int, fields: List[DissectField]):
    """PlpType 0x0D — Generic Event mit LoggerSync-Erkennung."""
    if len(data) < PLP_BUS_HDR_LEN:
        return

    root = DissectField("PLP Generic Event", "", base, base + len(data))
    length = _dissect_bus_header(data, base, root)

    p = PLP_BUS_HDR_LEN
    o = base + p

    if length >= 3 and len(data) >= p + 3:
        magic = struct.unpack('!H', data[p:p + 2])[0]

        if magic == 0xABCD:
            # LoggerSync
            ls_type = data[p + 2]
            ls_type_name = LOGGER_SYNC_TYPES.get(ls_type, f"Unknown ({ls_type})")

            ls = DissectField("PLP Logger Sync", f"Type: {ls_type_name}",
                              o, o + length)
            ls.children = [
                DissectField("Magic", f"0x{magic:04X}", o, o + 2),
                DissectField("Type", f"{ls_type} [{ls_type_name}]", o + 2, o + 3),
            ]

            if ls_type == 1 and length >= 31 and len(data) >= p + 31:
                # Measurement Start
                start_time = struct.unpack('!q', data[p + 3:p + 11])[0]
                trigger_num = struct.unpack('!I', data[p + 11:p + 15])[0]
                uuid_data = data[p + 15:p + 31]
                ls.children.extend([
                    DissectField("Measurement StartTime", str(start_time),
                                 o + 3, o + 11),
                    DissectField("Trigger Number", str(trigger_num),
                                 o + 11, o + 15),
                    DissectField("Measurement UUID", uuid_data.hex().upper(),
                                 o + 15, o + 31),
                ])
            elif ls_type == 2 and length >= 4 and len(data) >= p + 4:
                # Mode Change
                ls.children.append(DissectField("Mode", str(data[p + 3]),
                                                o + 3, o + 4))
            elif ls_type == 3 and length >= 5 and len(data) >= p + 5:
                # Label
                label_size = struct.unpack('!H', data[p + 3:p + 5])[0]
                ls.children.append(DissectField("Label Size", str(label_size),
                                                o + 3, o + 5))
                if label_size > 0 and len(data) >= p + 5 + label_size:
                    try:
                        label = data[p + 5:p + 5 + label_size].decode('utf-8', errors='replace')
                    except Exception:
                        label = data[p + 5:p + 5 + label_size].hex().upper()
                    ls.children.append(DissectField("Label", label,
                                                    o + 5, o + 5 + label_size))
            elif ls_type == 4 and length >= 4 and len(data) >= p + 4:
                ls.children.append(DissectField("Mode", str(data[p + 3]),
                                                o + 3, o + 4))
            elif ls_type == 5 and length >= 13 and len(data) >= p + 13:
                # User Event + Trigger
                user_event = struct.unpack('!I', data[p + 3:p + 7])[0]
                ue_id = struct.unpack('!H', data[p + 7:p + 9])[0]
                trigger = struct.unpack('!I', data[p + 9:p + 13])[0]
                ls.children.extend([
                    DissectField("User Event", str(user_event), o + 3, o + 7),
                    DissectField("User Event ID", str(ue_id), o + 7, o + 9),
                    DissectField("Trigger Number", str(trigger), o + 9, o + 13),
                ])
            elif length > 3:
                ls.children.append(DissectField("Data",
                                                data[p + 3:p + length].hex().upper(),
                                                o + 3, o + length))

            root.children.append(ls)
        elif length > 0:
            root.children.append(DissectField("Data", data[p:p + length].hex().upper(),
                                              o, o + length))
    elif length > 0 and len(data) >= p + length:
        root.children.append(DissectField("Data", data[p:p + length].hex().upper(),
                                          o, o + length))

    fields.append(root)


# ── Bus Payload Sub-Dissektoren ──────────────────────────────────────────

def _dispatch_bus_payload(msg_type: int, data: bytes,
                          base: int) -> Optional[DissectField]:
    """Dispatcht zum passenden PLP Bus Sub-Dissektor.

    data beginnt mit DataFlags (2 Bytes), gefolgt von den protokollspezifischen Daten.
    """
    dispatch = {
        0x0002: _dissect_plp_can,
        0x0003: _dissect_plp_can_fd,
        0x0004: _dissect_plp_lin,
        0x0008: _dissect_plp_flexray,
        0x0080: _dissect_plp_ethernet,
        0x0082: _dissect_plp_ethernet_t1s,
    }
    fn = dispatch.get(msg_type)
    if fn:
        try:
            return fn(data, base)
        except Exception as e:
            logger.debug("PLP Sub-Dissector Fehler (type=0x%04X): %s", msg_type, e)

    # Fallback: Raw-Daten anzeigen (DataFlags überspringen)
    if len(data) > 2:
        name = MSG_TYPE_NAMES.get(msg_type, f"Payload (0x{msg_type:04X})")
        return DissectField(name, data[2:].hex().upper(), base + 2, base + len(data))
    return None


# ── PLP CAN (MsgType 0x0002) ────────────────────────────────────────────

def _dissect_plp_can(data: bytes, base: int) -> DissectField:
    """PLP CAN Data — DataFlags(2) + ID(4) + Length(1) + Data."""
    if len(data) < 7:
        return DissectField("CAN", f"[Zu kurz: {len(data)} Bytes]", base, base + len(data))

    o = base
    df = struct.unpack('!H', data[0:2])[0]
    can_id = struct.unpack('!I', data[2:6])[0]
    can_len = data[6]

    ide = bool(df & 0x0004)
    rtr = bool(df & 0x0002)
    id_str = f"0x{can_id:08X}" if ide else f"0x{can_id:03X}"

    root = DissectField("CAN", f"ID: {id_str}, Len: {can_len}", o + 2, o + 7 + can_len)

    # DataFlags
    df_f = DissectField("DataFlags", f"0x{df:04X}", o, o + 2)
    df_f.children = [
        DissectField("ACK", str(int(bool(df & 0x0001))), o, o + 2),
        DissectField("RTR", str(int(rtr)), o, o + 2),
        DissectField("IDE", str(int(ide)), o, o + 2),
        DissectField("ERR", str(int(bool(df & 0x0008))), o, o + 2),
        DissectField("BRS", str(int(bool(df & 0x0010))), o, o + 2),
    ]
    root.children.append(df_f)

    root.children.append(DissectField("Identifier", id_str, o + 2, o + 6))
    root.children.append(DissectField("Length", str(can_len), o + 6, o + 7))

    if can_len > 0 and len(data) >= 7 + can_len:
        root.children.append(DissectField("Data", data[7:7 + can_len].hex().upper(),
                                          o + 7, o + 7 + can_len))
    return root


# ── PLP CAN-FD (MsgType 0x0003) ─────────────────────────────────────────

def _dissect_plp_can_fd(data: bytes, base: int) -> DissectField:
    """PLP CAN-FD Data — DataFlags(2) + ID(4) + Length(1) + Data."""
    if len(data) < 7:
        return DissectField("CAN-FD", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    df = struct.unpack('!H', data[0:2])[0]
    can_id = struct.unpack('!I', data[2:6])[0]
    can_len = data[6]

    ide = bool(df & 0x0004)
    brs = bool(df & 0x0010)
    id_str = f"0x{can_id:08X}" if ide else f"0x{can_id:03X}"

    root = DissectField("CAN-FD", f"ID: {id_str}, Len: {can_len}",
                        o + 2, o + 7 + can_len)

    df_f = DissectField("DataFlags", f"0x{df:04X}", o, o + 2)
    df_f.children = [
        DissectField("ACK", str(int(bool(df & 0x0001))), o, o + 2),
        DissectField("ESI", str(int(bool(df & 0x0002))), o, o + 2),
        DissectField("IDE", str(int(ide)), o, o + 2),
        DissectField("ERR", str(int(bool(df & 0x0008))), o, o + 2),
        DissectField("BRS", str(int(brs)), o, o + 2),
    ]
    root.children.append(df_f)

    root.children.append(DissectField("Identifier", id_str, o + 2, o + 6))
    root.children.append(DissectField("Length", str(can_len), o + 6, o + 7))

    if can_len > 0 and len(data) >= 7 + can_len:
        root.children.append(DissectField("Data", data[7:7 + can_len].hex().upper(),
                                          o + 7, o + 7 + can_len))
    return root


# ── PLP LIN (MsgType 0x0004) ────────────────────────────────────────────

def _dissect_plp_lin(data: bytes, base: int) -> DissectField:
    """PLP LIN — DataFlags(2) + ID(1) + Length(1) + Data + Checksum."""
    if len(data) < 5:
        return DissectField("LIN", f"[Zu kurz: {len(data)} Bytes]", base, base + len(data))

    o = base
    df = struct.unpack('!H', data[0:2])[0]
    lin_id = data[2]
    lin_len = data[3]

    root = DissectField("LIN", f"ID: 0x{lin_id:02X}, Len: {lin_len}",
                        o + 2, o + 4 + lin_len + 1)

    df_f = DissectField("DataFlags", f"0x{df:04X}", o, o + 2)
    df_f.children = [
        DissectField("Collision Error", str(int(bool(df & 0x0001))), o, o + 2),
        DissectField("Parity Error", str(int(bool(df & 0x0002))), o, o + 2),
    ]
    root.children.append(df_f)

    root.children.append(DissectField("Identifier", f"0x{lin_id:02X} ({lin_id})",
                                      o + 2, o + 3))
    root.children.append(DissectField("Length", str(lin_len), o + 3, o + 4))

    if lin_len > 0 and len(data) >= 4 + lin_len:
        root.children.append(DissectField("Data", data[4:4 + lin_len].hex().upper(),
                                          o + 4, o + 4 + lin_len))
    if len(data) >= 4 + lin_len + 1:
        checksum = data[4 + lin_len]
        root.children.append(DissectField("Checksum", f"0x{checksum:02X}",
                                          o + 4 + lin_len, o + 5 + lin_len))
    return root


# ── PLP FlexRay (MsgType 0x0008) ────────────────────────────────────────

def _dissect_plp_flexray(data: bytes, base: int) -> DissectField:
    """PLP FlexRay Data — DataFlags(2) + Cycle(1) + FrameID(2) + PayloadLen(1) + Data."""
    if len(data) < 6:
        return DissectField("FlexRay", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    df = struct.unpack('!H', data[0:2])[0]
    cycle = data[2]
    frame_id = struct.unpack('!H', data[3:5])[0]
    payload_len = data[5]

    root = DissectField("FlexRay", f"Frame ID: {frame_id}, Cycle: {cycle}",
                        o + 2, o + 6 + payload_len)

    df_f = DissectField("DataFlags", f"0x{df:04X}", o, o + 2)
    fr_flags = [
        (0x0001, "Nullframe"), (0x0002, "Startup Frame"),
        (0x0004, "Sync Frame"), (0x0008, "WUP Frame"),
        (0x0010, "Payload Preamble Indicator"),
        (0x0020, "Collision Avoidance Symbol"),
    ]
    for mask, name in fr_flags:
        df_f.children.append(DissectField(name, str(int(bool(df & mask))), o, o + 2))
    root.children.append(df_f)

    root.children.append(DissectField("Cycle", str(cycle), o + 2, o + 3))
    root.children.append(DissectField("Frame ID", str(frame_id), o + 3, o + 5))
    root.children.append(DissectField("Payload Length", str(payload_len), o + 5, o + 6))

    if payload_len > 0 and len(data) >= 6 + payload_len:
        root.children.append(DissectField("Data",
                                          data[6:6 + payload_len].hex().upper(),
                                          o + 6, o + 6 + payload_len))
    return root


# ── PLP Ethernet II (MsgType 0x0080) ────────────────────────────────────

def _dissect_plp_ethernet(data: bytes, base: int) -> DissectField:
    """PLP Ethernet II — DataFlags(2) + Dst(6) + Src(6) + Type(2) + Data."""
    if len(data) < 16:
        return DissectField("Ethernet", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    df = struct.unpack('!H', data[0:2])[0]
    dst_mac = ':'.join(f'{b:02x}' for b in data[2:8])
    src_mac = ':'.join(f'{b:02x}' for b in data[8:14])
    etype = struct.unpack('!H', data[14:16])[0]
    payload_len = len(data) - 16

    root = DissectField("Ethernet",
                        f"Dst: {dst_mac}, Src: {src_mac}",
                        o + 2, o + len(data))

    root.children.append(DissectField("Destination", dst_mac, o + 2, o + 8))
    root.children.append(DissectField("Source", src_mac, o + 8, o + 14))
    root.children.append(DissectField("Type", f"0x{etype:04X}", o + 14, o + 16))
    root.children.append(DissectField("Data Length", str(payload_len), o + 14, o + 16))

    if payload_len > 0:
        root.children.append(DissectField("Data", data[16:].hex().upper(),
                                          o + 16, o + len(data)))
    return root


# ── PLP Ethernet 10BASE T1S (MsgType 0x0082) ───────────────────────────

def _dissect_plp_ethernet_t1s(data: bytes, base: int) -> DissectField:
    """PLP Ethernet 10BASE T1S — DataFlags(2) + BeaconTs(8) + Dst(6) + Src(6) + Type(2) + Data."""
    if len(data) < 24:
        return DissectField("Ethernet 10BASE T1S", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    beacon_ts = struct.unpack('!Q', data[2:10])[0]
    dst_mac = ':'.join(f'{b:02x}' for b in data[10:16])
    src_mac = ':'.join(f'{b:02x}' for b in data[16:22])
    etype = struct.unpack('!H', data[22:24])[0]
    payload_len = len(data) - 24

    root = DissectField("Ethernet 10BASE T1S",
                        f"Dst: {dst_mac}, Src: {src_mac}",
                        o + 2, o + len(data))

    root.children.append(DissectField("Beacon Timestamp",
                                      f"0x{beacon_ts:016X}", o + 2, o + 10))
    root.children.append(DissectField("Destination", dst_mac, o + 10, o + 16))
    root.children.append(DissectField("Source", src_mac, o + 16, o + 22))
    root.children.append(DissectField("Type", f"0x{etype:04X}", o + 22, o + 24))

    if payload_len > 0:
        root.children.append(DissectField("Data", data[24:].hex().upper(),
                                          o + 24, o + len(data)))
    return root
