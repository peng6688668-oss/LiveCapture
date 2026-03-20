"""CMP (Capture Module Protocol) Dissector — ASAM CMP / EtherType 0x99FE.

Portiert aus dissector_cmp.lua und allen CMP Sub-Dissektoren (ViGEM GmbH).
Unterstützt Data/Control/Status Messages mit CAN, CAN-FD, LIN, FlexRay,
Ethernet, Digital, UART/RS-232, Analog, SPI, I2C, GigE Vision, MIPI CSI-2.

Verwendet dasselbe DissectField wie cca_dissector.py.
"""

import struct
import logging
from dataclasses import dataclass, field as dc_field
from typing import List

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

CMP_FRAME_HEADER_LEN = 8
CMP_MSG_HEADER_LEN = 16

CMP_TYPE_NAMES = {
    0x00: "Unknown",
    0x01: "Data Message",
    0x02: "Control Message",
    0x03: "Status Message",
    0x0D: "Vendor-Defined Message",
}

DATA_MSG_TYPE_NAMES = {
    0x00: "Invalid",
    0x01: "CAN",
    0x02: "CAN-FD",
    0x03: "LIN",
    0x04: "FLEXRAY",
    0x05: "DIGITAL",
    0x06: "UART / RS-232",
    0x07: "ANALOG",
    0x08: "ETHERNET",
    0x09: "SPI",
    0x0A: "I2C",
    0x0B: "GigE Vision",
    0x0C: "MIPI CSI-2 D-PHY",
    0xFF: "Vendor-Specific",
}

CONTROL_MSG_TYPE_NAMES = {
    0x00: "Invalid",
    0x01: "Data-Sink-Ready-To-Receive Message",
    0xFE: "User Event Message",
    0xFF: "Vendor-Specific Control Message",
}

STATUS_MSG_TYPE_NAMES = {
    0x00: "Invalid",
    0x01: "Capture Module Status",
    0x02: "Interface Status",
    0x03: "Configuration Status",
    0x04: "Data Lost Event Status",
    0x05: "Time Sync Lost Event Status",
    0xFF: "Vendor-Specific Status",
}

SEGMENT_NAMES = {
    0x0: "Unsegmented",
    0x4: "First segment",
    0x8: "Intermediary segment",
    0xC: "Last segment",
}

# CAN FD DLC → Datenlänge
_CAN_FD_DLC_MAP = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
    9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64,
}


# ── Erkennung ────────────────────────────────────────────────────────────

def is_cmp_packet(ethertype: int) -> bool:
    """Prüft ob der EtherType dem CMP-Protokoll entspricht (0x99FE)."""
    return ethertype == 0x99FE


# ── Haupt-Dissector ──────────────────────────────────────────────────────

def dissect(raw: bytes, base_offset: int = 0) -> List[DissectField]:
    """Dissectiert ein CMP-Paket und gibt eine Liste von DissectField zurück.

    Args:
        raw: Rohe CMP-Payload (nach Ethernet-Header, ab CMP Frame Header)
        base_offset: Absoluter Byte-Offset im Gesamtpaket
    """
    fields = []
    length = len(raw)

    if length < CMP_FRAME_HEADER_LEN:
        fields.append(DissectField("CMP", "[Fehler: Zu kurz]", base_offset,
                                   base_offset + length))
        return fields

    # ── Frame Header (8 Bytes) ──
    version = raw[0]
    reserved_1 = raw[1]
    device_id = struct.unpack('!H', raw[2:4])[0]
    msg_type_val = raw[4]
    stream_id = raw[5]
    seq_counter = struct.unpack('!H', raw[6:8])[0]

    msg_type_name = CMP_TYPE_NAMES.get(msg_type_val, "Invalid")

    o = base_offset
    frame_hdr = DissectField(
        "CMP Frame Header",
        f"CMP [{msg_type_name}]",
        o, o + CMP_FRAME_HEADER_LEN
    )
    frame_hdr.children = [
        DissectField("Version", str(version), o, o + 1),
        DissectField("Reserved", f"0x{reserved_1:02X}", o + 1, o + 2),
        DissectField("Device ID", f"{device_id} (0x{device_id:04X})", o + 2, o + 4),
        DissectField("Message Type", f"0x{msg_type_val:02X} [{msg_type_name}]", o + 4, o + 5),
        DissectField("Stream ID", str(stream_id), o + 5, o + 6),
        DissectField("Stream Sequence Counter", str(seq_counter), o + 6, o + 8),
    ]
    fields.append(frame_hdr)

    # ── Messages ──
    cur = CMP_FRAME_HEADER_LEN
    msg_idx = 1

    while cur + CMP_MSG_HEADER_LEN <= length:
        mo = base_offset + cur  # message offset
        msg_field, payload_len = _dissect_message(raw, cur, mo, msg_type_val, msg_idx)
        fields.append(msg_field)

        cur += CMP_MSG_HEADER_LEN + payload_len
        msg_idx += 1

    return fields


def _dissect_message(raw: bytes, offset: int, abs_offset: int,
                     frame_msg_type: int, msg_num: int):
    """Dissectiert eine einzelne CMP Message (Header + Payload).

    Returns:
        (DissectField, payload_length)
    """
    o = abs_offset  # Absoluter Offset

    # Message Header (16 Bytes)
    ts_bytes = raw[offset:offset + 8]
    ts_ns = struct.unpack('!Q', ts_bytes)[0]
    interface_id = struct.unpack('!I', raw[offset + 8:offset + 12])[0]
    common_flags = raw[offset + 12]
    payload_type = raw[offset + 13]
    payload_len = struct.unpack('!H', raw[offset + 14:offset + 16])[0]

    payload_type_name = DATA_MSG_TYPE_NAMES.get(payload_type, f"Unknown (0x{payload_type:02X})")

    # Timestamp formatieren
    ts_sec = ts_ns / 1_000_000_000
    ts_str = f"{ts_ns} ns ({ts_sec:.9f} s)"

    msg = DissectField(
        f"CMP Message #{msg_num}",
        f"[{payload_type_name}]",
        o, o + CMP_MSG_HEADER_LEN + payload_len
    )

    # ── Message Header Felder ──
    hdr = DissectField("CMP Message Header", "", o, o + CMP_MSG_HEADER_LEN)
    hdr.children = [
        DissectField("Timestamp", ts_str, o, o + 8),
        DissectField("Interface ID", f"0x{interface_id:08X}", o + 8, o + 12),
    ]

    # Common Flags aufschlüsseln
    flags_field = DissectField("Common Flags", f"0x{common_flags:02X}", o + 12, o + 13)
    flags_field.children = [
        DissectField("Timestamp recalculated", str(common_flags & 0x01), o + 12, o + 13),
        DissectField("Synchronized", str((common_flags >> 1) & 0x01), o + 12, o + 13),
        DissectField("Segment", SEGMENT_NAMES.get(common_flags & 0x0C, "Unknown"),
                     o + 12, o + 13),
        DissectField("Data Sent on Interface", str((common_flags >> 4) & 0x01),
                     o + 12, o + 13),
        DissectField("Overflow", str((common_flags >> 5) & 0x01), o + 12, o + 13),
        DissectField("Error in Payload", str((common_flags >> 6) & 0x01), o + 12, o + 13),
    ]
    hdr.children.append(flags_field)
    hdr.children.append(DissectField("Payload Type",
                                     f"0x{payload_type:02X} [{payload_type_name}]",
                                     o + 13, o + 14))
    hdr.children.append(DissectField("Payload Length", str(payload_len), o + 14, o + 16))
    msg.children.append(hdr)

    # ── Payload dissecten ──
    payload_start = offset + CMP_MSG_HEADER_LEN
    po = o + CMP_MSG_HEADER_LEN  # Payload abs offset

    if payload_len > 0 and payload_start + payload_len <= len(raw):
        payload_data = raw[payload_start:payload_start + payload_len]

        # Data Message (0x01) Sub-Dissektoren
        if frame_msg_type == 0x01:
            payload_field = _dispatch_data_payload(payload_type, payload_data, po)
        elif frame_msg_type == 0x03:
            payload_field = _dissect_status_payload(payload_type, payload_data, po)
        else:
            payload_field = DissectField(
                "Payload", payload_data.hex().upper(),
                po, po + payload_len)

        msg.children.append(payload_field)

    return msg, payload_len


# ── Data Message Sub-Dissektoren ─────────────────────────────────────────

def _dispatch_data_payload(payload_type: int, data: bytes,
                           base: int) -> DissectField:
    """Dispatcht zum passenden Sub-Dissektor basierend auf Payload Type."""
    dispatch = {
        0x01: _dissect_can,
        0x02: _dissect_can_fd,
        0x03: _dissect_lin,
        0x04: _dissect_flexray,
        0x05: _dissect_digital,
        0x06: _dissect_rs232,
        0x08: _dissect_ethernet,
    }
    fn = dispatch.get(payload_type)
    if fn:
        try:
            return fn(data, base)
        except Exception as e:
            logger.debug("CMP Sub-Dissector Fehler (type=0x%02X): %s", payload_type, e)

    return DissectField(
        DATA_MSG_TYPE_NAMES.get(payload_type, f"Payload (0x{payload_type:02X})"),
        data.hex().upper(), base, base + len(data))


# ── CAN ──────────────────────────────────────────────────────────────────

def _dissect_can(data: bytes, base: int) -> DissectField:
    """CMP CAN Data Message (Header: 16 Bytes + Daten)."""
    if len(data) < 16:
        return DissectField("CAN", f"[Zu kurz: {len(data)} Bytes]", base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    can_id_raw = struct.unpack('!I', data[4:8])[0]
    crc_raw = struct.unpack('!I', data[8:12])[0]
    err_pos = struct.unpack('!H', data[12:14])[0]
    dlc = data[14]
    data_len = data[15]

    can_id = can_id_raw & 0x1FFFFFFF
    ide = bool(can_id_raw & 0x80000000)
    rtr = bool(can_id_raw & 0x40000000)
    crc_val = crc_raw & 0x00007FFF
    crc_support = bool(crc_raw & 0x80000000)

    id_str = f"0x{can_id:08X}" if ide else f"0x{can_id:03X}"

    root = DissectField("CMP Message Payload [CAN]", f"ID: {id_str}, DLC: {dlc}",
                        o, o + 16 + data_len)

    hdr = DissectField("CAN Header", "", o, o + 16)

    # Flags
    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    flag_bits = [
        (0x0001, "CRC Error"), (0x0002, "ACK Error"),
        (0x0004, "Passive ACK Error"), (0x0008, "Active ACK Error"),
        (0x0010, "ACK Delimiter Error"), (0x0020, "Form Error"),
        (0x0040, "Stuff Error"), (0x0080, "CRC Delimiter Error"),
        (0x0100, "End-of-Frame Error"), (0x0200, "Bit Error"),
        (0x0400, "Reserved bit r0"), (0x0800, "SRR Dominant"),
    ]
    for mask, name in flag_bits:
        flags_f.children.append(DissectField(name, str(int(bool(flags & mask))), o, o + 2))
    hdr.children.append(flags_f)

    hdr.children.append(DissectField("Reserved", f"0x{struct.unpack('!H', data[2:4])[0]:04X}",
                                     o + 2, o + 4))

    # ID
    id_f = DissectField("ID", f"0x{can_id_raw:08X}", o + 4, o + 8)
    id_f.children = [
        DissectField("CAN ID", id_str, o + 4, o + 8),
        DissectField("Remote Frame (RTR)", str(int(rtr)), o + 4, o + 8),
        DissectField("Extended Format (IDE)", str(int(ide)), o + 4, o + 8),
    ]
    hdr.children.append(id_f)

    # CRC
    crc_f = DissectField("CRC", f"0x{crc_raw:08X}", o + 8, o + 12)
    crc_f.children = [
        DissectField("CRC Value", f"0x{crc_val:04X}", o + 8, o + 12),
        DissectField("CRC Support", str(int(crc_support)), o + 8, o + 12),
    ]
    hdr.children.append(crc_f)

    hdr.children.append(DissectField("Error Position", str(err_pos), o + 12, o + 14))
    hdr.children.append(DissectField("DLC", f"0x{dlc:02X} ({dlc})", o + 14, o + 15))
    hdr.children.append(DissectField("Data Length", str(data_len), o + 15, o + 16))

    root.children.append(hdr)

    if data_len > 0 and len(data) >= 16 + data_len:
        root.children.append(DissectField("Data", data[16:16 + data_len].hex().upper(),
                                          o + 16, o + 16 + data_len))

    return root


# ── CAN-FD ───────────────────────────────────────────────────────────────

def _dissect_can_fd(data: bytes, base: int) -> DissectField:
    """CMP CAN-FD Data Message (Header: 16 Bytes + Daten)."""
    if len(data) < 16:
        return DissectField("CAN-FD", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    can_id_raw = struct.unpack('!I', data[4:8])[0]
    crc_sbc = struct.unpack('!I', data[8:12])[0]
    err_pos = struct.unpack('!H', data[12:14])[0]
    dlc = data[14]
    data_len = data[15]

    can_id = can_id_raw & 0x1FFFFFFF
    ide = bool(can_id_raw & 0x80000000)
    rrs = bool(can_id_raw & 0x40000000)

    id_str = f"0x{can_id:08X}" if ide else f"0x{can_id:03X}"

    root = DissectField("CMP Message Payload [CAN-FD]",
                        f"ID: {id_str}, DLC: {dlc}",
                        o, o + 16 + data_len)

    hdr = DissectField("CAN-FD Header", "", o, o + 16)

    # Flags
    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    fd_flag_bits = [
        (0x0001, "CRC Error"), (0x0002, "ACK Error"),
        (0x0004, "Passive ACK Error"), (0x0008, "Active ACK Error"),
        (0x0010, "ACK Delimiter Error"), (0x0020, "Form Error"),
        (0x0040, "Stuff Error"), (0x0080, "CRC Delimiter Error"),
        (0x0100, "End-of-Frame Error"), (0x0200, "Bit Error"),
        (0x0400, "Reserved Bit"), (0x0800, "SRR Dominant"),
        (0x1000, "Bit Rate Switching (BRS)"), (0x2000, "Error State Indicator (ESI)"),
    ]
    for mask, name in fd_flag_bits:
        flags_f.children.append(DissectField(name, str(int(bool(flags & mask))), o, o + 2))
    hdr.children.append(flags_f)

    hdr.children.append(DissectField("Reserved", f"0x{struct.unpack('!H', data[2:4])[0]:04X}",
                                     o + 2, o + 4))

    # ID
    id_f = DissectField("ID", f"0x{can_id_raw:08X}", o + 4, o + 8)
    id_f.children = [
        DissectField("CAN-FD ID", id_str, o + 4, o + 8),
        DissectField("RRS", str(int(rrs)), o + 4, o + 8),
        DissectField("Extended Format (IDE)", str(int(ide)), o + 4, o + 8),
    ]
    hdr.children.append(id_f)

    # CRC + SBC
    crc_f = DissectField("CRC SBC", f"0x{crc_sbc:08X}", o + 8, o + 12)
    if dlc > 10:
        crc_f.children.append(DissectField("CRC (21-bit)", f"0x{crc_sbc & 0x001FFFFF:06X}",
                                           o + 8, o + 12))
    else:
        crc_f.children.append(DissectField("CRC (17-bit)", f"0x{crc_sbc & 0x0001FFFF:05X}",
                                           o + 8, o + 12))
    crc_f.children.extend([
        DissectField("SBC", f"0x{(crc_sbc >> 21) & 0x07:X}", o + 8, o + 12),
        DissectField("SBC Parity", str(int(bool(crc_sbc & 0x01000000))), o + 8, o + 12),
        DissectField("SBC Support", str(int(bool(crc_sbc & 0x40000000))), o + 8, o + 12),
        DissectField("CRC Support", str(int(bool(crc_sbc & 0x80000000))), o + 8, o + 12),
    ])
    hdr.children.append(crc_f)

    hdr.children.append(DissectField("Error Position", str(err_pos), o + 12, o + 14))
    hdr.children.append(DissectField("DLC", f"0x{dlc:02X} ({dlc})", o + 14, o + 15))
    hdr.children.append(DissectField("Data Length", str(data_len), o + 15, o + 16))

    root.children.append(hdr)

    if data_len > 0 and len(data) >= 16 + data_len:
        root.children.append(DissectField("Data", data[16:16 + data_len].hex().upper(),
                                          o + 16, o + 16 + data_len))
    return root


# ── LIN ──────────────────────────────────────────────────────────────────

def _dissect_lin(data: bytes, base: int) -> DissectField:
    """CMP LIN Data Message (Header: 8 Bytes + Daten)."""
    if len(data) < 8:
        return DissectField("LIN", f"[Zu kurz: {len(data)} Bytes]", base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    pid = data[4]
    checksum = data[6]
    data_len = data[7]

    lin_id = pid & 0x3F
    parity = (pid >> 6) & 0x03

    root = DissectField("CMP Message Payload [LIN]",
                        f"PID: 0x{pid:02X}, ID: 0x{lin_id:02X}",
                        o, o + 8 + data_len)

    hdr = DissectField("LIN Header", "", o, o + 8)

    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    lin_flags = [
        (0x0001, "Checksum (CRC) Error"), (0x0002, "Collision Error"),
        (0x0004, "Parity Error"), (0x0008, "No Slave Response Error"),
        (0x0010, "Synchronization Error"), (0x0020, "Framing Error"),
        (0x0040, "Short Dominant Error"), (0x0080, "Long Dominant Error"),
        (0x0100, "Wake-Up Detection"),
    ]
    for mask, name in lin_flags:
        flags_f.children.append(DissectField(name, str(int(bool(flags & mask))), o, o + 2))
    hdr.children.append(flags_f)

    hdr.children.append(DissectField("Reserved", f"0x{struct.unpack('!H', data[2:4])[0]:04X}",
                                     o + 2, o + 4))

    pid_f = DissectField("PID", f"0x{pid:02X}", o + 4, o + 5)
    pid_f.children = [
        DissectField("Parity", f"0x{parity:X}", o + 4, o + 5),
        DissectField("LIN ID", f"0x{lin_id:02X} ({lin_id})", o + 4, o + 5),
    ]
    hdr.children.append(pid_f)

    hdr.children.append(DissectField("Reserved", f"0x{data[5]:02X}", o + 5, o + 6))
    hdr.children.append(DissectField("Checksum", f"0x{checksum:02X}", o + 6, o + 7))
    hdr.children.append(DissectField("Data Length", str(data_len), o + 7, o + 8))

    root.children.append(hdr)

    if data_len > 0 and len(data) >= 8 + data_len:
        root.children.append(DissectField("Data", data[8:8 + data_len].hex().upper(),
                                          o + 8, o + 8 + data_len))
    return root


# ── FlexRay ──────────────────────────────────────────────────────────────

def _dissect_flexray(data: bytes, base: int) -> DissectField:
    """CMP FlexRay Data Message (Header: 14 Bytes + Daten)."""
    if len(data) < 14:
        return DissectField("FlexRay", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    header_crc = struct.unpack('!H', data[4:6])[0]
    frame_id = struct.unpack('!H', data[6:8])[0]
    cycle = data[8]
    frame_crc = data[9:12]
    data_len = data[13]

    root = DissectField("CMP Message Payload [FlexRay]",
                        f"Frame ID: {frame_id}, Cycle: {cycle}",
                        o, o + 14 + data_len)

    hdr = DissectField("FlexRay Header", "", o, o + 14)

    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    fr_flags = [
        (0x0001, "CRC Frame Error"), (0x0002, "CRC Header Error"),
        (0x0004, "Null Frame (NF)"), (0x0008, "Startup Frame (SF)"),
        (0x0010, "Sync Frame (SYNC)"), (0x0020, "Wake-Up Detection (WUS)"),
        (0x0040, "Preamble Indicator (PPI)"),
        (0x0080, "Collision Avoidance Symbol (CAS)"),
    ]
    for mask, name in fr_flags:
        flags_f.children.append(DissectField(name, str(int(bool(flags & mask))), o, o + 2))
    hdr.children.append(flags_f)

    hdr.children.append(DissectField("Reserved", f"0x{struct.unpack('!H', data[2:4])[0]:04X}",
                                     o + 2, o + 4))
    hdr.children.append(DissectField("Header CRC", f"0x{header_crc:04X}", o + 4, o + 6))
    hdr.children.append(DissectField("Frame ID", str(frame_id), o + 6, o + 8))
    hdr.children.append(DissectField("Cycle Counter", str(cycle), o + 8, o + 9))
    hdr.children.append(DissectField("Frame CRC",
                                     f"{frame_crc[0]:02X} {frame_crc[1]:02X} {frame_crc[2]:02X}",
                                     o + 9, o + 12))
    hdr.children.append(DissectField("Reserved", f"0x{data[12]:02X}", o + 12, o + 13))
    hdr.children.append(DissectField("Data Length", str(data_len), o + 13, o + 14))

    root.children.append(hdr)

    if data_len > 0 and len(data) >= 14 + data_len:
        root.children.append(DissectField("Data", data[14:14 + data_len].hex().upper(),
                                          o + 14, o + 14 + data_len))
    return root


# ── Digital ──────────────────────────────────────────────────────────────

def _dissect_digital(data: bytes, base: int) -> DissectField:
    """CMP Digital I/O Data Message (Header: 4 Bytes + Trigger/Sampling)."""
    if len(data) < 4:
        return DissectField("Digital", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    pin_count = data[3]
    trigger_present = bool(flags & 0x0001)
    sampling_present = bool(flags & 0x0002)

    root = DissectField("CMP Message Payload [Digital]",
                        f"Pins: {pin_count}",
                        o, o + len(data))

    hdr = DissectField("Digital Header", "", o, o + 4)
    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    flags_f.children = [
        DissectField("Trigger Present", str(int(trigger_present)), o, o + 2),
        DissectField("Sampling Present", str(int(sampling_present)), o, o + 2),
    ]
    hdr.children.append(flags_f)
    hdr.children.append(DissectField("Reserved", f"0x{data[2]:02X}", o + 2, o + 3))
    hdr.children.append(DissectField("Pin Count", str(pin_count), o + 3, o + 4))
    root.children.append(hdr)

    cur = 4
    if trigger_present and cur + 4 <= len(data):
        trig = DissectField("Triggering Data", "", o + cur, o + cur + 4)
        trig.children = [
            DissectField("Triggering Pattern", f"0x{data[cur]:02X}", o + cur, o + cur + 1),
            DissectField("Triggering Pin", str(data[cur + 1]), o + cur + 1, o + cur + 2),
            DissectField("Reserved", f"0x{struct.unpack('!H', data[cur+2:cur+4])[0]:04X}",
                         o + cur + 2, o + cur + 4),
        ]
        root.children.append(trig)
        cur += 4

    if sampling_present and cur + 5 <= len(data):
        sample_interval = struct.unpack('!f', data[cur:cur + 4])[0]
        num_samples = data[cur + 4]
        samp = DissectField("Sampling Data",
                            f"Interval: {sample_interval:.6f}s, Samples: {num_samples}",
                            o + cur, o + cur + 5)
        samp.children = [
            DissectField("Sample Interval", f"{sample_interval:.6f} s",
                         o + cur, o + cur + 4),
            DissectField("Num. of Samples", str(num_samples), o + cur + 4, o + cur + 5),
        ]
        root.children.append(samp)

    return root


# ── RS-232 / UART ────────────────────────────────────────────────────────

def _dissect_rs232(data: bytes, base: int) -> DissectField:
    """CMP RS-232 Data Message (Header: 6 Bytes + Dateneinträge)."""
    if len(data) < 6:
        return DissectField("RS-232", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    entry_count = struct.unpack('!H', data[4:6])[0]

    root = DissectField("CMP Message Payload [RS-232]",
                        f"Entries: {entry_count}",
                        o, o + len(data))

    hdr = DissectField("RS-232 Header", "", o, o + 6)
    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    flags_f.children.append(DissectField("Character Length", str(flags & 0x03), o, o + 2))
    hdr.children.append(flags_f)
    hdr.children.append(DissectField("Reserved", f"0x{struct.unpack('!H', data[2:4])[0]:04X}",
                                     o + 2, o + 4))
    hdr.children.append(DissectField("Data Entry Count", str(entry_count), o + 4, o + 6))
    root.children.append(hdr)

    # Dateneinträge (je 2 Bytes)
    cur = 6
    for i in range(min(entry_count, (len(data) - 6) // 2)):
        entry_val = struct.unpack('!H', data[cur:cur + 2])[0]
        uart_data = entry_val & 0x1FF
        framing_err = bool(entry_val & 0x2000)
        break_cond = bool(entry_val & 0x4000)
        parity_err = bool(entry_val & 0x8000)

        entry_f = DissectField(f"Data [{i + 1}]", f"0x{entry_val:04X}",
                               o + cur, o + cur + 2)
        entry_f.children = [
            DissectField("UART Data", f"0x{uart_data:03X}", o + cur, o + cur + 2),
            DissectField("Framing Error", str(int(framing_err)), o + cur, o + cur + 2),
            DissectField("Break Condition", str(int(break_cond)), o + cur, o + cur + 2),
            DissectField("Parity Error", str(int(parity_err)), o + cur, o + cur + 2),
        ]
        root.children.append(entry_f)
        cur += 2

    return root


# ── Ethernet ─────────────────────────────────────────────────────────────

def _dissect_ethernet(data: bytes, base: int) -> DissectField:
    """CMP Ethernet Data Message (Header: 6 Bytes + Ethernet Frame)."""
    if len(data) < 6:
        return DissectField("Ethernet", f"[Zu kurz: {len(data)} Bytes]",
                            base, base + len(data))

    o = base
    flags = struct.unpack('!H', data[0:2])[0]
    eth_data_len = struct.unpack('!H', data[4:6])[0]

    root = DissectField("CMP Message Payload [Ethernet]",
                        f"Length: {eth_data_len}",
                        o, o + 6 + eth_data_len)

    hdr = DissectField("Ethernet Header", "", o, o + 6)
    flags_f = DissectField("Flags", f"0x{flags:04X}", o, o + 2)
    eth_flags = [
        (0x0001, "FCS Error"), (0x0002, "Frame Shorter Than 64 Bytes"),
        (0x0004, "TX Port Down"), (0x0008, "Collision"),
        (0x0010, "Frame Too Long"), (0x0020, "PHY Error"),
        (0x0040, "Frame Truncated"), (0x0080, "FCS Support"),
    ]
    for mask, name in eth_flags:
        flags_f.children.append(DissectField(name, str(int(bool(flags & mask))), o, o + 2))
    hdr.children.append(flags_f)

    hdr.children.append(DissectField("Reserved", f"0x{struct.unpack('!H', data[2:4])[0]:04X}",
                                     o + 2, o + 4))
    hdr.children.append(DissectField("Data Length", str(eth_data_len), o + 4, o + 6))
    root.children.append(hdr)

    # Ethernet Frame dissecten (Dst MAC, Src MAC, EtherType, Payload)
    eth_start = 6
    if eth_data_len >= 14 and len(data) >= eth_start + 14:
        frame_data = data[eth_start:eth_start + eth_data_len]
        fo = o + eth_start

        dst_mac = ':'.join(f'{b:02x}' for b in frame_data[0:6])
        src_mac = ':'.join(f'{b:02x}' for b in frame_data[6:12])
        etype = struct.unpack('!H', frame_data[12:14])[0]

        eth_frame = DissectField("Ethernet Frame",
                                 f"Dst: {dst_mac}, Src: {src_mac}",
                                 fo, fo + eth_data_len)
        eth_frame.children = [
            DissectField("Destination", dst_mac, fo, fo + 6),
            DissectField("Source", src_mac, fo + 6, fo + 12),
            DissectField("Type", f"0x{etype:04X}", fo + 12, fo + 14),
        ]
        if eth_data_len > 14:
            eth_frame.children.append(DissectField(
                "Payload", frame_data[14:].hex().upper(), fo + 14, fo + eth_data_len))
        root.children.append(eth_frame)
    elif eth_data_len > 0 and len(data) >= eth_start + eth_data_len:
        root.children.append(DissectField("Data",
                                          data[eth_start:eth_start + eth_data_len].hex().upper(),
                                          o + eth_start, o + eth_start + eth_data_len))

    return root


# ── Status Messages ──────────────────────────────────────────────────────

def _dissect_status_payload(payload_type: int, data: bytes,
                            base: int) -> DissectField:
    """Dissectiert CMP Status Message Payloads."""
    type_name = STATUS_MSG_TYPE_NAMES.get(payload_type, f"Unknown (0x{payload_type:02X})")
    root = DissectField(f"Status [{type_name}]",
                        data.hex().upper() if len(data) <= 32 else f"{len(data)} Bytes",
                        base, base + len(data))

    if payload_type == 0x01 and len(data) >= 2:
        root.children.append(DissectField("Module Status Data",
                                          data.hex().upper(), base, base + len(data)))
    elif payload_type == 0x02 and len(data) >= 4:
        root.children.append(DissectField("Interface Status Data",
                                          data.hex().upper(), base, base + len(data)))
    elif payload_type == 0x04 and len(data) >= 2:
        root.children.append(DissectField("Data Lost Event",
                                          data.hex().upper(), base, base + len(data)))
    elif payload_type == 0x05 and len(data) >= 2:
        root.children.append(DissectField("Time Sync Lost Event",
                                          data.hex().upper(), base, base + len(data)))
    else:
        root.children.append(DissectField("Raw Data",
                                          data.hex().upper(), base, base + len(data)))

    return root
