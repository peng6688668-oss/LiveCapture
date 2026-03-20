"""CCA/VPCAP Protocol Dissector — ViGEM Logger Datenformat.

Portiert aus ccaDissector.lua (Version 4.3.0, ViGEM GmbH).
Unterstützt alle 48 CCA-Protokolle für VPCAP / DLT-148 Pakete.

Jeder Dissector gibt eine Liste von DissectField zurück,
die von WiresharkPanel in QTreeWidgetItems umgewandelt wird.
"""

import struct
import logging
import re
from dataclasses import dataclass, field as dc_field
from typing import List, Optional, Dict, Tuple

logger = logging.getLogger(__name__)

# ── Ergebnis-Datenstruktur ────────────────────────────────────────────────


@dataclass
class DissectField:
    """Ein Feld im Dissect-Ergebnis (für Tree-Darstellung)."""
    name: str
    value: str
    start: int = 0     # Byte-Offset (absolut im Paket)
    end: int = 0       # Byte-Offset Ende (exklusiv)
    children: List['DissectField'] = dc_field(default_factory=list)


# ── Konstanten ────────────────────────────────────────────────────────────

CLASS_NAMES: Dict[int, str] = {
    0x00: "Generic", 0x01: "CAN", 0x05: "RS232",
    0x06: "Ethernet", 0x07: "FlexRay", 0x08: "TMG (Test Message)",
    0x0a: "Marker / Event", 0x10: "MOST25 CMS", 0x11: "MOST25 ADS",
    0x12: "MOST25 RAW", 0x18: "MOST50 CMS", 0x19: "MOST50 ADS",
    0x1a: "MOST50 RAW", 0x20: "MOST150 CMS", 0x21: "MOST150 ADS",
    0x22: "MOST150 State", 0x23: "MOST150 Alloc", 0x24: "MOST150 RAW",
    0x30: "DLT", 0x31: "MTA", 0x32: "LVDS Status",
    0x33: "LIN", 0x34: "Analog I/O", 0x35: "Digital I/O",
    0x36: "PLP-RAW", 0x37: "SPI", 0x39: "TCP Payload",
    0x40: "UDP Payload", 0x41: "Image Fragment", 0x42: "Image Frame",
    0x50: "MIPI CSI-2", 0x60: "GNLog", 0x61: "GNLog Serial",
    0x80: "IF Info", 0xa0: "CCA System", 0xa1: "CCA Syslog",
    0xb0: "Mobileye TAPI", 0xb1: "Mobileye TAPI Init",
    0xb2: "Pre-Label", 0xb3: "KAFAS4 ECU Info", 0xb4: "XCP",
    0xc0: "Attachment", 0xfe: "Custom", 0xff: "Unknown",
}

# Bekannte CCA Class-IDs für Erkennung
_KNOWN_CLASSES = set(CLASS_NAMES.keys())

# CAN FD DLC → Datenlänge
_CAN_FD_DLC_MAP = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
    9: 12, 10: 16, 11: 20, 12: 24, 13: 32, 14: 48, 15: 64,
}

# XCP Command-Namen
_XCP_COMMANDS = {
    0xFF: "CONNECT", 0xFE: "DISCONNECT", 0xFD: "GET_STATUS",
    0xFC: "SYNCH", 0xFB: "GET_COMM_MODE_INFO", 0xFA: "GET_ID",
    0xF9: "SET_REQUEST", 0xF8: "GET_SEED", 0xF7: "UNLOCK",
    0xF6: "SET_MTA", 0xF5: "UPLOAD", 0xF4: "SHORT_UPLOAD",
    0xF3: "BUILD_CHECKSUM", 0xF2: "TRANSPORT_LAYER_CMD",
    0xF1: "USER_CMD", 0xF0: "DOWNLOAD", 0xEF: "DOWNLOAD_NEXT",
    0xEE: "DOWNLOAD_MAX", 0xED: "SHORT_DOWNLOAD",
    0xEC: "MODIFY_BITS", 0xEB: "SET_CAL_PAGE", 0xEA: "GET_CAL_PAGE",
    0xE9: "GET_PAG_PROCESSOR_INFO", 0xE8: "GET_SEGMENT_INFO",
    0xE7: "GET_PAGE_INFO", 0xE6: "SET_SEGMENT_MODE",
    0xE5: "GET_SEGMENT_MODE", 0xE4: "COPY_CAL_PAGE",
    0xE3: "CLEAR_DAQ_LIST", 0xE2: "SET_DAQ_PTR", 0xE1: "WRITE_DAQ",
    0xE0: "SET_DAQ_LIST_MODE", 0xDF: "GET_DAQ_LIST_MODE",
    0xDE: "START_STOP_DAQ_LIST", 0xDD: "START_STOP_SYNCH",
    0xDC: "GET_DAQ_CLOCK", 0xDB: "READ_DAQ",
    0xDA: "GET_DAQ_PROCESSOR_INFO", 0xD9: "GET_DAQ_RESOLUTION_INFO",
    0xD8: "GET_DAQ_LIST_INFO", 0xD7: "GET_DAQ_EVENT_INFO",
    0xD6: "FREE_DAQ", 0xD5: "ALLOC_DAQ", 0xD4: "ALLOC_ODT",
    0xD3: "ALLOC_ODT_ENTRY", 0xD2: "PROGRAM_START",
    0xD1: "PROGRAM_CLEAR", 0xD0: "PROGRAM", 0xCF: "PROGRAM_RESET",
    0xCE: "GET_PGM_PROCESSOR_INFO", 0xCD: "GET_SECTOR_INFO",
    0xCC: "PROGRAM_PREPARE", 0xCB: "PROGRAM_FORMAT",
    0xCA: "PROGRAM_NEXT", 0xC9: "PROGRAM_MAX",
    0xC8: "PROGRAM_VERIFY", 0xC7: "WRITE_DAQ_MULTIPLE",
    0xC6: "TIME_CORRELATION", 0xC5: "DTO_CTR_PROPERTIES",
    0xC4: "SET_DAQ_PACKED_MODE",
}

# PLP Type-Namen
_PLP_TYPES = {
    0x00: "UserEvent", 0x01: "Status Probe", 0x02: "Status Bus",
    0x03: "Logging Stream", 0x04: "Config Probe", 0x0A: "Replay Data",
}

# PLP Message Type-Namen
_PLP_MSG_TYPES = {
    0x0000: "None", 0x0001: "CAN(-FD) Raw", 0x0002: "CAN Data",
    0x0003: "CAN-FD Data", 0x0004: "LIN", 0x0007: "FlexRay Raw",
    0x0008: "FlexRay Data", 0x000A: "GPIO",
    0x0010: "UART/RS232 ASCII", 0x0011: "UART/RS232 RAW",
    0x0012: "UART/RS232 SLA", 0x0016: "UART/RS232",
    0x0020: "Analog", 0x0021: "Analog SLA",
    0x0080: "Ethernet II", 0x0090: "DLT (TCP)", 0x00A0: "XCP",
    0x0100: "SerDes", 0x0101: "MIPI-CSI2 Video",
    0x0102: "MIPI-CSI2 Lidar", 0x0103: "SPI",
    0x0104: "I2C 7-Bit", 0x0105: "I2C 8-Bit",
    0x0106: "I2C 10-Bit", 0x0107: "I2C 16-Bit",
    0x0200: "TAPI", 0x0201: "TAPI Initial State",
    0x0202: "TAPI Core Dump", 0x0400: "Radar",
    0xA000: "PLP Raw", 0xB000: "Pre-Label",
}

# DLT Message-Typen
_DLT_MSTP = {0: "Log", 1: "App Trace", 2: "NW Trace", 3: "Control"}
_DLT_LOG_LEVELS = {
    1: "Fatal", 2: "Error", 3: "Warn", 4: "Info", 5: "Debug", 6: "Verbose",
}


# ── Erkennungs-Heuristik ─────────────────────────────────────────────────

def is_cca_packet(raw: bytes) -> bool:
    """Prüft ob die Daten ein CCA-Paket sind (vs. TECMP)."""
    if len(raw) < 12:
        return False
    class_id = raw[0]
    version = raw[1]
    return class_id in _KNOWN_CLASSES and version <= 0x10


# ── Haupt-Dissector ──────────────────────────────────────────────────────

def dissect(raw: bytes, base_offset: int = 0) -> List[DissectField]:
    """Dissect ein CCA/VPCAP-Paket. Gibt Feld-Baum zurück."""
    if len(raw) < 12:
        return [DissectField("CCA Data", f"{len(raw)} bytes (zu kurz)", base_offset,
                             base_offset + len(raw))]

    results = []

    # ── CCA Header (12 Bytes) ──
    class_id = raw[0]
    version = raw[1]
    data_cs = raw[2]
    hdr_cs = raw[3]
    bus_id = struct.unpack_from('<I', raw, 4)[0]
    flags = struct.unpack_from('<I', raw, 8)[0]

    class_name = CLASS_NAMES.get(class_id, f"Unknown (0x{class_id:02X})")

    # Flags auswerten
    purge = bool(flags & 0x0001)
    overflow = bool(flags & 0x0002)
    ci_error = bool(flags & 0x0004)
    ci_crc = bool(flags & 0x0008)
    ci_cust1 = bool(flags & 0x0010)
    ci_cust2 = bool(flags & 0x0020)
    ci_cust3 = bool(flags & 0x0040)
    out_of_band = bool(flags & 0x0080)
    err_dcs = bool(flags & 0x0100)
    err_ts = bool(flags & 0x0200)
    err_size = bool(flags & 0x0400)
    bwlimit = bool(flags & 0x8000)

    ctx = {
        'ci_error': ci_error, 'ci_crc': ci_crc,
        'ci_cust3': ci_cust3, 'out_of_band': out_of_band,
        'bus_id': bus_id, 'flags': flags,
    }

    # CCA Header Item
    hdr = DissectField(
        f"CCA Header, Class: {class_name} (0x{class_id:02X}), "
        f"Version: {version}, Bus-ID: {bus_id}",
        "12 bytes", base_offset, base_offset + 12)

    hdr.children.append(DissectField("Class", f"0x{class_id:02X} ({class_name})",
                                     base_offset, base_offset + 1))
    hdr.children.append(DissectField("Version", str(version),
                                     base_offset + 1, base_offset + 2))
    hdr.children.append(DissectField("Data Checksum", f"0x{data_cs:02X}",
                                     base_offset + 2, base_offset + 3))
    hdr.children.append(DissectField("Header Checksum", f"0x{hdr_cs:02X}",
                                     base_offset + 3, base_offset + 4))
    hdr.children.append(DissectField("Bus ID", f"{bus_id} (0x{bus_id:08X})",
                                     base_offset + 4, base_offset + 8))

    # Flags-Feld mit Unter-Bits
    flags_item = DissectField("Flags", f"0x{flags:08X}", base_offset + 8, base_offset + 12)
    flag_defs = [
        (purge, "Purge"), (overflow, "Overflow"),
        (ci_error, "CI Error (Framing)"), (ci_crc, "CRC Error"),
        (ci_cust1, "Custom 1 (HW)"), (ci_cust2, "Custom 2 (HW)"),
        (ci_cust3, "Custom 3 / EOF"), (out_of_band, "Out-of-Band / SOF"),
        (err_dcs, "DCS Error (FIFO)"), (err_ts, "Timestamp Error"),
        (err_size, "Size Error"), (bwlimit, "Bandwidth Limit"),
    ]
    for val, name in flag_defs:
        if val:
            flags_item.children.append(DissectField(f"  {name}", "Set",
                                                    base_offset + 8, base_offset + 12))
    hdr.children.append(flags_item)
    results.append(hdr)

    # ── Payload Dispatch ──
    payload = raw[12:]
    p_off = base_offset + 12  # payload base offset

    proto_fields = _dispatch(class_id, version, payload, p_off, ctx)
    results.extend(proto_fields)

    return results


# ── Dispatch-Tabelle ──────────────────────────────────────────────────────

def _dispatch(class_id: int, version: int, payload: bytes, p_off: int,
              ctx: dict) -> List[DissectField]:
    """Dispatcht zum richtigen Sub-Dissector."""
    out_of_band = ctx['out_of_band']
    ci_cust3 = ctx['ci_cust3']
    ci_error = ctx['ci_error']

    # Version-spezifische Overrides
    if version == 0x01:
        v1_map = {
            0x01: _dissect_can_v1, 0x06: _dissect_ethernet,
            0x07: _dissect_flexray, 0x30: _dissect_dlt_v1,
            0x34: _dissect_analog_io, 0x50: _dissect_mipi_csi2,
            0x60: _dissect_gnlog_v1, 0x36: _dissect_plp_raw,
        }
        if class_id in v1_map:
            return v1_map[class_id](payload, p_off, ctx)
    elif version == 0x02 and class_id == 0x0a:
        return _dissect_marker_v2(payload, p_off, ctx)
    elif version == 0x03 and class_id == 0x01:
        return _dissect_can_v3(payload, p_off, ctx)
    elif version == 0x04 and class_id == 0x01:
        return _dissect_can_v4(payload, p_off, ctx)
    elif version == 0x10 and class_id == 0x06:
        return _dissect_ethernet_fcs(payload, p_off, ctx)

    # Version 0x00 (Default) Dispatch
    v0_map = {
        0x01: _dissect_can_v1,
        0x05: _dissect_rs232,
        0x06: _dissect_ethernet,
        0x07: _dissect_flexray,
        0x08: _dissect_tmg,
        0x0a: _dissect_marker_v0,
        0x11: _dissect_most25_ads,
        0x12: _dissect_most25_raw,
        0x18: _dissect_most50_cms,
        0x19: _dissect_most50_ads,
        0x1a: _dissect_most50_raw,
        0x20: _dissect_most150_cms,
        0x21: _dissect_most150_ads,
        0x22: _dissect_most150_state,
        0x23: _dissect_most150_alloc,
        0x24: _dissect_most150_raw,
        0x30: _dissect_dlt_v0,
        0x32: _dissect_lvds_status,
        0x33: _dissect_lin,
        0x34: _dissect_analog_io,
        0x35: _dissect_digital_io,
        0x37: _dissect_spi,
        0x39: _dissect_tcp_payload,
        0x40: _dissect_udp_payload,
        0x42: _dissect_image_frame,
        0x61: _dissect_gnlog_serial,
        0x80: _dissect_ifinfo,
        0xa0: _dissect_cca_system,
        0xa1: _dissect_cca_syslog,
        0xb0: _dissect_mobileye_tapi,
        0xb1: _dissect_mobileye_tapi_init,
        0xb2: _dissect_prelabel,
        0xb3: _dissect_kafas4,
        0xb4: _dissect_xcp,
        0xc0: _dissect_attachment,
    }

    # Spezialfälle mit Flag-Abhängigkeit
    if class_id == 0x10:  # MOST25
        if out_of_band:
            return _dissect_most25_state(payload, p_off, ctx)
        return _dissect_most25_cms(payload, p_off, ctx)

    if class_id == 0x31:  # MTA
        if out_of_band and ci_cust3:
            return _dissect_mta_single(payload, p_off, ctx)
        elif out_of_band:
            return _dissect_mta_first(payload, p_off, ctx)
        elif ci_cust3:
            return _dissect_mta_last(payload, p_off, ctx)
        return _dissect_mta_middle(payload, p_off, ctx)

    if class_id == 0x41:  # Image Fragment
        if out_of_band:
            return _dissect_image_fragment_first(payload, p_off, ctx)
        elif ci_cust3:
            return _dissect_image_fragment_last(payload, p_off, ctx)
        return _dissect_image_fragment_middle(payload, p_off, ctx)

    if class_id in v0_map:
        return v0_map[class_id](payload, p_off, ctx)

    # Unbekanntes Protokoll
    return [DissectField(
        f"Unknown Protocol (Class 0x{class_id:02X}, Version {version})",
        f"{len(payload)} bytes", p_off, p_off + len(payload))]


# ══════════════════════════════════════════════════════════════════════════
# ── CAN Dissektoren ──────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_can_v1(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """CAN V1 (Class 0x01, Version 0x00/0x01)."""
    if not payload:
        return []

    # Out-of-Band (Error/Overload Frame)
    if ctx['out_of_band']:
        oob = payload[0]
        item = DissectField("CAN Out-of-Band", "", p_off, p_off + 1)
        item.children.append(DissectField("Overload Frame",
                             "Yes" if oob & 0x01 else "No", p_off, p_off + 1))
        item.children.append(DissectField("Error Frame",
                             "Yes" if oob & 0x02 else "No", p_off, p_off + 1))
        return [item]

    if ctx['ci_error']:
        return [DissectField("CAN Error Frame", "", p_off, p_off + len(payload))]

    if len(payload) < 2:
        return [DissectField("CAN (zu kurz)", f"{len(payload)} bytes", p_off,
                             p_off + len(payload))]

    id_field = struct.unpack_from('>H', payload, 0)[0]
    can_id = (id_field >> 2) & 0x7FF
    rtr_srr = (id_field >> 1) & 1
    ide = id_field & 1

    off = 2
    if ide:  # Extended Frame
        if len(payload) < 5:
            return [DissectField("CAN Extended (zu kurz)", "", p_off, p_off + len(payload))]
        ext_field = (payload[2] << 16) | (payload[3] << 8) | payload[4]
        id_ext = (ext_field >> 1) & 0x3FFFF
        rtr = ext_field & 1
        full_id = (can_id << 18) | id_ext
        off = 5
        if len(payload) > off:
            dlc = payload[off] & 0x0F
            off += 1
            data_end = min(off + dlc, len(payload))
            data_bytes = payload[off:data_end]

            item = DissectField("ViGEM CAN V1 (Extended)",
                                f"ID: 0x{full_id:08X}, DLC: {dlc}", p_off, p_off + len(payload))
            item.children.append(DissectField("ID (11-bit)", f"0x{can_id:03X}",
                                              p_off, p_off + 2))
            item.children.append(DissectField("SRR", str(rtr_srr), p_off, p_off + 2))
            item.children.append(DissectField("IDE", "Extended (1)", p_off, p_off + 2))
            item.children.append(DissectField("Extended ID", f"0x{id_ext:05X}",
                                              p_off + 2, p_off + 5))
            item.children.append(DissectField("Full CAN ID", f"0x{full_id:08X}",
                                              p_off, p_off + 5))
            item.children.append(DissectField("RTR", str(rtr), p_off + 2, p_off + 5))
            item.children.append(DissectField("DLC", str(dlc), p_off + 5, p_off + 6))
            if data_bytes:
                item.children.append(DissectField("Payload",
                                     " ".join(f"{b:02X}" for b in data_bytes),
                                     p_off + off, p_off + data_end))
            return [item]
    else:  # Standard Frame
        if len(payload) > off:
            dlc = payload[off] & 0x0F
            off += 1
            data_end = min(off + dlc, len(payload))
            data_bytes = payload[off:data_end]
            rtr = rtr_srr

            frame_type = "Remote" if rtr else "Data"
            item = DissectField("ViGEM CAN V1 (Standard)",
                                f"ID: 0x{can_id:03X}, DLC: {dlc}, {frame_type}",
                                p_off, p_off + len(payload))
            item.children.append(DissectField("ID", f"0x{can_id:03X}", p_off, p_off + 2))
            item.children.append(DissectField("RTR", str(rtr), p_off, p_off + 2))
            item.children.append(DissectField("IDE", "Standard (0)", p_off, p_off + 2))
            item.children.append(DissectField("DLC", str(dlc), p_off + 2, p_off + 3))
            if data_bytes:
                item.children.append(DissectField("Payload",
                                     " ".join(f"{b:02X}" for b in data_bytes),
                                     p_off + off, p_off + data_end))
            # CRC (falls vorhanden)
            crc_off = data_end
            if crc_off + 2 <= len(payload):
                crc = struct.unpack_from('>H', payload, crc_off)[0]
                item.children.append(DissectField("CRC", f"0x{(crc >> 1):04X}",
                                     p_off + crc_off, p_off + crc_off + 2))
            return [item]

    return [DissectField("CAN V1", f"{len(payload)} bytes", p_off, p_off + len(payload))]


def _dissect_can_v3(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """CAN V3 / CAN FD (Class 0x01, Version 0x03)."""
    if len(payload) < 5:
        return [DissectField("CAN FD V3 (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    buf_len = len(payload)
    # ID und FTR sind am Ende des Buffers
    can_id = struct.unpack_from('<I', payload, buf_len - 5)[0] & 0x1FFFFFFF
    ftr = payload[buf_len - 1]

    dlc = ftr & 0x0F
    brs = bool(ftr & 0x10)
    edl = bool(ftr & 0x20)
    rtr = bool(ftr & 0x40)
    ide = bool(ftr & 0x80)

    data_len = _CAN_FD_DLC_MAP.get(dlc, dlc)
    data_bytes = payload[:buf_len - 5]

    frame_type = "CAN FD" if edl else "CAN"
    id_fmt = f"0x{can_id:08X}" if ide else f"0x{can_id:03X}"

    item = DissectField(f"ViGEM {frame_type} V3",
                        f"ID: {id_fmt}, DLC: {dlc} ({data_len} bytes)",
                        p_off, p_off + buf_len)
    item.children.append(DissectField("CAN ID", id_fmt, p_off + buf_len - 5, p_off + buf_len - 1))
    item.children.append(DissectField("IDE", "Extended" if ide else "Standard",
                                      p_off + buf_len - 1, p_off + buf_len))
    item.children.append(DissectField("RTR", str(int(rtr)), p_off + buf_len - 1, p_off + buf_len))
    item.children.append(DissectField("EDL (FD)", str(int(edl)),
                                      p_off + buf_len - 1, p_off + buf_len))
    item.children.append(DissectField("BRS", str(int(brs)), p_off + buf_len - 1, p_off + buf_len))
    item.children.append(DissectField("DLC", f"{dlc} → {data_len} bytes",
                                      p_off + buf_len - 1, p_off + buf_len))
    if data_bytes:
        item.children.append(DissectField("Payload",
                             " ".join(f"{b:02X}" for b in data_bytes[:data_len]),
                             p_off, p_off + min(data_len, len(data_bytes))))
    return [item]


def _dissect_can_v4(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """CAN V4 (Class 0x01, Version 0x04)."""
    if len(payload) < 9:
        return [DissectField("CAN V4 (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    flag_field = struct.unpack_from('>H', payload, 0)[0]
    can_id = struct.unpack_from('>I', payload, 2)[0] & 0x1FFFFFFF
    crc_field = struct.unpack_from('>H', payload, 6)[0]
    data_len_byte = payload[8]

    edl = bool(flag_field & 0x01)
    rtr_or_esi = bool(flag_field & 0x02)
    ide = bool(flag_field & 0x04)
    brs = bool(flag_field & 0x10)

    crc_val = crc_field >> 1
    data_bytes = payload[9:9 + data_len_byte]

    frame_type = "CAN FD" if edl else "CAN"
    id_fmt = f"0x{can_id:08X}" if ide else f"0x{can_id:03X}"

    item = DissectField(f"ViGEM {frame_type} V4",
                        f"ID: {id_fmt}, Len: {data_len_byte}",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("Flags", f"0x{flag_field:04X}", p_off, p_off + 2))
    item.children.append(DissectField("  EDL (FD)", str(int(edl)), p_off, p_off + 2))
    item.children.append(DissectField("  IDE", "Extended" if ide else "Standard",
                                      p_off, p_off + 2))
    item.children.append(DissectField("  BRS", str(int(brs)), p_off, p_off + 2))
    if edl:
        item.children.append(DissectField("  ESI", str(int(rtr_or_esi)), p_off, p_off + 2))
    else:
        item.children.append(DissectField("  RTR", str(int(rtr_or_esi)), p_off, p_off + 2))
    item.children.append(DissectField("CAN ID", id_fmt, p_off + 2, p_off + 6))
    item.children.append(DissectField("CRC", f"0x{crc_val:04X}", p_off + 6, p_off + 8))
    item.children.append(DissectField("Data Length", str(data_len_byte), p_off + 8, p_off + 9))
    if data_bytes:
        item.children.append(DissectField("Payload",
                             " ".join(f"{b:02X}" for b in data_bytes),
                             p_off + 9, p_off + 9 + len(data_bytes)))
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── LIN ──────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_lin(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """LIN V0 (Class 0x33)."""
    if not payload:
        return []

    pid = payload[0]
    lin_id = pid & 0x3F
    p0 = (pid >> 6) & 1
    p1 = (pid >> 7) & 1

    item = DissectField("ViGEM LIN", f"ID: 0x{lin_id:02X} (PID: 0x{pid:02X})",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("PID", f"0x{pid:02X}", p_off, p_off + 1))
    item.children.append(DissectField("  ID (6 bit)", f"0x{lin_id:02X} ({lin_id})",
                                      p_off, p_off + 1))
    item.children.append(DissectField("  Parity P0", str(p0), p_off, p_off + 1))
    item.children.append(DissectField("  Parity P1", str(p1), p_off, p_off + 1))

    if len(payload) > 2:
        data = payload[1:-1]
        checksum = payload[-1]
        item.children.append(DissectField("Data",
                             " ".join(f"{b:02X}" for b in data),
                             p_off + 1, p_off + 1 + len(data)))
        item.children.append(DissectField("Checksum", f"0x{checksum:02X}",
                             p_off + len(payload) - 1, p_off + len(payload)))
    elif len(payload) == 2:
        item.children.append(DissectField("Checksum", f"0x{payload[1]:02X}",
                             p_off + 1, p_off + 2))

    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── FlexRay ──────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_flexray(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """FlexRay V0 (Class 0x07)."""
    if ctx['out_of_band']:
        if len(payload) >= 2:
            oob_type = payload[-2]
            oob_zeros = payload[-1]
            item = DissectField("FlexRay Symbol", "", p_off, p_off + len(payload))
            item.children.append(DissectField("Type",
                                 "Symbol" if oob_type == 1 else f"0x{oob_type:02X}",
                                 p_off + len(payload) - 2, p_off + len(payload) - 1))
            item.children.append(DissectField("Zero Count", str(oob_zeros),
                                 p_off + len(payload) - 1, p_off + len(payload)))
            return [item]
        return [DissectField("FlexRay OOB", f"{len(payload)} bytes", p_off,
                             p_off + len(payload))]

    if len(payload) < 5:
        return [DissectField("FlexRay (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    hdr1 = struct.unpack_from('>H', payload, 0)[0]
    hdr2_bytes = (payload[2] << 16) | (payload[3] << 8) | payload[4]

    frame_id = hdr1 & 0x07FF
    startup = bool(hdr1 & 0x0800)
    sync = bool(hdr1 & 0x1000)
    null_frame = not bool(hdr1 & 0x2000)  # invertiert
    ppi = bool(hdr1 & 0x4000)

    cycle = hdr2_bytes & 0x3F
    hdr_crc = (hdr2_bytes >> 6) & 0xFF
    payload_len_words = (hdr2_bytes >> 14) & 0x7F
    payload_len_bytes = payload_len_words * 2

    data = payload[5:5 + payload_len_bytes] if len(payload) > 5 else b''

    item = DissectField("ViGEM FlexRay",
                        f"ID: {frame_id}, Cycle: {cycle}, Len: {payload_len_bytes}",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("Frame ID", str(frame_id), p_off, p_off + 2))
    item.children.append(DissectField("Startup Frame", str(startup), p_off, p_off + 2))
    item.children.append(DissectField("Sync Frame", str(sync), p_off, p_off + 2))
    item.children.append(DissectField("Null Frame", str(null_frame), p_off, p_off + 2))
    item.children.append(DissectField("Payload Preamble", str(ppi), p_off, p_off + 2))
    item.children.append(DissectField("Payload Length",
                         f"{payload_len_words} words ({payload_len_bytes} bytes)",
                         p_off + 2, p_off + 5))
    item.children.append(DissectField("Header CRC", f"0x{hdr_crc:02X}", p_off + 2, p_off + 5))
    item.children.append(DissectField("Cycle Count", str(cycle), p_off + 2, p_off + 5))
    if data:
        item.children.append(DissectField("Data",
                             " ".join(f"{b:02X}" for b in data),
                             p_off + 5, p_off + 5 + len(data)))

    # CRC am Ende
    crc_start = 5 + payload_len_bytes
    if crc_start + 3 <= len(payload):
        crc = (payload[crc_start] << 16) | (payload[crc_start + 1] << 8) | payload[crc_start + 2]
        item.children.append(DissectField("CRC", f"0x{crc:06X}",
                             p_off + crc_start, p_off + crc_start + 3))

    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── Ethernet ─────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_ethernet(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Ethernet Raw (Class 0x06, ohne FCS)."""
    if len(payload) < 14:
        return [DissectField("Ethernet (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]
    dst = ":".join(f"{b:02x}" for b in payload[0:6])
    src = ":".join(f"{b:02x}" for b in payload[6:12])
    etype = struct.unpack_from('>H', payload, 12)[0]

    item = DissectField("Ethernet II", f"{src} → {dst}, Type: 0x{etype:04X}",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("Destination", dst, p_off, p_off + 6))
    item.children.append(DissectField("Source", src, p_off + 6, p_off + 12))
    item.children.append(DissectField("EtherType", f"0x{etype:04X}", p_off + 12, p_off + 14))
    if len(payload) > 14:
        item.children.append(DissectField("Payload", f"{len(payload) - 14} bytes",
                             p_off + 14, p_off + len(payload)))
    return [item]


def _dissect_ethernet_fcs(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Ethernet mit FCS (Class 0x06, Version 0x10)."""
    result = _dissect_ethernet(payload, p_off, ctx)
    if result and len(payload) >= 18:
        fcs_off = len(payload) - 4
        fcs = struct.unpack_from('>I', payload, fcs_off)[0]
        result[0].children.append(DissectField("FCS", f"0x{fcs:08X}",
                                  p_off + fcs_off, p_off + fcs_off + 4))
    return result


# ══════════════════════════════════════════════════════════════════════════
# ── MIPI CSI-2 ───────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_mipi_csi2(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """MIPI CSI-2 V1 (Class 0x50)."""
    is_sof = ctx['out_of_band']
    is_eof = ctx['ci_cust3']

    item = DissectField("ViGEM MIPI CSI-2", "", p_off, p_off + len(payload))

    if is_sof:
        item.value = f"Start-of-Frame, {len(payload)} bytes"
        item.children.append(DissectField("Frame Marker", "SOF (Start-of-Frame)",
                             p_off, p_off + min(1, len(payload))))
    elif is_eof and len(payload) >= 21:
        item.value = f"End-of-Frame, {len(payload)} bytes"
        item.children.append(DissectField("Frame Marker", "EOF (End-of-Frame)",
                             p_off, p_off + min(1, len(payload))))

        # 21-Byte Metadata Trailer am Ende
        t_off = p_off + len(payload) - 21
        t_data = payload[-21:]
        pixel_fmt = t_data[0]
        raw_color = t_data[1]
        imager_type = struct.unpack_from('>Q', t_data, 2)[0]
        compression = t_data[10]
        width = struct.unpack_from('>H', t_data, 11)[0]
        height = struct.unpack_from('>H', t_data, 13)[0]
        frame_counter = struct.unpack_from('>I', t_data, 15)[0]
        error_flags = struct.unpack_from('>H', t_data, 19)[0]

        trailer = DissectField("MIPI Metadata Trailer", "21 bytes", t_off, t_off + 21)
        trailer.children.append(DissectField("Pixel Format", f"0x{pixel_fmt:02X}",
                                t_off, t_off + 1))
        trailer.children.append(DissectField("Raw Color", f"0x{raw_color:02X}",
                                t_off + 1, t_off + 2))
        trailer.children.append(DissectField("Imager Type", f"0x{imager_type:016X}",
                                t_off + 2, t_off + 10))
        trailer.children.append(DissectField("Compression", f"0x{compression:02X}",
                                t_off + 10, t_off + 11))
        trailer.children.append(DissectField("Width", str(width), t_off + 11, t_off + 13))
        trailer.children.append(DissectField("Height", str(height), t_off + 13, t_off + 15))
        trailer.children.append(DissectField("Frame Counter", str(frame_counter),
                                t_off + 15, t_off + 19))
        trailer.children.append(DissectField("Error Flags", f"0x{error_flags:04X}",
                                t_off + 19, t_off + 21))
        item.children.append(trailer)
    else:
        item.value = f"Frame Data, {len(payload)} bytes"

    if len(payload) > 0:
        data_end = len(payload) - 21 if is_eof and len(payload) >= 21 else len(payload)
        if data_end > 0:
            item.children.append(DissectField("Pixel Data", f"{data_end} bytes",
                                 p_off, p_off + data_end))
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── DLT (Diagnostic Log and Trace) ──────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_dlt_v0(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """DLT V0 (Class 0x30, Version 0x00) — veraltet."""
    return [DissectField("DLT V0 (deprecated)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_dlt_v1(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """DLT V1 (Class 0x30, Version 0x01)."""
    if len(payload) < 28:
        return [DissectField("DLT V1 (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    item = DissectField("ViGEM DLT V1", "", p_off, p_off + len(payload))

    # VPCAP Header (4 Bytes)
    pktno = payload[0]
    lastpktno = payload[1]
    vpcap_hdr = DissectField("VPCAP Header", f"Paket {pktno}/{lastpktno}", p_off, p_off + 4)
    vpcap_hdr.children.append(DissectField("Packet No", str(pktno), p_off, p_off + 1))
    vpcap_hdr.children.append(DissectField("Last Packet No", str(lastpktno),
                              p_off + 1, p_off + 2))
    item.children.append(vpcap_hdr)

    # Pseudo TCP/IP Header (24 Bytes)
    dst_mac = ":".join(f"{b:02x}" for b in payload[4:10])
    src_mac = ":".join(f"{b:02x}" for b in payload[10:16])
    dst_ip = ".".join(str(b) for b in payload[16:20])
    src_ip = ".".join(str(b) for b in payload[20:24])
    dst_port = struct.unpack_from('>H', payload, 24)[0]
    src_port = struct.unpack_from('>H', payload, 26)[0]

    pseudo = DissectField("Pseudo TCP/IP Header", f"{src_ip}:{src_port} → {dst_ip}:{dst_port}",
                          p_off + 4, p_off + 28)
    pseudo.children.append(DissectField("Dst MAC", dst_mac, p_off + 4, p_off + 10))
    pseudo.children.append(DissectField("Src MAC", src_mac, p_off + 10, p_off + 16))
    pseudo.children.append(DissectField("Dst IP", dst_ip, p_off + 16, p_off + 20))
    pseudo.children.append(DissectField("Src IP", src_ip, p_off + 20, p_off + 24))
    pseudo.children.append(DissectField("Dst Port", str(dst_port), p_off + 24, p_off + 26))
    pseudo.children.append(DissectField("Src Port", str(src_port), p_off + 26, p_off + 28))
    item.children.append(pseudo)

    # Storage Header (16 Bytes, falls vorhanden)
    off = 28
    if len(payload) >= off + 16:
        pattern = struct.unpack_from('>I', payload, off)[0]
        seconds = struct.unpack_from('<I', payload, off + 4)[0]
        microsecs = struct.unpack_from('<I', payload, off + 8)[0]
        ecu_id = payload[off + 12:off + 16]

        storage = DissectField("DLT Storage Header", "", p_off + off, p_off + off + 16)
        storage.children.append(DissectField("Pattern", f"0x{pattern:08X}",
                                p_off + off, p_off + off + 4))
        storage.children.append(DissectField("Seconds", str(seconds),
                                p_off + off + 4, p_off + off + 8))
        storage.children.append(DissectField("Microseconds", str(microsecs),
                                p_off + off + 8, p_off + off + 12))
        storage.children.append(DissectField("ECU ID",
                                ecu_id.decode('ascii', errors='replace').rstrip('\x00'),
                                p_off + off + 12, p_off + off + 16))
        item.children.append(storage)
        off += 16

    # Standard Header
    if len(payload) >= off + 4:
        htyp = payload[off]
        mcnt = payload[off + 1]
        msg_len = struct.unpack_from('>H', payload, off + 2)[0]

        ueh = bool(htyp & 0x01)
        msbf = bool(htyp & 0x02)
        weid = bool(htyp & 0x04)
        wsid = bool(htyp & 0x08)
        wtms = bool(htyp & 0x10)
        vers = (htyp >> 5) & 0x07

        std_hdr = DissectField("DLT Standard Header",
                               f"Version: {vers}, Counter: {mcnt}, Len: {msg_len}",
                               p_off + off, p_off + off + 4)
        std_hdr.children.append(DissectField("HTYP", f"0x{htyp:02X}", p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("  UEH (Extended Hdr)", str(ueh),
                                p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("  MSBF", str(msbf), p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("  WEID", str(weid), p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("  WSID", str(wsid), p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("  WTMS", str(wtms), p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("  Version", str(vers), p_off + off, p_off + off + 1))
        std_hdr.children.append(DissectField("Message Counter", str(mcnt),
                                p_off + off + 1, p_off + off + 2))
        std_hdr.children.append(DissectField("Length", str(msg_len),
                                p_off + off + 2, p_off + off + 4))
        item.children.append(std_hdr)
        off += 4

        # Optionale Felder
        if weid and len(payload) >= off + 4:
            ecu = payload[off:off + 4].decode('ascii', errors='replace').rstrip('\x00')
            item.children.append(DissectField("ECU ID", ecu, p_off + off, p_off + off + 4))
            off += 4
        if wsid and len(payload) >= off + 4:
            sid = struct.unpack_from('>I', payload, off)[0]
            item.children.append(DissectField("Session ID", f"0x{sid:08X}",
                                 p_off + off, p_off + off + 4))
            off += 4
        if wtms and len(payload) >= off + 4:
            tms = struct.unpack_from('>I', payload, off)[0]
            item.children.append(DissectField("Timestamp", str(tms),
                                 p_off + off, p_off + off + 4))
            off += 4

        # Extended Header
        if ueh and len(payload) >= off + 10:
            msin = payload[off]
            noar = payload[off + 1]
            apid = payload[off + 2:off + 6].decode('ascii', errors='replace').rstrip('\x00')
            ctid = payload[off + 6:off + 10].decode('ascii', errors='replace').rstrip('\x00')

            verbose = bool(msin & 0x01)
            mstp = (msin >> 1) & 0x07
            mtin = (msin >> 4) & 0x0F
            mstp_name = _DLT_MSTP.get(mstp, f"0x{mstp}")

            ext = DissectField("DLT Extended Header",
                               f"APID: {apid}, CTID: {ctid}, {mstp_name}",
                               p_off + off, p_off + off + 10)
            ext.children.append(DissectField("MSIN", f"0x{msin:02X}", p_off + off, p_off + off + 1))
            ext.children.append(DissectField("  Verbose", str(verbose),
                                p_off + off, p_off + off + 1))
            ext.children.append(DissectField("  MSTP", mstp_name, p_off + off, p_off + off + 1))
            ext.children.append(DissectField("  MTIN", str(mtin), p_off + off, p_off + off + 1))
            ext.children.append(DissectField("NOAR", str(noar), p_off + off + 1, p_off + off + 2))
            ext.children.append(DissectField("APID", apid, p_off + off + 2, p_off + off + 6))
            ext.children.append(DissectField("CTID", ctid, p_off + off + 6, p_off + off + 10))
            item.children.append(ext)
            off += 10

    item.value = f"{len(payload)} bytes"
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── PLP Raw ──────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_plp_raw(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """PLP Raw V1 (Class 0x36, Version 0x01)."""
    if len(payload) < 28:
        return [DissectField("PLP Raw (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    item = DissectField("ViGEM PLP Raw V1", "", p_off, p_off + len(payload))

    # PLP Header (12 Bytes)
    probe_id = struct.unpack_from('>H', payload, 0)[0]
    counter = struct.unpack_from('>H', payload, 2)[0]
    version = payload[4]
    plp_type = payload[5]
    msg_type = struct.unpack_from('>H', payload, 6)[0]
    probe_flags = struct.unpack_from('>H', payload, 10)[0]

    plp_type_name = _PLP_TYPES.get(plp_type, f"0x{plp_type:02X}")
    msg_type_name = _PLP_MSG_TYPES.get(msg_type, f"0x{msg_type:04X}")

    plp_hdr = DissectField("PLP Header",
                           f"Probe: 0x{probe_id:04X}, Type: {plp_type_name}, Msg: {msg_type_name}",
                           p_off, p_off + 12)
    plp_hdr.children.append(DissectField("Probe ID", f"0x{probe_id:04X}", p_off, p_off + 2))
    plp_hdr.children.append(DissectField("Counter", str(counter), p_off + 2, p_off + 4))
    plp_hdr.children.append(DissectField("Version", str(version), p_off + 4, p_off + 5))
    plp_hdr.children.append(DissectField("PLP Type", f"{plp_type} ({plp_type_name})",
                            p_off + 5, p_off + 6))
    plp_hdr.children.append(DissectField("Message Type", f"0x{msg_type:04X} ({msg_type_name})",
                            p_off + 6, p_off + 8))

    # Probe Flags
    pf = DissectField("Probe Flags", f"0x{probe_flags:04X}", p_off + 10, p_off + 12)
    pf.children.append(DissectField("EOS", str(bool(probe_flags & 0x01)),
                       p_off + 10, p_off + 12))
    pf.children.append(DissectField("SOS", str(bool(probe_flags & 0x02)),
                       p_off + 10, p_off + 12))
    pf.children.append(DissectField("SPY", str(bool(probe_flags & 0x04)),
                       p_off + 10, p_off + 12))
    pf.children.append(DissectField("Multi Frame", str(bool(probe_flags & 0x08)),
                       p_off + 10, p_off + 12))
    pf.children.append(DissectField("Probe Overflow", str(bool(probe_flags & 0x8000)),
                       p_off + 10, p_off + 12))
    plp_hdr.children.append(pf)
    item.children.append(plp_hdr)

    # Bus Header (16 Bytes)
    bus_spec_id = struct.unpack_from('<I', payload, 12)[0]
    timestamp = struct.unpack_from('<Q', payload, 16)[0]
    data_len = struct.unpack_from('<H', payload, 24)[0]
    data_flags = struct.unpack_from('<H', payload, 26)[0]

    bus_hdr = DissectField("Bus Header",
                           f"BusID: 0x{bus_spec_id:08X}, Len: {data_len}",
                           p_off + 12, p_off + 28)
    bus_hdr.children.append(DissectField("Bus-Specific ID", f"0x{bus_spec_id:08X}",
                            p_off + 12, p_off + 16))
    bus_hdr.children.append(DissectField("Timestamp", f"{timestamp} ns",
                            p_off + 16, p_off + 24))
    bus_hdr.children.append(DissectField("Data Length", str(data_len), p_off + 24, p_off + 26))

    df = DissectField("Data Flags", f"0x{data_flags:04X}", p_off + 26, p_off + 28)
    df.children.append(DissectField("CRC Error", str(bool(data_flags & 0x2000)),
                       p_off + 26, p_off + 28))
    df.children.append(DissectField("Tx Message", str(bool(data_flags & 0x4000)),
                       p_off + 26, p_off + 28))
    df.children.append(DissectField("Bus Overflow", str(bool(data_flags & 0x8000)),
                       p_off + 26, p_off + 28))
    bus_hdr.children.append(df)
    item.children.append(bus_hdr)

    # Payload-Daten
    if len(payload) > 28:
        plp_data = payload[28:]
        item.children.append(DissectField("PLP Data",
                             f"{len(plp_data)} bytes", p_off + 28, p_off + 28 + len(plp_data)))

    item.value = f"Probe: 0x{probe_id:04X}, {msg_type_name}, {data_len} bytes"
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── XCP ──────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_xcp(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """XCP (Class 0xb4)."""
    if not payload:
        return []

    pid = payload[0]
    cmd_name = _XCP_COMMANDS.get(pid, f"0x{pid:02X}")

    # Master (Befehle) vs. Slave (Antworten)
    if pid >= 0xC0:
        role = "Master"
    elif pid == 0xFF:
        role = "Positive Response"
    elif pid == 0xFE:
        role = "Error"
    else:
        role = "Slave"

    item = DissectField(f"ViGEM XCP ({role})", f"PID: 0x{pid:02X} ({cmd_name})",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("PID", f"0x{pid:02X} ({cmd_name})", p_off, p_off + 1))
    if len(payload) > 1:
        item.children.append(DissectField("Parameters",
                             " ".join(f"{b:02X}" for b in payload[1:]),
                             p_off + 1, p_off + len(payload)))
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── MTA (Message Transport Assembly) ─────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_mta_header(payload: bytes, p_off: int) -> Tuple[DissectField, int]:
    """Parst den MTA-Header. Gibt (DissectField, offset_nach_header) zurück."""
    if len(payload) < 2:
        return DissectField("MTA Header (zu kurz)", "", p_off, p_off + len(payload)), len(payload)

    hdr = struct.unpack_from('>H', payload, 0)[0]
    iface_id = hdr & 0x03
    channel_bundle = bool(hdr & 0x04)
    subframes = bool(hdr & 0x08)
    ext_hdr_present = bool(hdr & 0x10)
    delay_size = bool(hdr & 0x20)
    sw_packets = bool(hdr & 0x40)
    little_endian = bool(hdr & 0x80)

    mta = DissectField("MTA Header", f"0x{hdr:04X}", p_off, p_off + 2)
    mta.children.append(DissectField("Interface ID", str(iface_id), p_off, p_off + 2))
    mta.children.append(DissectField("Channel Bundle", str(channel_bundle), p_off, p_off + 2))
    mta.children.append(DissectField("Subframes", str(subframes), p_off, p_off + 2))
    mta.children.append(DissectField("Extended Header", str(ext_hdr_present), p_off, p_off + 2))
    mta.children.append(DissectField("Delay/Size Present", str(delay_size), p_off, p_off + 2))
    mta.children.append(DissectField("SW Packets", str(sw_packets), p_off, p_off + 2))
    mta.children.append(DissectField("Endianness", "LE" if little_endian else "BE",
                                     p_off, p_off + 2))

    off = 2
    if ext_hdr_present and len(payload) >= off + 4:
        ext = struct.unpack_from('>I', payload, off)[0]
        mta.children.append(DissectField("Extended Header", f"0x{ext:08X}",
                            p_off + off, p_off + off + 4))
        off += 4

    return mta, off


def _dissect_mta_single(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """MTA Single (OOB=1, CUST3=1)."""
    item = DissectField("ViGEM MTA (Single Message)", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    hdr_item, off = _dissect_mta_header(payload, p_off)
    item.children.append(hdr_item)
    if len(payload) > off + 5:
        data_end = len(payload) - 5
        item.children.append(DissectField("Data", f"{data_end - off} bytes",
                             p_off + off, p_off + data_end))
        item.children.append(DissectField("Frame Counter", str(payload[data_end]),
                             p_off + data_end, p_off + data_end + 1))
        if len(payload) >= data_end + 5:
            crc = struct.unpack_from('>I', payload, data_end + 1)[0]
            item.children.append(DissectField("CRC", f"0x{crc:08X}",
                                 p_off + data_end + 1, p_off + data_end + 5))
    return [item]


def _dissect_mta_first(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """MTA First Fragment (OOB=1)."""
    item = DissectField("ViGEM MTA (First Fragment)", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    hdr_item, off = _dissect_mta_header(payload, p_off)
    item.children.append(hdr_item)
    if len(payload) > off:
        item.children.append(DissectField("Fragment Data", f"{len(payload) - off} bytes",
                             p_off + off, p_off + len(payload)))
    return [item]


def _dissect_mta_middle(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """MTA Middle Fragment."""
    return [DissectField("ViGEM MTA (Middle Fragment)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_mta_last(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """MTA Last Fragment (CUST3=1)."""
    item = DissectField("ViGEM MTA (Last Fragment)", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    if len(payload) > 5:
        data_end = len(payload) - 5
        item.children.append(DissectField("Fragment Data", f"{data_end} bytes",
                             p_off, p_off + data_end))
        item.children.append(DissectField("Frame Counter", str(payload[data_end]),
                             p_off + data_end, p_off + data_end + 1))
        crc = struct.unpack_from('>I', payload, data_end + 1)[0]
        item.children.append(DissectField("CRC", f"0x{crc:08X}",
                             p_off + data_end + 1, p_off + len(payload)))
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── Image Frame / Fragment ───────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_image_frame(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Image Frame V0 (Class 0x42)."""
    if len(payload) < 25:
        return [DissectField("Image Frame (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    img_type = payload[0]
    width = struct.unpack_from('<H', payload, 1)[0]
    height = struct.unpack_from('<H', payload, 3)[0]
    fcnt = struct.unpack_from('<I', payload, 5)[0]
    frame_gap = struct.unpack_from('<I', payload, 9)[0]
    line_gap = struct.unpack_from('<I', payload, 13)[0]
    eof_ts = struct.unpack_from('<Q', payload, 17)[0]

    item = DissectField("ViGEM Image Frame",
                        f"{width}x{height}, Frame #{fcnt}",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("Image Type", f"0x{img_type:02X}", p_off, p_off + 1))
    item.children.append(DissectField("Width", str(width), p_off + 1, p_off + 3))
    item.children.append(DissectField("Height", str(height), p_off + 3, p_off + 5))
    item.children.append(DissectField("Frame Counter", str(fcnt), p_off + 5, p_off + 9))
    item.children.append(DissectField("Inter-Frame Gap", str(frame_gap), p_off + 9, p_off + 13))
    item.children.append(DissectField("Inter-Line Gap", str(line_gap), p_off + 13, p_off + 17))
    item.children.append(DissectField("EOF Timestamp", f"0x{eof_ts:016X}",
                         p_off + 17, p_off + 25))
    if len(payload) > 25:
        item.children.append(DissectField("Pixel Data", f"{len(payload) - 25} bytes",
                             p_off + 25, p_off + len(payload)))
    return [item]


def _dissect_image_fragment_first(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Image Fragment First (OOB=1)."""
    return [DissectField("ViGEM Image Fragment (First)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_image_fragment_middle(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Image Fragment Middle."""
    return [DissectField("ViGEM Image Fragment (Middle)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_image_fragment_last(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Image Fragment Last (CUST3=1) — mit 16-Byte Trailer."""
    item = DissectField("ViGEM Image Fragment (Last)", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    if len(payload) >= 16:
        t_off = p_off + len(payload) - 16
        t1 = struct.unpack_from('>I', payload, len(payload) - 16)[0]
        t2 = struct.unpack_from('>I', payload, len(payload) - 12)[0]
        ts = struct.unpack_from('>Q', payload, len(payload) - 8)[0]
        trailer = DissectField("Trailer", "16 bytes", t_off, t_off + 16)
        trailer.children.append(DissectField("Porch Info", f"0x{t1:08X}", t_off, t_off + 4))
        trailer.children.append(DissectField("H-Blank/Width", f"0x{t2:08X}",
                                t_off + 4, t_off + 8))
        trailer.children.append(DissectField("Last Pixel TS", f"0x{ts:016X}",
                                t_off + 8, t_off + 16))
        item.children.append(trailer)
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── Analog / Digital I/O ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_analog_io(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Analog I/O V0 (Class 0x34)."""
    item = DissectField("ViGEM Analog I/O", "", p_off, p_off + len(payload))
    ch = 1
    off = 0
    while off + 4 <= len(payload):
        mv = struct.unpack_from('<I', payload, off)[0]
        item.children.append(DissectField(f"Kanal {ch}", f"{mv} mV",
                             p_off + off, p_off + off + 4))
        ch += 1
        off += 4
    item.value = f"{ch - 1} Kanäle"
    return [item]


def _dissect_digital_io(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Digital I/O V0 (Class 0x35) — Protobuf-kodiert."""
    return [DissectField("ViGEM Digital I/O (Protobuf)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


# ══════════════════════════════════════════════════════════════════════════
# ── SPI ──────────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_spi(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """SPI V0 (Class 0x37)."""
    if len(payload) < 64:
        return [DissectField("SPI (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    status = struct.unpack_from('<I', payload, 0)[0]
    samplerate = struct.unpack_from('<I', payload, 4)[0]
    sop_ticks = struct.unpack_from('<Q', payload, 8)[0]
    duration = struct.unpack_from('<Q', payload, 16)[0]
    data_offset = struct.unpack_from('<I', payload, 24)[0]
    datalen = struct.unpack_from('<I', payload, 60)[0] if len(payload) > 63 else 0

    item = DissectField("ViGEM SPI", f"Rate: {samplerate} kHz, Len: {datalen}",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("Status", f"0x{status:08X}", p_off, p_off + 4))
    item.children.append(DissectField("Sample Rate", f"{samplerate} kHz", p_off + 4, p_off + 8))
    item.children.append(DissectField("SOP Ticks", str(sop_ticks), p_off + 8, p_off + 16))
    item.children.append(DissectField("Duration Ticks", str(duration), p_off + 16, p_off + 24))
    item.children.append(DissectField("Data Offset Ticks", str(data_offset),
                         p_off + 24, p_off + 28))
    item.children.append(DissectField("Data Length Total", str(datalen), p_off + 60, p_off + 64))

    if datalen > 0 and len(payload) > 64:
        half = datalen // 2
        mosi_end = min(64 + half, len(payload))
        item.children.append(DissectField("MOSI Data", f"{mosi_end - 64} bytes",
                             p_off + 64, p_off + mosi_end))
        if mosi_end < len(payload):
            item.children.append(DissectField("MISO Data", f"{len(payload) - mosi_end} bytes",
                                 p_off + mosi_end, p_off + len(payload)))
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── MOST Protokolle ──────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_most_generic(name: str, payload: bytes, p_off: int) -> List[DissectField]:
    """Generischer MOST-Dissector."""
    item = DissectField(f"ViGEM {name}", f"{len(payload)} bytes", p_off, p_off + len(payload))
    if len(payload) >= 4:
        item.children.append(DissectField("Data",
                             " ".join(f"{b:02X}" for b in payload[:min(64, len(payload))]),
                             p_off, p_off + min(64, len(payload))))
    return [item]


def _dissect_most25_cms(p, o, c): return _dissect_most_generic("MOST25 CMS", p, o)
def _dissect_most25_state(p, o, c): return _dissect_most_generic("MOST25 State", p, o)
def _dissect_most25_ads(p, o, c): return _dissect_most_generic("MOST25 ADS", p, o)
def _dissect_most25_raw(p, o, c): return _dissect_most_generic("MOST25 RAW", p, o)
def _dissect_most50_cms(p, o, c): return _dissect_most_generic("MOST50 CMS", p, o)
def _dissect_most50_ads(p, o, c): return _dissect_most_generic("MOST50 ADS", p, o)
def _dissect_most50_raw(p, o, c): return _dissect_most_generic("MOST50 RAW", p, o)
def _dissect_most150_cms(p, o, c): return _dissect_most_generic("MOST150 CMS", p, o)
def _dissect_most150_ads(p, o, c): return _dissect_most_generic("MOST150 ADS", p, o)
def _dissect_most150_state(p, o, c): return _dissect_most_generic("MOST150 State", p, o)
def _dissect_most150_alloc(p, o, c): return _dissect_most_generic("MOST150 Alloc", p, o)
def _dissect_most150_raw(p, o, c): return _dissect_most_generic("MOST150 RAW", p, o)


# ══════════════════════════════════════════════════════════════════════════
# ── Einfache Protokolle (Raw-Daten / Minimal-Header) ─────────────────────
# ══════════════════════════════════════════════════════════════════════════

def _dissect_rs232(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """RS232 (Class 0x05)."""
    item = DissectField("ViGEM RS232", f"{len(payload)} bytes", p_off, p_off + len(payload))
    if payload:
        # ASCII-Darstellung versuchen
        try:
            text = payload.decode('ascii', errors='replace')
            item.children.append(DissectField("ASCII", repr(text), p_off, p_off + len(payload)))
        except Exception:
            pass
        item.children.append(DissectField("Data",
                             " ".join(f"{b:02X}" for b in payload[:128]),
                             p_off, p_off + min(128, len(payload))))
    return [item]


def _dissect_tmg(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """TMG / Test Message (Class 0x08)."""
    return [DissectField("ViGEM TMG (Test Message)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_marker_v0(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Marker V0 (Class 0x0a, Version 0x00)."""
    item = DissectField("ViGEM Marker / Event V0", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    if payload:
        item.children.append(DissectField("Marker Data",
                             " ".join(f"{b:02X}" for b in payload[:64]),
                             p_off, p_off + min(64, len(payload))))
    return [item]


def _dissect_marker_v2(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Marker V2 (Class 0x0a, Version 0x02) — Protobuf (pb_rpc.Event)."""
    return [DissectField("ViGEM Marker / Event V2 (Protobuf)", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_lvds_status(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """LVDS Status (Class 0x32)."""
    return [DissectField("ViGEM LVDS Status", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_tcp_payload(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """TCP Payload (Class 0x39)."""
    return [DissectField("ViGEM TCP Payload", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_udp_payload(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """UDP Payload (Class 0x40)."""
    return [DissectField("ViGEM UDP Payload", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_gnlog_v1(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """GNLog V1 (Class 0x60)."""
    if len(payload) < 24:
        return [DissectField("GNLog V1 (zu kurz)", f"{len(payload)} bytes",
                             p_off, p_off + len(payload))]

    dst_mac = ":".join(f"{b:02x}" for b in payload[0:6])
    src_mac = ":".join(f"{b:02x}" for b in payload[6:12])
    dst_ip = ".".join(str(b) for b in payload[12:16])
    src_ip = ".".join(str(b) for b in payload[16:20])
    dst_port = struct.unpack_from('>H', payload, 20)[0]
    src_port = struct.unpack_from('>H', payload, 22)[0]

    item = DissectField("ViGEM GNLog V1",
                        f"{src_ip}:{src_port} → {dst_ip}:{dst_port}",
                        p_off, p_off + len(payload))
    item.children.append(DissectField("Dst MAC", dst_mac, p_off, p_off + 6))
    item.children.append(DissectField("Src MAC", src_mac, p_off + 6, p_off + 12))
    item.children.append(DissectField("Dst IP", dst_ip, p_off + 12, p_off + 16))
    item.children.append(DissectField("Src IP", src_ip, p_off + 16, p_off + 20))
    item.children.append(DissectField("Dst Port", str(dst_port), p_off + 20, p_off + 22))
    item.children.append(DissectField("Src Port", str(src_port), p_off + 22, p_off + 24))
    if len(payload) > 24:
        item.children.append(DissectField("Payload", f"{len(payload) - 24} bytes",
                             p_off + 24, p_off + len(payload)))
    return [item]


def _dissect_gnlog_serial(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """GNLog Serial (Class 0x61)."""
    return [DissectField("ViGEM GNLog Serial", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_ifinfo(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """IF Info (Class 0x80)."""
    return [DissectField("ViGEM IF Info", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_cca_system(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """CCA System (Class 0xa0) — Protobuf (pb_rpc.CcaIndexFile)."""
    item = DissectField("ViGEM CCA System", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    if len(payload) >= 2:
        msg_len = struct.unpack_from('>H', payload, 0)[0]
        item.children.append(DissectField("Message Length", str(msg_len), p_off, p_off + 2))
        item.children.append(DissectField("Protobuf Data", f"{len(payload) - 2} bytes",
                             p_off + 2, p_off + len(payload)))
    return [item]


def _dissect_cca_syslog(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """CCA Syslog (Class 0xa1)."""
    item = DissectField("ViGEM CCA Syslog", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    if payload:
        try:
            text = payload.decode('utf-8', errors='replace').rstrip('\x00')
            item.children.append(DissectField("Message", text, p_off, p_off + len(payload)))
        except Exception:
            pass
    return [item]


def _dissect_mobileye_tapi(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Mobileye TAPI (Class 0xb0)."""
    return [DissectField("ViGEM Mobileye TAPI", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_mobileye_tapi_init(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Mobileye TAPI Init (Class 0xb1)."""
    return [DissectField("ViGEM Mobileye TAPI Init", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_prelabel(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Pre-Label (Class 0xb2)."""
    return [DissectField("ViGEM Pre-Label", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_kafas4(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """KAFAS4 ECU Info (Class 0xb3)."""
    return [DissectField("ViGEM KAFAS4 ECU Info", f"{len(payload)} bytes",
                         p_off, p_off + len(payload))]


def _dissect_attachment(payload: bytes, p_off: int, ctx: dict) -> List[DissectField]:
    """Attachment (Class 0xc0)."""
    item = DissectField("ViGEM Attachment", f"{len(payload)} bytes",
                        p_off, p_off + len(payload))
    # Name ist Null-terminierter String
    null_pos = payload.find(b'\x00')
    if null_pos >= 0:
        name = payload[:null_pos].decode('utf-8', errors='replace')
        item.children.append(DissectField("Name", name, p_off, p_off + null_pos + 1))
        content_start = null_pos + 1
        if content_start < len(payload):
            item.children.append(DissectField("Content", f"{len(payload) - content_start} bytes",
                                 p_off + content_start, p_off + len(payload)))
    return [item]


# ══════════════════════════════════════════════════════════════════════════
# ── Lua-Datei Loader (Metadaten extrahieren) ─────────────────────────────
# ══════════════════════════════════════════════════════════════════════════

def load_lua_metadata(lua_path: str) -> dict:
    """Extrahiert Metadaten aus einer ccaDissector.lua Datei.

    Returns:
        dict mit 'version', 'protocols' (Liste), 'proto_count'
    """
    result = {'version': 'unbekannt', 'protocols': [], 'proto_count': 0, 'path': lua_path}

    try:
        with open(lua_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError as e:
        logger.warning("Konnte Lua-Datei nicht laden: %s", e)
        return result

    # Version extrahieren
    ver_match = re.search(r'--\s*Version\s+([\d.]+)', content)
    if ver_match:
        result['version'] = ver_match.group(1)

    # Proto()-Definitionen extrahieren
    proto_pattern = re.compile(r'(\w+)\s*=\s*Proto\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')
    protocols = []
    for m in proto_pattern.finditer(content):
        protocols.append({
            'var': m.group(1),
            'name': m.group(2),
            'description': m.group(3),
        })

    result['protocols'] = protocols
    result['proto_count'] = len(protocols)

    logger.info("CCA Lua geladen: Version %s, %d Protokolle", result['version'], len(protocols))
    return result
