"""UDS (ISO 14229) + ISO-TP (ISO 15765-2) Codec.

Enthaelt:
  - UDS Service/NRC Kataloge
  - ISO-TP Reassembler (Multi-Frame)
  - UDS Request Builder / Response Parser
"""

import struct
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════
# UDS Service Katalog (ISO 14229-1)
# ═══════════════════════════════════════════════════════════════════════════

UDS_SERVICES = {
    0x10: "DiagnosticSessionControl",
    0x11: "ECUReset",
    0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation",
    0x22: "ReadDataByIdentifier",
    0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier",
    0x27: "SecurityAccess",
    0x28: "CommunicationControl",
    0x29: "Authentication",
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

UDS_SESSIONS = {
    0x01: "Default", 0x02: "Programming", 0x03: "Extended",
    0x04: "SafetySystem",
}

UDS_RESET_TYPES = {
    0x01: "HardReset", 0x02: "KeyOffOnReset", 0x03: "SoftReset",
}

UDS_NRC = {
    0x10: "GeneralReject",
    0x11: "ServiceNotSupported",
    0x12: "SubFunctionNotSupported",
    0x13: "IncorrectMessageLengthOrInvalidFormat",
    0x14: "ResponseTooLong",
    0x21: "BusyRepeatRequest",
    0x22: "ConditionsNotCorrect",
    0x24: "RequestSequenceError",
    0x25: "NoResponseFromSubnetComponent",
    0x26: "FailurePreventsExecution",
    0x31: "RequestOutOfRange",
    0x33: "SecurityAccessDenied",
    0x35: "InvalidKey",
    0x36: "ExceededNumberOfAttempts",
    0x37: "RequiredTimeDelayNotExpired",
    0x70: "UploadDownloadNotAccepted",
    0x71: "TransferDataSuspended",
    0x72: "GeneralProgrammingFailure",
    0x73: "WrongBlockSequenceCounter",
    0x78: "RequestCorrectlyReceivedResponsePending",
    0x7E: "SubFunctionNotSupportedInActiveSession",
    0x7F: "ServiceNotSupportedInActiveSession",
}

# Bekannte DIDs
COMMON_DIDS = {
    0xF186: "ActiveDiagnosticSession",
    0xF187: "VehicleManufacturerSparePartNumber",
    0xF188: "VehicleManufacturerECUSoftwareNumber",
    0xF189: "VehicleManufacturerECUSoftwareVersionNumber",
    0xF18A: "SystemSupplierIdentifier",
    0xF18B: "ECUManufacturingDate",
    0xF18C: "ECUSerialNumber",
    0xF190: "VIN",
    0xF191: "VehicleManufacturerECUHardwareNumber",
    0xF192: "SystemSupplierECUHardwareNumber",
    0xF193: "SystemSupplierECUHardwareVersionNumber",
    0xF194: "SystemSupplierECUSoftwareNumber",
    0xF195: "SystemSupplierECUSoftwareVersionNumber",
}


def get_service_name(sid: int) -> str:
    return UDS_SERVICES.get(sid, f"Unknown (0x{sid:02X})")


def get_nrc_name(nrc: int) -> str:
    return UDS_NRC.get(nrc, f"Unknown (0x{nrc:02X})")


def get_did_name(did: int) -> str:
    return COMMON_DIDS.get(did, f"0x{did:04X}")


# ═══════════════════════════════════════════════════════════════════════════
# UDS Request Builder
# ═══════════════════════════════════════════════════════════════════════════

def build_request(sid: int, sub_function: int = None,
                  did: int = None, data: bytes = b'') -> bytes:
    """Baut einen UDS-Request zusammen."""
    req = bytes([sid])
    if sub_function is not None:
        req += bytes([sub_function])
    if did is not None:
        req += struct.pack('>H', did)
    req += data
    return req


def build_tester_present() -> bytes:
    return build_request(0x3E, sub_function=0x00)


def build_read_did(did: int) -> bytes:
    return build_request(0x22, did=did)


def build_write_did(did: int, value: bytes) -> bytes:
    return build_request(0x2E, did=did, data=value)


def build_session_control(session: int) -> bytes:
    return build_request(0x10, sub_function=session)


def build_ecu_reset(reset_type: int) -> bytes:
    return build_request(0x11, sub_function=reset_type)


def build_security_access(level: int, key: bytes = b'') -> bytes:
    return build_request(0x27, sub_function=level, data=key)


def build_clear_dtc(group: int = 0xFFFFFF) -> bytes:
    return bytes([0x14]) + struct.pack('>I', group)[1:]  # 3-byte group


def build_read_dtc(sub_function: int = 0x01, mask: int = 0xFF) -> bytes:
    return bytes([0x19, sub_function, mask])


# ═══════════════════════════════════════════════════════════════════════════
# UDS Response Parser
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class UDSResponse:
    """Geparstes UDS-Ergebnis."""
    is_positive: bool = False
    sid: int = 0
    sub_function: int = 0
    nrc: int = 0
    nrc_name: str = ''
    service_name: str = ''
    did: int = 0
    did_name: str = ''
    data: bytes = b''
    raw: bytes = b''
    fields: List[Tuple[str, str]] = field(default_factory=list)


def parse_response(data: bytes) -> UDSResponse:
    """Parst eine UDS-Response."""
    resp = UDSResponse(raw=data)
    if not data:
        return resp

    if data[0] == 0x7F:
        # Negative Response
        resp.is_positive = False
        resp.sid = data[1] if len(data) > 1 else 0
        resp.nrc = data[2] if len(data) > 2 else 0
        resp.service_name = get_service_name(resp.sid)
        resp.nrc_name = get_nrc_name(resp.nrc)
        resp.fields = [
            ("Typ", "Negative Response"),
            ("Service", f"0x{resp.sid:02X} ({resp.service_name})"),
            ("NRC", f"0x{resp.nrc:02X} ({resp.nrc_name})"),
        ]
    else:
        # Positive Response (SID + 0x40)
        resp.is_positive = True
        resp.sid = data[0] - 0x40
        resp.service_name = get_service_name(resp.sid)
        resp.fields = [
            ("Typ", "Positive Response"),
            ("Service", f"0x{resp.sid:02X} ({resp.service_name})"),
        ]

        if resp.sid in (0x22, 0x2E) and len(data) >= 3:
            resp.did = struct.unpack('>H', data[1:3])[0]
            resp.did_name = get_did_name(resp.did)
            resp.data = data[3:]
            resp.fields.append(("DID", f"0x{resp.did:04X} ({resp.did_name})"))
            resp.fields.append(("Wert", data[3:].hex().upper()))
        elif resp.sid == 0x10 and len(data) >= 2:
            resp.sub_function = data[1]
            session = UDS_SESSIONS.get(data[1], f"0x{data[1]:02X}")
            resp.fields.append(("Session", session))
            resp.data = data[2:]
        else:
            resp.data = data[1:]
            if resp.data:
                resp.fields.append(("Daten", resp.data.hex().upper()))

    return resp


# ═══════════════════════════════════════════════════════════════════════════
# ISO-TP Reassembler (ISO 15765-2)
# ═══════════════════════════════════════════════════════════════════════════

class ISOTPReassembler:
    """Setzt Multi-Frame ISO-TP Nachrichten zusammen.

    Frame-Typen:
      SF (0x0): Single Frame     — Daten in einem CAN-Frame
      FF (0x1): First Frame      — Beginn einer Multi-Frame Sequenz
      CF (0x2): Consecutive Frame — Folge-Frame
      FC (0x3): Flow Control     — Flusskontrolle
    """

    def __init__(self, timeout_s: float = 2.0):
        self._timeout = timeout_s
        self._buffer: Dict[int, dict] = {}  # can_id → state

    def feed(self, can_id: int, data: bytes) -> Optional[bytes]:
        """Fuettert einen CAN-Frame. Gibt vollstaendige Nachricht zurueck oder None."""
        if len(data) < 1:
            return None

        pci_type = (data[0] >> 4) & 0x0F

        if pci_type == 0:  # Single Frame
            length = data[0] & 0x0F
            if length == 0 and len(data) > 1:
                length = data[1]  # CAN-FD erweitert
                return data[2:2 + length] if len(data) >= 2 + length else None
            return data[1:1 + length] if len(data) >= 1 + length else None

        elif pci_type == 1:  # First Frame
            length = ((data[0] & 0x0F) << 8) | data[1]
            self._buffer[can_id] = {
                'expected_len': length,
                'data': bytearray(data[2:]),
                'next_sn': 1,
                'time': time.time(),
            }
            return None

        elif pci_type == 2:  # Consecutive Frame
            sn = data[0] & 0x0F
            state = self._buffer.get(can_id)
            if state is None:
                return None
            if time.time() - state['time'] > self._timeout:
                del self._buffer[can_id]
                return None
            if sn != state['next_sn'] & 0x0F:
                del self._buffer[can_id]
                return None
            state['data'].extend(data[1:])
            state['next_sn'] += 1
            state['time'] = time.time()
            if len(state['data']) >= state['expected_len']:
                result = bytes(state['data'][:state['expected_len']])
                del self._buffer[can_id]
                return result
            return None

        elif pci_type == 3:  # Flow Control
            return None  # FC wird nicht reassembliert

        return None

    def build_flow_control(self, block_size: int = 0, st_min: int = 0,
                           flag: int = 0) -> bytes:
        """Baut einen Flow-Control Frame."""
        return bytes([0x30 | (flag & 0x0F), block_size, st_min])

    def segment_request(self, data: bytes, max_len: int = 8) -> List[bytes]:
        """Segmentiert eine UDS-Nachricht in ISO-TP Frames."""
        if len(data) <= max_len - 1:
            # Single Frame
            return [bytes([len(data)]) + data + b'\x00' * (max_len - 1 - len(data))]

        # Multi-Frame: First Frame + Consecutive Frames
        frames = []
        total_len = len(data)
        ff = bytes([(0x10 | ((total_len >> 8) & 0x0F)), total_len & 0xFF])
        ff += data[:max_len - 2]
        frames.append(ff)

        offset = max_len - 2
        sn = 1
        while offset < total_len:
            cf_data = data[offset:offset + max_len - 1]
            cf = bytes([0x20 | (sn & 0x0F)]) + cf_data
            if len(cf) < max_len:
                cf += b'\x00' * (max_len - len(cf))
            frames.append(cf)
            offset += max_len - 1
            sn += 1

        return frames

    def clear(self):
        """Loescht alle offenen Reassembly-States."""
        self._buffer.clear()
