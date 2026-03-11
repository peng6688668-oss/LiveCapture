"""Plattform-Abstraktion fuer Windows-/Linux-/WSL-Kompatibilitaet.

Zentrales Modul, das alle plattformspezifischen Zugriffe kapselt:
- /proc/meminfo, /proc/net/dev, /proc/net/arp  (Linux)
- /sys/class/net/                                (Linux)
- ctypes.windll / WMI                            (Windows)
- AF_CAN, AF_PACKET                              (Linux-only Sockets)
- Tool-Erkennung (dumpcap, ffmpeg, vlc, lua, docker)
- Qt-Plattform-Initialisierung (xcb vs. Windows)
"""

import ctypes
import logging
import os
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# 1. Plattform-Flags
# ═══════════════════════════════════════════════════════════════════════════

IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')
IS_WSL = False
if IS_LINUX:
    try:
        IS_WSL = 'microsoft' in Path('/proc/version').read_text().lower()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# 2. Speicher-Informationen
# ═══════════════════════════════════════════════════════════════════════════

def _read_proc_meminfo(field: str) -> Optional[float]:
    """Liest ein Feld aus /proc/meminfo und gibt den Wert in MB zurueck."""
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                if line.startswith(field):
                    return int(line.split()[1]) / 1024  # kB -> MB
    except Exception:
        pass
    return None


def get_available_memory_mb() -> Optional[float]:
    """Gibt den verfuegbaren RAM in MB zurueck (oder None)."""
    if IS_WINDOWS:
        try:
            kernel32 = ctypes.windll.kernel32
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong),
                    ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong),
                    ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong),
                    ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullAvailPhys / (1024 * 1024)
        except Exception:
            pass
        return None
    return _read_proc_meminfo('MemAvailable:')


def get_total_memory_mb() -> Optional[float]:
    """Gibt den gesamten physischen RAM in MB zurueck (oder None)."""
    if IS_WINDOWS:
        try:
            kernel32 = ctypes.windll.kernel32
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', ctypes.c_ulonglong),
                    ('ullAvailPhys', ctypes.c_ulonglong),
                    ('ullTotalPageFile', ctypes.c_ulonglong),
                    ('ullAvailPageFile', ctypes.c_ulonglong),
                    ('ullTotalVirtual', ctypes.c_ulonglong),
                    ('ullAvailVirtual', ctypes.c_ulonglong),
                    ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
                ]
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(stat)
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return stat.ullTotalPhys / (1024 * 1024)
        except Exception:
            pass
        return None
    return _read_proc_meminfo('MemTotal:')


def get_system_memory_mb() -> Tuple[float, float]:
    """Gibt (total_mb, available_mb) zurueck. (0, 0) bei Fehler."""
    total = get_total_memory_mb() or 0
    avail = get_available_memory_mb() or 0
    return total, avail


def get_process_rss_mb(pid: int) -> Optional[float]:
    """Liest RSS (Resident Set Size) eines Prozesses in MB.

    Unter Windows wird psutil verwendet (falls vorhanden), sonst None.
    """
    if IS_WINDOWS:
        try:
            import psutil
            proc = psutil.Process(pid)
            return proc.memory_info().rss / (1024 * 1024)
        except Exception:
            return None
    try:
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    return int(line.split()[1]) / 1024  # kB -> MB
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# 3. OOM-Schutz
# ═══════════════════════════════════════════════════════════════════════════

def adjust_oom_score(score: int) -> None:
    """Setzt oom_score_adj fuer den aktuellen Prozess (Linux).

    Hoehere Werte (z.B. +500) machen den Prozess zum bevorzugten
    OOM-Kill-Kandidaten und schuetzen so den Eltern-Prozess (GUI).
    NOP auf Windows.
    """
    if IS_WINDOWS:
        return
    try:
        with open(f'/proc/{os.getpid()}/oom_score_adj', 'w') as f:
            f.write(str(score))
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# 4. Netzwerk-Interfaces
# ═══════════════════════════════════════════════════════════════════════════

def get_network_interfaces() -> List[str]:
    """Gibt verfuegbare Netzwerk-Interfaces zurueck (ohne Loopback)."""
    if IS_WINDOWS:
        try:
            import psutil
            return [name for name in psutil.net_if_addrs()
                    if name != 'Loopback Pseudo-Interface 1']
        except ImportError:
            pass
        # Fallback: socket + ipconfig
        try:
            out = subprocess.check_output(
                ['ipconfig'], text=True, timeout=5,
                creationflags=subprocess_creation_flags())
            ifaces = []
            for line in out.splitlines():
                if 'adapter' in line.lower() and ':' in line:
                    name = line.split(':')[0].strip()
                    if name:
                        ifaces.append(name)
            return ifaces
        except Exception:
            return []
    try:
        return [iface for iface in os.listdir('/sys/class/net/')
                if iface != 'lo']
    except Exception:
        return []


def get_can_interfaces() -> List[str]:
    """Sucht verfuegbare SocketCAN-Schnittstellen.

    Auf Windows: Gibt Standard-PCAN-Kanaele zurueck.
    """
    if IS_WINDOWS:
        return ['PCAN_USBBUS1', 'PCAN_USBBUS2']
    interfaces = []
    try:
        net_path = '/sys/class/net'
        if os.path.exists(net_path):
            for name in os.listdir(net_path):
                type_path = os.path.join(net_path, name, 'type')
                if os.path.exists(type_path):
                    with open(type_path, 'r') as f:
                        if f.read().strip() == '280':  # ARPHRD_CAN
                            interfaces.append(name)
    except OSError:
        pass
    if not interfaces:
        interfaces = ['can0', 'can1', 'vcan0']
    return interfaces


def get_eth_interfaces() -> List[str]:
    """Sucht verfuegbare Ethernet-Schnittstellen.

    Auf Windows: Gibt erkannte Adapter zurueck.
    """
    if IS_WINDOWS:
        return [iface for iface in get_network_interfaces()
                if 'ethernet' in iface.lower() or 'eth' in iface.lower()]
    interfaces = []
    try:
        net_path = '/sys/class/net'
        if os.path.exists(net_path):
            for name in os.listdir(net_path):
                if name == 'lo':
                    continue
                type_path = os.path.join(net_path, name, 'type')
                if os.path.exists(type_path):
                    with open(type_path, 'r') as f:
                        if f.read().strip() == '1':  # ARPHRD_ETHER
                            interfaces.append(name)
    except OSError:
        pass
    if not interfaces:
        interfaces = ['eth0']
    return interfaces


def get_interface_mac(iface: str) -> Optional[str]:
    """Liest die MAC-Adresse eines Netzwerk-Interfaces.

    Returns:
        MAC-Adresse als 'XX:XX:XX:XX:XX:XX' oder None.
    """
    if IS_WINDOWS:
        try:
            import psutil
            addrs = psutil.net_if_addrs().get(iface, [])
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    mac = addr.address.upper().replace('-', ':')
                    if len(mac) == 17:
                        return mac
        except Exception:
            pass
        return None
    mac_path = f'/sys/class/net/{iface}/address'
    try:
        with open(mac_path, 'r') as f:
            mac = f.read().strip().upper()
            if len(mac) == 17:
                return mac
    except OSError:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════════
# 5. Netzwerk-Statistiken
# ═══════════════════════════════════════════════════════════════════════════

def get_net_io_counters() -> Dict[str, Tuple[int, int]]:
    """Gibt pro Interface (rx_bytes, tx_bytes) zurueck.

    Liest /proc/net/dev (Linux) oder psutil (Windows).
    """
    if IS_WINDOWS:
        try:
            import psutil
            counters = psutil.net_io_counters(pernic=True)
            return {name: (c.bytes_recv, c.bytes_sent)
                    for name, c in counters.items()}
        except ImportError:
            return {}
    result: Dict[str, Tuple[int, int]] = {}
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()
        for line in lines[2:]:
            line = line.strip()
            if ':' not in line:
                continue
            iface, stats = line.split(':', 1)
            iface = iface.strip()
            parts = stats.split()
            if len(parts) >= 9:
                rx_bytes = int(parts[0])
                tx_bytes = int(parts[8])
                result[iface] = (rx_bytes, tx_bytes)
    except (OSError, ValueError):
        pass
    return result


# ═══════════════════════════════════════════════════════════════════════════
# 6. ARP-Cache
# ═══════════════════════════════════════════════════════════════════════════

def resolve_mac_from_arp(ip: str) -> str:
    """Versucht die MAC-Adresse aus dem ARP-Cache aufzuloesen.

    Returns:
        MAC-Adresse oder '—'.
    """
    if IS_WINDOWS:
        try:
            out = subprocess.check_output(
                ['arp', '-a', ip], text=True, timeout=5,
                creationflags=subprocess_creation_flags())
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    mac = parts[1].upper().replace('-', ':')
                    if mac != '00:00:00:00:00:00':
                        return mac
        except Exception:
            pass
        return '—'
    try:
        with open('/proc/net/arp', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3].upper()
                    if mac != '00:00:00:00:00:00':
                        return mac
    except Exception:
        pass
    return '—'


# ═══════════════════════════════════════════════════════════════════════════
# 7. Broadcast-Adressen
# ═══════════════════════════════════════════════════════════════════════════

def get_broadcast_addresses() -> List[str]:
    """Ermittelt Broadcast-Adressen aller Interfaces."""
    if IS_WINDOWS:
        try:
            import psutil
            addrs = []
            for name, ifaddrs in psutil.net_if_addrs().items():
                for addr in ifaddrs:
                    if addr.family == socket.AF_INET and addr.broadcast:
                        addrs.append(addr.broadcast)
            return addrs
        except ImportError:
            pass
        return ['255.255.255.255']
    addrs = []
    try:
        out = subprocess.check_output(
            ['ip', '-4', 'addr', 'show'], text=True, timeout=3)
        for line in out.splitlines():
            line = line.strip()
            if line.startswith('inet ') and 'brd' in line:
                parts = line.split()
                try:
                    brd_idx = parts.index('brd')
                    brd = parts[brd_idx + 1]
                    if brd != '255.255.255.255':
                        addrs.append(brd)
                except (ValueError, IndexError):
                    pass
    except Exception:
        pass
    return addrs


# ═══════════════════════════════════════════════════════════════════════════
# 8. Sockets (CAN / Raw Ethernet)
# ═══════════════════════════════════════════════════════════════════════════

# Pruefe ob Linux-Socket-Familien verfuegbar sind
CAN_AVAILABLE = hasattr(socket, 'AF_CAN')
RAW_ETH_AVAILABLE = hasattr(socket, 'AF_PACKET')

# CAN-Konstanten (Linux SocketCAN)
AF_CAN = getattr(socket, 'AF_CAN', 29)
CAN_RAW = getattr(socket, 'CAN_RAW', 1)
CAN_EFF_FLAG = 0x80000000
CAN_MTU = 16
CANFD_MTU = 72
SOL_CAN_RAW = 101
CAN_RAW_FD_FRAMES = 5


def create_can_socket() -> socket.socket:
    """Erstellt einen SocketCAN-Raw-Socket.

    Raises:
        OSError: Auf Windows oder wenn AF_CAN nicht verfuegbar ist.
    """
    if IS_WINDOWS or not CAN_AVAILABLE:
        raise OSError(
            "SocketCAN ist auf diesem System nicht verfuegbar. "
            "Bitte python-can mit PCAN-Treiber verwenden."
        )
    return socket.socket(AF_CAN, socket.SOCK_RAW, CAN_RAW)


def create_raw_eth_socket() -> socket.socket:
    """Erstellt einen Raw-Ethernet-Socket (AF_PACKET).

    Raises:
        OSError: Auf Windows oder wenn AF_PACKET nicht verfuegbar ist.
    """
    if IS_WINDOWS or not RAW_ETH_AVAILABLE:
        raise OSError(
            "Raw-Ethernet-Sockets (AF_PACKET) sind auf diesem System nicht verfuegbar. "
            "Bitte Npcap installieren und Scapy/WinPcap verwenden."
        )
    return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))


def get_can_bustype() -> str:
    """Gibt den python-can Bustype fuer die aktuelle Plattform zurueck."""
    if IS_WINDOWS:
        return 'pcan'
    return 'socketcan'


# ═══════════════════════════════════════════════════════════════════════════
# 9. Capture-Rechte
# ═══════════════════════════════════════════════════════════════════════════

def needs_capture_permission_setup() -> bool:
    """Prueft ob eine Capture-Berechtigung eingerichtet werden muss."""
    if IS_WINDOWS:
        # Unter Windows: Npcap muss installiert sein
        return not Path(r'C:\Windows\System32\Npcap').exists()
    return True  # Linux braucht CAP_NET_RAW


def setup_capture_permissions_command() -> Optional[str]:
    """Gibt den Befehl zurueck, um Capture-Berechtigungen einzurichten.

    Returns:
        Befehl als String oder None (Windows: keine Befehlszeile noetig).
    """
    if IS_WINDOWS:
        return None  # Npcap-Installer muss manuell ausgefuehrt werden
    python_path = os.path.realpath(sys.executable)
    setcap_path = shutil.which('setcap') or '/usr/sbin/setcap'
    return f"{setcap_path} cap_net_raw,cap_net_admin+eip '{python_path}'"


# ═══════════════════════════════════════════════════════════════════════════
# 10. Tool-Erkennung
# ═══════════════════════════════════════════════════════════════════════════

def find_dumpcap() -> Optional[str]:
    """Sucht den Pfad zu dumpcap/dumpcap.exe."""
    if IS_WINDOWS:
        # Standard-Installationspfade
        for prog_dir in [
            Path(os.environ.get('ProgramFiles', r'C:\Program Files')),
            Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')),
        ]:
            p = prog_dir / 'Wireshark' / 'dumpcap.exe'
            if p.exists():
                return str(p)
        return shutil.which('dumpcap')
    if IS_WSL:
        # WSL2: dumpcap.exe auf der Windows-Seite
        wsl_path = '/mnt/c/Program Files/Wireshark/dumpcap.exe'
        if os.path.isfile(wsl_path):
            return wsl_path
    return shutil.which('dumpcap')


def find_ffmpeg() -> Optional[str]:
    """Sucht den Pfad zu ffmpeg."""
    found = shutil.which('ffmpeg')
    if found:
        return found
    if IS_WINDOWS:
        for prog_dir in [
            Path(os.environ.get('ProgramFiles', r'C:\Program Files')),
            Path(os.environ.get('LOCALAPPDATA', '')),
        ]:
            for sub in ['ffmpeg/bin', 'ffmpeg']:
                p = prog_dir / sub / 'ffmpeg.exe'
                if p.exists():
                    return str(p)
    return None


def find_vlc() -> Optional[str]:
    """Sucht den Pfad zu VLC."""
    if IS_WINDOWS:
        for prog_dir in [
            Path(os.environ.get('ProgramFiles', r'C:\Program Files')),
            Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')),
        ]:
            p = prog_dir / 'VideoLAN' / 'VLC' / 'vlc.exe'
            if p.exists():
                return str(p)
        return shutil.which('vlc')
    found = shutil.which('vlc')
    if found:
        return found
    # Pruefe ob vlc --version funktioniert
    try:
        result = subprocess.run(
            ['vlc', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            return 'vlc'
    except Exception:
        pass
    return None


def find_lua() -> Optional[str]:
    """Sucht den Pfad zu einem Lua-Interpreter."""
    for name in ['lua5.4', 'lua5.3', 'lua']:
        found = shutil.which(name)
        if found:
            return found
    if IS_WINDOWS:
        for prog_dir in [
            Path(os.environ.get('ProgramFiles', r'C:\Program Files')),
        ]:
            for ver in ['lua54', 'lua53', 'lua']:
                p = prog_dir / ver / 'lua.exe'
                if p.exists():
                    return str(p)
    return None


def find_docker() -> Optional[str]:
    """Sucht den Pfad zu Docker."""
    found = shutil.which('docker')
    if found:
        return found
    if IS_WINDOWS:
        p = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) \
            / 'Docker' / 'Docker' / 'resources' / 'bin' / 'docker.exe'
        if p.exists():
            return str(p)
    elif IS_WSL:
        p = '/mnt/c/Program Files/Docker/Docker/resources/bin/docker.exe'
        if os.path.isfile(p):
            return p
    return 'docker'  # Fallback


# ═══════════════════════════════════════════════════════════════════════════
# 11. Installationshinweise
# ═══════════════════════════════════════════════════════════════════════════

_INSTALL_HINTS = {
    'libportaudio2': {
        'linux': 'sudo apt install libportaudio2',
        'windows': 'PortAudio wird mit sounddevice mitgeliefert (pip install sounddevice)',
    },
    'lua5.4': {
        'linux': 'sudo apt install lua5.4',
        'windows': 'Lua von https://github.com/rjpcomputing/luaforwindows herunterladen',
    },
    'python3-tk': {
        'linux': 'sudo apt install python3-tk',
        'windows': 'tkinter ist in der Standard-Python-Installation fuer Windows enthalten',
    },
    'npcap': {
        'linux': 'Nicht erforderlich unter Linux (CAP_NET_RAW genuegt)',
        'windows': 'Npcap von https://npcap.com herunterladen und installieren',
    },
}


def install_hint(package: str) -> str:
    """Gibt einen plattformspezifischen Installationshinweis zurueck."""
    hints = _INSTALL_HINTS.get(package, {})
    if IS_WINDOWS:
        return hints.get('windows', f'Bitte {package} installieren')
    return hints.get('linux', f'sudo apt install {package}')


# ═══════════════════════════════════════════════════════════════════════════
# 12. Qt-Plattform
# ═══════════════════════════════════════════════════════════════════════════

def setup_qt_platform() -> None:
    """Konfiguriert die Qt-Plattform-Umgebung.

    Linux/WSL: Laedt libxcb-cursor und setzt QT_QPA_PLATFORM=xcb.
    Windows: Keine spezielle Konfiguration noetig.
    """
    if IS_WINDOWS:
        return

    # libxcb-cursor vorab laden (Qt >= 6.5 benoetigt es fuer das xcb-Plugin)
    try:
        ctypes.cdll.LoadLibrary('libxcb-cursor.so.0')
    except OSError:
        # Versuche aus dem PyQt6-Verzeichnis zu laden
        base = Path(__file__).parent.parent
        qt6_lib = base / 'venv' / 'lib' / 'python3.12' / 'site-packages' \
            / 'PyQt6' / 'Qt6' / 'lib'
        lib_path = qt6_lib / 'libxcb-cursor.so.0'
        if lib_path.is_file():
            try:
                ctypes.cdll.LoadLibrary(str(lib_path))
            except OSError:
                pass

    os.environ.setdefault('QT_QPA_PLATFORM', 'xcb')
    # WSLg meldet 3840x2160 Root-Fenster, aber XWayland arbeitet mit 1920x1080
    os.environ.setdefault('XCURSOR_SIZE', '24')


def subprocess_creation_flags() -> int:
    """Gibt CREATE_NO_WINDOW Flag fuer subprocess zurueck (nur Windows).

    Verhindert, dass Konsolen-Fenster aufpoppen.
    Auf Linux: gibt 0 zurueck.
    """
    if IS_WINDOWS:
        return 0x08000000  # CREATE_NO_WINDOW
    return 0
