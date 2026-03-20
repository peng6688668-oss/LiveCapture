"""TX Template Manager — Speichert und laedt TX-Konfigurationen als JSON.

Jedes Template enthaelt:
  - name: Anzeigename
  - bus_type: 'CAN' oder 'LIN'
  - frames: Liste von {id, dlc, data, cycle_ms, extended, fd}
"""

import json
import logging
import os
from typing import Dict, List, Optional

from PyQt6.QtCore import QSettings

_log = logging.getLogger(__name__)

_TEMPLATE_DIR_KEY = 'tx_templates/directory'
_DEFAULT_DIR = os.path.expanduser('~/.config/livecapture/tx_templates')


def _ensure_dir():
    """Stellt sicher, dass das Template-Verzeichnis existiert."""
    d = QSettings('ViGEM', 'LiveCapture').value(
        _TEMPLATE_DIR_KEY, _DEFAULT_DIR)
    os.makedirs(d, exist_ok=True)
    return d


def list_templates(bus_type: str) -> List[Dict]:
    """Gibt alle Templates fuer einen Bus-Typ zurueck."""
    d = _ensure_dir()
    templates = []
    prefix = f"{bus_type.lower()}_"
    for fname in sorted(os.listdir(d)):
        if fname.startswith(prefix) and fname.endswith('.json'):
            path = os.path.join(d, fname)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    tpl = json.load(f)
                tpl['_path'] = path
                templates.append(tpl)
            except Exception as e:
                _log.debug("Template %s nicht lesbar: %s", fname, e)
    return templates


def save_template(bus_type: str, name: str,
                  frames: List[Dict]) -> str:
    """Speichert ein Template und gibt den Dateipfad zurueck."""
    d = _ensure_dir()
    safe_name = ''.join(c if c.isalnum() or c in '_-' else '_' for c in name)
    fname = f"{bus_type.lower()}_{safe_name}.json"
    path = os.path.join(d, fname)

    tpl = {
        'name': name,
        'bus_type': bus_type,
        'frames': frames,
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(tpl, f, indent=2, ensure_ascii=False)
    _log.info("Template gespeichert: %s", path)
    return path


def load_template(path: str) -> Optional[Dict]:
    """Laedt ein Template aus einer Datei."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        _log.error("Template laden fehlgeschlagen: %s", e)
        return None


def delete_template(path: str) -> bool:
    """Loescht ein Template."""
    try:
        os.remove(path)
        _log.info("Template geloescht: %s", path)
        return True
    except Exception as e:
        _log.error("Template loeschen fehlgeschlagen: %s", e)
        return False
