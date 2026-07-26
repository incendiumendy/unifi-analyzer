"""Persistente Laufzeit-Einstellungen (Modell, Uhrzeit).
Prioritaet: settings.json (persistent) > ENV > Default.
"""
import json
import os
import threading

SETTINGS_PATH = os.getenv("SETTINGS_PATH", "/data/settings.json")
_lock = threading.Lock()

# Schluessel, die ueber die GUI editierbar sind
_EDITABLE = ("ollama_model", "report_schedule",
             "unifi_block_enabled", "unifi_dry_run", "unifi_host",
             "unifi_api_key", "unifi_block_threshold", "unifi_allowlist")

_DEFAULTS = {
    "ollama_model": os.getenv("OLLAMA_MODEL", "gemma4:12b"),
    "report_schedule": os.getenv("REPORT_SCHEDULE", "08:00"),
    "unifi_block_enabled": os.getenv("UNIFI_BLOCK_ENABLED", "") in ("1", "true", "True", "on"),
    "unifi_dry_run": os.getenv("UNIFI_DRY_RUN", "1") in ("1", "true", "True", "on"),
    "unifi_host": os.getenv("UNIFI_HOST", "https://192.168.1.1"),
    "unifi_api_key": os.getenv("UNIFI_API_KEY", ""),
    "unifi_block_threshold": int(os.getenv("UNIFI_BLOCK_THRESHOLD", "95")),
    "unifi_allowlist": os.getenv("UNIFI_ALLOWLIST", ""),
}


def _read_file():
    try:
        with open(SETTINGS_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load():
    data = dict(_DEFAULTS)
    for k, v in _read_file().items():
        if k not in _EDITABLE:
            continue
        if isinstance(v, bool) or isinstance(v, int):
            data[k] = v
        elif v not in (None, ""):
            data[k] = v
    return data


def get(key):
    return load().get(key)


def save(updates):
    """Speichert nur erlaubte Keys, validiert und schreibt atomar."""
    cur = _read_file()
    for k, v in updates.items():
        if k not in _EDITABLE:
            continue
        if isinstance(v, bool) or isinstance(v, int):
            cur[k] = v
        elif v:
            cur[k] = v
    with _lock:
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        tmp = SETTINGS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cur, f, indent=2)
        os.replace(tmp, SETTINGS_PATH)
    return load()
