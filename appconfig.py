"""Persistente Laufzeit-Einstellungen (Modell, Uhrzeit).
Prioritaet: settings.json (persistent) > ENV > Default.
"""
import json
import os
import threading

SETTINGS_PATH = os.getenv("SETTINGS_PATH", "/data/settings.json")
_lock = threading.Lock()

# Schluessel, die ueber die GUI editierbar sind
_EDITABLE = ("ollama_model", "report_schedule", "llm_base_url", "abuseipdb_key",
             "searxng_url", "llm_prompt_template",
             "log_source",
             "graylog_host", "graylog_port", "graylog_user", "graylog_password",
             "smtp_host", "smtp_port", "smtp_user", "smtp_password",
             "smtp_security", "smtp_from", "email_to", "email_subject",
             "unifi_block_enabled", "unifi_dry_run", "unifi_host",
             "unifi_api_key", "unifi_block_threshold", "unifi_allowlist")

# Hinweis: settings.json liegt unverschluesselt auf Platte (gleiches Muster wie
# schon immer bei unifi_api_key). Fuer einen reinen Homelab-Container mit
# eingeschraenktem Host-Zugriff ist das ein bewusster, dokumentierter Trade-off.
_DEFAULTS = {
    "ollama_model": os.getenv("OLLAMA_MODEL", "gemma4:12b"),
    "report_schedule": os.getenv("REPORT_SCHEDULE", "08:00"),
    "llm_base_url": os.getenv("LLM_BASE_URL", os.getenv("LM_STUDIO_BASE_URL", "http://lm-studio:1234/v1")),
    "abuseipdb_key": os.getenv("ABUSEIPDB_KEY", ""),
    "searxng_url": os.getenv("SEARXNG_URL", ""),
    "llm_prompt_template": os.getenv("LLM_PROMPT_TEMPLATE", ""),
    "log_source": os.getenv("LOG_SOURCE", "graylog"),
    "graylog_host": os.getenv("GRAYLOG_HOST", "graylog"),
    "graylog_port": os.getenv("GRAYLOG_PORT", "9000"),
    "graylog_user": os.getenv("GRAYLOG_USER", "admin"),
    "graylog_password": os.getenv("GRAYLOG_PASSWORD", "admin"),
    "smtp_host": os.getenv("SMTP_HOST", ""),
    "smtp_port": int(os.getenv("SMTP_PORT", "465")),
    "smtp_user": os.getenv("SMTP_USER", ""),
    "smtp_password": os.getenv("SMTP_PASSWORD", ""),
    "smtp_security": os.getenv("SMTP_SECURITY", "ssl"),
    "smtp_from": os.getenv("SMTP_FROM", ""),
    "email_to": os.getenv("EMAIL_TO", ""),
    "email_subject": os.getenv("EMAIL_SUBJECT", ""),
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
