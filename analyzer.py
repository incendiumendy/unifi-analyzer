#!/usr/bin/env python3
"""
UniFi Log Analyzer – analysiert UniFi-Netzwerk-Logs (via Graylog oder direkt
vom Controller) mit einem lokalen/entfernten LLM (OpenAI-kompatible API) und
verschickt den Bericht per E-Mail. Alle Zugangsdaten sind unabhaengig von
Drittsystemen ueber die GUI konfigurierbar (appconfig.py / settings.json).
"""

import os
import re
import time
import json
import calendar
import smtplib
import logging
import requests
import schedule
import webui
import appconfig
import unifi_block
import llm_pool
from string import Template
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

HEADERS          = {"X-Requested-By": "unifi-analyzer", "Accept": "application/json"}
REPORT_SCHEDULE  = os.getenv("REPORT_SCHEDULE", "08:00")


# ── Live-Konfiguration (GUI-editierbar, appconfig.py) ────────────────────────
def _graylog_base():
    cfg = appconfig.load()
    return f"http://{cfg['graylog_host']}:{cfg['graylog_port']}/api"


def _graylog_auth():
    cfg = appconfig.load()
    return (cfg["graylog_user"], cfg["graylog_password"])


def get_llm_base_url():
    return (appconfig.get("llm_base_url") or "http://lm-studio:1234/v1").rstrip("/")


def get_abuseipdb_key():
    return appconfig.get("abuseipdb_key") or ""


def get_searxng_url():
    return (appconfig.get("searxng_url") or "").rstrip("/")


def get_email_to():
    return appconfig.get("email_to") or ""


def get_llm_timeout():
    """Sekunden, die auf die LLM-Antwort gewartet wird. Lokale CPU-Inferenz braucht
    fuer einen ausfuehrlichen Bericht deutlich laenger als eine GPU/Cloud-API."""
    try:
        return max(30, int(appconfig.get("llm_timeout") or 600))
    except (TypeError, ValueError):
        return 600


def get_llm_max_tokens():
    try:
        return max(256, int(appconfig.get("llm_max_tokens") or 4096))
    except (TypeError, ValueError):
        return 4096


def get_llm_unload_after():
    """Ob das Modell nach der Analyse wieder entladen werden soll. Betrifft nur
    Modelle, die der Analyzer selbst geladen hat - siehe llm_pool.chat()."""
    val = appconfig.get("llm_unload_after")
    return bool(val) if isinstance(val, bool) else str(val).lower() in ("1", "true", "on", "yes")


def get_llm_endpoints():
    """Fallback-Kette als Liste. Ist nichts gepflegt, wird die klassische
    Einzelkonfiguration (llm_base_url + ollama_model) als einziger Endpunkt
    benutzt - so laufen bestehende Installationen unveraendert weiter."""
    raw = appconfig.get("llm_endpoints") or "[]"
    try:
        items = json.loads(raw) if isinstance(raw, str) else list(raw)
    except Exception:
        log.warning("llm_endpoints ist kein gueltiges JSON - benutze Einzelkonfiguration.")
        items = []
    out = []
    for i, it in enumerate(items if isinstance(items, list) else []):
        if not isinstance(it, dict):
            continue
        base = (it.get("base_url") or "").strip()
        model = (it.get("model") or "").strip()
        if not base or not model:
            continue
        out.append({"name": (it.get("name") or f"Endpunkt {i + 1}").strip(),
                    "base_url": base, "model": model})
    if out:
        return out
    return [{"name": "Standard", "base_url": get_llm_base_url(), "model": get_active_model()}]


# Standard-Prompts und -Betreff (GUI-editierbar via appconfig, Platzhalter im
# $name-Format via string.Template; safe_substitute ignoriert unbekannte
# Platzhalter, damit ein individuell angepasstes Template nie einen Absturz
# verursacht). Jeweils auf Deutsch und Englisch vorhanden, siehe
# get_report_language()/PROMPT_PRESETS - die "STATUS: ..."-Zeile wird in
# beiden Sprachen von parse_ampel() erkannt.
DEFAULT_PROMPT_TEMPLATE_DE = """Du bist ein Netzwerk-Sicherheitsexperte und analysierst UniFi-Netzwerk-Logs.

Analysiere die folgenden Log-Daten und erstelle einen strukturierten deutschen Bericht in GENAU
diesem Format (Reihenfolge und Ueberschriften exakt so beibehalten):

STATUS: <GRUEN|GELB|ROT>

## Kurzfassung
2-3 Saetze Gesamtueberblick ueber die letzten 24 Stunden - das Wichtigste zuerst.

## Auffaelligkeiten & Warnungen
Kritische Ereignisse, Fehler, ungewoehnliche Muster.

## Sicherheitsrelevantes
Login-Versuche, Port-Scans, verdaechtige IPs, Verbindungsabbrueche.

## Netzwerkleistung
Verbindungsqualitaet, Latenz-Probleme, Geraeteausfaelle.

## Empfehlungen
Konkrete Massnahmen basierend auf den Logs.

Wichtig: Die allererste Zeile MUSS exakt "STATUS: GRUEN", "STATUS: GELB" oder "STATUS: ROT" sein
(GRUEN = alles normal, GELB = Achtung/Beobachten, ROT = kritisch/sofort handeln).

${threat_intel}${research}LOG-DATEN (letzte 24 Stunden):
${log_text}

Erstelle den Bericht auf Deutsch, exakt im obigen Format:"""

PROMPT_TEMPLATE_KURZ_DE = """Du bist ein Netzwerk-Sicherheitsexperte. Analysiere die folgenden UniFi-Netzwerk-Logs und
erstelle einen SEHR KURZEN Bericht auf Deutsch.

Die allererste Zeile MUSS exakt "STATUS: GRUEN", "STATUS: GELB" oder "STATUS: ROT" sein
(GRUEN = alles normal, GELB = Achtung, ROT = kritisch).

Danach in maximal 4-5 Saetzen als Fliesstext (keine Ueberschriften, keine Aufzaehlungen):
Was ist passiert, gibt es Sicherheitsprobleme, was sollte der Nutzer tun (falls ueberhaupt
etwas noetig ist). Nur das Wichtigste - kein Rauschen.

${threat_intel}${research}LOG-DATEN (letzte 24 Stunden):
${log_text}

Kurzbericht auf Deutsch:"""

PROMPT_TEMPLATE_TECHNISCH_DE = """Du bist ein Senior-Netzwerk-Sicherheitsanalyst und erstellst einen technischen
Detailbericht fuer IT-Administratoren auf Deutsch.

Die allererste Zeile MUSS exakt "STATUS: GRUEN", "STATUS: GELB" oder "STATUS: ROT" sein
(GRUEN = alles normal, GELB = Achtung/Beobachten, ROT = kritisch/sofort handeln).

Erstelle danach einen detaillierten Bericht mit folgenden Abschnitten (Ueberschriften exakt
so beibehalten):

## Kurzfassung
## Zeitachse auffaelliger Ereignisse
Liste chronologisch die wichtigsten Ereignisse mit Zeitstempel, betroffenem Geraet/IP und
Einschaetzung.
## Sicherheitsanalyse
Detaillierte Analyse aller sicherheitsrelevanten Eintraege: Quelle, Ziel, Port/Protokoll
(soweit erkennbar), Angriffsmuster, betroffene IPs mit Reputationsdaten.
## Netzwerkleistung & Stabilitaet
Verbindungsabbrueche, Roaming-Probleme, Bandbreitenauffaelligkeiten, betroffene Geraete.
## Technische Empfehlungen
Konkrete, priorisierte Massnahmen (Sofortmassnahmen vs. mittelfristig).
## Offene Fragen / Unklarheiten
Was aus den Logs nicht eindeutig hervorgeht und manuell geprueft werden sollte.

${threat_intel}${research}LOG-DATEN (letzte 24 Stunden):
${log_text}

Erstelle den technischen Bericht auf Deutsch:"""

DEFAULT_PROMPT_TEMPLATE_EN = """You are a network security expert analyzing UniFi network logs.

Analyze the following log data and produce a structured report in EXACTLY this
format (keep the order and headings exactly as shown):

STATUS: <GREEN|YELLOW|RED>

## Summary
2-3 sentences overview of the last 24 hours - the most important points first.

## Issues & Warnings
Critical events, errors, unusual patterns.

## Security
Login attempts, port scans, suspicious IPs, connection drops.

## Network Performance
Connection quality, latency issues, device outages.

## Recommendations
Concrete actions based on the logs.

Important: the very first line MUST be exactly "STATUS: GREEN", "STATUS: YELLOW", or "STATUS: RED"
(GREEN = all normal, YELLOW = attention/monitor, RED = critical/act immediately).

${threat_intel}${research}LOG DATA (last 24 hours):
${log_text}

Write the report in English, exactly in the format above:"""

PROMPT_TEMPLATE_KURZ_EN = """You are a network security expert. Analyze the following UniFi network logs and
write a VERY SHORT report in English.

The very first line MUST be exactly "STATUS: GREEN", "STATUS: YELLOW", or "STATUS: RED"
(GREEN = all normal, YELLOW = attention, RED = critical).

Then, in at most 4-5 sentences of plain prose (no headings, no bullet points):
what happened, are there any security issues, what should the user do (if
anything at all). Only the essentials - no noise.

${threat_intel}${research}LOG DATA (last 24 hours):
${log_text}

Short report in English:"""

PROMPT_TEMPLATE_TECHNISCH_EN = """You are a senior network security analyst producing a technical detail report
for IT administrators in English.

The very first line MUST be exactly "STATUS: GREEN", "STATUS: YELLOW", or "STATUS: RED"
(GREEN = all normal, YELLOW = attention/monitor, RED = critical/act immediately).

Then produce a detailed report with the following sections (keep the headings
exactly as shown):

## Summary
## Timeline of Notable Events
List the most important events chronologically with timestamp, affected device/IP,
and assessment.
## Security Analysis
Detailed analysis of all security-relevant entries: source, destination, port/protocol
(where identifiable), attack patterns, affected IPs with reputation data.
## Network Performance & Stability
Connection drops, roaming issues, bandwidth anomalies, affected devices.
## Technical Recommendations
Concrete, prioritized actions (immediate vs. medium-term).
## Open Questions / Uncertainties
What isn't clear from the logs and should be checked manually.

${threat_intel}${research}LOG DATA (last 24 hours):
${log_text}

Write the technical report in English:"""

# Eingebaute Prompt-Vorlagen, in der GUI ueber ein Dropdown auswaehlbar (nicht
# loeschbar/veraenderbar - eigene Vorlagen landen stattdessen in der Prompt-
# Bibliothek, siehe get_prompt_library()). Nach Sprache gruppiert; welche
# Sprache als Standard (unkonfiguriertes Template) verwendet wird, steuert
# get_report_language()/report_language in der GUI.
PROMPT_PRESETS = {
    "de": {
        "standard":  {"label": "Standard (ausfuehrlich)", "template": DEFAULT_PROMPT_TEMPLATE_DE},
        "kurz":      {"label": "Kurzbericht", "template": PROMPT_TEMPLATE_KURZ_DE},
        "technisch": {"label": "Technisch / Detailliert", "template": PROMPT_TEMPLATE_TECHNISCH_DE},
    },
    "en": {
        "standard":  {"label": "Standard (detailed)", "template": DEFAULT_PROMPT_TEMPLATE_EN},
        "kurz":      {"label": "Short report", "template": PROMPT_TEMPLATE_KURZ_EN},
        "technisch": {"label": "Technical / Detailed", "template": PROMPT_TEMPLATE_TECHNISCH_EN},
    },
}

_DEFAULT_EMAIL_SUBJECT = {
    "de": "UniFi Netzwerk-Analyse - $date",
    "en": "UniFi Network Analysis - $date",
}

# Feste Textbausteine rund um den Bericht (E-Mail-Kopfzeilen, Ampel-Label),
# unabhaengig vom frei editierbaren Prompt-Text - siehe send_email_report().
_EMAIL_CHROME = {
    "de": {"title": "UniFi Netzwerk-Analyse", "date": "Datum", "model": "Modell",
           "period": "Analysezeitraum", "last24h": "Letzte 24 Stunden", "status": "Status",
           "unknown": "Unbekannt", "footer": "Automatisch generiert von UniFi-Analyzer"},
    "en": {"title": "UniFi Network Analysis", "date": "Date", "model": "Model",
           "period": "Analysis period", "last24h": "Last 24 hours", "status": "Status",
           "unknown": "Unknown", "footer": "Automatically generated by UniFi-Analyzer"},
}

_AMPEL_LABELS = {
    "de": {"gruen": ("Normal", "#2e7d32"), "gelb": ("Achtung", "#f9a825"), "rot": ("Kritisch", "#c62828")},
    "en": {"gruen": ("Normal", "#2e7d32"), "gelb": ("Attention", "#f9a825"), "rot": ("Critical", "#c62828")},
}

# E-Mail-Farbschemata. "auto" folgt der Systemeinstellung des Mail-Clients
# (prefers-color-scheme, nicht von allen Clients unterstuetzt); "light"/"dark"
# erzwingen ein festes Schema unabhaengig vom Client.
_EMAIL_PALETTES = {
    "light": {"bg": "#ffffff", "text": "#333333", "accent": "#1a73e8",
              "meta_bg": "#f5f5f5", "footer_text": "#888888", "footer_border": "#dddddd"},
    "dark": {"bg": "#2a2d35", "text": "#d7dbe0", "accent": "#7fb0e6",
             "meta_bg": "#34383f", "footer_text": "#9aa1a8", "footer_border": "#454952"},
}

_PALETTE_CSS_TEMPLATE = Template("""
  body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; color: $text; background: $bg; }
  h2 { color: $accent; border-bottom: 2px solid $accent; padding-bottom: 8px; }
  h3 { color: $accent; margin-top: 22px; margin-bottom: 6px; }
  .meta { background: $meta_bg; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-size: 13px; }
  .footer { margin-top: 30px; font-size: 12px; color: $footer_text; border-top: 1px solid $footer_border; padding-top: 10px; }
""")

_DARK_MEDIA_TEMPLATE = Template("""
  @media (prefers-color-scheme: dark) {
    body { background: $bg !important; color: $text !important; }
    h2, h3 { color: $accent !important; border-bottom-color: $accent !important; }
    .meta { background: $meta_bg !important; }
    .footer { color: $footer_text !important; border-top-color: $footer_border !important; }
  }
""")


def get_email_theme():
    theme = (appconfig.get("email_theme") or "auto").lower()
    return theme if theme in ("auto", "light", "dark") else "auto"


def get_report_language():
    lang = (appconfig.get("report_language") or "de").lower()
    return lang if lang in ("de", "en") else "de"


def get_prompt_template():
    return appconfig.get("llm_prompt_template") or PROMPT_PRESETS[get_report_language()]["standard"]["template"]


def get_email_subject_template():
    return appconfig.get("email_subject") or _DEFAULT_EMAIL_SUBJECT[get_report_language()]


def get_prompt_library():
    """Eigene, vom Nutzer gespeicherte Prompt-Vorlagen ({name: text})."""
    try:
        return json.loads(appconfig.get("llm_prompt_library") or "{}")
    except Exception:
        return {}


def manage_prompt_library(action, name, content=""):
    """Fuegt eine eigene Prompt-Vorlage hinzu/aktualisiert sie oder loescht sie."""
    name = (name or "").strip()
    if not name:
        return get_prompt_library()
    lib = get_prompt_library()
    if action == "delete":
        lib.pop(name, None)
    else:
        lib[name] = content
    appconfig.save({"llm_prompt_library": json.dumps(lib, ensure_ascii=False)})
    return lib


def probe_llm_endpoints():
    """Statusbild aller konfigurierten Endpunkte fuer die GUI: erreichbar,
    erkannte Backend-Art, ob das Modell geladen ist und ob gerade gerechnet wird."""
    return [llm_pool.probe(ep) for ep in get_llm_endpoints()]


def test_llm_connection(base_url=None):
    """Prueft die Verbindung zum LLM-Endpoint und liefert die verfuegbaren Modelle."""
    base = (base_url or get_llm_base_url() or "").rstrip("/")
    if not base:
        return {"ok": False, "models": [], "message": "Kein LLM-Endpoint angegeben."}
    try:
        r = requests.get(f"{base}/models", timeout=10)
        r.raise_for_status()
        models = sorted([m.get("id") for m in r.json().get("data", []) if m.get("id")])
        return {"ok": True, "models": models,
                "message": f"Verbindung zu {base} erfolgreich - {len(models)} Modell(e) gefunden."}
    except Exception as e:
        return {"ok": False, "models": [], "message": f"Verbindung zu {base} fehlgeschlagen: {e}"}


# ── SMTP-Konfiguration (rein GUI-basiert, kein Drittsystem noetig) ───────────
def get_smtp_config():
    """Liest SMTP-Konfiguration aus den GUI-Einstellungen (appconfig)."""
    cfg = appconfig.load()
    host = (cfg.get("smtp_host") or "").strip()
    user = (cfg.get("smtp_user") or "").strip()
    if not host or not user:
        log.error("Keine SMTP-Konfiguration hinterlegt (siehe GUI unter 'E-Mail / SMTP').")
        return None
    return {
        "host":     host,
        "port":     int(cfg.get("smtp_port") or 465),
        "user":     user,
        "password": cfg.get("smtp_password") or "",
        "security": cfg.get("smtp_security") or "ssl",
        "from":     cfg.get("smtp_from") or user,
    }


# Syslog-Schweregrade (RFC 5424) - Graylog liefert "level" oft als Zahl statt
# als Text, hier auf sprechende Namen abgebildet (u.a. damit research_errors()
# die richtigen Eintraege als "interessant" erkennt).
_SYSLOG_LEVEL_NAMES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "error",
    4: "warn", 5: "notice", 6: "info", 7: "debug",
}


def _normalize_level(raw):
    if isinstance(raw, bool):
        return str(raw)
    if isinstance(raw, int):
        return _SYSLOG_LEVEL_NAMES.get(raw, str(raw))
    if isinstance(raw, str) and raw.strip().isdigit():
        return _SYSLOG_LEVEL_NAMES.get(int(raw.strip()), raw)
    return str(raw or "")


# ── Log-Quelle 1: Graylog ─────────────────────────────────────────────────────
def fetch_logs_from_graylog(hours=24):
    """Holt UniFi-Logs der letzten N Stunden aus Graylog, normalisiert."""
    try:
        params = {
            "query":   "*",
            "range":   hours * 3600,
            "limit":   500,
            "sort":    "timestamp:desc",
            "filter":  "streams:*",
        }
        resp = requests.get(
            f"{_graylog_base()}/search/universal/relative",
            auth=_graylog_auth(),
            headers=HEADERS,
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        raw = data.get("messages", [])
        log.info(f"{len(raw)} Log-Eintraege aus Graylog geladen.")
        out = []
        for m in raw:
            msg = m.get("message", {})
            out.append({
                "timestamp": (msg.get("timestamp") or "")[:19],
                "source":    msg.get("source", "unbekannt"),
                "level":     _normalize_level(msg.get("level", "")),
                "message":   msg.get("message", msg.get("short_message", "")),
            })
        return out
    except Exception as e:
        log.error(f"Fehler beim Abrufen der Graylog-Logs: {e}")
        return []


# ── Log-Quelle 2: UniFi-Controller direkt (Best-Effort) ──────────────────────
def fetch_logs_from_unifi_direct(hours=24):
    """Holt Events/Alarme direkt vom UniFi-Controller (ohne Graylog).

    Nutzt die gleichen unifi_host/unifi_api_key-Einstellungen wie die
    Gateway-IP-Sperrung. Diese Endpunkte gehoeren zur aelteren, nicht offiziell
    dokumentierten Controller-API (nicht Teil der Integration-API v1) und
    koennen je nach Controller-/Firmware-Version abweichen."""
    cfg = appconfig.load()
    host = (cfg.get("unifi_host") or "").strip()
    key = (cfg.get("unifi_api_key") or "").strip()
    if not host or not key:
        log.error("unifi_host/unifi_api_key fehlt – kann Logs nicht direkt vom Controller holen.")
        return []
    try:
        cli = unifi_block.UniFiClient(host, key)
        cli.resolve_site()
        events = cli.get_events(hours=hours)
        alarms = cli.get_alarms(hours=hours)
        log.info(f"{len(events)} Events, {len(alarms)} Alarme direkt vom UniFi-Controller geladen.")

        def _normalize(raw_list, level):
            result = []
            for e in raw_list:
                ts_ms = e.get("time") or e.get("datetime") or 0
                try:
                    ts = datetime.utcfromtimestamp(int(ts_ms) / 1000).strftime("%Y-%m-%dT%H:%M:%S") if ts_ms else ""
                except Exception:
                    ts = ""
                result.append({
                    "timestamp": ts,
                    "source":    e.get("subsystem") or e.get("key") or "unifi",
                    "level":     level,
                    "message":   e.get("msg") or e.get("key") or str(e),
                })
            return result

        return _normalize(events, "event") + _normalize(alarms, "alarm")
    except Exception as e:
        log.error(f"Fehler beim direkten Abruf vom UniFi-Controller: {e}")
        return []


def fetch_logs(hours=24):
    """Dispatcht auf die in der GUI gewaehlte Log-Quelle."""
    source = appconfig.get("log_source") or "graylog"
    if source == "unifi_direct":
        return fetch_logs_from_unifi_direct(hours=hours)
    return fetch_logs_from_graylog(hours=hours)


def format_logs_for_analysis(entries):
    """Formatiert normalisierte Log-Eintraege fuer die LLM-Analyse."""
    if not entries:
        return "Keine Log-Eintraege vorhanden."

    lines = []
    for e in entries[:300]:  # Max 300 Eintraege
        lines.append(f"[{e.get('timestamp','')}] [{e.get('source','unbekannt')}] "
                      f"[{e.get('level','')}] {e.get('message','')}")

    return "\n".join(lines)


# ── Ollama: KI-Analyse ────────────────────────────────────────────────────────
# --- AbuseIPDB: IP-Reputation ---
_PRIV = ("10.", "192.168.", "127.", "169.254.")
def _is_public_ip(ip):
    if ip.startswith(_PRIV):
        return False
    if ip.startswith("172."):
        try:
            return not (16 <= int(ip.split(".")[1]) <= 31)
        except Exception:
            return False
    return True

def extract_public_ips(log_text, limit=5):
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text or "")
    seen = []
    for ip in ips:
        if _is_public_ip(ip) and ip not in seen:
            seen.append(ip)
        if len(seen) >= limit:
            break
    return seen

def check_ip_reputation(ip):
    key = get_abuseipdb_key()
    if not key:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "ip": ip,
            "score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
            "usage": d.get("usageType"),
            "reports": d.get("totalReports", 0),
            "tor": d.get("isTor", False),
        }
    except Exception as e:
        log.error(f"AbuseIPDB-Fehler fuer {ip}: {e}")
        return None

def _run_unifi_block(candidate_ips):
    """Sperrt boesartige IPs am UniFi-Gateway und liefert einen Report-Block."""
    if not candidate_ips:
        return ""
    try:
        cfg = appconfig.load()
        res = unifi_block.block_ips(candidate_ips, cfg)
    except Exception as e:  # noqa
        log.error(f"UniFi-Block-Aufruf fehlgeschlagen: {e}")
        return f"UNIFI-GATEWAY-SPERRUNG: FEHLER ({e})\n\n"
    if not res.get("enabled"):
        return "UNIFI-GATEWAY-SPERRUNG: deaktiviert (in der GUI aktivierbar)\n\n"
    mode = "DRY-RUN (nur Vorschau)" if res.get("dry_run") else "AKTIV"
    out = [f"UNIFI-GATEWAY-SPERRUNG [{mode}], Schwelle Score >= {cfg.get('unifi_block_threshold')}:"]
    if res.get("blocked"):
        verb = "Wuerde sperren" if res.get("dry_run") else "Gesperrt"
        out.append(f"  {verb}: " + ", ".join(res["blocked"]))
    else:
        out.append("  Keine neuen IPs zum Sperren.")
    if res.get("skipped"):
        out.append("  Uebersprungen: " + ", ".join(f"{ip} ({why})" for ip, why in res["skipped"]))
    if res.get("errors"):
        out.append("  Fehler: " + "; ".join(res["errors"]))
    return "\n".join(out) + "\n\n"


def build_threat_intel(log_text):
    if not get_abuseipdb_key():
        return ""
    ips = extract_public_ips(log_text)
    if not ips:
        return ""
    lines = []
    _block_candidates = []
    for ip in ips:
        info = check_ip_reputation(ip)
        if not info:
            continue
        flag = "!! BOESARTIG" if info["score"] >= 50 else ("verdaechtig" if info["score"] >= 25 else "unauffaellig")
        if info["score"] >= int(appconfig.get("unifi_block_threshold") or 95):
            _block_candidates.append(info["ip"])
        lines.append(
            f"- {info['ip']}: AbuseIPDB-Score {info['score']}/100 ({flag}), "
            f"Land {info['country']}, ISP {info['isp']}, {info['reports']} Meldungen"
            + (", TOR-Exit" if info['tor'] else "")
        )
        log.info(f"AbuseIPDB {info['ip']}: Score {info['score']}, {info['reports']} Meldungen")
    if not lines:
        return ""
    intel = "EXTERNE IP-REPUTATION (AbuseIPDB, Live-Abfrage):\n" + "\n".join(lines) + "\n\n"
    intel += _run_unifi_block(_block_candidates)
    return intel


# -- Online-Recherche zu auffaelligen Fehlermeldungen (SearXNG) ---------------
def web_research(query, max_results=3):
    """Fragt eine SearXNG-Instanz ab (muss JSON-Format aktiviert haben,
    siehe SearXNG settings.yml: search.formats: [html, json]).
    Gibt eine kompakte Textzusammenfassung der Top-Treffer zurueck oder ""
    wenn keine SearXNG-URL konfiguriert ist oder die Abfrage fehlschlaegt."""
    base = get_searxng_url()
    if not base:
        return ""
    try:
        r = requests.get(
            f"{base}/search",
            params={"q": query, "format": "json"},
            timeout=10,
        )
        r.raise_for_status()
        results = r.json().get("results", [])[:max_results]
        if not results:
            return ""
        lines = [f"Suche: \"{query}\""]
        for res in results:
            title = (res.get("title") or "").strip()
            content = (res.get("content") or "").strip()
            lines.append(f"  - {title}: {content[:200]}")
        return "\n".join(lines)
    except Exception as e:
        log.warning(f"SearXNG-Recherche fehlgeschlagen ({query}): {e}")
        return ""


def research_errors(entries, max_queries=3):
    """Recherchiert online zu den auffaelligsten Fehler-/Warn-Log-Zeilen
    (nur wenn searxng_url konfiguriert ist). Dedupliziert aehnliche
    Meldungen grob ueber die ersten Worte, um nicht dieselbe Meldung
    mehrfach nachzuschlagen."""
    if not get_searxng_url():
        return ""
    interesting_levels = ("error", "err", "warn", "warning", "alarm", "crit", "critical")
    seen_prefixes = set()
    findings = []
    for e in entries:
        level = str(e.get("level") or "").lower()
        message = (e.get("message") or "").strip()
        if not message or level not in interesting_levels:
            continue
        prefix = " ".join(message.split()[:6]).lower()
        if prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)
        result = web_research(f"UniFi Ubiquiti {message[:120]}")
        if result:
            findings.append(result)
        if len(findings) >= max_queries:
            break
    if not findings:
        return ""
    return "ONLINE-RECHERCHE ZU AUFFAELLIGEN FEHLERN (SearXNG, Best-Effort):\n" + "\n\n".join(findings) + "\n\n"


def analyze_with_llm(log_text, entries=None):
    """Analysiert die Logs mit dem konfigurierten LLM (OpenAI-kompatible API)."""
    if not log_text or log_text == "Keine Log-Eintraege vorhanden.":
        return "STATUS: GRUEN\n\nKeine Logs zum Analysieren vorhanden."

    threat_intel = build_threat_intel(log_text)
    research = research_errors(entries or [])

    prompt = Template(get_prompt_template()).safe_substitute(
        threat_intel=threat_intel, research=research, log_text=log_text[:8000]
    )

    timeout = get_llm_timeout()
    endpoints = get_llm_endpoints()
    started = time.time()

    result, info = llm_pool.chat(
        prompt, endpoints,
        timeout=timeout,
        max_tokens=get_llm_max_tokens(),
        unload_after=get_llm_unload_after(),
    )

    if result:
        log.info(f"Analyse abgeschlossen ueber '{info['endpoint']}' "
                 f"({len(result)} Zeichen, {time.time() - started:.0f}s"
                 f"{', Modell wieder entladen' if info.get('unloaded') else ''}).")
        return result

    # Kein Endpunkt hat geliefert - im Report steht, woran es bei welchem lag.
    details = "\n".join(f"  - {e}" for e in info.get("errors") or []) or "  - keine Endpunkte konfiguriert"
    log.error(f"Kein LLM-Endpunkt hat geantwortet:\n{details}")
    return ("Fehler bei der KI-Analyse: Kein LLM-Endpunkt hat geantwortet.\n\n"
            f"Versuchte Endpunkte:\n{details}\n\n"
            "Moegliche Abhilfe: Timeout erhoehen, 'Max. Antwort-Tokens' reduzieren, "
            "oder einen schnelleren Fallback-Endpunkt eintragen (GUI: 'KI-Modell').")


# ── Ampel-Status parsen (STATUS: GRUEN/GELB/ROT oder GREEN/YELLOW/RED) ───────
# Interne Schluessel bleiben immer "gruen"/"gelb"/"rot", unabhaengig davon, ob
# der Prompt (und damit die LLM-Antwort) auf Deutsch oder Englisch war.
_STATUS_WORD_TO_KEY = {
    "gruen": "gruen", "green": "gruen",
    "gelb": "gelb", "yellow": "gelb",
    "rot": "rot", "red": "rot",
}


def parse_ampel(analysis):
    """Extrahiert die STATUS-Zeile vom Berichtsanfang.
    Gibt (farbschluessel_oder_None, bericht_ohne_status_zeile) zurueck."""
    lines = (analysis or "").splitlines()
    if lines:
        m = re.match(r"^\s*STATUS:\s*(GRUEN|GELB|ROT|GREEN|YELLOW|RED)\s*$", lines[0], re.IGNORECASE)
        if m:
            rest = "\n".join(lines[1:]).lstrip("\n")
            return _STATUS_WORD_TO_KEY[m.group(1).lower()], rest
    return None, analysis


def _markdown_lite_to_html(text):
    """Wandelt die vom LLM erzeugten ## Ueberschriften und **fett** Markierungen
    in einfaches HTML um (kein vollwertiger Markdown-Parser noetig)."""
    out = []
    for line in text.split("\n"):
        line = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
        if line.startswith("## "):
            out.append(f"<h3>{line[3:].strip()}</h3>")
        elif not line.strip():
            out.append("<br>")
        else:
            out.append(line + "<br>")
    return "\n".join(out)


# ── E-Mail senden (SMTP-Config aus der GUI) ──────────────────────────────────
def send_email_report(analysis):
    """Sendet den Analysebericht per E-Mail – SMTP-Config aus der GUI."""
    smtp = get_smtp_config()
    email_to = get_email_to()
    if not smtp or not email_to:
        log.error("SMTP-Konfiguration/Empfaenger fehlt (siehe GUI unter 'E-Mail / SMTP') – E-Mail wird nicht gesendet.")
        return False

    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    subject = Template(get_email_subject_template()).safe_substitute(date=now)

    lang = get_report_language()
    chrome = _EMAIL_CHROME[lang]
    ampel, body = parse_ampel(analysis)
    label, color = _AMPEL_LABELS[lang].get(ampel, (chrome["unknown"], "#757575"))
    html_analysis = _markdown_lite_to_html(body)

    # E-Mail-Design: "auto" folgt der Systemeinstellung des Mail-Clients (Best-
    # Effort, nicht von allen Clients unterstuetzt), "light"/"dark" erzwingen
    # ein festes Schema unabhaengig vom Client.
    theme = get_email_theme()
    base_palette = _EMAIL_PALETTES["dark"] if theme == "dark" else _EMAIL_PALETTES["light"]
    base_css = _PALETTE_CSS_TEMPLATE.safe_substitute(**base_palette)
    if theme == "auto":
        extra_css = _DARK_MEDIA_TEMPLATE.safe_substitute(**_EMAIL_PALETTES["dark"])
        color_scheme = "light dark"
    else:
        extra_css = ""
        color_scheme = theme

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<meta name="color-scheme" content="{color_scheme}">
<meta name="supported-color-schemes" content="{color_scheme}">
<style>
{base_css}
  .ampel {{ display: inline-block; padding: 8px 16px; border-radius: 6px; color: #fff; font-weight: bold; margin-bottom: 20px; background: {color}; }}
  .content {{ line-height: 1.7; }}
{extra_css}
</style>
</head>
<body>
  <h2>{chrome["title"]}</h2>
  <div class="meta">
    <b>{chrome["date"]}:</b> {now} &nbsp;|&nbsp;
    <b>{chrome["model"]}:</b> {get_active_model()} &nbsp;|&nbsp;
    <b>{chrome["period"]}:</b> {chrome["last24h"]}
  </div>
  <div class="ampel">{chrome["status"]}: {label}</div>
  <div class="content">{html_analysis}</div>
  <div class="footer">{chrome["footer"]}</div>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = smtp["from"]
        msg["To"]      = email_to
        msg["Subject"] = subject
        msg.attach(MIMEText(analysis, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        if smtp["security"] == "ssl":
            with smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=30) as server:
                server.login(smtp["user"], smtp["password"])
                server.sendmail(smtp["from"], email_to, msg.as_string())
        elif smtp["security"] == "starttls":
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=30) as server:
                server.starttls()
                server.login(smtp["user"], smtp["password"])
                server.sendmail(smtp["from"], email_to, msg.as_string())
        else:
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=30) as server:
                if smtp["password"]:
                    server.login(smtp["user"], smtp["password"])
                server.sendmail(smtp["from"], email_to, msg.as_string())

        log.info(f"E-Mail-Bericht erfolgreich an {email_to} gesendet.")
        return True
    except Exception as e:
        log.error(f"Fehler beim Senden der E-Mail: {e}")
        return False


# ── Hauptanalyse ──────────────────────────────────────────────────────────────
def get_active_model():
    return appconfig.get("ollama_model") or "gemma4:12b"


def get_active_schedule():
    return appconfig.get("report_schedule") or REPORT_SCHEDULE


# Wochentags-Reihenfolge passend zu datetime.weekday() (Montag=0..Sonntag=6).
_WEEKDAY_ORDER = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_WEEKDAY_LABELS = {
    "de": {"mon": "Montag", "tue": "Dienstag", "wed": "Mittwoch", "thu": "Donnerstag",
           "fri": "Freitag", "sat": "Samstag", "sun": "Sonntag"},
    "en": {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday",
           "fri": "Friday", "sat": "Saturday", "sun": "Sunday"},
}


def get_report_frequency():
    freq = (appconfig.get("report_frequency") or "daily").lower()
    return freq if freq in ("daily", "weekly", "monthly") else "daily"


def get_report_weekday():
    wd = (appconfig.get("report_weekday") or "mon").lower()
    return wd if wd in _WEEKDAY_ORDER else "mon"


def get_report_day_of_month():
    try:
        day = int(appconfig.get("report_day_of_month") or 1)
    except (TypeError, ValueError):
        day = 1
    return max(1, min(31, day))


def _is_due_today(freq, weekday, day_of_month, now=None):
    """Prueft, ob der Report bei der gewaehlten Haeufigkeit heute faellig ist.
    Bei monthly wird ein zu hoher Tag (z.B. 31) in kuerzeren Monaten auf den
    letzten Tag des Monats geklemmt, damit der Report nie ausfaellt."""
    now = now or datetime.now()
    if freq == "weekly":
        return now.weekday() == _WEEKDAY_ORDER.index(weekday)
    if freq == "monthly":
        last_day = calendar.monthrange(now.year, now.month)[1]
        return now.day == min(day_of_month, last_day)
    return True  # daily


def get_schedule_summary():
    """Menschenlesbare Zeitplan-Beschreibung fuer die Status-Karte."""
    lang = get_report_language()
    time_str = get_active_schedule()
    freq = get_report_frequency()
    if freq == "weekly":
        wd_label = _WEEKDAY_LABELS[lang][get_report_weekday()]
        return f"Woechentlich, {wd_label}, {time_str}" if lang == "de" else f"Weekly, {wd_label}, {time_str}"
    if freq == "monthly":
        dom = get_report_day_of_month()
        return f"Monatlich, Tag {dom}, {time_str}" if lang == "de" else f"Monthly, day {dom}, {time_str}"
    return f"Taeglich, {time_str}" if lang == "de" else f"Daily, {time_str}"


def _scheduled_tick():
    """Taeglicher Trigger von 'schedule' zur eingestellten Uhrzeit - fuehrt
    run_analysis() nur aus, wenn die konfigurierte Haeufigkeit heute faellig
    ist (siehe _is_due_today())."""
    if _is_due_today(get_report_frequency(), get_report_weekday(), get_report_day_of_month()):
        run_analysis()
    else:
        log.info(f"Kein Report faellig heute (Haeufigkeit={get_report_frequency()}).")


def apply_settings(updates):
    """Speichert Settings und setzt den Zeitplan live neu."""
    appconfig.save(updates)
    schedule.clear()
    schedule.every().day.at(get_active_schedule()).do(_scheduled_tick)
    log.info(f"Einstellungen aktualisiert: Modell={get_active_model()}, Zeitplan={get_schedule_summary()}")
    return appconfig.load()


def run_analysis():
    log.info("=== Starte taegliche UniFi-Netzwerkanalyse ===")
    webui.record_start()
    try:
        messages  = fetch_logs(hours=24)
        log_text  = format_logs_for_analysis(messages)
        analysis  = analyze_with_llm(log_text, messages)
        send_email_report(analysis)
        ampel, _ = parse_ampel(analysis)
        webui.record_result(analysis, status="OK - Mail gesendet", ampel=ampel)
        log.info("=== Analyse abgeschlossen ===")
    except Exception as e:
        webui.record_error(e)
        log.error(f"Analyse fehlgeschlagen: {e}")
        raise


# ── Graylog-Bereitschaft pruefen ──────────────────────────────────────────────
def wait_for_graylog():
    log.info("Warte auf Graylog...")
    for i in range(30):
        try:
            resp = requests.get(f"{_graylog_base()}/system", auth=_graylog_auth(), headers=HEADERS, timeout=5)
            if resp.status_code == 200:
                log.info("Graylog ist bereit!")
                return True
        except Exception:
            pass
        log.info(f"Graylog noch nicht bereit, warte... ({i+1}/30)")
        time.sleep(10)
    log.error("Graylog konnte nicht erreicht werden nach 5 Minuten.")
    return False


def get_settings_snapshot():
    cfg = appconfig.load()
    return {
        "schedule": get_active_schedule(),
        "schedule_summary": get_schedule_summary(),
        "report_frequency": get_report_frequency(),
        "report_weekday": get_report_weekday(),
        "report_day_of_month": get_report_day_of_month(),
        "email": get_email_to(),
        "model": get_active_model(),
        "abuseipdb": bool(get_abuseipdb_key()),
        "log_source": cfg.get("log_source"),
        "graylog_host": cfg.get("graylog_host"),
        "graylog_port": cfg.get("graylog_port"),
        "graylog_user": cfg.get("graylog_user"),
        "graylog_password": cfg.get("graylog_password"),
        "llm_base_url": cfg.get("llm_base_url"),
        "llm_timeout": get_llm_timeout(),
        "llm_max_tokens": get_llm_max_tokens(),
        "llm_unload_after": get_llm_unload_after(),
        "llm_endpoints": get_llm_endpoints(),
        "abuseipdb_key": cfg.get("abuseipdb_key"),
        "searxng_url": cfg.get("searxng_url"),
        "report_language": get_report_language(),
        "llm_prompt_template": cfg.get("llm_prompt_template"),
        "llm_prompt_template_default": PROMPT_PRESETS[get_report_language()]["standard"]["template"],
        "llm_prompt_presets": {
            f"{lang}:{k}": v["template"]
            for lang, presets in PROMPT_PRESETS.items() for k, v in presets.items()
        },
        "llm_prompt_preset_labels": {
            f"{lang}:{k}": v["label"]
            for lang, presets in PROMPT_PRESETS.items() for k, v in presets.items()
        },
        "llm_prompt_library": get_prompt_library(),
        "smtp_host": cfg.get("smtp_host"),
        "smtp_port": cfg.get("smtp_port"),
        "smtp_user": cfg.get("smtp_user"),
        "smtp_password": cfg.get("smtp_password"),
        "smtp_security": cfg.get("smtp_security"),
        "smtp_from": cfg.get("smtp_from"),
        "email_to": cfg.get("email_to"),
        "email_subject": cfg.get("email_subject"),
        "email_theme": cfg.get("email_theme"),
        "unifi_block_enabled": cfg.get("unifi_block_enabled"),
        "unifi_dry_run": cfg.get("unifi_dry_run"),
        "unifi_host": cfg.get("unifi_host"),
        "unifi_api_key": cfg.get("unifi_api_key"),
        "unifi_block_threshold": cfg.get("unifi_block_threshold"),
        "unifi_allowlist": cfg.get("unifi_allowlist"),
    }


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("UniFi-Analyzer gestartet.")
    log.info(f"Log-Quelle: {appconfig.get('log_source')}")
    log.info(f"Graylog:  {appconfig.get('graylog_host')}:{appconfig.get('graylog_port')}")
    log.info(f"LLM:      {get_llm_base_url()}  Modell: {get_active_model()}")
    log.info(f"E-Mail:   {get_email_to() or '(nicht konfiguriert)'}")
    log.info(f"Bericht:  {get_schedule_summary()}")

    # SMTP-Config beim Start pruefen
    smtp_cfg = get_smtp_config()
    if smtp_cfg:
        log.info(f"SMTP:     {smtp_cfg['host']}:{smtp_cfg['port']} als {smtp_cfg['user']} ✓")
    else:
        log.warning("SMTP-Konfiguration fehlt noch – bitte in der GUI unter 'E-Mail / SMTP' eintragen.")

    if appconfig.get("log_source") == "graylog" and not wait_for_graylog():
        log.warning("Starte trotzdem – Graylog wird moeglicherweise spaeter verfuegbar.")

    # Status-Webserver fuer Unraid-WebUI starten
    webui.set_run_callback(run_analysis)
    webui.set_settings_callbacks(
        get_settings=get_settings_snapshot,
        apply_settings=apply_settings,
        test_llm=test_llm_connection,
        manage_prompt_library=manage_prompt_library,
        probe_endpoints=probe_llm_endpoints,
    )
    try:
        webui.start(port=8088)
        log.info("Status-WebUI laeuft auf Port 8088")
    except Exception as e:
        log.warning(f"WebUI konnte nicht gestartet werden: {e}")

    schedule.every().day.at(get_active_schedule()).do(_scheduled_tick)
    log.info(f"Naechster Report-Check taeglich um {get_active_schedule()} Uhr (Zeitplan: {get_schedule_summary()}).")

    while True:
        schedule.run_pending()
        time.sleep(60)
