#!/usr/bin/env python3
"""
UniFi Log Analyzer – analysiert UniFi-Netzwerk-Logs (via Graylog oder direkt
vom Controller) mit einem lokalen/entfernten LLM (OpenAI-kompatible API) und
verschickt den Bericht per E-Mail. Alle Zugangsdaten sind unabhaengig von
Drittsystemen ueber die GUI konfigurierbar (appconfig.py / settings.json).
"""

import os
import time
import smtplib
import logging
import requests
import schedule
import webui
import appconfig
import unifi_block
from datetime import datetime, timedelta
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
                "level":     msg.get("level", ""),
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
import re as _re

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
    ips = _re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_text or "")
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
        level = (e.get("level") or "").lower()
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

    prompt = f"""Du bist ein Netzwerk-Sicherheitsexperte und analysierst UniFi-Netzwerk-Logs.

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

{threat_intel}{research}LOG-DATEN (letzte 24 Stunden):
{log_text[:8000]}

Erstelle den Bericht auf Deutsch, exakt im obigen Format:"""

    try:
        resp = requests.post(
            f"{get_llm_base_url()}/chat/completions",
            json={
                "model": get_active_model(),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 4096,
                "stream": False,
            },
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        content = (data.get("choices") or [{}])[0].get("message", {}).get("content")
        result = (content or "").strip() or "Keine Antwort vom Modell."
        log.info(f"Analyse abgeschlossen ({len(result)} Zeichen).")
        return result
    except Exception as e:
        log.error(f"Fehler bei der LLM-Analyse: {e}")
        return f"Fehler bei der KI-Analyse: {e}"


# ── Ampel-Status parsen (STATUS: GRUEN/GELB/ROT am Berichtsanfang) ───────────
_AMPEL_LABELS = {"gruen": ("Normal", "#2e7d32"), "gelb": ("Achtung", "#f9a825"),
                 "rot": ("Kritisch", "#c62828")}


def parse_ampel(analysis):
    """Extrahiert die STATUS-Zeile vom Berichtsanfang.
    Gibt (farbschluessel_oder_None, bericht_ohne_status_zeile) zurueck."""
    lines = (analysis or "").splitlines()
    if lines:
        m = _re.match(r"^\s*STATUS:\s*(GRUEN|GELB|ROT)\s*$", lines[0], _re.IGNORECASE)
        if m:
            rest = "\n".join(lines[1:]).lstrip("\n")
            return m.group(1).lower(), rest
    return None, analysis


def _markdown_lite_to_html(text):
    """Wandelt die vom LLM erzeugten ## Ueberschriften und **fett** Markierungen
    in einfaches HTML um (kein vollwertiger Markdown-Parser noetig)."""
    out = []
    for line in text.split("\n"):
        line = _re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
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
    subject = f"UniFi Netzwerk-Analyse – {now}"

    ampel, body = parse_ampel(analysis)
    label, color = _AMPEL_LABELS.get(ampel, ("Unbekannt", "#757575"))
    html_analysis = _markdown_lite_to_html(body)

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
  body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; color: #333; }}
  h2 {{ color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 8px; }}
  h3 {{ color: #1a73e8; margin-top: 22px; margin-bottom: 6px; }}
  .meta {{ background: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-size: 13px; }}
  .ampel {{ display: inline-block; padding: 8px 16px; border-radius: 6px; color: #fff; font-weight: bold; margin-bottom: 20px; background: {color}; }}
  .content {{ line-height: 1.7; }}
  .footer {{ margin-top: 30px; font-size: 12px; color: #888; border-top: 1px solid #ddd; padding-top: 10px; }}
</style>
</head>
<body>
  <h2>🔍 UniFi Netzwerk-Analyse</h2>
  <div class="meta">
    <b>Datum:</b> {now} &nbsp;|&nbsp;
    <b>Modell:</b> {get_active_model()} &nbsp;|&nbsp;
    <b>Analysezeitraum:</b> Letzte 24 Stunden
  </div>
  <div class="ampel">Status: {label}</div>
  <div class="content">{html_analysis}</div>
  <div class="footer">Automatisch generiert von UniFi-Analyzer</div>
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


def list_ollama_models():
    """Holt die am konfigurierten LLM-Endpoint geladenen Modelle (OpenAI-kompatible API)."""
    try:
        r = requests.get(f"{get_llm_base_url()}/models", timeout=10)
        r.raise_for_status()
        models = [m.get("id") for m in r.json().get("data", []) if m.get("id")]
        return sorted(models)
    except Exception as e:
        log.warning(f"LM-Studio-Modell-Liste konnte nicht geladen werden: {e}")
        return []

def apply_settings(updates):
    """Speichert Settings und setzt den Zeitplan live neu."""
    appconfig.save(updates)
    new_time = get_active_schedule()
    schedule.clear()
    schedule.every().day.at(new_time).do(run_analysis)
    log.info(f"Einstellungen aktualisiert: Modell={get_active_model()}, Uhrzeit={new_time}")
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
        "email": get_email_to(),
        "model": get_active_model(),
        "abuseipdb": bool(get_abuseipdb_key()),
        "log_source": cfg.get("log_source"),
        "graylog_host": cfg.get("graylog_host"),
        "graylog_port": cfg.get("graylog_port"),
        "graylog_user": cfg.get("graylog_user"),
        "graylog_password": cfg.get("graylog_password"),
        "llm_base_url": cfg.get("llm_base_url"),
        "abuseipdb_key": cfg.get("abuseipdb_key"),
        "searxng_url": cfg.get("searxng_url"),
        "smtp_host": cfg.get("smtp_host"),
        "smtp_port": cfg.get("smtp_port"),
        "smtp_user": cfg.get("smtp_user"),
        "smtp_password": cfg.get("smtp_password"),
        "smtp_security": cfg.get("smtp_security"),
        "smtp_from": cfg.get("smtp_from"),
        "email_to": cfg.get("email_to"),
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
    log.info(f"Bericht:  taeglich um {REPORT_SCHEDULE}")

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
        list_models=list_ollama_models,
        apply_settings=apply_settings,
    )
    try:
        webui.start(get_settings_snapshot(), port=8088)
        log.info("Status-WebUI laeuft auf Port 8088")
    except Exception as e:
        log.warning(f"WebUI konnte nicht gestartet werden: {e}")

    schedule.every().day.at(get_active_schedule()).do(run_analysis)
    log.info(f"Naechste Analyse geplant um {get_active_schedule()} Uhr.")

    while True:
        schedule.run_pending()
        time.sleep(60)
