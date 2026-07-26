#!/usr/bin/env python3
"""
UniFi Log Analyzer – liest SMTP-Credentials direkt aus der Odysseus-DB,
verwendet gemma4:12b fuer die Analyse und sendet den Bericht per E-Mail.
"""

import os
import sys
import time
import sqlite3
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

# ── Konfiguration aus Umgebungsvariablen ─────────────────────────────────────
GRAYLOG_HOST     = os.getenv("GRAYLOG_HOST", "graylog")
GRAYLOG_PORT     = os.getenv("GRAYLOG_PORT", "9000")
GRAYLOG_USER     = os.getenv("GRAYLOG_USER", "admin")
GRAYLOG_PASSWORD = os.getenv("GRAYLOG_PASSWORD", "admin")
GRAYLOG_BASE     = f"http://{GRAYLOG_HOST}:{GRAYLOG_PORT}/api"
GRAYLOG_AUTH     = (GRAYLOG_USER, GRAYLOG_PASSWORD)
HEADERS          = {"X-Requested-By": "unifi-analyzer", "Accept": "application/json"}

OLLAMA_HOST      = os.getenv("OLLAMA_HOST", "192.168.1.111")
OLLAMA_PORT      = os.getenv("OLLAMA_PORT", "11434")
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "gemma4:12b")
LM_STUDIO_BASE_URL = os.getenv("LM_STUDIO_BASE_URL", "http://lm-studio:1234/v1").rstrip("/")
ABUSEIPDB_KEY    = os.getenv("ABUSEIPDB_KEY", "")

EMAIL_TO         = os.getenv("EMAIL_TO", "andreas.frei@incendium.eu")
REPORT_SCHEDULE  = os.getenv("REPORT_SCHEDULE", "08:00")

# Pfad zur Odysseus-Datenbank (als Volume im Container gemountet)
ODYSSEUS_DB      = os.getenv("ODYSSEUS_DB", "/odysseus/app.db")

# ── SMTP-Credentials aus Odysseus-DB laden ───────────────────────────────────
def get_smtp_config():
    """Liest SMTP-Konfiguration direkt aus der Odysseus SQLite-Datenbank."""
    try:
        conn = sqlite3.connect(ODYSSEUS_DB)
        cur = conn.cursor()
        cur.execute("""
            SELECT smtp_host, smtp_port, smtp_user, smtp_password,
                   smtp_security, from_address
            FROM email_accounts
            WHERE is_default = 1 OR enabled = 1
            ORDER BY is_default DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        conn.close()

        if not row:
            log.error("Kein aktiver E-Mail-Account in Odysseus-DB gefunden.")
            return None

        smtp_host, smtp_port, smtp_user, smtp_password_enc, smtp_security, from_addr = row

        # Passwort entschluesseln (Odysseus nutzt Fernet-Verschluesselung)
        # ENV-Variable hat Vorrang (aus Odysseus vorab extrahiert)
        env_pw = os.getenv("SMTP_PASSWORD", "")
        password = env_pw if env_pw else _decrypt_odysseus_password(smtp_password_enc)

        return {
            "host":     smtp_host,
            "port":     int(smtp_port or 465),
            "user":     smtp_user,
            "password": password,
            "security": smtp_security or "ssl",
            "from":     from_addr or smtp_user,
        }
    except Exception as e:
        log.error(f"Fehler beim Lesen der Odysseus-DB: {e}")
        return None


def _decrypt_odysseus_password(encrypted):
    """Liest Passwort aus Env-Variable oder entschluesselt via Odysseus."""
    # Zuerst direkt aus Env-Variable (von Odysseus vorab extrahiert)
    env_pw = os.getenv("SMTP_PASSWORD", "")
    if env_pw:
        return env_pw
    if not encrypted:
        return ""
    try:
        import sys
        ODYSSEUS_APP = os.getenv("ODYSSEUS_APP", "/odysseus/app")
        if ODYSSEUS_APP not in sys.path:
            sys.path.insert(0, ODYSSEUS_APP)
        from routes.email_helpers import _decrypt
        return _decrypt(encrypted)
    except Exception as e:
        log.warning(f"Odysseus _decrypt fehlgeschlagen ({e}) – versuche Klartext.")
        return encrypted


def _get_odysseus_key():
    return None  # Nicht benoetigt – wird von _decrypt intern gehandhabt


# ── Graylog: Logs holen ───────────────────────────────────────────────────────
def fetch_logs_from_graylog(hours=24):
    """Holt UniFi-Logs der letzten N Stunden aus Graylog."""
    try:
        from_ts = int((datetime.utcnow() - timedelta(hours=hours)).timestamp() * 1000)
        params = {
            "query":   "*",
            "range":   hours * 3600,
            "limit":   500,
            "sort":    "timestamp:desc",
            "filter":  "streams:*",
        }
        resp = requests.get(
            f"{GRAYLOG_BASE}/search/universal/relative",
            auth=GRAYLOG_AUTH,
            headers=HEADERS,
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        messages = data.get("messages", [])
        log.info(f"{len(messages)} Log-Eintraege aus Graylog geladen.")
        return messages
    except Exception as e:
        log.error(f"Fehler beim Abrufen der Graylog-Logs: {e}")
        return []


def format_logs_for_analysis(messages):
    """Formatiert Graylog-Nachrichten fuer die LLM-Analyse."""
    if not messages:
        return "Keine Log-Eintraege vorhanden."

    lines = []
    for m in messages[:300]:  # Max 300 Eintraege
        msg = m.get("message", {})
        ts      = msg.get("timestamp", "")[:19]
        source  = msg.get("source", "unbekannt")
        level   = msg.get("level", "")
        message = msg.get("message", msg.get("short_message", ""))
        lines.append(f"[{ts}] [{source}] [{level}] {message}")

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
    if not ABUSEIPDB_KEY:
        return None
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
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
    if not ABUSEIPDB_KEY:
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

def analyze_with_llm(log_text):
    """Analysiert die Logs mit dem lokalen Ollama-Modell."""
    if not log_text or log_text == "Keine Log-Eintraege vorhanden.":
        return "Keine Logs zum Analysieren vorhanden."

    threat_intel = build_threat_intel(log_text)

    prompt = f"""Du bist ein Netzwerk-Sicherheitsexperte und analysierst UniFi-Netzwerk-Logs.

Analysiere die folgenden Log-Daten und erstelle einen strukturierten deutschen Bericht mit:

1. **Zusammenfassung** – Kurzer Überblick über die letzten 24 Stunden
2. **Auffälligkeiten & Warnungen** – Kritische Ereignisse, Fehler, ungewöhnliche Muster
3. **Sicherheitsrelevantes** – Login-Versuche, Port-Scans, verdächtige IPs, Verbindungsabbrüche
4. **Netzwerkleistung** – Verbindungsqualität, Latenz-Probleme, Geräteausfälle
5. **Empfehlungen** – Konkrete Massnahmen basierend auf den Logs
6. **Status** – Gesamtbewertung: 🟢 Normal / 🟡 Achtung / 🔴 Kritisch

{threat_intel}LOG-DATEN (letzte 24 Stunden):
{log_text[:8000]}

Erstelle einen prägnanten, informativen Bericht auf Deutsch:"""

    try:
        resp = requests.post(
            f"{LM_STUDIO_BASE_URL}/chat/completions",
            json={
                "model": appconfig.get("ollama_model") or OLLAMA_MODEL,
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


# ── E-Mail senden via Odysseus-SMTP-Config ────────────────────────────────────
def send_email_report(analysis):
    """Sendet den Analysebericht per E-Mail – SMTP-Config aus Odysseus-DB."""
    smtp = get_smtp_config()
    if not smtp:
        log.error("SMTP-Konfiguration konnte nicht geladen werden – E-Mail wird nicht gesendet.")
        return False

    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    subject = f"UniFi Netzwerk-Analyse – {now}"

    # HTML-Body erstellen
    html_analysis = analysis.replace("\n", "<br>").replace("**", "<b>", 1)
    # Markdown Bold vereinfacht umwandeln
    import re
    html_analysis = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', analysis.replace("\n", "<br>"))

    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8">
<style>
  body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; color: #333; }}
  h2 {{ color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 8px; }}
  .meta {{ background: #f5f5f5; padding: 10px; border-radius: 5px; margin-bottom: 20px; font-size: 13px; }}
  .content {{ line-height: 1.7; }}
  .footer {{ margin-top: 30px; font-size: 12px; color: #888; border-top: 1px solid #ddd; padding-top: 10px; }}
</style>
</head>
<body>
  <h2>🔍 UniFi Netzwerk-Analyse</h2>
  <div class="meta">
    <b>Datum:</b> {now} &nbsp;|&nbsp;
    <b>Modell:</b> {OLLAMA_MODEL} &nbsp;|&nbsp;
    <b>Analysezeitraum:</b> Letzte 24 Stunden
  </div>
  <div class="content">{html_analysis}</div>
  <div class="footer">Automatisch generiert von UniFi-Analyzer | Odysseus-KI-System</div>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["From"]    = smtp["from"]
        msg["To"]      = EMAIL_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(analysis, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        if smtp["security"] == "ssl":
            with smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=30) as server:
                server.login(smtp["user"], smtp["password"])
                server.sendmail(smtp["from"], EMAIL_TO, msg.as_string())
        else:
            with smtplib.SMTP(smtp["host"], smtp["port"], timeout=30) as server:
                server.starttls()
                server.login(smtp["user"], smtp["password"])
                server.sendmail(smtp["from"], EMAIL_TO, msg.as_string())

        log.info(f"E-Mail-Bericht erfolgreich an {EMAIL_TO} gesendet.")
        return True
    except Exception as e:
        log.error(f"Fehler beim Senden der E-Mail: {e}")
        return False


# ── Hauptanalyse ──────────────────────────────────────────────────────────────
def get_active_model():
    return appconfig.get("ollama_model") or OLLAMA_MODEL


def get_active_schedule():
    return appconfig.get("report_schedule") or REPORT_SCHEDULE


def list_ollama_models():
    """Holt die in LM Studio geladenen Modelle (OpenAI-kompatible API)."""
    try:
        r = requests.get(f"{LM_STUDIO_BASE_URL}/models", timeout=10)
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
        messages  = fetch_logs_from_graylog(hours=24)
        log_text  = format_logs_for_analysis(messages)
        analysis  = analyze_with_llm(log_text)
        send_email_report(analysis)
        webui.record_result(analysis, status="OK - Mail gesendet")
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
            resp = requests.get(f"{GRAYLOG_BASE}/system", auth=GRAYLOG_AUTH, headers=HEADERS, timeout=5)
            if resp.status_code == 200:
                log.info("Graylog ist bereit!")
                return True
        except Exception:
            pass
        log.info(f"Graylog noch nicht bereit, warte... ({i+1}/30)")
        time.sleep(10)
    log.error("Graylog konnte nicht erreicht werden nach 5 Minuten.")
    return False


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info("UniFi-Analyzer gestartet.")
    log.info(f"Graylog:  {GRAYLOG_HOST}:{GRAYLOG_PORT}")
    log.info(f"Ollama:   {OLLAMA_HOST}:{OLLAMA_PORT}  Modell: {OLLAMA_MODEL}")
    log.info(f"E-Mail:   {EMAIL_TO}")
    log.info(f"Bericht:  taeglich um {REPORT_SCHEDULE}")
    log.info(f"Odysseus-DB: {ODYSSEUS_DB}")

    # SMTP-Config beim Start pruefen
    smtp_cfg = get_smtp_config()
    if smtp_cfg:
        log.info(f"SMTP:     {smtp_cfg['host']}:{smtp_cfg['port']} als {smtp_cfg['user']} ✓")
    else:
        log.warning("SMTP-Konfiguration konnte nicht aus Odysseus-DB geladen werden!")

    if not wait_for_graylog():
        log.warning("Starte trotzdem – Graylog wird moeglicherweise spaeter verfuegbar.")

    # Status-Webserver fuer Unraid-WebUI starten
    webui.set_run_callback(run_analysis)
    webui.set_settings_callbacks(
        get_settings=lambda: {
            "schedule": get_active_schedule(),
            "email": EMAIL_TO,
            "model": get_active_model(),
            "abuseipdb": bool(ABUSEIPDB_KEY),
            "unifi_block_enabled": appconfig.get("unifi_block_enabled"),
            "unifi_dry_run": appconfig.get("unifi_dry_run"),
            "unifi_host": appconfig.get("unifi_host"),
            "unifi_api_key": appconfig.get("unifi_api_key"),
            "unifi_block_threshold": appconfig.get("unifi_block_threshold"),
            "unifi_allowlist": appconfig.get("unifi_allowlist"),
        },
        list_models=list_ollama_models,
        apply_settings=apply_settings,
    )
    try:
        webui.start({
            "schedule": get_active_schedule(),
            "email": EMAIL_TO,
            "model": get_active_model(),
            "abuseipdb": bool(ABUSEIPDB_KEY),
        }, port=8088)
        log.info("Status-WebUI laeuft auf Port 8088")
    except Exception as e:
        log.warning(f"WebUI konnte nicht gestartet werden: {e}")

    schedule.every().day.at(get_active_schedule()).do(run_analysis)
    log.info(f"Naechste Analyse geplant um {get_active_schedule()} Uhr.")

    while True:
        schedule.run_pending()
        time.sleep(60)
