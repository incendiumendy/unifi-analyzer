"""Status- und Einstellungs-Webserver fuer den UniFi-Analyzer (Unraid WebUI)."""
import json
import threading
import html
from urllib.parse import parse_qs
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {
    "last_run": None,
    "last_status": "noch nicht ausgefuehrt",
    "last_report": "",
    "running": False,
}

_run_callback = None
_get_settings = None
_list_models = None
_apply_settings = None
_lock = threading.Lock()


def set_run_callback(cb):
    global _run_callback
    _run_callback = cb


def set_settings_callbacks(get_settings=None, list_models=None, apply_settings=None):
    global _get_settings, _list_models, _apply_settings
    _get_settings = get_settings
    _list_models = list_models
    _apply_settings = apply_settings


def record_start():
    with _lock:
        STATE["running"] = True
        STATE["last_status"] = "Analyse laeuft..."


def record_result(report, status="OK"):
    with _lock:
        STATE["running"] = False
        STATE["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        STATE["last_status"] = status
        if report:
            STATE["last_report"] = report


def record_error(msg):
    with _lock:
        STATE["running"] = False
        STATE["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        STATE["last_status"] = "Fehler: " + str(msg)


def _trigger_run():
    if _run_callback is None or STATE["running"]:
        return False

    def _job():
        try:
            _run_callback()
        except Exception as e:  # noqa
            record_error(e)

    threading.Thread(target=_job, daemon=True).start()
    return True


PAGE = """<!DOCTYPE html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UniFi Security Analyzer</title>
<style>
 body{{font-family:Segoe UI,Roboto,Arial,sans-serif;background:#1b1b1f;color:#e6e6e6;margin:0;padding:0}}
 header{{background:#0f2747;padding:18px 24px;border-bottom:3px solid #2b8aef}}
 header h1{{margin:0;font-size:20px;color:#fff}}
 header span{{color:#8fb7ef;font-size:13px}}
 .wrap{{max-width:900px;margin:0 auto;padding:24px}}
 .card{{background:#26262c;border-radius:10px;padding:18px 20px;margin-bottom:18px;box-shadow:0 1px 4px rgba(0,0,0,.4)}}
 .card h2{{margin:0 0 12px;font-size:15px;color:#8fb7ef;font-weight:600}}
 .row{{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #34343c}}
 .row:last-child{{border-bottom:none}}
 .k{{color:#9a9aa5}} .v{{color:#fff;font-weight:600}}
 .ok{{color:#3ecf6b}} .warn{{color:#f0a431}} .err{{color:#ef5350}}
 label{{display:block;color:#9a9aa5;font-size:13px;margin:10px 0 4px}}
 select,input[type=time],input[type=text],input[type=password],input[type=number],input[type=email]{{width:100%;max-width:340px;background:#1b1b1f;color:#fff;border:1px solid #3a3a44;border-radius:7px;padding:9px 10px;font-size:14px;box-sizing:border-box}}
 .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:0 16px;max-width:700px}}
 .grid2 label,.grid2 select,.grid2 input{{max-width:100%}}
 button{{background:#2b8aef;color:#fff;border:none;padding:11px 22px;border-radius:8px;font-size:15px;cursor:pointer;margin-top:14px}}
 button:hover{{background:#1f6fd0}} button:disabled{{background:#555;cursor:not-allowed}}
 .btn-run{{background:#1f9d57}} .btn-run:hover{{background:#178045}}
 pre{{white-space:pre-wrap;word-wrap:break-word;background:#1b1b1f;padding:16px;border-radius:8px;font-size:13px;line-height:1.5;max-height:520px;overflow:auto}}
 .muted{{color:#777;font-size:12px;margin-top:6px}}
 .flash{{background:#1f9d57;color:#fff;padding:10px 14px;border-radius:7px;margin-bottom:16px;font-size:14px}}
</style></head>
<body>
<header><h1><a href="/" style="color:#fff;text-decoration:none;">&#128737; UniFi Security Analyzer</a></h1>
<span>UniFi/Graylog &rarr; LLM &rarr; AbuseIPDB &rarr; Tagesreport per Mail</span></header>
<div class="wrap">
 {flash}
 <div class="card">
  <h2>Status</h2>
  <div class="row"><span class="k">Status</span><span class="v {statusclass}">{status}</span></div>
  <div class="row"><span class="k">Letzte Analyse</span><span class="v">{last_run}</span></div>
  <div class="row"><span class="k">Zeitplan (taeglich)</span><span class="v">{schedule}</span></div>
  <div class="row"><span class="k">Empfaenger</span><span class="v">{email}</span></div>
  <div class="row"><span class="k">Aktives Modell</span><span class="v">{model}</span></div>
  <div class="row"><span class="k">Log-Quelle</span><span class="v">{log_source_label}</span></div>
  <div class="row"><span class="k">AbuseIPDB</span><span class="v {abuseclass}">{abuse}</span></div>
 </div>
 <div class="card">
  <h2>KI-Modell &amp; Zeitplan</h2>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="model">
   <label for="llmurl">LLM-Endpoint (OpenAI-kompatibel, z.B. LM Studio/Ollama/OpenAI)</label>
   <input type="text" name="llm_base_url" id="llmurl" value="{llm_base_url}" placeholder="http://lm-studio:1234/v1">
   <label for="model">Modell (aus dem Endpoint geladen, oder frei eintragen)</label>
   <input type="text" name="ollama_model" id="model" list="model_list" value="{model}">
   <datalist id="model_list">{model_options}</datalist>
   <label for="time">Uhrzeit fuer den taeglichen Report</label>
   <input type="time" name="report_schedule" id="time" value="{schedule}">
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">Aenderungen werden persistent gespeichert und sofort wirksam (kein Neustart noetig).</div>
 </div>
 <div class="card">
  <h2>Log-Quelle</h2>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="logsource">
   <label for="lsrc">Woher die Logs fuer die Analyse kommen</label>
   <select name="log_source" id="lsrc">
    <option value="graylog" {ls_graylog_sel}>Graylog</option>
    <option value="unifi_direct" {ls_unifi_sel}>UniFi-Controller direkt (Beta)</option>
   </select>
   <div class="grid2">
    <div><label for="ghost">Graylog-Host</label><input type="text" name="graylog_host" id="ghost" value="{graylog_host}"></div>
    <div><label for="gport">Graylog-Port</label><input type="text" name="graylog_port" id="gport" value="{graylog_port}"></div>
    <div><label for="guser">Graylog-Benutzer</label><input type="text" name="graylog_user" id="guser" value="{graylog_user}"></div>
    <div><label for="gpass">Graylog-Passwort</label><input type="password" name="graylog_password" id="gpass" value="{graylog_password}" autocomplete="new-password"></div>
   </div>
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">"UniFi-Controller direkt" nutzt Host/API-Key aus der Gateway-Sperrung unten und braucht kein Graylog. Beta: haengt von Controller-/Firmware-Version ab.</div>
 </div>
 <div class="card">
  <h2>E-Mail / SMTP</h2>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="smtp">
   <div class="grid2">
    <div><label for="shost">SMTP-Host</label><input type="text" name="smtp_host" id="shost" value="{smtp_host}" placeholder="smtp.example.com"></div>
    <div><label for="sport">SMTP-Port</label><input type="number" name="smtp_port" id="sport" value="{smtp_port}"></div>
    <div><label for="suser">SMTP-Benutzer</label><input type="text" name="smtp_user" id="suser" value="{smtp_user}"></div>
    <div><label for="spass">SMTP-Passwort</label><input type="password" name="smtp_password" id="spass" value="{smtp_password}" autocomplete="new-password"></div>
   </div>
   <label for="ssec">Verschluesselung</label>
   <select name="smtp_security" id="ssec">
    <option value="ssl" {sec_ssl}>SSL</option>
    <option value="starttls" {sec_tls}>STARTTLS</option>
    <option value="none" {sec_none}>Keine</option>
   </select>
   <label for="sfrom">Absender-Adresse</label>
   <input type="email" name="smtp_from" id="sfrom" value="{smtp_from}">
   <label for="sto">Empfaenger (Report-Adresse)</label>
   <input type="email" name="email_to" id="sto" value="{email_to}">
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">Eigenstaendige SMTP-Konfiguration, unabhaengig von anderen Systemen.</div>
 </div>
 <div class="card">
  <h2>Bedrohungserkennung (AbuseIPDB)</h2>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="abuseipdb">
   <label for="aik">AbuseIPDB API-Key</label>
   <input type="password" name="abuseipdb_key" id="aik" value="{abuseipdb_key}" autocomplete="new-password">
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">Optional. Ohne Key wird die externe IP-Reputationspruefung uebersprungen.</div>
 </div>
 <div class="card">
  <h2>UniFi-Gateway IP-Sperrung</h2>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="unifiblock">
   <label><input type="checkbox" name="unifi_block_enabled" value="1" {ub_enabled}> Sperrung aktiviert</label>
   <label><input type="checkbox" name="unifi_dry_run" value="1" {ub_dry}> Dry-Run (nur Vorschau, sperrt NICHT)</label>
   <label for="ubh">UniFi-Host (z.B. https://192.168.1.1)</label>
   <input type="text" name="unifi_host" id="ubh" value="{ub_host}">
   <label for="ubk">UniFi API-Key (X-API-KEY)</label>
   <input type="password" name="unifi_api_key" id="ubk" value="{ub_key}" autocomplete="new-password">
   <label for="ubt">Block-Schwelle (AbuseIPDB-Score, 0-100)</label>
   <input type="number" name="unifi_block_threshold" id="ubt" min="0" max="100" value="{ub_thr}">
   <label for="uba">Allowlist (IPs/CIDR, kommagetrennt - werden nie gesperrt)</label>
   <input type="text" name="unifi_allowlist" id="uba" value="{ub_allow}">
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">Empfehlung: erst mit aktiviertem Dry-Run testen. Gesperrte IPs landen in der Firewall-Policy "AbuseIPDB Auto-Block". Host/API-Key werden auch fuer "UniFi-Controller direkt" als Log-Quelle verwendet.</div>
 </div>
 <div class="card">
  <h2>Manuell ausloesen</h2>
  <form method="POST" action="/run">
   <button type="submit" class="btn-run" {disabled}>&#9654; Jetzt analysieren &amp; Mail senden</button>
  </form>
  <div class="muted">Loest eine sofortige Analyse aus und sendet den Report per Mail.</div>
 </div>
 <div class="card">
  <h2>Letzter Report</h2>
  <pre>{report}</pre>
 </div>
</div></body></html>"""


_SETTINGS_DEFAULTS = {
    "schedule": "-", "email": "-", "model": "-", "abuseipdb": False,
    "log_source": "graylog",
    "graylog_host": "graylog", "graylog_port": "9000",
    "graylog_user": "admin", "graylog_password": "",
    "llm_base_url": "", "abuseipdb_key": "",
    "smtp_host": "", "smtp_port": 465, "smtp_user": "", "smtp_password": "",
    "smtp_security": "ssl", "smtp_from": "", "email_to": "",
    "unifi_block_enabled": False, "unifi_dry_run": True, "unifi_host": "",
    "unifi_api_key": "", "unifi_block_threshold": 95, "unifi_allowlist": "",
}


def _settings():
    if _get_settings:
        try:
            merged = dict(_SETTINGS_DEFAULTS)
            merged.update(_get_settings() or {})
            return merged
        except Exception:
            pass
    return dict(_SETTINGS_DEFAULTS)


def _models():
    if _list_models:
        try:
            return _list_models() or []
        except Exception:
            pass
    return []


def make_handler(cfg):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _render(self, flash=""):
            st = _settings()
            cur_model = st.get("model", "-")
            models = _models()
            if cur_model not in models and cur_model not in ("-", None):
                models = [cur_model] + models
            opts = "".join(
                '<option value="{0}">'.format(html.escape(m))
                for m in models
            )

            report = STATE["last_report"] or "(noch kein Report vorhanden)"
            status = STATE["last_status"]
            sc = "ok"
            if "Fehler" in status:
                sc = "err"
            elif "laeuft" in status:
                sc = "warn"
            abuse_active = bool(st.get("abuseipdb"))
            log_source = st.get("log_source") or "graylog"
            security = st.get("smtp_security") or "ssl"
            flash_html = '<div class="flash">{}</div>'.format(html.escape(flash)) if flash else ""

            def esc(key, default=""):
                return html.escape(str(st.get(key, default) or default))

            return PAGE.format(
                flash=flash_html,
                status=html.escape(status), statusclass=sc,
                last_run=html.escape(str(STATE["last_run"] or "-")),
                schedule=html.escape(str(st.get("schedule", "-"))),
                email=html.escape(str(st.get("email", "-"))),
                model=html.escape(str(cur_model)),
                abuse=("aktiv" if abuse_active else "nicht konfiguriert"),
                abuseclass=("ok" if abuse_active else "warn"),
                model_options=opts,
                report=html.escape(report),
                disabled=("disabled" if STATE["running"] else ""),
                log_source_label=("UniFi direkt" if log_source == "unifi_direct" else "Graylog"),
                llm_base_url=esc("llm_base_url"),
                ls_graylog_sel=("selected" if log_source == "graylog" else ""),
                ls_unifi_sel=("selected" if log_source == "unifi_direct" else ""),
                graylog_host=esc("graylog_host", "graylog"),
                graylog_port=esc("graylog_port", "9000"),
                graylog_user=esc("graylog_user", "admin"),
                graylog_password=esc("graylog_password"),
                smtp_host=esc("smtp_host"),
                smtp_port=esc("smtp_port", "465"),
                smtp_user=esc("smtp_user"),
                smtp_password=esc("smtp_password"),
                sec_ssl=("selected" if security == "ssl" else ""),
                sec_tls=("selected" if security == "starttls" else ""),
                sec_none=("selected" if security == "none" else ""),
                smtp_from=esc("smtp_from"),
                email_to=esc("email_to"),
                abuseipdb_key=esc("abuseipdb_key"),
                ub_enabled=("checked" if st.get("unifi_block_enabled") else ""),
                ub_dry=("checked" if st.get("unifi_dry_run") else ""),
                ub_host=html.escape(str(st.get("unifi_host", "") or "")),
                ub_key=html.escape(str(st.get("unifi_api_key", "") or "")),
                ub_thr=html.escape(str(st.get("unifi_block_threshold", 95))),
                ub_allow=html.escape(str(st.get("unifi_allowlist", "") or "")),
            )

        def _send_html(self, body, code=200):
            b = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _redirect(self, loc="/"):
            self.send_response(303)
            self.send_header("Location", loc)
            self.end_headers()

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send_html(self._render())
            elif self.path == "/saved":
                self._send_html(self._render(flash="Einstellungen gespeichert."))
            elif self.path == "/healthz":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": STATE["last_status"]}).encode())
            else:
                self.send_response(404); self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length).decode("utf-8") if length else ""
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            if self.path == "/run":
                _trigger_run()
                self._redirect("/")
            elif self.path == "/settings":
                # form_id trennt die getrennten Karten/Formulare, damit das Speichern
                # einer Karte nicht Felder einer anderen Karte (z.B. Checkboxen,
                # die bei Abwesenheit im POST-Body sonst faelschlich "aus" waeren) ueberschreibt.
                form_id = form.get("form_id", "")
                updates = {}
                if form_id == "model":
                    if form.get("llm_base_url"):
                        updates["llm_base_url"] = form["llm_base_url"].strip()
                    if form.get("ollama_model"):
                        updates["ollama_model"] = form["ollama_model"].strip()
                    if form.get("report_schedule"):
                        updates["report_schedule"] = form["report_schedule"]
                elif form_id == "logsource":
                    if form.get("log_source") in ("graylog", "unifi_direct"):
                        updates["log_source"] = form["log_source"]
                    if "graylog_host" in form:
                        updates["graylog_host"] = form["graylog_host"].strip()
                    if "graylog_port" in form:
                        updates["graylog_port"] = form["graylog_port"].strip()
                    if "graylog_user" in form:
                        updates["graylog_user"] = form["graylog_user"].strip()
                    if "graylog_password" in form:
                        updates["graylog_password"] = form["graylog_password"]
                elif form_id == "smtp":
                    if "smtp_host" in form:
                        updates["smtp_host"] = form["smtp_host"].strip()
                    if form.get("smtp_port"):
                        try:
                            updates["smtp_port"] = int(form["smtp_port"])
                        except ValueError:
                            pass
                    if "smtp_user" in form:
                        updates["smtp_user"] = form["smtp_user"].strip()
                    if "smtp_password" in form:
                        updates["smtp_password"] = form["smtp_password"]
                    if form.get("smtp_security") in ("ssl", "starttls", "none"):
                        updates["smtp_security"] = form["smtp_security"]
                    if "smtp_from" in form:
                        updates["smtp_from"] = form["smtp_from"].strip()
                    if "email_to" in form:
                        updates["email_to"] = form["email_to"].strip()
                elif form_id == "abuseipdb":
                    if "abuseipdb_key" in form:
                        updates["abuseipdb_key"] = form["abuseipdb_key"].strip()
                elif form_id == "unifiblock":
                    # Checkboxen: vorhanden => an, fehlt => aus (nur bei diesem Formular)
                    updates["unifi_block_enabled"] = bool(form.get("unifi_block_enabled"))
                    updates["unifi_dry_run"] = bool(form.get("unifi_dry_run"))
                    if "unifi_host" in form:
                        updates["unifi_host"] = form["unifi_host"].strip()
                    if "unifi_api_key" in form:
                        updates["unifi_api_key"] = form["unifi_api_key"].strip()
                    if form.get("unifi_block_threshold"):
                        try:
                            updates["unifi_block_threshold"] = max(0, min(100, int(form["unifi_block_threshold"])))
                        except ValueError:
                            pass
                    if "unifi_allowlist" in form:
                        updates["unifi_allowlist"] = form["unifi_allowlist"].strip()
                if updates and _apply_settings:
                    try:
                        _apply_settings(updates)
                    except Exception as e:  # noqa
                        pass
                self._redirect("/saved")
            else:
                self.send_response(404); self.end_headers()
    return Handler


def start(cfg, port=8088):
    handler = make_handler(cfg)
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
