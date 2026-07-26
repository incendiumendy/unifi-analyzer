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
 select,input[type=time]{{width:100%;max-width:340px;background:#1b1b1f;color:#fff;border:1px solid #3a3a44;border-radius:7px;padding:9px 10px;font-size:14px}}
 button{{background:#2b8aef;color:#fff;border:none;padding:11px 22px;border-radius:8px;font-size:15px;cursor:pointer;margin-top:14px}}
 button:hover{{background:#1f6fd0}} button:disabled{{background:#555;cursor:not-allowed}}
 .btn-run{{background:#1f9d57}} .btn-run:hover{{background:#178045}}
 pre{{white-space:pre-wrap;word-wrap:break-word;background:#1b1b1f;padding:16px;border-radius:8px;font-size:13px;line-height:1.5;max-height:520px;overflow:auto}}
 .muted{{color:#777;font-size:12px;margin-top:6px}}
 .flash{{background:#1f9d57;color:#fff;padding:10px 14px;border-radius:7px;margin-bottom:16px;font-size:14px}}
</style></head>
<body>
<header><h1><a href="http://192.168.1.111:8088/" style="color:#fff;text-decoration:none;">&#128737; UniFi Security Analyzer</a></h1>
<span>Graylog &rarr; Ollama LLM &rarr; AbuseIPDB &rarr; Tagesreport per Mail</span></header>
<div class="wrap">
 {flash}
 <div class="card">
  <h2>Status</h2>
  <div class="row"><span class="k">Status</span><span class="v {statusclass}">{status}</span></div>
  <div class="row"><span class="k">Letzte Analyse</span><span class="v">{last_run}</span></div>
  <div class="row"><span class="k">Zeitplan (taeglich)</span><span class="v">{schedule}</span></div>
  <div class="row"><span class="k">Empfaenger</span><span class="v">{email}</span></div>
  <div class="row"><span class="k">Aktives Modell</span><span class="v">{model}</span></div>
  <div class="row"><span class="k">AbuseIPDB</span><span class="v {abuseclass}">{abuse}</span></div>
 </div>
 <div class="card">
  <h2>Einstellungen</h2>
  <form method="POST" action="/settings">
   <label for="model">Ollama-Modell (lokal verfuegbar)</label>
   <select name="ollama_model" id="model">{model_options}</select>
   <label for="time">Uhrzeit fuer den taeglichen Report</label>
   <input type="time" name="report_schedule" id="time" value="{schedule}">
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">Modell &amp; Uhrzeit werden persistent gespeichert und sofort wirksam (kein Neustart noetig).</div>
 </div>
 <div class="card">
  <h2>UniFi-Gateway IP-Sperrung</h2>
  <form method="POST" action="/settings">
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
  <div class="muted">Empfehlung: erst mit aktiviertem Dry-Run testen. Gesperrte IPs landen in der Firewall-Policy "AbuseIPDB Auto-Block".</div>
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


def _settings():
    if _get_settings:
        try:
            return _get_settings()
        except Exception:
            pass
    return {"schedule": "-", "email": "-", "model": "-", "abuseipdb": False,
            "unifi_block_enabled": False, "unifi_dry_run": True, "unifi_host": "",
            "unifi_api_key": "", "unifi_block_threshold": 95, "unifi_allowlist": ""}


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
                '<option value="{0}"{1}>{0}</option>'.format(
                    html.escape(m), " selected" if m == cur_model else "")
                for m in models
            ) or '<option value="">(keine Modelle gefunden)</option>'

            report = STATE["last_report"] or "(noch kein Report vorhanden)"
            status = STATE["last_status"]
            sc = "ok"
            if "Fehler" in status:
                sc = "err"
            elif "laeuft" in status:
                sc = "warn"
            abuse_active = bool(st.get("abuseipdb"))
            flash_html = '<div class="flash">{}</div>'.format(html.escape(flash)) if flash else ""
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
                updates = {}
                if form.get("ollama_model"):
                    updates["ollama_model"] = form["ollama_model"]
                if form.get("report_schedule"):
                    updates["report_schedule"] = form["report_schedule"]
                # Checkboxen: vorhanden => an, fehlt => aus (immer setzen)
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
