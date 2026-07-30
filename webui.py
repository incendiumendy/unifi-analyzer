"""Status- und Einstellungs-Webserver fuer den UniFi-Analyzer (Unraid WebUI)."""
import json
import threading
import html
from urllib.parse import parse_qs, urlparse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {
    "last_run": None,
    "last_status": "noch nicht ausgefuehrt",
    "last_report": "",
    "last_ampel": None,
    "running": False,
}

_AMPEL_LABELS = {"gruen": ("Normal", "ok"), "gelb": ("Achtung", "warn"),
                 "rot": ("Kritisch", "err")}

_WEEKDAY_LABELS_DE = [
    ("mon", "Montag"), ("tue", "Dienstag"), ("wed", "Mittwoch"), ("thu", "Donnerstag"),
    ("fri", "Freitag"), ("sat", "Samstag"), ("sun", "Sonntag"),
]

_run_callback = None
_get_settings = None
_list_models = None
_apply_settings = None
_test_llm = None
_manage_prompt_library = None
_probe_endpoints = None
_lock = threading.Lock()


def set_run_callback(cb):
    global _run_callback
    _run_callback = cb


def set_settings_callbacks(get_settings=None, list_models=None, apply_settings=None,
                            test_llm=None, manage_prompt_library=None,
                            probe_endpoints=None):
    global _get_settings, _list_models, _apply_settings, _test_llm, _manage_prompt_library
    global _probe_endpoints
    _get_settings = get_settings
    _list_models = list_models
    _apply_settings = apply_settings
    _test_llm = test_llm
    _manage_prompt_library = manage_prompt_library
    _probe_endpoints = probe_endpoints


def record_start():
    with _lock:
        STATE["running"] = True
        STATE["last_status"] = "Analyse laeuft..."


def record_result(report, status="OK", ampel=None):
    with _lock:
        STATE["running"] = False
        STATE["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        STATE["last_status"] = status
        STATE["last_ampel"] = ampel
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
 textarea{{width:100%;max-width:640px;background:#1b1b1f;color:#fff;border:1px solid #3a3a44;border-radius:7px;padding:9px 10px;font-size:13px;line-height:1.4;box-sizing:border-box;font-family:Consolas,monospace}}
 .btn-secondary{{background:#4a4a54;margin-left:10px}} .btn-secondary:hover{{background:#3a3a44}}
 .grid2{{display:grid;grid-template-columns:1fr 1fr;gap:0 16px;max-width:700px}}
 .label-row{{display:flex;align-items:center;gap:8px;margin:10px 0 4px}}
 .label-row label{{margin:0}}
 .help-toggle{{background:#3a3a44;color:#c7d6ea;border:1px solid #4a4a56;border-radius:50%;
  width:20px;height:20px;line-height:18px;padding:0;margin:0;font-size:12px;font-weight:700;
  cursor:pointer;display:inline-flex;align-items:center;justify-content:center;flex:none}}
 .help-toggle:hover{{background:#4a4a54}}
 .helpbox{{background:#1b1b1f;border:1px solid #3a3a44;border-radius:7px;padding:10px 12px;
  margin-bottom:10px;font-size:12.5px;color:#c7c7cf;line-height:1.5;max-width:640px}}
 .helpbox ul{{margin:6px 0 0;padding-left:18px}}
 .btnrow{{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px}}
 .btnrow button{{margin:0}}
 .epgrid{{display:grid;grid-template-columns:22px 1.1fr 2fr 1.7fr;gap:6px 10px;align-items:center;
  max-width:820px;margin-bottom:6px}}
 .epgrid input{{max-width:100%;margin:0}}
 .epgrid-head{{color:#8a8a95;font-size:12px;margin-top:8px}}
 .epnum{{color:#8fb7ef;font-weight:700;font-size:13px}}
 .eprow-status{{grid-column:2 / -1;font-size:12px;color:#9a9aa5;margin:-2px 0 4px}}
 .grid2 label,.grid2 select,.grid2 input{{max-width:100%}}
 /* Eingabefelder unten buendig halten, auch wenn ein Label zweizeilig umbricht */
 .grid2>div{{display:flex;flex-direction:column;justify-content:flex-end}}
 .grid2>div>label{{margin-top:10px}}
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
 <script>
  var _lastKnownStatus = {status_json};
  function _pollStatus(){{
   fetch('/healthz').then(function(r){{return r.json();}}).then(function(data){{
    if(data.status !== _lastKnownStatus){{ location.reload(); }}
   }}).catch(function(){{}});
  }}
  setInterval(_pollStatus, 3000);
 </script>
 <div class="card">
  <h2>Status</h2>
  <div class="row"><span class="k">Status</span><span class="v {statusclass}">{status}</span></div>
  <div class="row"><span class="k">Letzte Analyse</span><span class="v">{last_run}</span></div>
  <div class="row"><span class="k">Zeitplan</span><span class="v">{schedule_summary}</span></div>
  <div class="row"><span class="k">Empfaenger</span><span class="v">{email}</span></div>
  <div class="row"><span class="k">Aktives Modell</span><span class="v">{model}</span></div>
  <div class="row"><span class="k">Log-Quelle</span><span class="v">{log_source_label}</span></div>
  <div class="row"><span class="k">AbuseIPDB</span><span class="v {abuseclass}">{abuse}</span></div>
 </div>
 <div class="card">
  <h2>KI-Modelle &amp; Fallback-Kette</h2>
  <script>
   const DEFAULT_PROMPT_TEMPLATE = {default_prompt_json};
   const PRESET_TEMPLATES = {preset_templates_json};
   const CUSTOM_TEMPLATES = {custom_templates_json};

   function testLLM(){{
    const el = document.getElementById('llmTestResult');
    el.textContent = 'Teste Verbindung...';
    el.style.color = '#9a9aa5';
    const url = document.getElementById('ep1_url').value;
    fetch('/test_llm?base_url=' + encodeURIComponent(url)).then(function(r){{return r.json();}}).then(function(data){{
     el.textContent = data.message;
     el.style.color = data.ok ? '#3ecf6b' : '#ef5350';
     if(data.ok && data.models && data.models.length){{
      const dl = document.getElementById('model_list');
      dl.innerHTML = '';
      data.models.forEach(function(m){{
       const opt = document.createElement('option');
       opt.value = m;
       dl.appendChild(opt);
      }});
     }}
    }}).catch(function(e){{ el.textContent = 'Fehler: ' + e; el.style.color = '#ef5350'; }});
   }}

   function probeEndpoints(){{
    const el = document.getElementById('llmTestResult');
    el.textContent = 'Pruefe Endpunkte...';
    el.style.color = '#9a9aa5';
    for(let i=1;i<=3;i++){{
     const s = document.getElementById('epstatus'+i);
     if(s) s.textContent = '';
    }}
    fetch('/probe_endpoints').then(function(r){{return r.json();}}).then(function(list){{
     el.textContent = list.length ? 'Reihenfolge = Fallback-Reihenfolge. Der erste erreichbare Endpunkt macht die Analyse.' : 'Keine Endpunkte konfiguriert.';
     list.forEach(function(d, i){{
      const s = document.getElementById('epstatus'+(i+1));
      if(!s) return;
      s.textContent = (d.ok ? '\\u2713 ' : '\\u2717 ') + d.name + ': ' + d.message;
      s.style.color = d.ok ? '#3ecf6b' : '#ef5350';
     }});
    }}).catch(function(e){{ el.textContent = 'Fehler: ' + e; el.style.color = '#ef5350'; }});
   }}

   function onModelFocus(el){{
    el.dataset.prev = el.value;
    el.value = '';
   }}

   function onModelBlur(el){{
    if(el.value.trim() === ''){{ el.value = el.dataset.prev || ''; }}
   }}

   function toggleHelp(id){{
    const el = document.getElementById(id);
    el.hidden = !el.hidden;
   }}

   function onFrequencyChange(){{
    const v = document.getElementById('freq').value;
    document.getElementById('freqWeekly').style.display = (v === 'weekly') ? '' : 'none';
    document.getElementById('freqMonthly').style.display = (v === 'monthly') ? '' : 'none';
   }}

   function checkPromptDirty(){{
    const ta = document.getElementById('prompt');
    const badge = document.getElementById('promptDirty');
    badge.style.display = (ta.value !== ta.dataset.original) ? 'inline' : 'none';
   }}

   function onPromptSelect(){{
    const v = document.getElementById('promptSelect').value;
    if(!v) return;
    if(v.indexOf('preset:') === 0){{
     document.getElementById('prompt').value = PRESET_TEMPLATES[v.slice(7)] || '';
    }} else if(v.indexOf('custom:') === 0){{
     document.getElementById('prompt').value = CUSTOM_TEMPLATES[v.slice(7)] || '';
    }}
    checkPromptDirty();
   }}

   function _savePrompt(action, name, content){{
    return fetch('/promptlib', {{method:'POST', headers:{{'Content-Type':'application/x-www-form-urlencoded'}},
     body: 'action=' + encodeURIComponent(action) + '&name=' + encodeURIComponent(name) + '&content=' + encodeURIComponent(content || '')}});
   }}

   function addPromptToLibrary(){{
    const name = window.prompt('Name fuer die neue Vorlage:');
    if(!name) return;
    _savePrompt('save', name, document.getElementById('prompt').value).then(function(){{ location.reload(); }});
   }}

   function updatePromptInLibrary(){{
    const v = document.getElementById('promptSelect').value;
    if(v.indexOf('custom:') !== 0){{ alert('Bitte zuerst eine eigene Vorlage aus der Liste waehlen.'); return; }}
    _savePrompt('save', v.slice(7), document.getElementById('prompt').value).then(function(){{ location.reload(); }});
   }}

   function deletePromptFromLibrary(){{
    const v = document.getElementById('promptSelect').value;
    if(v.indexOf('custom:') !== 0){{ alert('Bitte zuerst eine eigene Vorlage aus der Liste waehlen.'); return; }}
    const name = v.slice(7);
    if(!confirm('Vorlage "' + name + '" wirklich loeschen?')) return;
    _savePrompt('delete', name).then(function(){{ location.reload(); }});
   }}
  </script>
  <div class="label-row">
   <span style="color:#9a9aa5;font-size:13px">Endpunkte in Fallback-Reihenfolge - der erste erreichbare macht die Analyse</span>
   <button type="button" class="help-toggle" onclick="toggleHelp('modelHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="modelHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li>Ihr koennt bis zu drei OpenAI-kompatible Endpunkte eintragen. Sie werden <b>von oben nach unten</b>
     durchprobiert: der erste, der erreichbar ist und nicht gerade rechnet, erstellt den Bericht.
     Faellt einer aus, uebernimmt automatisch der naechste.</li>
    <li>URL endet meist auf <code>/v1</code>, z.B. <code>http://192.168.1.111:11434/v1</code> (Ollama),
     <code>:1234/v1</code> (LM Studio), <code>:8090/v1</code> (llama.cpp).</li>
    <li>"Endpunkte pruefen" zeigt pro Zeile: erkannte Backend-Art, ob das Modell geladen ist
     und ob gerade gerechnet wird.</li>
    <li><b>Entladen:</b> Ollama und LM Studio koennen das Modell nach der Analyse wieder aus dem
     Speicher werfen. Das passiert nur, wenn der Analyzer es selbst geladen hat - war es vorher
     schon geladen, benutzt es jemand anderes und es bleibt liegen. llama.cpp haelt sein Modell
     dauerhaft und eignet sich deshalb gut als letzter Fallback.</li>
    <li>Timeout: wie lange auf die Antwort gewartet wird. Lokale CPU-Inferenz braucht fuer einen
     langen Bericht oft mehrere Minuten - bei "Read timed out" diesen Wert erhoehen.</li>
    <li>Max. Antwort-Tokens: Laenge der Antwort. Kleinerer Wert = schnellerer, kuerzerer Bericht.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li>You can configure up to three OpenAI-compatible endpoints. They are tried <b>top to bottom</b>:
     the first one reachable and not already busy writes the report. If one fails, the next takes over.</li>
    <li>URLs usually end in <code>/v1</code>, e.g. <code>http://192.168.1.111:11434/v1</code> (Ollama),
     <code>:1234/v1</code> (LM Studio), <code>:8090/v1</code> (llama.cpp).</li>
    <li>"Check endpoints" shows per row: detected backend type, whether the model is loaded,
     and whether it is currently generating.</li>
    <li><b>Unloading:</b> Ollama and LM Studio can drop the model from memory after the analysis.
     This only happens if the analyzer loaded it itself - if it was already loaded, someone else
     is using it and it stays. llama.cpp keeps its model resident, which makes it a good last fallback.</li>
    <li>Timeout: how long to wait for the response. Local CPU inference often needs several minutes
     for a long report - raise this on "Read timed out".</li>
    <li>Max response tokens: length of the answer. Lower value = faster, shorter report.</li>
   </ul>
  </div>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="model">
   <div class="epgrid epgrid-head">
    <div>#</div><div>Name</div><div>Endpoint-URL</div><div>Modell</div>
   </div>
   {endpoint_rows}
   <div class="btnrow">
    <button type="button" class="btn-secondary" onclick="probeEndpoints()">&#128269; Endpunkte pruefen</button>
    <button type="button" class="btn-secondary" onclick="testLLM()">Modelle von Endpunkt 1 laden</button>
   </div>
   <div id="llmTestResult" class="muted"></div>
   <datalist id="model_list">{model_options}</datalist>
   <label><input type="checkbox" name="llm_unload_after" value="1" {unload_after}>
    Modell nach der Analyse wieder entladen (nur wenn der Analyzer es selbst geladen hat)</label>
   <div class="grid2">
    <div><label for="llmto">Timeout in Sekunden</label>
     <input type="number" name="llm_timeout" id="llmto" min="30" max="3600" value="{llm_timeout}"></div>
    <div><label for="llmmt">Max. Antwort-Tokens</label>
     <input type="number" name="llm_max_tokens" id="llmmt" min="256" max="32768" value="{llm_max_tokens}"></div>
   </div>
   <br><button type="submit">&#128190; Speichern</button>
  </form>
 </div>
 <div class="card">
  <h2>Zeitplan &amp; Sprache</h2>
  <div class="label-row">
   <span style="color:#9a9aa5;font-size:13px">Wann und in welcher Sprache der Report erstellt wird</span>
   <button type="button" class="help-toggle" onclick="toggleHelp('scheduleHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="scheduleHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li>Haeufigkeit: taeglich, woechentlich (an einem festen Wochentag) oder monatlich (an einem festen Tag im Monat - faellt in kuerzeren Monaten automatisch auf den letzten Tag).</li>
    <li>Die Uhrzeit gilt fuer alle drei Haeufigkeiten.</li>
    <li>Berichtssprache bestimmt E-Mail-Text, Status-Woerter und die Sprache der eingebauten Standard-Prompt-Vorlage.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li>Frequency: daily, weekly (on a fixed weekday) or monthly (on a fixed day of month - automatically clamped to the last day in shorter months).</li>
    <li>The time applies to all three frequencies.</li>
    <li>Report language controls the email text, status words, and the language of the built-in default prompt template.</li>
   </ul>
  </div>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="schedule">
   <label for="freq">Haeufigkeit</label>
   <select name="report_frequency" id="freq" onchange="onFrequencyChange()">
    <option value="daily" {freq_daily_sel}>Taeglich</option>
    <option value="weekly" {freq_weekly_sel}>Woechentlich</option>
    <option value="monthly" {freq_monthly_sel}>Monatlich</option>
   </select>
   <div id="freqWeekly" style="{freq_weekly_style}">
    <label for="weekday">Wochentag</label>
    <select name="report_weekday" id="weekday">{weekday_options}</select>
   </div>
   <div id="freqMonthly" style="{freq_monthly_style}">
    <label for="dom">Tag im Monat (1-31, wird bei kurzen Monaten auf den Monatsletzten geklemmt)</label>
    <input type="number" name="report_day_of_month" id="dom" min="1" max="31" value="{report_day_of_month}">
   </div>
   <label for="time">Uhrzeit</label>
   <input type="time" name="report_schedule" id="time" value="{schedule}">
   <label for="replang">Berichtssprache (E-Mail-Text, Status-Woerter, Standard-Prompt)</label>
   <select name="report_language" id="replang">
    <option value="de" {lang_de_sel}>Deutsch</option>
    <option value="en" {lang_en_sel}>English</option>
   </select>
   <br><button type="submit">&#128190; Speichern</button>
  </form>
 </div>
 <div class="card">
  <h2>Prompt-Vorlage</h2>
  <div class="label-row">
   <label for="promptSelect" style="margin:0">Vorlage laden (Eingebaut oder Eigene)</label>
   <button type="button" class="help-toggle" onclick="toggleHelp('promptHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="promptHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li><b>Eingebaut</b>: feste Vorlagen (Standard/Kurz/Technisch, DE/EN) - nicht veraenderbar.</li>
    <li><b>Eigene Vorlagen</b>: eure gespeicherten Texte - verwaltet ueber Hinzufuegen/Aktualisieren/Loeschen.</li>
    <li>Eine Auswahl aus der Liste laedt den Text nur in das Feld unten - erst "Speichern" macht ihn aktiv
     (ein "nicht gespeichert"-Hinweis erscheint, solange das Feld vom gespeicherten Stand abweicht).</li>
    <li>Platzhalter im Text: <code>$threat_intel</code> (AbuseIPDB), <code>$research</code> (SearXNG),
     <code>$log_text</code> (Rohlogs).</li>
    <li>Leeres Feld + Speichern = eingebaute Standard-Vorlage der gewaehlten Berichtssprache.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li><b>Built-in</b>: fixed templates (Standard/Short/Technical, DE/EN) - cannot be changed.</li>
    <li><b>Custom templates</b>: your saved texts - manage via Add/Update/Delete.</li>
    <li>Picking one from the list only loads its text into the field below - only "Save" makes it active
     (an "unsaved" hint appears while the field differs from the saved version).</li>
    <li>Placeholders: <code>$threat_intel</code> (AbuseIPDB), <code>$research</code> (SearXNG),
     <code>$log_text</code> (raw logs).</li>
    <li>Empty field + Save = built-in default template for the selected report language.</li>
   </ul>
  </div>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="prompt">
   <div class="btnrow">
    <select id="promptSelect" onchange="onPromptSelect()">
     <option value="">-- eigener Text (unten) --</option>
     <optgroup label="Eingebaut (Deutsch)">{preset_options_de}</optgroup>
     <optgroup label="Eingebaut (English)">{preset_options_en}</optgroup>
     <optgroup label="Eigene Vorlagen">{custom_prompt_options}</optgroup>
    </select>
   </div>
   <div class="btnrow">
    <button type="button" class="btn-secondary" onclick="addPromptToLibrary()">&#10133; Hinzufuegen</button>
    <button type="button" class="btn-secondary" onclick="updatePromptInLibrary()">&#128260; Aktualisieren</button>
    <button type="button" class="btn-secondary" onclick="deletePromptFromLibrary()">&#128465; Loeschen</button>
   </div>
   <label for="prompt">Prompt-Text (Platzhalter: $threat_intel, $research, $log_text)</label>
   <textarea name="llm_prompt_template" id="prompt" rows="12" oninput="checkPromptDirty()">{llm_prompt_template}</textarea>
   <script>document.getElementById('prompt').dataset.original = document.getElementById('prompt').value;</script>
   <div class="btnrow">
    <button type="submit">&#128190; Speichern</button>
    <button type="button" class="btn-secondary" onclick="document.getElementById('prompt').value = DEFAULT_PROMPT_TEMPLATE; checkPromptDirty();">Standard wiederherstellen</button>
    <span id="promptDirty" class="warn" style="font-size:12px;display:none">&#9679; nicht gespeichert / unsaved</span>
   </div>
  </form>
 </div>
 <div class="card">
  <h2>Log-Quelle</h2>
  <div class="label-row">
   <span style="color:#9a9aa5;font-size:13px">Woher die Logs fuer die Analyse kommen</span>
   <button type="button" class="help-toggle" onclick="toggleHelp('logsourceHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="logsourceHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li>Graylog: Standard-Log-Quelle, braucht Host/Port/Zugangsdaten eurer Graylog-Instanz.</li>
    <li>UniFi-Controller direkt (Beta): nutzt Host/API-Key aus der Gateway-Sperrung weiter unten, kein Graylog noetig; haengt von Controller-/Firmware-Version ab.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li>Graylog: default log source, needs host/port/credentials of your Graylog instance.</li>
    <li>UniFi controller directly (beta): uses host/API key from the gateway blocking section below, no Graylog needed; depends on controller/firmware version.</li>
   </ul>
  </div>
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
  <div class="label-row">
   <span style="color:#9a9aa5;font-size:13px">Wie und wohin der Report per Mail verschickt wird</span>
   <button type="button" class="help-toggle" onclick="toggleHelp('smtpHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="smtpHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li>Eigenstaendige SMTP-Konfiguration fuer den Report-Versand, unabhaengig von anderen Systemen.</li>
    <li>Verschluesselung: SSL (meist Port 465), STARTTLS (meist Port 587) oder Keine.</li>
    <li>Betreff-Vorlage akzeptiert den Platzhalter <code>$date</code>.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li>Standalone SMTP configuration for sending the report, independent of other systems.</li>
    <li>Encryption: SSL (usually port 465), STARTTLS (usually port 587), or None.</li>
    <li>Subject template accepts the <code>$date</code> placeholder.</li>
   </ul>
  </div>
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
   <label for="ssubj">Betreff-Vorlage (Platzhalter: $date)</label>
   <input type="text" name="email_subject" id="ssubj" value="{email_subject}" placeholder="UniFi Netzwerk-Analyse - $date">
   <label for="etheme">E-Mail-Design</label>
   <select name="email_theme" id="etheme">
    <option value="auto" {theme_auto_sel}>Automatisch (folgt dem Mail-Programm)</option>
    <option value="light" {theme_light_sel}>Hell</option>
    <option value="dark" {theme_dark_sel}>Dunkel</option>
   </select>
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">Eigenstaendige SMTP-Konfiguration, unabhaengig von anderen Systemen.</div>
 </div>
 <div class="card">
  <h2>Bedrohungserkennung &amp; Recherche</h2>
  <div class="label-row">
   <span style="color:#9a9aa5;font-size:13px">Optionale IP-Reputation und Online-Recherche</span>
   <button type="button" class="help-toggle" onclick="toggleHelp('abuseHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="abuseHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li>AbuseIPDB API-Key (kostenlos auf abuseipdb.com erstellbar): ohne Key wird die IP-Reputationspruefung uebersprungen.</li>
    <li>SearXNG-URL (optional): eigene Instanz mit aktiviertem JSON-Format (<code>search.formats</code> in settings.yml), fuer Online-Recherche zu auffaelligen Fehlermeldungen.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li>AbuseIPDB API key (free at abuseipdb.com): without a key, IP reputation checks are skipped.</li>
    <li>SearXNG URL (optional): your own instance with JSON format enabled (<code>search.formats</code> in settings.yml), used for online research on unusual error messages.</li>
   </ul>
  </div>
  <form method="POST" action="/settings">
   <input type="hidden" name="form_id" value="abuseipdb">
   <label for="aik">AbuseIPDB API-Key</label>
   <input type="password" name="abuseipdb_key" id="aik" value="{abuseipdb_key}" autocomplete="new-password">
   <label for="sxng">SearXNG-URL (optional, fuer Online-Recherche zu Fehlermeldungen)</label>
   <input type="text" name="searxng_url" id="sxng" value="{searxng_url}" placeholder="http://searxng-host:8080">
   <br><button type="submit">&#128190; Speichern</button>
  </form>
  <div class="muted">AbuseIPDB optional (ohne Key wird die IP-Reputationspruefung uebersprungen). SearXNG optional (ohne URL wird zu Fehlern/Warnungen nicht online recherchiert). Eigene SearXNG-Instanz noetig, JSON-Format muss dort aktiviert sein.</div>
 </div>
 <div class="card">
  <h2>UniFi-Gateway IP-Sperrung</h2>
  <div class="label-row">
   <span style="color:#9a9aa5;font-size:13px">Automatisches Blockieren boesartiger IPs am Gateway</span>
   <button type="button" class="help-toggle" onclick="toggleHelp('blockHelp')" aria-label="Hilfe anzeigen" title="Hilfe anzeigen">?</button>
  </div>
  <div id="blockHelp" class="helpbox" hidden>
   <b>Deutsch:</b>
   <ul>
    <li>Sperrung aktiviert: Master-Schalter fuer automatisches Blockieren am Gateway.</li>
    <li>Dry-Run: nur simulieren/loggen, es wird nichts wirklich gesperrt - empfohlen zum ersten Testen.</li>
    <li>UniFi-Host/API-Key: Adresse und Integration-API-Key (X-API-KEY) eures Controllers; werden auch fuer "UniFi-Controller direkt" als Log-Quelle verwendet.</li>
    <li>Block-Schwelle: Mindest-AbuseIPDB-Score, ab dem eine IP gesperrt wird.</li>
    <li>Allowlist: IPs/CIDR-Bloecke, kommagetrennt, die nie gesperrt werden.</li>
   </ul>
   <b>English:</b>
   <ul>
    <li>Blocking enabled: master switch for automatic blocking on the gateway.</li>
    <li>Dry-run: only simulate/log, nothing is actually blocked - recommended for initial testing.</li>
    <li>UniFi host/API key: address and Integration API key (X-API-KEY) of your controller; also used for "UniFi controller directly" as log source.</li>
    <li>Block threshold: minimum AbuseIPDB score at which an IP gets blocked.</li>
    <li>Allowlist: comma-separated IPs/CIDR blocks that are never blocked.</li>
   </ul>
  </div>
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
  {ampel_badge}
  <pre>{report}</pre>
 </div>
</div></body></html>"""


_SETTINGS_DEFAULTS = {
    "schedule": "-", "schedule_summary": "-", "email": "-", "model": "-", "abuseipdb": False,
    "report_frequency": "daily", "report_weekday": "mon", "report_day_of_month": 1,
    "report_language": "de",
    "log_source": "graylog",
    "graylog_host": "graylog", "graylog_port": "9000",
    "graylog_user": "admin", "graylog_password": "",
    "llm_base_url": "", "llm_timeout": 600, "llm_max_tokens": 4096,
    "llm_endpoints": [], "llm_unload_after": True,
    "abuseipdb_key": "", "searxng_url": "",
    "llm_prompt_template": "", "llm_prompt_template_default": "",
    "llm_prompt_presets": {}, "llm_prompt_preset_labels": {}, "llm_prompt_library": {},
    "smtp_host": "", "smtp_port": 465, "smtp_user": "", "smtp_password": "",
    "smtp_security": "ssl", "smtp_from": "", "email_to": "", "email_subject": "", "email_theme": "auto",
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


def make_handler():
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

            ampel = STATE.get("last_ampel")
            if ampel in _AMPEL_LABELS:
                label, cls = _AMPEL_LABELS[ampel]
                ampel_badge = '<div class="row"><span class="k">Ampel</span><span class="v {0}">{1}</span></div>'.format(cls, label)
            else:
                ampel_badge = ""

            def esc(key, default=""):
                return html.escape(str(st.get(key, default) or default))

            default_prompt_json = json.dumps(st.get("llm_prompt_template_default") or "").replace("</", "<\\/")
            preset_templates = st.get("llm_prompt_presets") or {}
            preset_labels = st.get("llm_prompt_preset_labels") or {}
            custom_templates = st.get("llm_prompt_library") or {}
            preset_templates_json = json.dumps(preset_templates).replace("</", "<\\/")
            custom_templates_json = json.dumps(custom_templates).replace("</", "<\\/")
            def _preset_opts(prefix):
                return "".join(
                    '<option value="preset:{0}">{1}</option>'.format(html.escape(k), html.escape(preset_labels.get(k, k)))
                    for k in sorted(preset_templates)
                    if k.startswith(prefix)
                )
            preset_options_de = _preset_opts("de:")
            preset_options_en = _preset_opts("en:")
            custom_prompt_options = "".join(
                '<option value="custom:{0}">{0}</option>'.format(html.escape(name))
                for name in sorted(custom_templates.keys())
            ) or '<option value="" disabled>(keine)</option>'
            status_json = json.dumps(status).replace("</", "<\\/")
            report_language = st.get("report_language") or "de"

            # Drei Endpunkt-Slots: vorhandene Konfiguration auffuellen, Rest leer.
            eps = list(st.get("llm_endpoints") or [])
            ep_rows = []
            for i in range(3):
                ep = eps[i] if i < len(eps) else {}
                idx = i + 1
                label = "primaer" if i == 0 else "Fallback"
                ep_rows.append(
                    '<div class="epgrid">'
                    '<div class="epnum" title="{lbl}">{n}</div>'
                    '<div><input type="text" name="ep{n}_name" value="{nm}" placeholder="{ph}"></div>'
                    '<div><input type="text" name="ep{n}_url" id="ep{n}_url" value="{url}" placeholder="http://host:11434/v1"></div>'
                    '<div><input type="text" name="ep{n}_model" list="model_list" value="{mdl}" placeholder="Modellname"></div>'
                    '<div class="eprow-status" id="epstatus{n}"></div>'
                    '</div>'.format(
                        n=idx, lbl=label,
                        nm=html.escape(str(ep.get("name") or "")),
                        url=html.escape(str(ep.get("base_url") or "")),
                        mdl=html.escape(str(ep.get("model") or "")),
                        ph=("Ollama" if i == 0 else ("LM Studio" if i == 1 else "llama.cpp")),
                    )
                )
            endpoint_rows = "".join(ep_rows)

            frequency = st.get("report_frequency") or "daily"
            weekday = st.get("report_weekday") or "mon"
            weekday_options = "".join(
                '<option value="{0}" {1}>{2}</option>'.format(
                    key, "selected" if key == weekday else "", label
                )
                for key, label in _WEEKDAY_LABELS_DE
            )

            return PAGE.format(
                flash=flash_html,
                status=html.escape(status), statusclass=sc,
                last_run=html.escape(str(STATE["last_run"] or "-")),
                schedule=html.escape(str(st.get("schedule", "-"))),
                schedule_summary=html.escape(str(st.get("schedule_summary", "-"))),
                freq_daily_sel=("selected" if frequency == "daily" else ""),
                freq_weekly_sel=("selected" if frequency == "weekly" else ""),
                freq_monthly_sel=("selected" if frequency == "monthly" else ""),
                freq_weekly_style=("" if frequency == "weekly" else "display:none"),
                freq_monthly_style=("" if frequency == "monthly" else "display:none"),
                weekday_options=weekday_options,
                report_day_of_month=html.escape(str(st.get("report_day_of_month", 1) or 1)),
                email=html.escape(str(st.get("email", "-"))),
                model=html.escape(str(cur_model)),
                abuse=("aktiv" if abuse_active else "nicht konfiguriert"),
                abuseclass=("ok" if abuse_active else "warn"),
                model_options=opts,
                report=html.escape(report),
                ampel_badge=ampel_badge,
                disabled=("disabled" if STATE["running"] else ""),
                log_source_label=("UniFi direkt" if log_source == "unifi_direct" else "Graylog"),
                endpoint_rows=endpoint_rows,
                unload_after=("checked" if st.get("llm_unload_after") else ""),
                llm_timeout=esc("llm_timeout", "600"),
                llm_max_tokens=esc("llm_max_tokens", "4096"),
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
                searxng_url=esc("searxng_url"),
                llm_prompt_template=esc("llm_prompt_template"),
                default_prompt_json=default_prompt_json,
                preset_templates_json=preset_templates_json,
                custom_templates_json=custom_templates_json,
                preset_options_de=preset_options_de,
                preset_options_en=preset_options_en,
                lang_de_sel=("selected" if report_language == "de" else ""),
                lang_en_sel=("selected" if report_language == "en" else ""),
                custom_prompt_options=custom_prompt_options,
                status_json=status_json,
                email_subject=esc("email_subject"),
                theme_auto_sel=("selected" if (st.get("email_theme") or "auto") == "auto" else ""),
                theme_light_sel=("selected" if st.get("email_theme") == "light" else ""),
                theme_dark_sel=("selected" if st.get("email_theme") == "dark" else ""),
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
            elif self.path == "/probe_endpoints":
                try:
                    result = _probe_endpoints() if _probe_endpoints else []
                except Exception as e:  # noqa
                    result = [{"name": "Fehler", "ok": False, "message": str(e)}]
                body = json.dumps(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path.startswith("/test_llm"):
                qs = parse_qs(urlparse(self.path).query)
                base_url = (qs.get("base_url") or [""])[0]
                if _test_llm:
                    result = _test_llm(base_url or None)
                else:
                    result = {"ok": False, "models": [], "message": "Nicht verfuegbar"}
                body = json.dumps(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
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
                    # Endpunkt-Slots einsammeln; nur Zeilen mit URL und Modell
                    # zaehlen, die Reihenfolge ist die Fallback-Reihenfolge.
                    eps = []
                    for i in (1, 2, 3):
                        url = (form.get(f"ep{i}_url") or "").strip()
                        mdl = (form.get(f"ep{i}_model") or "").strip()
                        nm = (form.get(f"ep{i}_name") or "").strip() or f"Endpunkt {i}"
                        if url and mdl:
                            eps.append({"name": nm, "base_url": url, "model": mdl})
                    if eps:
                        updates["llm_endpoints"] = json.dumps(eps, ensure_ascii=False)
                        # Erster Endpunkt bleibt zusaetzlich in den Einzelfeldern,
                        # damit Status-Karte und aeltere ENV-Nutzung stimmig bleiben.
                        updates["llm_base_url"] = eps[0]["base_url"]
                        updates["ollama_model"] = eps[0]["model"]
                    updates["llm_unload_after"] = bool(form.get("llm_unload_after"))
                    if form.get("llm_timeout"):
                        try:
                            updates["llm_timeout"] = max(30, min(3600, int(form["llm_timeout"])))
                        except ValueError:
                            pass
                    if form.get("llm_max_tokens"):
                        try:
                            updates["llm_max_tokens"] = max(256, min(32768, int(form["llm_max_tokens"])))
                        except ValueError:
                            pass
                elif form_id == "schedule":
                    if form.get("report_schedule"):
                        updates["report_schedule"] = form["report_schedule"]
                    if form.get("report_frequency") in ("daily", "weekly", "monthly"):
                        updates["report_frequency"] = form["report_frequency"]
                    if form.get("report_weekday") in ("mon", "tue", "wed", "thu", "fri", "sat", "sun"):
                        updates["report_weekday"] = form["report_weekday"]
                    if form.get("report_day_of_month"):
                        try:
                            updates["report_day_of_month"] = max(1, min(31, int(form["report_day_of_month"])))
                        except ValueError:
                            pass
                    if form.get("report_language") in ("de", "en"):
                        updates["report_language"] = form["report_language"]
                elif form_id == "prompt":
                    # parse_qs() verwirft standardmaessig leere Werte - das Prompt-Feld
                    # muss aber explizit leerbar sein (Fallback auf Standard-Vorlage).
                    raw_form = parse_qs(raw, keep_blank_values=True)
                    updates["llm_prompt_template"] = raw_form.get("llm_prompt_template", [""])[0].strip()
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
                    if "email_subject" in form:
                        updates["email_subject"] = form["email_subject"].strip()
                    if form.get("email_theme") in ("auto", "light", "dark"):
                        updates["email_theme"] = form["email_theme"]
                elif form_id == "abuseipdb":
                    if "abuseipdb_key" in form:
                        updates["abuseipdb_key"] = form["abuseipdb_key"].strip()
                    if "searxng_url" in form:
                        updates["searxng_url"] = form["searxng_url"].strip()
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
            elif self.path == "/promptlib":
                action = form.get("action", "")
                name = form.get("name", "")
                content = form.get("content", "")
                if _manage_prompt_library:
                    try:
                        _manage_prompt_library(action, name, content)
                    except Exception:  # noqa
                        pass
                self._redirect("/")
            else:
                self.send_response(404); self.end_headers()
    return Handler


def start(port=8088):
    handler = make_handler()
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv
