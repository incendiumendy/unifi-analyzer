"""Mehrere LLM-Endpunkte mit Fallback-Kette und Modell-Lebenszyklus.

Der Analyzer kann mehrere OpenAI-kompatible Endpunkte kennen (z.B. Ollama,
LM Studio, llama.cpp) und arbeitet sie der Reihe nach ab: der erste, der
erreichbar ist und antwortet, liefert den Bericht.

Zusaetzlich wird - soweit das Backend das hergibt - das Modell nur fuer die
Analyse in den Speicher geladen und danach wieder entladen. Entladen wird
dabei ausschliesslich, was der Analyzer selbst geladen hat: war das Modell
vorher schon geladen, benutzt es offensichtlich noch jemand anderes und es
bleibt unangetastet.

Was die Backends koennen:
  ollama    - laedt bei Bedarf, entladen via keep_alive=0, /api/ps zeigt Geladenes
  lmstudio  - JIT-Loading, entladen via ttl im Request, /api/v0/models zeigt state
  llamacpp  - Modell ist beim Serverstart fest geladen, kein Laden/Entladen
              moeglich; dafuer zeigt /slots ob gerade gerechnet wird
  openai    - generisch, kein Lebenszyklus (z.B. echte OpenAI-API)
"""
import json
import logging
import requests

log = logging.getLogger("llm_pool")

# Wie lange auf die reinen Status-Abfragen gewartet wird (nicht die Analyse).
PROBE_TIMEOUT = 6


def api_root(base_url):
    """Wurzel-URL ohne das OpenAI-Suffix. Die Verwaltungs-Endpunkte von Ollama
    und LM Studio liegen neben /v1, nicht darunter."""
    base = (base_url or "").rstrip("/")
    for suffix in ("/v1", "/api/v0"):
        if base.endswith(suffix):
            return base[: -len(suffix)]
    return base


def chat_url(base_url):
    """Vollstaendige URL fuer den Chat-Completion-Aufruf."""
    base = (base_url or "").rstrip("/")
    if base.endswith("/chat/completions"):
        return base
    if not base.endswith("/v1"):
        base += "/v1"
    return base + "/chat/completions"


def detect_kind(base_url, timeout=PROBE_TIMEOUT):
    """Erkennt die Backend-Art anhand ihrer typischen Zusatz-Endpunkte."""
    root = api_root(base_url)
    probes = (
        ("ollama", "/api/tags"),
        ("lmstudio", "/api/v0/models"),
        ("llamacpp", "/props"),
    )
    for kind, path in probes:
        try:
            r = requests.get(root + path, timeout=timeout)
            if r.status_code == 200:
                return kind
        except Exception:
            continue
    return "openai"


def is_reachable(base_url, timeout=PROBE_TIMEOUT):
    base = (base_url or "").rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    try:
        return requests.get(base + "/models", timeout=timeout).status_code == 200
    except Exception:
        return False


def loaded_models(base_url, kind, timeout=PROBE_TIMEOUT):
    """Aktuell im Speicher liegende Modelle. Leere Liste heisst 'keines' ODER
    'Backend kann das nicht sagen' - beides fuehrt dazu, dass wir nichts
    entladen, was wir nicht selbst geladen haben."""
    root = api_root(base_url)
    try:
        if kind == "ollama":
            data = requests.get(root + "/api/ps", timeout=timeout).json()
            return [m.get("name") or m.get("model") for m in data.get("models", [])]
        if kind == "lmstudio":
            data = requests.get(root + "/api/v0/models", timeout=timeout).json()
            return [m.get("id") for m in data.get("data", []) if m.get("state") == "loaded"]
        if kind == "llamacpp":
            # Modell haengt fest am laufenden Server - was /v1/models meldet, ist geladen.
            data = requests.get(root + "/v1/models", timeout=timeout).json()
            return [m.get("id") for m in data.get("data", [])]
    except Exception as e:
        log.debug(f"loaded_models({base_url}, {kind}) fehlgeschlagen: {e}")
    return []


def is_busy(base_url, kind, timeout=PROBE_TIMEOUT):
    """True, wenn das Backend gerade an einer Anfrage rechnet. Nur llama.cpp
    legt das offen (/slots); bei den anderen nehmen wir 'nicht beschaeftigt'
    an, da sie Anfragen ohnehin serialisieren."""
    if kind != "llamacpp":
        return False
    try:
        slots = requests.get(api_root(base_url) + "/slots", timeout=timeout).json()
        if isinstance(slots, list):
            return any(s.get("is_processing") for s in slots)
    except Exception as e:
        log.debug(f"is_busy({base_url}) fehlgeschlagen: {e}")
    return False


def unload(base_url, kind, model, timeout=PROBE_TIMEOUT):
    """Entlaedt das Modell aus dem Speicher, sofern das Backend das kann.
    Gibt True zurueck, wenn tatsaechlich entladen wurde."""
    root = api_root(base_url)
    try:
        if kind == "ollama":
            # keep_alive=0 weist Ollama an, das Modell sofort freizugeben.
            requests.post(root + "/api/generate",
                          json={"model": model, "keep_alive": 0}, timeout=timeout)
            log.info(f"Modell '{model}' auf {root} entladen (Ollama keep_alive=0).")
            return True
        if kind == "lmstudio":
            # LM Studio kennt kein explizites Unload ueber die REST-API; die
            # kurze TTL im Analyse-Request (siehe _lifecycle_extra) laesst das
            # JIT-geladene Modell von selbst wieder auslaufen.
            log.info(f"LM Studio auf {root}: Modell laeuft ueber die gesetzte TTL aus.")
            return False
    except Exception as e:
        log.warning(f"Entladen von '{model}' auf {root} fehlgeschlagen: {e}")
    return False


def _lifecycle_extra(kind, unload_after):
    """Zusatzfelder im Chat-Request, mit denen das Backend das Modell nach
    getaner Arbeit selbst wieder freigibt."""
    if not unload_after:
        return {}
    if kind == "ollama":
        return {"keep_alive": 0}
    if kind == "lmstudio":
        return {"ttl": 60}
    return {}


def probe(endpoint, timeout=PROBE_TIMEOUT):
    """Statusbild eines Endpunkts fuer die GUI."""
    base = endpoint.get("base_url") or ""
    name = endpoint.get("name") or base
    model = endpoint.get("model") or ""
    if not base:
        return {"name": name, "base_url": base, "ok": False, "kind": "-",
                "message": "Keine URL hinterlegt", "loaded": [], "busy": False}
    kind = detect_kind(base, timeout=timeout)
    ok = is_reachable(base, timeout=timeout)
    if not ok:
        return {"name": name, "base_url": base, "ok": False, "kind": kind,
                "message": "nicht erreichbar", "loaded": [], "busy": False}
    loaded = loaded_models(base, kind, timeout=timeout)
    busy = is_busy(base, kind, timeout=timeout)
    hit = bool(model) and any(model in (m or "") or (m or "") in model for m in loaded)
    parts = [kind]
    parts.append("Modell geladen" if hit else ("nichts geladen" if not loaded else "anderes Modell geladen"))
    if busy:
        parts.append("rechnet gerade")
    return {"name": name, "base_url": base, "ok": True, "kind": kind,
            "message": ", ".join(parts), "loaded": [m for m in loaded if m], "busy": busy}


def chat(prompt, endpoints, timeout, max_tokens, unload_after=True, temperature=0.3):
    """Arbeitet die Endpunkte der Reihe nach ab und liefert (text, info).

    info enthaelt den verwendeten Endpunkt und die Fehler der uebersprungenen,
    damit im Log nachvollziehbar ist, warum welcher Endpunkt drankam.
    """
    errors = []
    for ep in endpoints:
        base = (ep.get("base_url") or "").strip()
        model = (ep.get("model") or "").strip()
        name = ep.get("name") or base
        if not base or not model:
            continue

        kind = detect_kind(base)
        if not is_reachable(base):
            errors.append(f"{name}: nicht erreichbar")
            log.info(f"LLM-Endpunkt '{name}' ({base}) nicht erreichbar - naechster.")
            continue
        if is_busy(base, kind):
            errors.append(f"{name}: rechnet bereits an etwas anderem")
            log.info(f"LLM-Endpunkt '{name}' ist beschaeftigt - naechster.")
            continue

        # Merken, ob das Modell schon vor uns im Speicher lag: dann benutzt es
        # jemand anderes und wir raeumen es hinterher nicht weg.
        before = loaded_models(base, kind)
        was_loaded = any(model in (m or "") or (m or "") in model for m in before)
        if not was_loaded:
            log.info(f"Modell '{model}' auf '{name}' noch nicht geladen - wird fuer die Analyse geladen.")

        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        payload.update(_lifecycle_extra(kind, unload_after and not was_loaded))

        try:
            resp = requests.post(chat_url(base), json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            content = (data.get("choices") or [{}])[0].get("message", {}).get("content")
            text = (content or "").strip()
            if not text:
                errors.append(f"{name}: leere Antwort")
                continue
            info = {"endpoint": name, "base_url": base, "model": model, "kind": kind,
                    "was_loaded": was_loaded, "unloaded": False, "errors": errors}
            if unload_after and not was_loaded:
                info["unloaded"] = unload(base, kind, model)
            return text, info
        except requests.exceptions.ReadTimeout:
            errors.append(f"{name}: Timeout nach {timeout}s")
            log.warning(f"LLM-Endpunkt '{name}' Timeout nach {timeout}s - naechster.")
            if unload_after and not was_loaded:
                unload(base, kind, model)
        except Exception as e:
            errors.append(f"{name}: {e}")
            log.warning(f"LLM-Endpunkt '{name}' fehlgeschlagen: {e} - naechster.")
            if unload_after and not was_loaded:
                unload(base, kind, model)

    return None, {"endpoint": None, "errors": errors}
