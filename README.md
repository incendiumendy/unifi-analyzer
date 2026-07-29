# UniFi Analyzer

Docker-Container, der die UniFi-Netzwerk-Logs periodisch (oder auf Knopfdruck)
einsammelt, von einem beliebigen OpenAI-kompatiblen LLM (z. B. LM Studio,
Ollama, OpenAI) analysieren lässt und das Ergebnis als E-Mail-Bericht mit
Ampel-Status (Grün/Gelb/Rot) verschickt. Komplett über eine Web-GUI
konfigurierbar, kein Neustart nötig.

## Features

- **Log-Quelle**: Graylog oder direkt vom UniFi-Controller (Beta)
- **Analyse** durch ein frei wählbares OpenAI-kompatibles LLM
- **Täglicher Report per E-Mail** (SMTP, Design hell/dunkel/automatisch) mit
  Ampel-Status
- **AbuseIPDB**-Reputationsprüfung für erkannte öffentliche IPs im Log
- **Automatische IP-Sperrung** am UniFi-Gateway ab einem konfigurierbaren
  AbuseIPDB-Score (Dry-Run standardmäßig aktiv, Allowlist konfigurierbar)
- **Online-Recherche** zu auffälligen Fehlermeldungen via SearXNG (optional)
- **Prompt-Bibliothek**: eigene Prompt-Vorlagen speichern/bearbeiten,
  eingebaute Vorlagen (Standard/Kurz/Technisch) auf Deutsch und Englisch
- **Web-GUI** für die gesamte Konfiguration, Statusanzeige und manuelles
  Auslösen einer Analyse

## Schnellstart (Docker)

```bash
docker run -d \
  --name unifi-analyzer \
  -p 8088:8088 \
  -v /mnt/user/appdata/unifi-analyzer:/data \
  -e TZ=Europe/Berlin \
  ghcr.io/incendiumendy/unifi-analyzer:latest
```

Danach die Web-GUI unter `http://<host>:8088` öffnen und dort LLM-Endpoint,
Log-Quelle, SMTP, AbuseIPDB usw. konfigurieren. ENV-Variablen sind nur ein
optionaler Startwert – sobald etwas in der GUI gespeichert wurde, hat das
Vorrang (siehe [appconfig.py](appconfig.py)).

## Docker Compose

```yaml
services:
  unifi-analyzer:
    image: ghcr.io/incendiumendy/unifi-analyzer:latest
    container_name: unifi-analyzer
    restart: unless-stopped
    ports:
      - "8088:8088"
    volumes:
      - ./data:/data
    environment:
      - TZ=Europe/Berlin
```

## Konfiguration

Alle Einstellungen sind über die Web-GUI editierbar und werden persistent
unter `/data/settings.json` gespeichert (Pfad über `SETTINGS_PATH`
änderbar). Die folgenden ENV-Variablen dienen nur als initialer Startwert:

| Variable | Standard | Bedeutung |
|---|---|---|
| `OLLAMA_MODEL` | `gemma4:12b` | Modellname am LLM-Endpoint |
| `LLM_BASE_URL` | `http://lm-studio:1234/v1` | OpenAI-kompatibler LLM-Endpoint |
| `REPORT_FREQUENCY` | `daily` | Häufigkeit: `daily`/`weekly`/`monthly` |
| `REPORT_SCHEDULE` | `08:00` | Uhrzeit für den Report |
| `REPORT_WEEKDAY` | `mon` | Wochentag bei `weekly` (`mon`..`sun`) |
| `REPORT_DAY_OF_MONTH` | `1` | Tag im Monat bei `monthly` (1-31, wird in kürzeren Monaten geklemmt) |
| `REPORT_LANGUAGE` | `de` | Berichtssprache (`de`/`en`) |
| `LOG_SOURCE` | `graylog` | `graylog` oder `unifi_direct` |
| `GRAYLOG_HOST` / `GRAYLOG_PORT` | `graylog` / `9000` | Graylog-Zugang |
| `GRAYLOG_USER` / `GRAYLOG_PASSWORD` | `admin` / `admin` | Graylog-Zugangsdaten |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_SECURITY`, `SMTP_FROM` | – | SMTP-Konfiguration für den Report-Versand |
| `EMAIL_TO` | – | Empfänger des Reports |
| `EMAIL_SUBJECT` | – | Betreff-Vorlage (Platzhalter `$date`) |
| `EMAIL_THEME` | `auto` | E-Mail-Design: `auto`/`light`/`dark` |
| `ABUSEIPDB_KEY` | – | API-Key für die IP-Reputationsprüfung |
| `SEARXNG_URL` | – | SearXNG-Instanz für Online-Recherche zu Fehlern |
| `UNIFI_BLOCK_ENABLED` | `false` | Automatische Gateway-IP-Sperrung aktivieren |
| `UNIFI_DRY_RUN` | `true` | Nur simulieren, nicht wirklich sperren |
| `UNIFI_HOST` | `https://192.168.1.1` | UniFi-Controller (für Sperrung / `unifi_direct`) |
| `UNIFI_API_KEY` | – | UniFi Integration-API-Key (X-API-KEY) |
| `UNIFI_BLOCK_THRESHOLD` | `95` | Mindest-AbuseIPDB-Score zum Sperren |
| `UNIFI_ALLOWLIST` | – | IPs/CIDR, kommagetrennt, die nie gesperrt werden |

## Unraid

Läuft direkt als Unraid-Docker-Container. Über **Community Applications**
installierbar (sobald gelistet) oder manuell als Template-Repository unter
**Docker → Add Container → Template Repositories** mit dieser URL:

```
https://raw.githubusercontent.com/incendiumendy/unifi-analyzer/master/unraid/unifi-analyzer.xml
```

Siehe [unraid/](unraid/) für das Template selbst.

## Sicherheitshinweis

`settings.json` (API-Keys, SMTP-Passwort etc.) liegt unverschlüsselt im
`/data`-Volume. Für ein Homelab mit eingeschränktem Host-Zugriff ist das ein
bewusster, dokumentierter Trade-off (siehe [appconfig.py](appconfig.py)) –
das Volume entsprechend schützen.

## Lizenz

[MIT](LICENSE)
