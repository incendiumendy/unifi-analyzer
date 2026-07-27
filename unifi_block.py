"""UniFi Gateway IP-Blocking via offizielle Integrations-API (X-API-KEY).

Verwaltet EINE Firewall-Policy ("AbuseIPDB Auto-Block") deren IP-Liste
bei jedem Lauf um neue boesartige IPs (AbuseIPDB-Score >= Schwelle) ergaenzt
wird. Quelle = External-Zone, Action = BLOCK.

Konfiguration kommt aus appconfig (GUI-editierbar):
  unifi_block_enabled : bool   - Master-Schalter
  unifi_dry_run       : bool   - nur loggen, nichts aendern (Default True)
  unifi_host          : str    - z.B. https://192.168.1.1
  unifi_api_key       : str    - X-API-KEY
  unifi_block_threshold : int  - Mindest-Score zum Sperren (Default 95)
  unifi_allowlist     : str    - kommaseparierte IPs/Praefixe die NIE gesperrt werden
"""
import ipaddress
import logging
import time as _time
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("unifi_block")

POLICY_NAME = "AbuseIPDB Auto-Block"
EXTERNAL_ZONE = "External"   # Quelle: eingehender Traffic von extern
GATEWAY_ZONE = "Gateway"     # Ziel: das Gateway selbst


class UniFiClient:
    def __init__(self, host, api_key, verify=False, timeout=15):
        self.host = host.rstrip("/")
        self.base = self.host + "/proxy/network/integration/v1"
        self.s = requests.Session()
        self.s.headers.update({"X-API-KEY": api_key, "Accept": "application/json"})
        self.verify = verify
        self.timeout = timeout
        self.site_id = None

    def _get(self, path):
        r = self.s.get(self.base + path, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post(self, path, body):
        r = self.s.post(self.base + path, json=body, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _put(self, path, body):
        r = self.s.put(self.base + path, json=body, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post_legacy(self, path, body):
        """Wie _post(), aber gegen die klassische Controller-API (nicht unter
        /integration/v1/), siehe get_events()/get_alarms()."""
        r = self.s.post(self.host + path, json=body, verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_events(self, hours=24, limit=500):
        """Best-Effort: klassische (nicht offiziell dokumentierte) Controller-API
        unter /proxy/network/api/ (nicht Teil der Integration-API v1).
        Muss ggf. je nach Controller-/Firmware-Version angepasst werden."""
        end = int(_time.time() * 1000)
        start = end - hours * 3600 * 1000
        path = f"/proxy/network/api/s/{self.site_id}/stat/event"
        body = {"start": start, "end": end, "_limit": limit}
        return self._post_legacy(path, body).get("data", [])

    def get_alarms(self, hours=24, limit=500):
        """Best-Effort, siehe get_events()."""
        end = int(_time.time() * 1000)
        start = end - hours * 3600 * 1000
        path = f"/proxy/network/api/s/{self.site_id}/stat/alarm"
        body = {"start": start, "end": end, "_limit": limit}
        return self._post_legacy(path, body).get("data", [])

    def resolve_site(self):
        data = self._get("/sites").get("data", [])
        if not data:
            raise RuntimeError("Keine UniFi-Site gefunden")
        # bevorzugt internalReference == 'default'
        for s in data:
            if s.get("internalReference") == "default":
                self.site_id = s["id"]
                return self.site_id
        self.site_id = data[0]["id"]
        return self.site_id

    def zones(self):
        return self._get(f"/sites/{self.site_id}/firewall/zones").get("data", [])

    def zone_id(self, name):
        for z in self.zones():
            if z.get("name") == name:
                return z["id"]
        raise RuntimeError(f"Firewall-Zone '{name}' nicht gefunden")

    def policies(self):
        return self._get(
            f"/sites/{self.site_id}/firewall/policies?limit=1000"
        ).get("data", [])

    def find_policy(self, name):
        for p in self.policies():
            if p.get("name") == name:
                return p
        return None

    def create_block_policy(self, src_zone, dst_zone, ip_items):
        body = {
            "enabled": True,
            "name": POLICY_NAME,
            "action": {"type": "BLOCK"},
            "source": {"zoneId": src_zone},
            "destination": {
                "zoneId": dst_zone,
                "trafficFilter": {
                    "type": "IP_ADDRESS",
                    "ipAddressFilter": {
                        "type": "IP_ADDRESSES",
                        "matchOpposite": False,
                        "items": ip_items,
                    },
                },
            },
            "ipProtocolScope": {"ipVersion": "IPV4"},
            "loggingEnabled": True,
        }
        return self._post(f"/sites/{self.site_id}/firewall/policies", body)

    def update_policy_items(self, policy, ip_items):
        import copy
        policy = copy.deepcopy(policy)
        pid = policy.pop("id", None)  # ID nicht im Body - kommt in der URL
        policy.pop("index", None)     # read-only
        policy.pop("metadata", None)  # read-only
        policy.setdefault("destination", {}).setdefault("trafficFilter", {})
        policy["destination"]["trafficFilter"]["type"] = "IP_ADDRESS"
        policy["destination"]["trafficFilter"]["ipAddressFilter"] = {
            "type": "IP_ADDRESSES",
            "matchOpposite": False,
            "items": ip_items,
        }
        if not pid:
            raise RuntimeError("Policy hat keine ID")
        return self._put(f"/sites/{self.site_id}/firewall/policies/{pid}", policy)


def _is_public_ipv4(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.version == 4 and not (a.is_private or a.is_loopback
                                       or a.is_link_local or a.is_multicast
                                       or a.is_reserved)
    except ValueError:
        return False


def _parse_allowlist(raw):
    nets = []
    for token in (raw or "").replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            log.warning(f"Allowlist-Eintrag ungueltig, ignoriert: {token}")
    return nets


def _allowlisted(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True  # ungueltig -> sicherheitshalber nicht sperren
    return any(a in n for n in nets)


def block_ips(ips, cfg):
    """ips: Iterable von IPv4-Strings mit Score >= Schwelle.
    cfg: dict aus appconfig.load(). Gibt Ergebnis-Dict fuer Report zurueck."""
    result = {"enabled": False, "dry_run": True, "candidates": [],
              "blocked": [], "skipped": [], "errors": []}

    if not cfg.get("unifi_block_enabled"):
        result["errors"].append("Blocking deaktiviert (unifi_block_enabled=False)")
        return result
    result["enabled"] = True

    dry = bool(cfg.get("unifi_dry_run", True))
    result["dry_run"] = dry
    host = (cfg.get("unifi_host") or "").strip()
    key = (cfg.get("unifi_api_key") or "").strip()
    if not host or not key:
        result["errors"].append("unifi_host oder unifi_api_key fehlt")
        return result

    allow = _parse_allowlist(cfg.get("unifi_allowlist"))

    clean = []
    for ip in dict.fromkeys(ips):  # dedupe, Reihenfolge erhalten
        if not _is_public_ipv4(ip):
            result["skipped"].append((ip, "nicht oeffentlich/IPv4"))
            continue
        if _allowlisted(ip, allow):
            result["skipped"].append((ip, "Allowlist"))
            continue
        clean.append(ip)
    result["candidates"] = list(clean)

    if not clean:
        return result

    if dry:
        result["blocked"] = list(clean)  # was gesperrt WUERDE
        log.info(f"[DRY-RUN] Wuerde sperren: {clean}")
        return result

    try:
        cli = UniFiClient(host, key)
        cli.resolve_site()
        src = cli.zone_id(EXTERNAL_ZONE)
        dst = cli.zone_id(GATEWAY_ZONE)
        policy = cli.find_policy(POLICY_NAME)

        if policy:
            existing = [
                it.get("value")
                for it in policy.get("destination", {})
                              .get("trafficFilter", {})
                              .get("ipAddressFilter", {})
                              .get("items", [])
                if it.get("value")
            ]
        else:
            existing = []

        merged = list(dict.fromkeys(existing + clean))
        new_ones = [ip for ip in clean if ip not in existing]
        items = [{"type": "IP_ADDRESS", "value": ip} for ip in merged]

        if policy:
            cli.update_policy_items(policy, items)
        else:
            cli.create_block_policy(src, dst, items)

        result["blocked"] = new_ones
        log.info(f"UniFi: {len(new_ones)} neue IP(s) gesperrt, Liste hat nun {len(merged)}")
    except Exception as e:  # noqa
        result["errors"].append(str(e))
        log.error(f"UniFi-Block fehlgeschlagen: {e}")

    return result
