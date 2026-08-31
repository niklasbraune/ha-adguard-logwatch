#!/usr/bin/env python3
"""AdGuard Log Watch add-on service."""

import base64
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

DATA_DIR = Path(os.getenv("LOGWATCH_DATA_DIR", "/data"))
CONFIG_PATH = DATA_DIR / "logwatch.json"
OPTIONS_PATH = DATA_DIR / "options.json"
STATE_PATH = DATA_DIR / "state.json"
LOG = logging.getLogger("adguard-logwatch")

DEFAULT_CONFIG = {
    "adguard_url": "",
    "username": "",
    "password": "",
    "monitor_interval": 5,
    "pushover_token": "",
    "pushover_user": "",
    "pushover_device": "",
    "pushover_priority": 0,
    "pushover_sound": "",
    "pushover_url": "",
    "pushover_url_title": "",
    "query_page_size": 500,
    "query_max_pages": 20,
    "request_timeout": 15,
    "retry_attempts": 3,
    "retry_delay_seconds": 1,
    "rules": [],
}


def now_utc():
    return datetime.now(timezone.utc)


def parse_time(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.config = DEFAULT_CONFIG.copy()
        self.state = {"last_run": None, "last_error": None, "last_results": [], "notifications": {}}
        self.load()

    def load(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        source = OPTIONS_PATH if OPTIONS_PATH.exists() else CONFIG_PATH
        if source.exists():
            try:
                saved = json.loads(source.read_text(encoding="utf-8"))
                self.config.update({key: value for key, value in saved.items() if key in DEFAULT_CONFIG})
            except (OSError, json.JSONDecodeError) as error:
                LOG.warning("Konfiguration konnte nicht geladen werden: %s", error)
        if CONFIG_PATH.exists() and source != CONFIG_PATH:
            try:
                saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                self.config.update({key: value for key, value in saved.items() if key in DEFAULT_CONFIG})
            except (OSError, json.JSONDecodeError):
                pass
        if STATE_PATH.exists():
            try:
                saved = json.loads(STATE_PATH.read_text(encoding="utf-8"))
                self.state["notifications"] = saved.get("notifications", {})
            except (OSError, json.JSONDecodeError):
                LOG.warning("Benachrichtigungsstatus konnte nicht geladen werden")

    def save_state(self):
        temporary_path = STATE_PATH.with_suffix(".tmp")
        temporary_path.write_text(json.dumps({"notifications": self.state["notifications"]}), encoding="utf-8")
        temporary_path.replace(STATE_PATH)

    def public_config(self):
        with self.lock:
            result = self.config.copy()
            result["password"] = "" if not result["password"] else "********"
            result["pushover_token"] = "" if not result["pushover_token"] else "********"
            result["pushover_user"] = "" if not result["pushover_user"] else "********"
            return result

    def update(self, incoming):
        with self.lock:
            candidate = self.config.copy()
            for key in DEFAULT_CONFIG:
                if key not in incoming:
                    continue
                value = incoming[key]
                if key in {"password", "pushover_token", "pushover_user"} and value == "********":
                    continue
                candidate[key] = value
            self.validate(candidate)
            self.config = candidate
            CONFIG_PATH.write_text(json.dumps(self.config, indent=2), encoding="utf-8")

    @staticmethod
    def validate(config):
        if not isinstance(config["rules"], list):
            raise ValueError("rules muss eine Liste sein")
        interval = int(config["monitor_interval"])
        if not 1 <= interval <= 60:
            raise ValueError("monitor_interval muss zwischen 1 und 60 liegen")
        config["monitor_interval"] = interval
        for key, minimum, maximum in (
            ("query_page_size", 1, 1000),
            ("query_max_pages", 1, 100),
            ("request_timeout", 1, 60),
            ("retry_attempts", 1, 5),
            ("retry_delay_seconds", 0, 60),
            ("pushover_priority", -2, 1),
        ):
            value = int(config[key])
            if not minimum <= value <= maximum:
                raise ValueError(f"{key} muss zwischen {minimum} und {maximum} liegen")
            config[key] = value
        for rule in config["rules"]:
            if not rule.get("id") or not rule.get("name") or not rule.get("pattern"):
                raise ValueError("Jede Regel braucht ID, Name und Suchmuster")
            if rule.get("match_type", "contains") not in {"contains", "suffix", "regex"}:
                raise ValueError("Unbekannter match_type")
            if rule.get("match_type") == "regex":
                try:
                    re.compile(rule["pattern"], re.IGNORECASE)
                except re.error as error:
                    raise ValueError(f"Ungueltiger regulaerer Ausdruck: {error}") from error
            if int(rule.get("period_minutes", 60)) < 1 or int(rule.get("min_occurrences", 1)) < 1:
                raise ValueError("Zeitfenster und Mindestanzahl muessen positiv sein")


STORE = Store()


def query_log_page(base_url, credentials, parameters, config):
    url = f"{base_url}/control/querylog?{urlencode(parameters)}"
    request = Request(url, headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"})
    attempts = config["retry_attempts"]
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=config["request_timeout"]) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if not isinstance(payload.get("data"), list):
                raise RuntimeError("Unerwartete Antwort von AdGuard")
            return payload
        except HTTPError as error:
            retryable = error.code in {408, 429} or error.code >= 500
            message = f"AdGuard antwortet mit HTTP {error.code}"
        except (URLError, TimeoutError, OSError) as error:
            retryable = True
            message = f"AdGuard ist nicht erreichbar: {error.reason if isinstance(error, URLError) else error}"
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            retryable = False
            message = f"AdGuard liefert kein gueltiges JSON: {error}"
        if not retryable or attempt == attempts - 1:
            raise RuntimeError(message) from error
        delay = config["retry_delay_seconds"] * (attempt + 1)
        LOG.warning("%s; erneuter Versuch in %s Sekunden", message, delay)
        time.sleep(delay)


def adguard_query(cutoff=None):
    with STORE.lock:
        config = STORE.config.copy()
    base_url = config["adguard_url"].rstrip("/")
    if not base_url:
        raise RuntimeError("AdGuard-URL ist nicht konfiguriert")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("AdGuard-URL muss mit http:// oder https:// beginnen")
    credentials = base64.b64encode(f"{config['username']}:{config['password']}".encode()).decode()
    entries = []
    older_than = None
    seen_cursors = set()
    for _ in range(config["query_max_pages"]):
        parameters = {"limit": config["query_page_size"]}
        if older_than:
            parameters["older_than"] = older_than
        payload = query_log_page(base_url, credentials, parameters, config)
        page = payload["data"]
        entries.extend(page)
        oldest = payload.get("oldest")
        oldest_time = parse_time(oldest)
        if not page or len(page) < config["query_page_size"] or not oldest or oldest in seen_cursors:
            break
        if cutoff and oldest_time and oldest_time <= cutoff:
            break
        seen_cursors.add(oldest)
        older_than = oldest
    return entries


def matches_rule(entry, rule, cutoff):
    timestamp = parse_time(entry.get("time"))
    if not timestamp or timestamp < cutoff:
        return False
    status = entry.get("status", "")
    statuses = rule.get("statuses", ["Blocked", "Allowed"])
    if statuses and status not in statuses:
        return False
    client = entry.get("client", "")
    clients = [item.strip() for item in rule.get("clients", "").split(",") if item.strip()]
    if clients and client not in clients:
        return False
    domain = entry.get("question", {}).get("name", "").rstrip(".")
    pattern = rule["pattern"]
    match_type = rule.get("match_type", "contains")
    if match_type == "regex":
        return bool(re.search(pattern, domain, re.IGNORECASE))
    if match_type == "suffix":
        return domain.lower().endswith(pattern.lower().lstrip("."))
    return pattern.lower() in domain.lower()


def evaluate(notify=False):
    with STORE.lock:
        config = STORE.config.copy()
    current = now_utc()
    longest_period = max((int(rule.get("period_minutes", 60)) for rule in config["rules"]), default=60)
    entries = adguard_query(current - timedelta(minutes=longest_period))
    results = []
    for rule in config["rules"]:
        cutoff = current - timedelta(minutes=int(rule.get("period_minutes", 60)))
        hits = [entry for entry in entries if matches_rule(entry, rule, cutoff)]
        threshold = int(rule.get("min_occurrences", 1))
        result = {"id": rule["id"], "name": rule["name"], "count": len(hits), "threshold": threshold, "matched": len(hits) >= threshold, "samples": hits[:5]}
        results.append(result)
        if notify and result["matched"]:
            maybe_notify(rule, result)
    with STORE.lock:
        STORE.state["last_run"] = current.isoformat()
        STORE.state["last_error"] = None
        STORE.state["last_results"] = results
    return results


def notification_text(rule, result):
    domains = ", ".join(entry.get("question", {}).get("name", "?") for entry in result["samples"][:3])
    values = {
        "count": result["count"],
        "threshold": result["threshold"],
        "period_minutes": rule.get("period_minutes", 60),
        "domains": domains,
        "rule_name": rule["name"],
    }
    default_message = f"{result['count']} Treffer in {rule.get('period_minutes', 60)} Min. {domains}"
    notification = rule.get("notification", {})
    title = notification.get("title") or rule["name"]
    message = notification.get("message") or default_message
    replace = lambda template: re.sub(r"\{([a-z_]+)\}", lambda match: str(values.get(match.group(1), match.group(0))), template)
    return replace(title), replace(message)


def maybe_notify(rule, result):
    cooldown = int(rule.get("cooldown_minutes", 60))
    with STORE.lock:
        last = parse_time(STORE.state["notifications"].get(rule["id"]))
    if last and now_utc() - last < timedelta(minutes=cooldown):
        return
    title, message = notification_text(rule, result)
    delivered = False
    try:
        delivered = send_pushover(title, message, rule) or delivered
    except RuntimeError as error:
        LOG.error("Pushover-Benachrichtigung fehlgeschlagen: %s", error)
    delivered = send_home_assistant_event(rule, result) or delivered
    if not delivered:
        return
    with STORE.lock:
        STORE.state["notifications"][rule["id"]] = now_utc().isoformat()
        STORE.save_state()


def send_pushover(title, message, rule=None, required=False):
    with STORE.lock:
        config = STORE.config.copy()
    if not config["pushover_token"] or not config["pushover_user"]:
        if required:
            raise RuntimeError("Pushover Token und User Key muessen konfiguriert sein")
        return False
    notification = rule.get("notification", {}) if rule else {}
    form_data = {
        "token": config["pushover_token"], "user": config["pushover_user"], "device": config["pushover_device"],
        "title": title, "message": message, "priority": notification.get("priority", config["pushover_priority"]),
        "sound": notification.get("sound", config["pushover_sound"]), "url": notification.get("url", config["pushover_url"]),
        "url_title": notification.get("url_title", config["pushover_url_title"]),
    }
    form = urlencode({key: value for key, value in form_data.items() if value != ""}).encode()
    request = Request("https://api.pushover.net/1/messages.json", data=form, method="POST")
    for attempt in range(config["retry_attempts"]):
        try:
            with urlopen(request, timeout=config["request_timeout"]):
                LOG.info("Pushover-Benachrichtigung versendet: %s", title)
                return True
        except HTTPError as error:
            retryable = error.code in {408, 429} or error.code >= 500
        except (URLError, TimeoutError, OSError) as error:
            retryable = True
        if not retryable or attempt == config["retry_attempts"] - 1:
            raise RuntimeError(str(error)) from error
        time.sleep(config["retry_delay_seconds"] * (attempt + 1))


def send_home_assistant_event(rule, result):
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        return False
    event_name = quote("adguard_logwatch_match", safe="")
    body = json.dumps({"rule": rule["name"], "rule_id": rule["id"], "count": result["count"], "threshold": result["threshold"]}).encode()
    request = Request(f"http://supervisor/core/api/events/{event_name}", data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=10):
            return True
    except (HTTPError, URLError) as error:
        LOG.warning("Home-Assistant-Event konnte nicht gesendet werden: %s", error)
        return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        LOG.info("Web: " + format_string, *args)

    def send_json(self, status, value):
        data = json.dumps(value, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        if self.path == "/api/config":
            return self.send_json(200, STORE.public_config())
        if self.path == "/api/status":
            with STORE.lock:
                return self.send_json(200, STORE.state)
        if self.path in {"/", "/index.html"}:
            return self.serve_file("index.html", "text/html; charset=utf-8")
        if self.path == "/app.css":
            return self.serve_file("app.css", "text/css; charset=utf-8")
        if self.path == "/app.js":
            return self.serve_file("app.js", "application/javascript; charset=utf-8")
        self.send_error(404)

    def do_PUT(self):
        if self.path != "/api/config":
            return self.send_error(404)
        try:
            STORE.update(self.read_json())
            self.send_json(200, {"ok": True})
        except (ValueError, TypeError, json.JSONDecodeError) as error:
            self.send_json(400, {"error": str(error)})

    def do_POST(self):
        try:
            if self.path == "/api/test":
                return self.send_json(200, {"results": evaluate(notify=False)})
            if self.path == "/api/pushover-test":
                send_pushover("AdGuard Log Watch", "Pushover-Verbindung erfolgreich getestet.", required=True)
                return self.send_json(200, {"ok": True})
            self.send_error(404)
        except RuntimeError as error:
            with STORE.lock:
                STORE.state["last_error"] = str(error)
            self.send_json(502, {"error": str(error)})

    def serve_file(self, name, content_type):
        path = Path("/opt/adguard-logwatch/web") / name
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def monitor():
    while True:
        try:
            evaluate(notify=True)
        except RuntimeError as error:
            with STORE.lock:
                STORE.state["last_error"] = str(error)
            LOG.warning("Auswertung fehlgeschlagen: %s", error)
        with STORE.lock:
            interval = STORE.config["monitor_interval"]
        time.sleep(interval * 60)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    threading.Thread(target=monitor, daemon=True).start()
    LOG.info("AdGuard Log Watch startet auf Port 8099")
    ThreadingHTTPServer(("0.0.0.0", 8099), Handler).serve_forever()