import importlib.util
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import MagicMock, patch
from urllib.error import URLError
from urllib.parse import parse_qs
from urllib.request import Request, urlopen


MODULE_PATH = Path(__file__).parents[1] / "rootfs" / "opt" / "adguard-logwatch" / "app.py"
TEMP_DIRECTORY = tempfile.TemporaryDirectory()
os.environ["LOGWATCH_DATA_DIR"] = TEMP_DIRECTORY.name
SPEC = importlib.util.spec_from_file_location("logwatch", MODULE_PATH)
APP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APP)


class RuleEvaluationTests(unittest.TestCase):
    app = APP

    def test_matches_domain_status_client_and_period(self):
        rule = {
            "pattern": "doubleclick.net",
            "match_type": "suffix",
            "statuses": ["Blocked"],
            "clients": "192.168.1.50",
        }
        entry = {
            "time": "2026-08-31T13:45:00Z",
            "status": "Blocked",
            "client": "192.168.1.50",
            "question": {"name": "ads.doubleclick.net."},
        }
        cutoff = datetime(2026, 8, 31, 13, 0, tzinfo=timezone.utc)
        self.assertTrue(self.app.matches_rule(entry, rule, cutoff))
        entry["status"] = "Allowed"
        self.assertFalse(self.app.matches_rule(entry, rule, cutoff))

    def test_invalid_update_preserves_existing_configuration(self):
        store = self.app.Store()
        store.config["monitor_interval"] = 5
        with self.assertRaises(ValueError):
            store.update({"monitor_interval": 0})
        self.assertEqual(store.config["monitor_interval"], 5)

    def test_invalid_regex_is_a_validation_error(self):
        store = self.app.Store()
        rule = {"id": "bad", "name": "Bad", "pattern": "(", "match_type": "regex"}
        with self.assertRaisesRegex(ValueError, "Ungueltiger regulaerer Ausdruck"):
            store.update({"rules": [rule]})

    def test_evaluate_counts_matching_entries_against_threshold(self):
        self.app.STORE.config.update({
            "rules": [{
                "id": "tracking",
                "name": "Tracking-Alarm",
                "pattern": "doubleclick.net",
                "match_type": "suffix",
                "statuses": ["Blocked"],
                "min_occurrences": 2,
                "period_minutes": 60,
            }],
        })
        timestamp = self.app.now_utc().isoformat()
        entries = [
            {"time": timestamp, "status": "Blocked", "client": "192.168.1.2", "question": {"name": "ads.doubleclick.net"}},
            {"time": timestamp, "status": "Blocked", "client": "192.168.1.3", "question": {"name": "pixel.doubleclick.net"}},
            {"time": timestamp, "status": "Allowed", "client": "192.168.1.4", "question": {"name": "doubleclick.net"}},
        ]
        with patch.object(self.app, "adguard_query", return_value=entries):
            results = self.app.evaluate()
        self.assertEqual(results[0]["count"], 2)
        self.assertTrue(results[0]["matched"])

    def test_query_log_uses_older_than_until_cutoff(self):
        self.app.STORE.config.update({
            "adguard_url": "http://adguard.local:3000", "username": "admin", "password": "secret",
            "query_page_size": 2, "query_max_pages": 3,
        })
        pages = [
            {"data": [{"time": "2026-08-31T14:00:00Z"}, {"time": "2026-08-31T13:50:00Z"}], "oldest": "2026-08-31T13:50:00Z"},
            {"data": [{"time": "2026-08-31T13:40:00Z"}, {"time": "2026-08-31T13:20:00Z"}], "oldest": "2026-08-31T13:20:00Z"},
        ]
        cutoff = datetime(2026, 8, 31, 13, 30, tzinfo=timezone.utc)
        with patch.object(self.app, "query_log_page", side_effect=pages) as query_page:
            entries = self.app.adguard_query(cutoff)
        self.assertEqual(len(entries), 4)
        self.assertEqual(query_page.call_args_list[1].args[2]["older_than"], "2026-08-31T13:50:00Z")

    def test_query_page_retries_temporary_network_error(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data": []}'
        config = {"retry_attempts": 2, "retry_delay_seconds": 0, "request_timeout": 1}
        with patch.object(self.app, "urlopen", side_effect=[URLError("offline"), response]), patch.object(self.app.time, "sleep") as sleep:
            payload = self.app.query_log_page("http://adguard.local", "token", {"limit": 1}, config)
        self.assertEqual(payload, {"data": []})
        sleep.assert_called_once_with(0)

    def test_pushover_uses_configured_notification_options(self):
        self.app.STORE.config.update({
            "pushover_token": "token", "pushover_user": "user", "pushover_device": "phone",
            "pushover_priority": 1, "pushover_sound": "siren", "pushover_url": "https://ha.local",
            "pushover_url_title": "Details", "request_timeout": 9, "retry_attempts": 1,
        })
        response = MagicMock()
        with patch.object(self.app, "urlopen", return_value=response) as request_open:
            self.assertTrue(self.app.send_pushover("Alarm", "Treffer"))
        request = request_open.call_args.args[0]
        payload = parse_qs(request.data.decode())
        self.assertEqual(payload["priority"], ["1"])
        self.assertEqual(payload["sound"], ["siren"])
        self.assertEqual(payload["url"], ["https://ha.local"])
        self.assertEqual(request_open.call_args.kwargs["timeout"], 9)

    def test_rule_can_customize_pushover_title_and_message(self):
        self.app.STORE = self.app.Store()
        rule = {
            "id": "custom", "name": "Tracking", "period_minutes": 15,
            "notification": {"title": "Alarm: {rule_name}", "message": "{count}/{threshold} in {period_minutes} Min.: {domains}"},
        }
        result = {"count": 2, "threshold": 1, "samples": [{"question": {"name": "ads.example.org"}}]}
        with patch.object(self.app, "send_pushover", return_value=True) as pushover, patch.object(self.app, "send_home_assistant_event", return_value=False):
            self.app.maybe_notify(rule, result)
        pushover.assert_called_once_with("Alarm: Tracking", "2/1 in 15 Min.: ads.example.org", rule)

    def test_cooldown_is_persisted_across_store_reload(self):
        self.app.STORE = self.app.Store()
        rule = {"id": "cooldown", "name": "Cooldown", "period_minutes": 60, "cooldown_minutes": 60}
        result = {"count": 1, "threshold": 1, "samples": []}
        with patch.object(self.app, "send_pushover", return_value=True) as pushover, patch.object(self.app, "send_home_assistant_event", return_value=False):
            self.app.maybe_notify(rule, result)
            self.app.maybe_notify(rule, result)
            self.app.STORE = self.app.Store()
            self.app.maybe_notify(rule, result)
        pushover.assert_called_once()


class ApiTests(unittest.TestCase):
    app = APP

    @classmethod
    def setUpClass(cls):
        cls.app.STORE = cls.app.Store()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), cls.app.Handler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def api_request(self, path, method="GET", payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = Request(f"{self.base_url}{path}", data=data, method=method)
        if data:
            request.add_header("Content-Type", "application/json")
        with urlopen(request) as response:
            return response.status, json.loads(response.read().decode())

    def test_config_api_persists_and_masks_secrets(self):
        payload = {
            "adguard_url": "http://adguard.local:3000",
            "username": "admin",
            "password": "adguard-password",
            "monitor_interval": 10,
            "pushover_token": "application-token",
            "pushover_user": "user-key",
            "pushover_device": "phone",
            "rules": [],
        }
        status, response = self.api_request("/api/config", "PUT", payload)
        self.assertEqual(status, 200)
        self.assertTrue(response["ok"])
        status, response = self.api_request("/api/config")
        self.assertEqual(status, 200)
        self.assertEqual(response["password"], "********")
        self.assertEqual(response["pushover_token"], "********")
        self.assertEqual(response["pushover_user"], "********")
        self.assertEqual(response["adguard_url"], payload["adguard_url"])

    def test_invalid_regex_returns_bad_request(self):
        payload = {"rules": [{"id": "bad", "name": "Bad", "pattern": "(", "match_type": "regex"}]}
        data = json.dumps(payload).encode()
        request = Request(f"{self.base_url}/api/config", data=data, method="PUT", headers={"Content-Type": "application/json"})
        with self.assertRaises(Exception) as error:
            urlopen(request)
        self.assertEqual(error.exception.code, 400)

    def test_test_api_returns_results_without_notifications(self):
        self.app.STORE.config.update({
            "rules": [{
                "id": "api-rule",
                "name": "API-Regel",
                "pattern": "example.org",
                "statuses": ["Blocked"],
                "min_occurrences": 1,
                "period_minutes": 60,
            }],
        })
        entry = {"time": self.app.now_utc().isoformat(), "status": "Blocked", "question": {"name": "ads.example.org"}}
        with patch.object(self.app, "adguard_query", return_value=[entry]), patch.object(self.app, "send_pushover") as pushover:
            status, response = self.api_request("/api/test", "POST")
        self.assertEqual(status, 200)
        self.assertTrue(response["results"][0]["matched"])
        pushover.assert_not_called()


if __name__ == "__main__":
    unittest.main()