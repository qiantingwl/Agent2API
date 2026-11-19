"""Local-only tests; Docker and production key files are never accessed."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
import hashlib
import hmac
import http.client
import io
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import host_bridge as hb


KEY = b"test-key-0123456789abcdef0123456789abcdef"
NONCE = "nonce_0123456789abcdef"


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.wall = 1000.0
        self.mono = 20.0
        self.auth = hb.Authenticator(KEY, lambda: self.wall, lambda: self.mono)

    def verify(self, timestamp="1000", nonce=NONCE, body=b"{}", digest=None):
        self.auth.verify(timestamp, nonce,
                         digest or hb.signature(KEY, timestamp, nonce, body), body)

    def assert_error(self, status, function, *args, **kwargs):
        with self.assertRaises(hb.BridgeError) as cm:
            function(*args, **kwargs)
        self.assertEqual(cm.exception.status, status)

    def test_signature_matches_independent_hmac(self):
        expected = hmac.new(KEY, b"1000\n" + NONCE.encode() + b"\n{}", hashlib.sha256).hexdigest()
        self.assertEqual(hb.signature(KEY, "1000", NONCE, b"{}"), expected)
        self.verify(digest=expected)

    def test_tampering_body_timestamp_nonce_and_key(self):
        digest = hb.signature(KEY, "1000", NONCE, b"{}")
        for overrides in ({"body": b'{"command":"upsert"}'}, {"timestamp": "1001"},
                          {"nonce": NONCE + "x"},
                          {"digest": hb.signature(b"wrong", "1000", NONCE, b"{}")}):
            with self.subTest(overrides=overrides):
                self.assert_error(401, self.verify, **({"digest": digest} | overrides))
        self.verify()  # Invalid signatures must not consume the nonce.

    def test_constant_time_comparison(self):
        with patch.object(hb.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            self.verify()
        compare.assert_called_once()

    def test_stale_future_and_boundary_timestamps(self):
        for stamp in ("939", "1061"):
            self.assert_error(401, self.verify, timestamp=stamp)
        self.verify(timestamp="940", nonce=NONCE + "a")
        self.verify(timestamp="1060", nonce=NONCE + "b")

    def test_malformed_auth(self):
        for overrides in ({"timestamp": "1e3"}, {"timestamp": "-1"}, {"nonce": "short"},
                          {"nonce": "a" * 129}, {"nonce": "x" * 16 + "!"},
                          {"digest": "x" * 64}, {"digest": "a" * 63}):
            with self.subTest(overrides=overrides):
                args = {"timestamp": "1000", "nonce": NONCE, "digest": "a" * 64,
                        "body": b"{}"} | overrides
                self.assert_error(401, self.auth.verify, **args)

    def test_replay_including_new_body_and_timestamp(self):
        self.verify()
        self.assert_error(409, self.verify)
        self.assert_error(409, self.verify, timestamp="1001", body=b"[]")

    def test_concurrent_replay_only_one_accepted(self):
        def attempt(_):
            try:
                self.verify()
                return 200
            except hb.BridgeError as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(attempt, range(24)))
        self.assertEqual(statuses.count(200), 1)
        self.assertEqual(statuses.count(409), 23)

    def test_future_nonce_survives_entire_validity_window(self):
        self.verify(timestamp="1060")
        self.wall = 1120
        self.mono = 140
        self.assert_error(409, self.verify, timestamp="1060")
        self.wall = 1121
        self.mono = 141
        self.assert_error(401, self.verify, timestamp="1060")
        self.verify(timestamp="1121", nonce=NONCE + "next")
        self.assertNotIn(NONCE, self.auth.seen)

    def test_bounded_cache_fails_closed_and_recovers(self):
        self.auth.capacity = 1
        self.verify()
        self.assert_error(503, self.verify, nonce=NONCE + "next")
        self.assert_error(409, self.verify)
        self.assertEqual(len(self.auth.seen), 1)
        self.wall = 1121
        self.mono = 141
        self.verify(timestamp="1121", nonce=NONCE + "next")
        self.assertEqual(len(self.auth.seen), 1)

    def test_short_key_rejected(self):
        with self.assertRaises(ValueError):
            hb.Authenticator(b"short")


class FakeDocker:
    def __init__(self):
        self.cid = "a" * 64
        self.started = "2026-11-09T00:00:00Z"
        self.restarts = 0
        self.calls = []
        self.result = b'{"ok":true,"result":[1,2]}'
        self.returncode = 0
        self.on_copy = None

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args[1] == "inspect":
            output = json.dumps([{"Id": self.cid, "State": {"Running": True,
                                  "StartedAt": self.started}, "RestartCount": self.restarts}]).encode()
            return subprocess.CompletedProcess(args, 0, output)
        if args[1] == "cp":
            if self.on_copy:
                self.on_copy()
            return subprocess.CompletedProcess(args, 0, b"")
        return subprocess.CompletedProcess(args, self.returncode, self.result)

    def count(self, command):
        return sum(args[1] == command for args, _ in self.calls)


class DockerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.helper = Path(self.temp.name) / "mirai_bridge.py"
        self.helper.write_text("# fixture\n", encoding="utf-8")
        self.runner = FakeDocker()
        self.bridge = hb.DockerBridge(self.helper, self.runner)

    def test_fixed_arguments_stdin_and_cached_install(self):
        payload = {"command": "upsert", "credential": "$(secret); --privileged"}
        self.assertEqual(self.bridge.call(payload), {"ok": True, "result": [1, 2]})
        self.bridge.call({"command": "inventory"})
        self.assertEqual(self.runner.count("cp"), 1)
        args, kwargs = self.runner.calls[-1]
        self.assertEqual(args, ["docker", "exec", "-i", "a" * 64,
                                "python", "/tmp/mirai_bridge.py"])
        for _, options in self.runner.calls:
            self.assertFalse(options["shell"])
            self.assertIs(options["stderr"], subprocess.DEVNULL)
            self.assertGreater(options["timeout"], 0)
            self.assertLessEqual(options["timeout"], 120)
        first_exec = next(options for args, options in self.runner.calls if args[1] == "exec")
        self.assertEqual(json.loads(first_exec["input"]), payload)

    def test_install_refreshes_on_id_restart_started_and_hash_change(self):
        self.bridge.call({"command": "inventory"})
        for attr, value in (("cid", "b" * 64), ("restarts", 1), ("started", "later")):
            setattr(self.runner, attr, value)
            self.bridge.call({"command": "inventory"})
        self.helper.write_text("# updated\n", encoding="utf-8")
        self.bridge.call({"command": "inventory"})
        self.assertEqual(self.runner.count("cp"), 5)

    def test_restart_during_copy_rejected_and_not_cached(self):
        self.runner.on_copy = lambda: setattr(self.runner, "restarts", 1)
        with self.assertRaisesRegex(hb.BridgeError, "helper_changed_retry"):
            self.bridge.call({"command": "inventory"})
        self.assertIsNone(self.bridge.installed)
        self.assertEqual(self.runner.count("exec"), 0)

    def test_parallel_install_only_copies_once(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda i: self.bridge.call({"command": "task",
                                         "account_id": str(i)}), range(6)))
        self.assertEqual(len(results), 6)
        self.assertEqual(self.runner.count("cp"), 1)

    def test_duplicate_task_lock_cleanup_and_different_accounts(self):
        payload = {"command": "task", "account_id": "acct"}
        with self.bridge._command_lock(payload):
            with self.assertRaisesRegex(hb.BridgeError, "account_task_busy"):
                self.bridge.call(payload)
            self.bridge.call({"command": "task", "account_id": "other"})
        self.bridge.call(payload)
        self.assertEqual(self.bridge.tasks, set())

    def test_inventory_upsert_and_ownership_share_write_lock(self):
        with self.bridge._command_lock({"command": "inventory"}):
            for command in ("inventory", "upsert", "take_ownership"):
                with self.assertRaisesRegex(hb.BridgeError, "inventory_write_busy"):
                    self.bridge.call({"command": command})
        self.bridge.call({"command": "take_ownership"})

    def test_invalid_commands_and_task_ids_never_invoke_docker(self):
        for payload in ([], {}, {"command": []}, {"command": "exec"},
                        {"command": "task"}, {"command": "task", "account_id": " "},
                        {"command": "task", "account_id": " acct "},
                        {"command": "task", "account_id": 1}):
            with self.subTest(payload=payload), self.assertRaises(hb.BridgeError):
                self.bridge.call(payload)
        self.assertEqual(self.runner.calls, [])

    def test_nonzero_and_invalid_cli_json_do_not_expose_output(self):
        for code, output in ((1, b"secret credential"), (0, b"log line\n{}"),
                             (0, b'{"x":NaN}'), (0, b'{"x":1,"x":2}')):
            self.runner.returncode = code
            self.runner.result = output
            with self.assertRaises(hb.BridgeError) as cm:
                self.bridge.call({"command": "inventory"})
            self.assertNotIn("secret", str(cm.exception))

    def test_timeout_does_not_leak_and_releases_task_lock(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired("secret command", 120, output=b"secret")
        self.bridge.runner = timeout
        with self.assertRaisesRegex(hb.BridgeError, "helper_timeout") as cm:
            self.bridge.call({"command": "task", "account_id": "acct"})
        self.assertEqual(cm.exception.status, 504)
        self.assertEqual(self.bridge.tasks, set())

    def test_single_deadline_includes_install_work(self):
        now = [0.0]
        self.bridge.monotonic = lambda: now[0]
        original = self.runner
        def advancing(args, **kwargs):
            result = original(args, **kwargs)
            now[0] += 40
            return result
        self.bridge.runner = advancing
        with self.assertRaisesRegex(hb.BridgeError, "helper_timeout"):
            self.bridge.call({"command": "inventory"})
        self.assertEqual(self.runner.count("exec"), 0)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge = Mock()
        cls.server = hb.BridgeServer(("127.0.0.1", 0), hb.Authenticator(KEY), cls.bridge)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def setUp(self):
        self.bridge.reset_mock()
        self.bridge.call.side_effect = None
        self.bridge.call.return_value = {"ok": True}

    def headers(self, body=b"", nonce=None):
        timestamp = str(int(time.time()))
        nonce = nonce or secrets.token_hex(16)
        return {"X-Bridge-Timestamp": timestamp, "X-Bridge-Nonce": nonce,
                "X-Bridge-Signature": hb.signature(KEY, timestamp, nonce, body),
                "Content-Type": "application/json"}

    def request(self, method="GET", path="/health", body=b"", headers=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_health_requires_auth_and_rejects_replay(self):
        self.assertEqual(self.request()[0], 401)
        headers = self.headers()
        self.assertEqual(self.request(headers=headers), (200, {"ok": True}))
        self.assertEqual(self.request(headers=headers)[0], 409)
        self.bridge.call.assert_not_called()

    def test_call_json_and_authenticated_exact_body(self):
        body = b'{"command": "inventory"}'
        headers = self.headers(body)
        self.assertEqual(self.request("POST", "/call", body + b" ", headers)[0], 401)
        self.assertEqual(self.request("POST", "/call", body, headers)[0], 200)
        self.bridge.call.assert_called_once_with({"command": "inventory"})

    def test_payload_limit_checked_before_reading(self):
        headers = self.headers()
        headers["Content-Length"] = str(hb.MAX_PAYLOAD + 1)
        self.assertEqual(self.request("POST", "/call", headers=headers)[0], 413)
        self.bridge.call.assert_not_called()

    def test_exact_payload_limit_allowed(self):
        prefix = b'{"command":"inventory","padding":"'
        body = prefix + b"x" * (hb.MAX_PAYLOAD - len(prefix) - 2) + b'"}'
        self.assertEqual(len(body), hb.MAX_PAYLOAD)
        self.assertEqual(self.request("POST", "/call", body, self.headers(body))[0], 200)

    def test_invalid_json_duplicate_keys_and_nonfinite_values(self):
        for body in (b"bad", b'{"command":"task","command":"inventory"}', b'{"x":NaN}'):
            self.assertEqual(self.request("POST", "/call", body, self.headers(body))[0], 400)
        self.bridge.call.assert_not_called()

    def test_chunking_and_get_body_rejected(self):
        headers = self.headers()
        headers["Transfer-Encoding"] = "chunked"
        self.assertEqual(self.request(headers=headers)[0], 400)
        self.assertEqual(self.request(body=b"{}", headers=self.headers(b"{}"))[0], 400)

    def test_duplicate_signature_headers_rejected(self):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            conn.putrequest("GET", "/health")
            for name, value in self.headers().items():
                conn.putheader(name, value)
                if name == "X-Bridge-Signature":
                    conn.putheader(name, value)
            conn.endheaders()
            response = conn.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            conn.close()

    def test_generic_errors_never_log_secrets(self):
        self.bridge.call.side_effect = RuntimeError("credential-secret")
        body = b'{"command":"inventory"}'
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            status, response = self.request("POST", "/call", body, self.headers(body))
        self.assertEqual(status, 500)
        self.assertNotIn("credential-secret", json.dumps(response))
        self.assertEqual(stderr.getvalue(), "")

    def test_semaphore_rejects_seventh_request(self):
        for _ in range(hb.CONCURRENCY):
            # Previous HTTP response can arrive before its handler releases the slot.
            self.assertTrue(self.server.slots.acquire(timeout=3))
        try:
            self.assertEqual(self.request(headers=self.headers())[0], 503)
        finally:
            for _ in range(hb.CONCURRENCY):
                self.server.slots.release()


if __name__ == "__main__":
    unittest.main()

