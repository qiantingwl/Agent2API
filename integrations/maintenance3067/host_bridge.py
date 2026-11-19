"""Internal Mirai host bridge; run directly with Python 3.10+ on the Docker host.

GET /health (empty body) and POST /call require these single-valued headers:
  X-Bridge-Timestamp: decimal Unix seconds (within +/-60 seconds)
  X-Bridge-Nonce: unique 16..128 character ASCII [A-Za-z0-9_-] token
  X-Bridge-Signature: lowercase hex HMAC-SHA256(key, timestamp + "\\n" +
                      nonce + "\\n" + exact HTTP body bytes)
The key is the key file's bytes with surrounding whitespace stripped, NOT hex
decoded. Nonces must be unique across both endpoints. POST bodies are objects
with command inventory/upsert/task/take_ownership; task requires account_id.
All other JSON fields are passed unchanged to the helper. Successful CLI JSON
is returned directly. Transport errors have {"error": {"code": "..."}}.
No key generation, remote deployment, or request/subprocess output logging.
"""

from contextlib import contextmanager
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import socket
import subprocess
import threading
import time


BIND = ("172.17.0.1", 3077)
KEY_PATH = Path("/opt/agent2api-maintenance-v1/secrets/unified-bridge.key")
HELPER_PATH = Path("/opt/agent2api-maintenance-v1/app/mirai_bridge.py")
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_RESPONSE = 64 * 1024 * 1024
CONCURRENCY = 24
TTL = 60
NONCE_CAPACITY = 16384
CALL_TIMEOUT = 120
IO_TIMEOUT = 15
COMMANDS = frozenset({"inventory", "upsert", "task", "take_ownership"})


class BridgeError(Exception):
    def __init__(self, status, code):
        self.status = status
        self.code = code
        super().__init__(code)


def signature(key, timestamp, nonce, body):
    prefix = (timestamp + "\n" + nonce + "\n").encode("ascii")
    return hmac.new(key, prefix + body, hashlib.sha256).hexdigest()


class Authenticator:
    def __init__(self, key, clock=time.time, monotonic=time.monotonic,
                 capacity=NONCE_CAPACITY):
        if len(key) < 32:
            raise ValueError("bridge key must contain at least 32 bytes")
        self.key = key
        self.clock = clock
        self.monotonic = monotonic
        self.capacity = capacity
        self.seen = {}
        self.lock = threading.Lock()

    def verify(self, timestamp, nonce, digest, body):
        if (not re.fullmatch(r"[0-9]{1,12}", timestamp)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise BridgeError(401, "unauthorized")
        if abs(self.clock() - int(timestamp)) > TTL:
            raise BridgeError(401, "unauthorized")
        if not hmac.compare_digest(signature(self.key, timestamp, nonce, body), digest):
            raise BridgeError(401, "unauthorized")
        with self.lock:
            now = self.monotonic()
            self.seen = {n: expiry for n, expiry in self.seen.items() if expiry >= now}
            if nonce in self.seen:
                raise BridgeError(409, "replay")
            if len(self.seen) >= self.capacity:
                raise BridgeError(503, "replay_cache_full")
            # Future-dated requests remain valid for up to 2*TTL after receipt.
            self.seen[nonce] = now + 2 * TTL


def parse_json(raw):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("invalid JSON constant")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                      parse_constant=invalid_constant)


class DockerBridge:
    def __init__(self, helper=HELPER_PATH, runner=subprocess.run,
                 monotonic=time.monotonic):
        self.helper = Path(helper)
        self.runner = runner
        self.monotonic = monotonic
        self.install_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.tasks_lock = threading.Lock()
        self.tasks = set()
        self.installed = None

    def _run(self, args, deadline, body=None):
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            raise BridgeError(504, "helper_timeout")
        try:
            result = self.runner(args, input=body, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, timeout=remaining,
                                 check=False, shell=False)
        except subprocess.TimeoutExpired:
            raise BridgeError(504, "helper_timeout") from None
        except OSError:
            raise BridgeError(502, "docker_unavailable") from None
        if result.returncode:
            raise BridgeError(502, "helper_failed")
        if len(result.stdout) > MAX_RESPONSE:
            raise BridgeError(502, "helper_response_too_large")
        return result.stdout

    def _container(self, deadline):
        raw = self._run(["docker", "inspect", "--type", "container", "miraihub"], deadline)
        try:
            info = parse_json(raw)[0]
            cid = info["Id"]
            state = info["State"]
            started = state["StartedAt"]
            restarts = info["RestartCount"]
            if (not isinstance(cid, str) or not re.fullmatch(r"[0-9a-f]{64}", cid)
                    or state["Running"] is not True or not isinstance(started, str)
                    or not isinstance(restarts, int)):
                raise ValueError()
            return cid, started, restarts
        except (ValueError, TypeError, KeyError, IndexError):
            raise BridgeError(502, "container_unavailable") from None

    def _ensure_helper(self, deadline):
        remaining = deadline - self.monotonic()
        if remaining <= 0 or not self.install_lock.acquire(timeout=remaining):
            raise BridgeError(504, "helper_timeout")
        try:
            state = self._container(deadline)
            try:
                digest = hashlib.sha256(self.helper.read_bytes()).hexdigest()
            except OSError:
                raise BridgeError(502, "helper_source_unavailable") from None
            version = (*state, digest)
            if self.installed != version:
                self.installed = None
                self._run(["docker", "cp", str(self.helper),
                           state[0] + ":/tmp/mirai_bridge.py"], deadline)
                # Never cache a copy spanning a restart or a source update.
                try:
                    unchanged = hashlib.sha256(self.helper.read_bytes()).hexdigest() == digest
                except OSError:
                    unchanged = False
                if self._container(deadline) != state or not unchanged:
                    raise BridgeError(503, "helper_changed_retry")
                self.installed = version
            return state[0]
        finally:
            self.install_lock.release()

    @contextmanager
    def _command_lock(self, payload):
        if payload["command"]=='inventory' and payload.get('view') in ('runtime','wps'):
            # Read-only HTTP + SELECT observation cannot contend with mirror upserts.
            yield
        elif payload["command"] == "task":
            account = payload["account_id"]
            with self.tasks_lock:
                if account in self.tasks:
                    raise BridgeError(409, "account_task_busy")
                self.tasks.add(account)
            try:
                yield
            finally:
                with self.tasks_lock:
                    self.tasks.remove(account)
        else:
            if not self.write_lock.acquire(blocking=False):
                raise BridgeError(409, "inventory_write_busy")
            try:
                yield
            finally:
                self.write_lock.release()

    def call(self, payload):
        if (not isinstance(payload, dict) or not isinstance(payload.get("command"), str)
                or payload["command"] not in COMMANDS):
            raise BridgeError(400, "invalid_command")
        if payload["command"] == "task":
            account = payload.get("account_id")
            if (not isinstance(account, str) or not account.strip()
                    or account != account.strip() or len(account) > 256):
                raise BridgeError(400, "invalid_account_id")
        deadline = self.monotonic() + CALL_TIMEOUT
        with self._command_lock(payload):
            cid = self._ensure_helper(deadline)
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            raw = self._run(["docker", "exec", "-i", cid, "python",
                             "/tmp/mirai_bridge.py"], deadline, body)
            try:
                return parse_json(raw)
            except (ValueError, RecursionError):
                raise BridgeError(502, "invalid_helper_json") from None


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "HostBridge"
    sys_version = ""

    def setup(self):
        self.request.settimeout(IO_TIMEOUT)
        super().setup()

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._send(code, {"error": {"code": "http_error"}})

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _header(self, name, default=""):
        values = self.headers.get_all(name, [])
        if len(values) > 1:
            raise BridgeError(400, "duplicate_header")
        return values[0] if values else default

    def _dispatch(self):
        if (self.command, self.path) not in {("GET", "/health"), ("POST", "/call")}:
            raise BridgeError(404, "not_found")
        if self.headers.get_all("Transfer-Encoding"):
            raise BridgeError(400, "unsupported_transfer_encoding")
        length = self._header("Content-Length", "0" if self.command == "GET" else "")
        if not re.fullmatch(r"[0-9]{1,10}", length):
            raise BridgeError(400, "invalid_content_length")
        size = int(length)
        if size > MAX_PAYLOAD:
            raise BridgeError(413, "payload_too_large")
        if self.command == "GET" and size:
            raise BridgeError(400, "health_body_not_empty")
        if self.command == "POST" and self._header("Content-Type").split(";")[0].strip().lower() != "application/json":
            raise BridgeError(415, "json_required")
        timestamp = self._header("X-Bridge-Timestamp")
        nonce = self._header("X-Bridge-Nonce")
        digest = self._header("X-Bridge-Signature")
        body = self.rfile.read(size)
        if len(body) != size:
            raise BridgeError(400, "incomplete_body")
        self.server.auth.verify(timestamp, nonce, digest, body)
        if self.command == "GET":
            return {"ok": True}
        try:
            payload = parse_json(body)
        except (ValueError, RecursionError):
            raise BridgeError(400, "invalid_json") from None
        return self.server.bridge.call(payload)

    def _handle(self):
        try:
            result = self._dispatch()
        except BridgeError as exc:
            self._send(exc.status, {"error": {"code": exc.code}})
        except (TimeoutError, socket.timeout):
            self._send(408, {"error": {"code": "request_timeout"}})
        except Exception:
            self._send(500, {"error": {"code": "internal_error"}})
        else:
            self._send(200, result)

    do_GET = _handle
    do_POST = _handle


class BridgeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = CONCURRENCY

    def __init__(self, address, auth, bridge):
        self.auth = auth
        self.bridge = bridge
        self.slots = threading.BoundedSemaphore(CONCURRENCY)
        super().__init__(address, BridgeHandler)

    def process_request(self, request, client_address):
        # Acquire BEFORE spawning a thread, including slow/unauthenticated clients.
        if not self.slots.acquire(blocking=False):
            body = b'{"error":{"code":"busy"}}'
            try:
                request.settimeout(0.1)
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\n"
                                b"Content-Type: application/json\r\n"
                                b"Cache-Control: no-store\r\nConnection: close\r\n"
                                + b"Content-Length: " + str(len(body)).encode()
                                + b"\r\n\r\n" + body)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Base implementation prints tracebacks; payloads/errors may hold secrets.
        pass


def main():
    try:
        key = KEY_PATH.read_bytes().strip()
        auth = Authenticator(key)
    except (OSError, ValueError):
        raise SystemExit("host bridge key unavailable or invalid") from None
    with BridgeServer(BIND, auth, DockerBridge()) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

