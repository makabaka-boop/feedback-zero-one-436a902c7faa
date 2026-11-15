"""Independent HTTP key service (separate process, separate SQLite database).

The keystore owns every per-generation master key.  One AES-256-GCM key per
generation is generated locally and never leaves this database file.

Idempotency and destruction
---------------------------
* ``create`` is idempotent per generation: if the key exists it is returned,
  never replaced.  If the generation was destroyed, ``create`` answers
  ``410 gen_destroyed`` -- a late creation can never resurrect it.
* ``wrap``/``unwrap`` for a destroyed generation also answer 410 forever.
* ``destroy`` deletes the key row and writes a tombstone in the same
  transaction.  Tombstones are never removed.
* There is no API that ever returns a master key.

HTTP API
--------
    GET  /health
    GET  /v1/keys/<gen>           -> {gen, exists, tombstoned[, key_id]}
    POST /v1/keys/<gen>/create    -> {gen, key_id, created}
    POST /v1/keys/<gen>/wrap      {data_key: b64} -> {gen, key_id, nonce, wrapped}
    POST /v1/keys/<gen>/unwrap    {key_id, nonce, wrapped} -> {gen, data_key}
    POST /v1/keys/<gen>/destroy   -> {gen, destroyed, existed}

Run:  python3 -m archive.keyserver --db keys/key.db --port 0 \
                                   --endpoint-file keys/endpoint.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .crypto import InvalidTag, aead_decrypt, aead_encrypt, new_data_key
from .faults import kill_point

SCHEMA = """
CREATE TABLE IF NOT EXISTS gen_keys (
    gen          INTEGER PRIMARY KEY,
    key_material BLOB NOT NULL,
    key_id       TEXT NOT NULL,
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tombstones (
    gen          INTEGER PRIMARY KEY,
    destroyed_at REAL NOT NULL
);
"""

MAX_BODY = 1 << 16


class GenerationGone(Exception):
    pass


class UnknownGeneration(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(value) -> bytes:
    if not isinstance(value, str):
        raise ValueError("bad base64")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        raise ValueError("bad base64") from None


class KeyStore:
    """Keystore operations, all idempotent and serialized by one lock."""

    def __init__(self, db_path: str, *, create_gen0: bool = True):
        self.db_path = os.path.abspath(db_path)
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, timeout=30,
                                     isolation_level=None,
                                     check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.executescript(SCHEMA)
        if create_gen0:
            try:
                self.create(0, reply_kill=False)
            except GenerationGone:
                # A previous run already destroyed generation 0; the tombstone
                # is permanent and must not be resurrected on restart.
                pass

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- internals -----------------------------------------------------
    def _key_row(self, gen: int):
        return self._conn.execute(
            "SELECT key_material, key_id FROM gen_keys WHERE gen=?", (gen,)).fetchone()

    def _tombstoned(self, gen: int) -> bool:
        return self._conn.execute(
            "SELECT 1 FROM tombstones WHERE gen=?", (gen,)).fetchone() is not None

    @staticmethod
    def _aad(gen: int, kid: str) -> bytes:
        return b"archive-wrap-v1:" + gen.to_bytes(8, "big") + kid.encode("ascii")

    # -- API -----------------------------------------------------------
    def create(self, gen: int, *, reply_kill: bool = True) -> dict:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._tombstoned(gen):
                    raise GenerationGone()
                row = self._key_row(gen)
                if row is not None:
                    self._conn.execute("COMMIT")
                    if reply_kill:
                        kill_point("create_commit")
                    return {"gen": gen, "key_id": row[1], "created": False}
                key = new_data_key()
                kid = "k" + hashlib.sha256(key).hexdigest()[:32]
                self._conn.execute(
                    "INSERT INTO gen_keys(gen, key_material, key_id, created_at) "
                    "VALUES (?,?,?,?)", (gen, key, kid, time.time()))
                self._conn.execute("COMMIT")
            except BaseException:
                self._rollback()
                raise
        # Durable commit done; the reply may now be lost.
        if reply_kill:
            kill_point("create_commit")
        return {"gen": gen, "key_id": kid, "created": True}

    def info(self, gen: int) -> dict:
        with self._lock:
            if self._tombstoned(gen):
                return {"gen": gen, "exists": False, "tombstoned": True}
            row = self._key_row(gen)
            if row is None:
                return {"gen": gen, "exists": False, "tombstoned": False}
            return {"gen": gen, "exists": True, "tombstoned": False,
                    "key_id": row[1]}

    def wrap(self, gen: int, data_key: bytes) -> dict:
        with self._lock:
            if self._tombstoned(gen):
                raise GenerationGone()
            row = self._key_row(gen)
            if row is None:
                raise UnknownGeneration()
            master, kid = row
        nonce, wrapped = aead_encrypt(master, data_key, self._aad(gen, kid))
        return {"gen": gen, "key_id": kid, "nonce": _b64e(nonce),
                "wrapped": _b64e(wrapped)}

    def unwrap(self, gen: int, kid, nonce_b64, wrapped_b64) -> bytes:
        nonce = _b64d(nonce_b64)
        wrapped = _b64d(wrapped_b64)
        with self._lock:
            if self._tombstoned(gen):
                raise GenerationGone()
            row = self._key_row(gen)
            if row is None:
                raise UnknownGeneration()
            master, real_kid = row
            if not isinstance(kid, str) or kid != real_kid:
                raise ValueError("wrong key id")
        try:
            return aead_decrypt(master, nonce, wrapped, self._aad(gen, real_kid))
        except InvalidTag:
            raise ValueError("bad wrap") from None

    def destroy(self, gen: int) -> dict:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existed = self._key_row(gen) is not None
                self._conn.execute("DELETE FROM gen_keys WHERE gen=?", (gen,))
                self._conn.execute(
                    "INSERT OR IGNORE INTO tombstones(gen, destroyed_at) "
                    "VALUES (?,?)", (gen, time.time()))
                self._conn.execute("COMMIT")
            except BaseException:
                self._rollback()
                raise
        # Tombstone is durable; only now may a crash-before-reply be injected.
        kill_point("destroy_commit")
        return {"gen": gen, "destroyed": True, "existed": existed}

    def _rollback(self) -> None:
        try:
            self._conn.execute("ROLLBACK")
        except sqlite3.OperationalError:
            pass


# ---------------------------------------------------------------------------
# HTTP front end
# ---------------------------------------------------------------------------

_PATH_RE = re.compile(r"^/v1/keys/(0|[1-9][0-9]*)(?:/(create|wrap|unwrap|destroy))?$")


class KeyHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "ArchiveKeyService/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_json(self) -> dict:
        try:
            ln = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("bad length") from None
        if ln < 0 or ln > MAX_BODY:
            raise ValueError("bad length")
        raw = self.rfile.read(ln) if ln else b"{}"
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("body must be an object")
        return obj

    def _route(self):
        path = urlparse(self.path).path
        m = _PATH_RE.match(path)
        if not m:
            return None, None
        return int(m.group(1)), m.group(2)

    def do_GET(self):
        if urlparse(self.path).path == "/health":
            return self._send(200, {"ok": True})
        gen, action = self._route()
        if gen is None or action is not None:
            return self._send(404, {"error": "not_found"})
        return self._send(200, self.server.store.info(gen))

    def do_POST(self):
        gen, action = self._route()
        if gen is None or action is None:
            return self._send(404, {"error": "not_found"})
        try:
            body = self._read_json()
        except Exception:
            return self._send(400, {"error": "bad_request"})
        store = self.server.store
        try:
            if action == "create":
                return self._send(200, store.create(gen))
            if action == "destroy":
                return self._send(200, store.destroy(gen))
            if action == "wrap":
                data_key = _b64d(body.get("data_key"))
                if len(data_key) != 32:
                    return self._send(400, {"error": "bad_data_key"})
                return self._send(200, store.wrap(gen, data_key))
            if action == "unwrap":
                data_key = store.unwrap(gen, body.get("key_id"),
                                        body.get("nonce"), body.get("wrapped"))
                return self._send(200, {"gen": gen, "data_key": _b64e(data_key)})
            return self._send(404, {"error": "not_found"})
        except GenerationGone:
            return self._send(410, {"error": "gen_destroyed", "gen": gen})
        except UnknownGeneration:
            return self._send(404, {"error": "unknown_gen", "gen": gen})
        except ValueError:
            return self._send(400, {"error": "bad_request"})
        except Exception:
            return self._send(500, {"error": "internal"})


def make_server(store: KeyStore, host: str = "127.0.0.1", port: int = 0):
    srv = ThreadingHTTPServer((host, port), KeyHTTPHandler)
    srv.daemon_threads = True
    srv.store = store
    return srv


def write_endpoint(path: str, url: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"url": url}, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def acquire_db_lock(db_path: str):
    """Refuse to run two keystore processes against one database file."""
    import fcntl
    f = open(db_path + ".lock", "a+b")
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit(f"keystore already running on {db_path}")
    return f


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="archive key service")
    ap.add_argument("--db", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--endpoint-file", default=None,
                    help="write {\"url\": ...} here once listening")
    ap.add_argument("--no-gen0", action="store_true",
                    help="do not create the generation-0 key at startup")
    args = ap.parse_args(argv)

    db_path = os.path.abspath(args.db)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    lock = acquire_db_lock(db_path)
    store = KeyStore(db_path, create_gen0=not args.no_gen0)
    srv = make_server(store, args.host, args.port)
    host, port = srv.server_address[:2]
    url = f"http://{host}:{port}"
    if args.endpoint_file:
        write_endpoint(args.endpoint_file, url)
    print(json.dumps({"keystore_url": url, "pid": os.getpid()}), flush=True)
    try:
        srv.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        store.close()
        lock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
