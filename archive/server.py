"""HTTP front end for the archive backend.

The handler is a thin adapter: validation errors become
``{"error": "<parameter name>"}`` and business state is never changed by a
rejected request.  Every method is serialized-equivalent: the backend's
cross-process locks make concurrent calls behave as if they ran one at a time.

    POST /put     {"id": ..., "text": ...}   -> null
    GET  /read?id=...                        -> text          (via POST /read too)
    POST /rotate  {"job": ...}               -> <target int>
    GET  /status?job=...                     -> {"target": n, "state": ...}

plus a JSON-RPC style ``/call`` endpoint used by the CLI convenience wrapper.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .backend import ArchiveStore, UnknownObject
from .common import Fault, KeySideError

MAX_BODY = 8 << 20


class ArchiveHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "ArchiveService/1"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    # -- plumbing ------------------------------------------------------
    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
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

    def _params(self, body: dict) -> dict:
        query = parse_qs(urlparse(self.path).query)
        params = dict(body)
        for key, values in query.items():
            if key not in params and len(values) == 1:
                params[key] = values[0]
        return params

    # -- dispatch ------------------------------------------------------
    def do_GET(self):
        if urlparse(self.path).path == "/health":
            return self._send(200, {"ok": True})
        return self._dispatch(None)

    def do_POST(self):
        body = None
        try:
            body = self._read_json()
        except Exception:
            pass
        return self._dispatch(body)

    def _dispatch(self, body) -> None:
        path = urlparse(self.path).path
        params = self._params(body or {})
        store = self.server.store
        try:
            if path == "/put":
                result = store.put(params.get("id"), params.get("text"))
                # "put 回 null"
            elif path in ("/read", "/get"):
                result = store.read(params.get("id"))
            elif path == "/rotate":
                result = store.rotate(params.get("job"))
            elif path == "/status":
                result = store.status(params.get("job"))
            else:
                return self._send(404, {"error": "path"})
        except Fault as exc:
            return self._send(400, {"error": exc.param})
        except UnknownObject:
            return self._send(404, {"error": "id"})
        except KeySideError as exc:
            # Unreachable/refusing keystore: no business state was changed.
            return self._send(503, {"error": "keystore"})
        except Exception:
            return self._send(500, {"error": "internal"})
        return self._send(200, result)


def make_server(store: ArchiveStore, host: str = "127.0.0.1", port: int = 0):
    srv = ThreadingHTTPServer((host, port), ArchiveHTTPHandler)
    srv.daemon_threads = True
    srv.store = store
    return srv


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="archive HTTP server")
    ap.add_argument("--db", required=True, help="archive index database")
    ap.add_argument("--data", required=True, help="archive body directory")
    ap.add_argument("--keystore", default=None,
                    help="keystore URL (or use --endpoint-file)")
    ap.add_argument("--endpoint-file", default=None,
                    help="file containing the keystore url, written by the keystore")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--endpoint-out", default=None,
                    help="write {\"url\": ...} here once listening")
    ap.add_argument("--key-retries", type=int, default=8)
    ap.add_argument("--lock-timeout", type=float, default=30.0)
    args = ap.parse_args(argv)

    store = ArchiveStore(args.db, args.data, args.keystore,
                         endpoint_file=args.endpoint_file,
                         key_retries=args.key_retries,
                         lock_timeout=args.lock_timeout)
    srv = make_server(store, args.host, args.port)
    host, port = srv.server_address[:2]
    out = f"http://{host}:{port}"
    if args.endpoint_out:
        tmp = args.endpoint_out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"url": out, "pid": os.getpid()}, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, args.endpoint_out)
    print(json.dumps({"archive_url": out, "pid": os.getpid()}), flush=True)
    try:
        srv.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
