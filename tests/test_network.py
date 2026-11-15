"""Fault-injection tests over HTTP: dropped replies, duplicates, delays.

A tiny in-process TCP proxy sits between the archive and the keystore and
corrupts the *transport*, never the messages.  The archive must still behave
idempotently: lost replies are retried, duplicated requests are harmless.

Run:  python3 -I -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import os
import random
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from archive.backend import ArchiveStore  # noqa: E402
from archive.keyserver import KeyStore, make_server  # noqa: E402


class FlakyProxy:
    """Forwards TCP to a target; optionally drops/duplicates/delays."""

    def __init__(self, target_port: int, *, drop_rate=0.0, dup_rate=0.0,
                 delay=0.0, seed=0):
        self.target_port = target_port
        self.drop_rate = drop_rate
        self.dup_rate = dup_rate
        self.delay = delay
        self.rng = random.Random(seed)
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.stats = {"requests": 0, "dropped": 0, "duplicated": 0}
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        with conn:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, _, rest = data.partition(b"\r\n\r\n")
            length = 0
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    length = int(line.split(b":")[1])
            while len(rest) < length:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                rest += chunk
            request = head + b"\r\n\r\n" + rest

            with self.lock:
                self.stats["requests"] += 1
                drop = self.rng.random() < self.drop_rate
                dup = self.rng.random() < self.dup_rate
                if drop:
                    self.stats["dropped"] += 1
                if dup:
                    self.stats["duplicated"] += 1
            if dup:
                # Duplicate request arrives first; the "real" one follows.
                self._forward(request, reply=False)
            if self.delay:
                time.sleep(self.delay * self.rng.random())
            if drop:
                # Close without replying: the client sees a lost response.
                conn.close()
                return
            response = self._forward(request, reply=True)
            if response:
                try:
                    conn.sendall(response)
                except OSError:
                    pass

    def _forward(self, request: bytes, *, reply: bool):
        try:
            with socket.create_connection(("127.0.0.1", self.target_port),
                                          timeout=15) as s:
                s.sendall(request)
                if not reply:
                    # Read and discard; we only need the side effect.
                    try:
                        s.settimeout(5)
                        s.recv(65536)
                    except OSError:
                        pass
                    return None
                out = b""
                s.settimeout(15)
                while True:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    out += chunk
                return out
        except OSError:
            return None

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


class FlakyNetworkTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ks = KeyStore(os.path.join(self.dir, "keys.db"))
        self.key_srv = make_server(self.ks)
        threading.Thread(target=self.key_srv.serve_forever, daemon=True).start()
        self.key_port = self.key_srv.server_address[1]

    def tearDown(self):
        self.key_srv.shutdown()
        self.key_srv.server_close()
        self.ks.close()

    def _store(self, proxy_port):
        return ArchiveStore(os.path.join(self.dir, "a.db"),
                            os.path.join(self.dir, "data"),
                            f"http://127.0.0.1:{proxy_port}",
                            key_retries=12)

    def test_dropped_replies_are_retried(self):
        proxy = FlakyProxy(self.key_port, drop_rate=0.5, seed=7)
        store = self._store(proxy.port)
        try:
            store.put("a", "甲")
            self.assertEqual(store.read("a"), "甲")
            self.assertEqual(store.rotate("j"), 1)
            store.run_job("j")
            self.assertEqual(store.status("j"), {"target": 1, "state": "done"})
            self.assertEqual(store.read("a"), "甲")
            store.put("b", "乙")
            self.assertEqual(store.read("b"), "乙")
            self.assertGreater(proxy.stats["dropped"], 0)
        finally:
            store.close()
            proxy.close()

    def test_duplicated_requests_are_harmless(self):
        proxy = FlakyProxy(self.key_port, dup_rate=0.5, seed=11)
        store = self._store(proxy.port)
        try:
            for i in range(4):
                store.put(f"o{i}", f"v{i}")
            self.assertEqual(store.rotate("j"), 1)
            store.run_job("j")
            self.assertEqual(store.status("j"), {"target": 1, "state": "done"})
            for i in range(4):
                self.assertEqual(store.read(f"o{i}"), f"v{i}")
            self.assertTrue(self.ks.info(0)["tombstoned"])
            self.assertGreater(proxy.stats["duplicated"], 0)
        finally:
            store.close()
            proxy.close()

    def test_delayed_transport_keeps_interface_serialized(self):
        proxy = FlakyProxy(self.key_port, delay=0.02, drop_rate=0.1,
                           dup_rate=0.1, seed=3)
        store = self._store(proxy.port)
        errors = []

        def worker(n):
            try:
                for k in range(3):
                    oid = f"d{n}x{k}"
                    store.put(oid, f"t{n}{k}")
                    if store.read(oid) != f"t{n}{k}":
                        errors.append(f"mismatch {oid}")
            except Exception as exc:  # pragma: no cover
                errors.append(repr(exc))

        try:
            store.put("seed", "甲")
            store.rotate("j")
            threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
            for t in threads:
                t.start()
            store.run_job("j")
            for t in threads:
                t.join()
            self.assertEqual(errors, [])
            self.assertEqual(store.status("j"), {"target": 1, "state": "done"})
            self.assertEqual(store.read("seed"), "甲")
        finally:
            store.close()
            proxy.close()


if __name__ == "__main__":
    unittest.main()
