"""In-process unit/integration tests (unittest; no external deps).

Run:  python3 -I -m unittest discover -s tests -p "test_*.py" -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from archive import crypto  # noqa: E402
from archive.backend import ArchiveStore  # noqa: E402
from archive.common import Fault, KeySideError  # noqa: E402
from archive.keyserver import GenerationGone, KeyStore, make_server  # noqa: E402


class KeyStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ks = KeyStore(os.path.join(self.dir, "keys.db"))

    def test_gen0_exists_on_start(self):
        self.assertTrue(self.ks.info(0)["exists"])
        self.assertFalse(self.ks.info(0)["tombstoned"])

    def test_wrap_unwrap_roundtrip(self):
        dk = crypto.new_data_key()
        w = self.ks.wrap(0, dk)
        self.assertEqual(self.ks.unwrap(0, w["key_id"], w["nonce"], w["wrapped"]), dk)

    def test_wrap_rejects_wrong_key_id(self):
        dk = crypto.new_data_key()
        w = self.ks.wrap(0, dk)
        with self.assertRaises(ValueError):
            self.ks.unwrap(0, "kbogus", w["nonce"], w["wrapped"])

    def test_create_is_idempotent(self):
        first = self.ks.create(5)
        second = self.ks.create(5)
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["key_id"], second["key_id"])

    def test_destroy_is_idempotent_and_permanent(self):
        self.ks.create(3)
        self.assertTrue(self.ks.destroy(3)["existed"])
        self.assertFalse(self.ks.destroy(3)["existed"])
        self.assertTrue(self.ks.info(3)["tombstoned"])
        self.assertFalse(self.ks.info(3)["exists"])
        with self.assertRaises(GenerationGone):
            self.ks.create(3)
        with self.assertRaises(GenerationGone):
            self.ks.wrap(3, crypto.new_data_key())
        with self.assertRaises(GenerationGone):
            self.ks.unwrap(3, "k", "MDAwMDAwMDAwMDAw", "MTExMTExMTExMTEx")
        self.assertFalse(self.ks.info(3)["exists"])

    def test_restart_keeps_tombstone(self):
        self.ks.destroy(0)
        self.ks.close()
        self.ks = KeyStore(os.path.join(self.dir, "keys.db"))
        self.assertTrue(self.ks.info(0)["tombstoned"])
        with self.assertRaises(GenerationGone):
            self.ks.create(0)

    def test_no_api_returns_master_key(self):
        info = self.ks.info(0)
        self.assertNotIn("key_material", info)
        self.assertNotIn("key", info)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.ks = KeyStore(os.path.join(self.dir, "keys.db"))
        self.srv = make_server(self.ks)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        host, port = self.srv.server_address[:2]
        self.store = ArchiveStore(os.path.join(self.dir, "a.db"),
                                  os.path.join(self.dir, "data"),
                                  f"http://{host}:{port}")

    def tearDown(self):
        self.store.close()
        self.srv.shutdown()
        self.srv.server_close()
        self.ks.close()

    def test_put_read_roundtrip(self):
        self.assertIsNone(self.store.put("a", "甲"))
        self.assertEqual(self.store.read("a"), "甲")
        self.assertIsNone(self.store.put("a", "甲"))
        self.assertEqual(self.store.read("a"), "甲")
        with self.assertRaises(Fault) as cm:
            self.store.put("a", "乙")
        self.assertEqual(cm.exception.param, "text")
        self.assertEqual(self.store.read("a"), "甲")

    def test_validation(self):
        for bad in (None, 1, "", "a-b", "a_b", "a b", "é"):
            with self.assertRaises(Fault) as cm:
                self.store.put(bad, "x")
            self.assertEqual(cm.exception.param, "id")
        for bad in (None, 1, b"x", ["x"]):
            with self.assertRaises(Fault) as cm:
                self.store.put("a", bad)
            self.assertEqual(cm.exception.param, "text")
        with self.assertRaises(Fault) as cm:
            self.store.read("missing")
        self.assertEqual(cm.exception.param, "id")
        with self.assertRaises(Fault) as cm:
            self.store.rotate("bad job")
        self.assertEqual(cm.exception.param, "job")
        with self.assertRaises(Fault) as cm:
            self.store.status("missing")
        self.assertEqual(cm.exception.param, "job")

    def test_rotation_completes_and_destroys_old_key(self):
        self.store.put("a", "甲")
        self.assertEqual(self.store.rotate("j"), 1)
        self.assertEqual(self.store.status("j"), {"target": 1, "state": "pending"})
        self.assertEqual(self.store.rotate("j"), 1)
        self.assertTrue(self.store.run_job("j"))
        self.assertEqual(self.store.status("j"), {"target": 1, "state": "done"})
        self.assertEqual(self.store.read("a"), "甲")
        self.assertTrue(self.ks.info(0)["tombstoned"])
        self.store.put("b", "乙")
        self.assertEqual(self.store.read("b"), "乙")
        self.assertEqual(self.store.upload_gen(), 1)

    def test_new_job_rejected_while_pending(self):
        self.store.put("a", "甲")
        self.store.rotate("j1")
        with self.assertRaises(Fault) as cm:
            self.store.rotate("j2")
        self.assertEqual(cm.exception.param, "job")
        self.assertEqual(self.store.status("j1")["state"], "pending")
        self.store.run_job("j1")
        self.assertEqual(self.store.rotate("j2"), 2)

    def test_worker_resumes_after_mid_migration_crash(self):
        for i in range(5):
            self.store.put(f"o{i}", f"v{i}")
        self.store.rotate("j")
        # Simulate a crash after exactly one envelope replacement: run a
        # partial migration by hand, then complete with the real routine.
        with self.store._db() as conn:
            rows = conn.execute(
                "SELECT id, gen, wrap FROM objects WHERE gen<1 LIMIT 2").fetchall()
        for obj_id, gen, wrap_blob in rows:
            self.store._migrate_one(obj_id, gen, wrap_blob, 1)
        self.assertTrue(self.store.run_job("j"))
        for i in range(5):
            self.assertEqual(self.store.read(f"o{i}"), f"v{i}")
        self.assertEqual(self.store.status("j"), {"target": 1, "state": "done"})

    def test_old_envelope_read_after_destroy(self):
        self.store.put("a", "甲")
        with self.store._db() as conn:
            gen, wrap_blob, _l, _s = self.store._row(conn, "a")
        self.store.rotate("j")
        self.store.run_job("j")
        # The captured envelope is now stale and its generation destroyed.
        self.assertEqual(
            self.store.read_with_envelope("a", gen, wrap_blob), "甲")

    def test_body_ciphertext_not_rewritten_by_rotation(self):
        for i in range(3):
            self.store.put(f"o{i}", f"v{i}")
        with self.store._db() as conn:
            before = dict(conn.execute("SELECT id, body_sha FROM objects").fetchall())
        self.store.rotate("j")
        self.store.run_job("j")
        with self.store._db() as conn:
            after = dict(conn.execute("SELECT id, body_sha FROM objects").fetchall())
        self.assertEqual(before, after)

    def test_disk_has_no_plaintext(self):
        self.store.put("secret", "绝密内容XYZ")
        for dirpath, _d, files in os.walk(self.store.data_dir):
            for name in files:
                with open(os.path.join(dirpath, name), "rb") as f:
                    self.assertNotIn("绝密内容XYZ".encode(), f.read())

    def test_concurrent_puts_are_serialized(self):
        errors = []

        def worker(n):
            try:
                for k in range(5):
                    oid = f"c{n}x{k}"
                    self.store.put(oid, f"t{n}{k}")
                    assert self.store.read(oid) == f"t{n}{k}"
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_concurrent_conflicting_put_has_one_winner(self):
        results = []

        def attempt(text):
            try:
                self.store.put("same", text)
                results.append(("ok", text))
            except Fault as exc:
                results.append((exc.param, text))

        # Publish one value first, then race identical and different writers.
        self.store.put("same", "原值")
        threads = [threading.Thread(target=attempt, args=(t,))
                   for t in ("原值", "甲", "乙", "原值", "丙")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        ok = [r for r in results if r[0] == "ok"]
        bad = [r for r in results if r[0] != "ok"]
        self.assertEqual(len(ok), 2)          # the two identical retries
        self.assertTrue(all(r[0] == "text" for r in bad))
        self.assertEqual(self.store.read("same"), "原值")

    def test_rejected_requests_leave_no_trace(self):
        before = self.store.upload_gen()
        with self.assertRaises(Fault):
            self.store.rotate("bad job")
        with self.assertRaises(Fault):
            self.store.status("bad job")
        with self.assertRaises(Fault):
            self.store.put("a", object())
        self.assertEqual(self.store.upload_gen(), before)
        with self.store._db() as conn:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM objects").fetchone()[0], 0)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 0)

    def test_keystore_gone_blocks_rotation_but_not_old_reads(self):
        self.store.put("a", "甲")
        self.store.rotate("j")
        self.ks.destroy(1)  # target key destroyed behind our back
        with self.assertRaises(KeySideError):
            self.store.run_job("j")
        self.assertEqual(self.store.status("j")["state"], "pending")
        # Old generation still works for reads.
        self.assertEqual(self.store.read("a"), "甲")


if __name__ == "__main__":
    unittest.main()
