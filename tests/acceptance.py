#!/usr/bin/env python3
"""End-to-end acceptance run (processes, independent databases, HTTP).

Starts, as separate OS processes:
  * key service  (own SQLite DB, own directory)
  * archive server
  * rotation worker

then exercises the required scenarios, including hard kills (SIGKILL) at the
"durably committed, reply not yet sent" points:

  A. put a="甲", rotate(job), worker completes it
     -> read(a) == "甲", status == {target: 1, state: done}, keystore gen 0
        tombstoned (and its key row gone)
  B. late upload + old-envelope read while the migration is paused
  C. keystore killed after destroying gen 0 but before replying; restarted;
     a reader still holding the old envelope and an upload both work
  D. keystore killed after committing key creation, before replying
  E. archive server killed after committing a put, before replying
  F. worker killed after confirming destroy, before writing done; restarted

Exit status is 0 only if every check passes.

Run:  python3 -m tests.acceptance      (or python3 tests/acceptance.py)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from archive.common import arm_kill_file, disarm_kill_file, kill_pid  # noqa: E402
from archive.client import ArchiveClient, ArchiveError  # noqa: E402

PY = sys.executable
FAILS: list[str] = []
CHECKS = 0


def check(name: str, cond: bool, extra=""):
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {extra}")
        FAILS.append(name)


def eq(name: str, got, want):
    check(name, got == want, f"(got {got!r}, want {want!r})")


def wait_file(path: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(path):
            return
        time.sleep(0.02)
    raise RuntimeError(f"timeout waiting for {path}")


def wait_port(path: str, timeout: float = 30.0) -> str:
    wait_file(path, timeout)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["url"]


class Proc:
    def __init__(self, argv, env=None, name="proc"):
        self.name = name
        full_env = dict(os.environ)
        full_env.pop("PYTHONPATH", None)
        if env:
            full_env.update(env)
        self.p = subprocess.Popen([PY, "-I", os.path.join(ROOT, "bin", "run.py")] + argv, cwd=ROOT,
                                  env=full_env, start_new_session=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True)

    def kill(self):
        kill_pid(self.p.pid)

    def wait(self, timeout=30):
        return self.p.wait(timeout=timeout)

    @property
    def pid(self):
        return self.p.pid

    def output(self) -> str:
        try:
            out, err = self.p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.kill()
            out, err = self.p.communicate(timeout=5)
        return (out or "") + (err or "")

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.kill()
        for stream in (self.p.stdout, self.p.stderr):
            try:
                stream.close()
            except Exception:
                pass


class Env:
    def __init__(self, root: str):
        self.root = root
        self.key_dir = os.path.join(root, "keys")
        self.arch_dir = os.path.join(root, "archive")
        for d in (self.key_dir, self.arch_dir,
                  os.path.join(self.arch_dir, "data")):
            os.makedirs(d, exist_ok=True)
        self.key_db = os.path.join(self.key_dir, "keys.db")
        self.key_endpoint = os.path.join(self.key_dir, "endpoint.json")
        self.arch_db = os.path.join(self.arch_dir, "archive.db")
        self.arch_data = os.path.join(self.arch_dir, "data")
        self.arch_endpoint = os.path.join(self.arch_dir, "endpoint.json")
        self.kill_files = os.path.join(root, "kill")
        os.makedirs(self.kill_files, exist_ok=True)
        self.key = None
        self.server = None
        self.worker = None

    # -- keystore ------------------------------------------------------
    def start_key(self, *, kill_after=None, extra_env=None):
        env = {}
        if kill_after:
            env["ARCH_KILL_AFTER_" + kill_after.upper()] = self.kill_path(kill_after)
        if extra_env:
            env.update(extra_env)
        for path in (self.key_endpoint,):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
        self.key = Proc([
            "keyserver", "--db", self.key_db, "--port", "0",
            "--endpoint-file", self.key_endpoint], env=env, name="key")
        url = wait_port(self.key_endpoint)
        return url

    def key_url(self) -> str:
        with open(self.key_endpoint, "r", encoding="utf-8") as f:
            return json.load(f)["url"]

    def kill_path(self, name: str) -> str:
        return os.path.join(self.kill_files, name)

    # -- archive server ------------------------------------------------
    def start_server(self, *, kill_after=None, extra_env=None):
        env = {}
        if kill_after:
            env["ARCH_KILL_AFTER_" + kill_after.upper()] = self.kill_path(kill_after)
        if extra_env:
            env.update(extra_env)
        try:
            os.unlink(self.arch_endpoint)
        except FileNotFoundError:
            pass
        self.server = Proc([
            "server", "--db", self.arch_db, "--data", self.arch_data,
            "--endpoint-file", self.key_endpoint,
            "--endpoint-out", self.arch_endpoint], env=env, name="server")
        return wait_port(self.arch_endpoint)

    def start_worker(self, *, kill_after=None, extra_env=None, job=None):
        env = {}
        if kill_after:
            env["ARCH_KILL_AFTER_" + kill_after.upper()] = self.kill_path(kill_after)
        if extra_env:
            env.update(extra_env)
        argv = ["worker", "--db", self.arch_db, "--data", self.arch_data,
                "--endpoint-file", self.key_endpoint, "--poll", "0.2"]
        if job:
            argv += ["--job", job]
        self.worker = Proc(argv, env=env, name="worker")
        return self.worker

    def stop_all(self):
        for p in (self.worker, self.server, self.key):
            if p is not None:
                p.stop()
        self.worker = self.server = self.key = None


def client(env: Env) -> ArchiveClient:
    with open(env.arch_endpoint, "r", encoding="utf-8") as f:
        return ArchiveClient(json.load(f)["url"])


def wait_status(cli: ArchiveClient, job: str, state: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = cli.status(job)
        except ArchiveError as exc:
            last = exc.payload
        if isinstance(last, dict) and last.get("state") == state:
            return last
        time.sleep(0.05)
    raise RuntimeError(f"job {job} never reached {state}; last={last!r}")


def keystore_info(url: str, gen: int) -> dict:
    with urllib.request.urlopen(f"{url}/v1/keys/{gen}", timeout=10) as resp:
        return json.loads(resp.read().decode())


def keystore_call(url: str, gen: int, action: str) -> tuple[int, dict]:
    req = urllib.request.Request(f"{url}/v1/keys/{gen}/{action}", data=b"{}",
                                 method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def all_files_contain(root: str, needle: bytes) -> bool:
    """Scan every file (including SQLite/WAL files) for plaintext bytes."""
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            try:
                with open(path, "rb") as f:
                    if needle in f.read():
                        return True
            except OSError:
                pass
    return False


def archive_gens(db_path: str) -> set[int]:
    import sqlite3
    conn = sqlite3.connect(db_path)
    try:
        return {int(g) for (g,) in conn.execute("SELECT DISTINCT gen FROM objects")}
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

def scenario_main(root: str) -> None:
    print("A. store, rotate to 1, complete, verify")
    env = Env(root)
    env.start_key()
    env.start_server()
    cli = client(env)

    eq("put returns null", cli.put("a", "甲"), None)
    eq("read returns text", cli.read("a"), "甲")
    eq("idempotent retry returns null", cli.put("a", "甲"), None)
    try:
        cli.put("a", "乙")
        check("conflicting text rejected", False)
    except ArchiveError as exc:
        eq("conflicting text rejected with {error}", exc.payload, {"error": "text"})
    eq("text unchanged after conflict", cli.read("a"), "甲")
    eq("empty text allowed", cli.put("empty", ""), None)
    eq("empty text read back", cli.read("empty"), "")
    eq("unicode safe (emoji/astral)", (cli.put("u", "𝕏😀\u0000é"), cli.read("u")),
       (None, "𝕏😀\u0000é"))
    long_id = "L" * 5000
    eq("long ASCII alphanumeric id accepted",
       (cli.put(long_id, "长"), cli.read(long_id)), (None, "长"))
    for bad in (123, True, None, "", "a-b", "a b", "a\n", "é", "a_b", "a.b"):
        try:
            cli.put(bad, "x")
            check(f"bad id rejected: {bad!r}", False)
        except ArchiveError as exc:
            eq(f"bad id {bad!r} -> error id", exc.payload, {"error": "id"})
    for bad in (123, None, ["a"], {"a": 1}, True, "\ud800"):
        try:
            cli.put("badtext", bad)
            check(f"bad text rejected: {bad!r}", False)
        except ArchiveError as exc:
            eq(f"bad text {bad!r} -> error text", exc.payload, {"error": "text"})
    try:
        cli.read("nope")
        check("unknown read rejected", False)
    except ArchiveError as exc:
        eq("unknown read -> error id", exc.payload, {"error": "id"})

    key_url = env.key_url()
    eq("keystore gen0 exists initially", keystore_info(key_url, 0)["exists"], True)

    target = cli.rotate("job1")
    eq("rotate returns target 1", target, 1)
    eq("retry of rotate returns same target", cli.rotate("job1"), 1)
    eq("status pending", cli.status("job1"), {"target": 1, "state": "pending"})
    try:
        cli.rotate("job2")
        check("new job while pending rejected", False)
    except ArchiveError as exc:
        eq("new job rejected -> {error: job}", exc.payload, {"error": "job"})
    try:
        cli.status("job2")
        check("unknown job status rejected", False)
    except ArchiveError as exc:
        eq("unknown job -> error job", exc.payload, {"error": "job"})

    env.start_worker(job="job1")
    wait_status(cli, "job1", "done")
    eq("status done", cli.status("job1"), {"target": 1, "state": "done"})
    eq("read after rotation", cli.read("a"), "甲")
    eq("read other objects after rotation", (cli.read("empty"), cli.read("u")),
       ("", "𝕏😀\u0000é"))
    info0 = keystore_info(key_url, 0)
    eq("gen0 destroyed at keystore", info0["tombstoned"], True)
    eq("gen0 key material gone", info0["exists"], False)
    code, payload = keystore_call(key_url, 0, "create")
    eq("late create of gen0 refused", code, 410)
    eq("gen0 resurrected?", keystore_info(key_url, 0)["exists"], False)
    eq("new upload after rotation uses gen1", cli.put("b", "后"), None)
    eq("read new upload", cli.read("b"), "后")
    eq("retry of done job returns its original target", cli.rotate("job1"), 1)
    eq("done job status unchanged", cli.status("job1"),
       {"target": 1, "state": "done"})
    cli.put("sentinel", "绝密SENTINEL甲")
    check("archive disk has no plaintext text",
          not all_files_contain(env.arch_data, "甲".encode()), "")
    check("archive index/data has no plaintext sentinel (incl. WAL)",
          not all_files_contain(env.arch_dir, "绝密SENTINEL".encode()), "")
    check("keystore dir has no plaintext sentinel",
          not all_files_contain(env.key_dir, "绝密SENTINEL".encode()), "")
    check("all published objects use gen1 after done",
          archive_gens(env.arch_db) == {1}, archive_gens(env.arch_db))

    print("B. concurrent put/read while migration paused; old-envelope read")
    # Prepare objects at gen 1, then start rotation 2 and pause the worker.
    for i in range(3):
        cli.put(f"pre{i}", f"值{i}")
    # Capture an envelope while it still belongs to gen 1.
    from archive.backend import ArchiveStore
    cap = ArchiveStore(env.arch_db, env.arch_data, None,
                       endpoint_file=env.key_endpoint, clean_tmp=False)
    try:
        with cap._db() as conn:
            g1_row = cap._row(conn, "pre1")
        eq("captured pre1 envelope on gen1", g1_row[0], 1)
        old_envelope = (g1_row[0], g1_row[1])
    finally:
        cap.close()
    eq("rotate to 2", cli.rotate("job2"), 2)
    try:
        cli.rotate("job3")
        check("new job during pending rotation rejected", False)
    except ArchiveError as exc:
        eq("rejected during pending -> {error: job}", exc.payload, {"error": "job"})
    pause = os.path.join(root, "pause_migration")
    arm_kill_file(pause)
    w = env.start_worker(job="job2",
                         extra_env={"ARCH_PAUSE_MIGRATION": pause})
    # While the worker is paused, uploads and reads must still work.
    time.sleep(0.5)
    eq("upload during paused migration", cli.put("late", "迟到"), None)
    eq("late upload published under the new target generation",
       archive_gens(env.arch_db), {1, 2})
    eq("read during paused migration", cli.read("a"), "甲")
    eq("read new during paused migration", cli.read("late"), "迟到")
    # An object migrated to the new generation still reads fine.
    eq("status still pending during pause", cli.status("job2")["state"], "pending")
    disarm_kill_file(pause)
    wait_status(cli, "job2", "done", timeout=60)
    eq("status job2 done", cli.status("job2"), {"target": 2, "state": "done"})
    eq("read after second rotation", cli.read("pre0"), "值0")
    eq("read late upload after rotation", cli.read("late"), "迟到")
    eq("gen1 destroyed", keystore_info(env.key_url(), 1)["tombstoned"], True)
    eq("read all pre objects", [cli.read(f"pre{i}") for i in range(3)],
       ["值0", "值1", "值2"])
    # Old-envelope read after the rotation: gen1 is destroyed, so the reader
    # must re-fetch the current envelope instead of failing.
    rd = ArchiveStore(env.arch_db, env.arch_data, None,
                      endpoint_file=env.key_endpoint, clean_tmp=False)
    try:
        eq("old-envelope read after rotation", rd.read_with_envelope("pre1", *old_envelope), "值1")
    finally:
        rd.close()
    w.stop()

    print("C. keystore killed after tombstone commit, before reply")
    # Reader captures the *stale* envelope of an object at gen 2, then rotation
    # 3 retires gen 2.  The reader uses the stale envelope -> 410 -> re-fetch.
    from archive.backend import ArchiveStore
    from archive.keyserver import KeyStore

    # Capture the envelope of object "a" as it is now (gen 2).
    db_store = ArchiveStore(env.arch_db, env.arch_data, None,
                            endpoint_file=env.key_endpoint, clean_tmp=False)
    try:
        with db_store._db() as conn:
            row = db_store._row(conn, "a")
        stale_env = (row[0], row[1])
        eq("captured envelope for a uses gen2", row[0], 2)
    finally:
        db_store.close()

    eq("rotate to 3", cli.rotate("job3"), 3)
    # Restart the keystore with a kill point that fires right after it commits
    # the gen-2 tombstone and before it writes the HTTP reply.
    kp = env.kill_path("destroy_commit")
    arm_kill_file(kp)
    env.key.stop()
    try:
        os.unlink(env.key_endpoint)
    except FileNotFoundError:
        pass
    env.start_key(kill_after="destroy_commit")
    w = env.start_worker(job="job3")
    # Wait for keystore to die.
    deadline = time.time() + 60
    while time.time() < deadline and env.key.p.poll() is None:
        time.sleep(0.05)
    check("keystore was SIGKILLed at destroy commit", env.key.p.poll() is not None)
    disarm_kill_file(kp)
    # Worker should not have marked the job done without a confirmed destroy.
    st = cli.status("job3")
    check("job3 not done while keystore still down", st["state"] == "pending", st)
    # Restart keystore: tombstone is durable, key row is gone.
    env.start_key()
    key_url = env.key_url()
    info2 = keystore_info(key_url, 2)
    eq("gen2 tombstoned after restart", info2["tombstoned"], True)
    eq("gen2 key gone after restart", info2["exists"], False)
    code, _ = keystore_call(key_url, 2, "create")
    eq("create for gen2 in tombstone -> 410", code, 410)
    # A reader with the stale envelope must transparently re-fetch.
    stale_read = db_store2 = ArchiveStore(env.arch_db, env.arch_data, None,
                                          endpoint_file=env.key_endpoint,
                                          clean_tmp=False)
    try:
        eq("stale-envelope read re-fetches current envelope",
           db_store2.read_with_envelope("a", *stale_env), "甲")
    finally:
        db_store2.close()
    # Rotation must complete now that the keystore is back.
    wait_status(cli, "job3", "done", timeout=90)
    eq("status job3 done", cli.status("job3"), {"target": 3, "state": "done"})
    eq("read after keystore restart + rotation", cli.read("a"), "甲")
    eq("late upload after keystore restart", (cli.put("after", "后到"),
                                              cli.read("after")),
       (None, "后到"))
    w.stop()

    print("D. keystore killed after create commit, before reply")
    eq("rotate to 4", cli.rotate("job4"), 4)
    kp = env.kill_path("create_commit")
    arm_kill_file(kp)
    env.key.stop()          # stop current keystore
    try:
        os.unlink(env.key_endpoint)
    except FileNotFoundError:
        pass
    env.start_key(kill_after="create_commit")
    # The keystore will kill itself when the worker asks it to create gen 4.
    w = env.start_worker(job="job4")
    deadline = time.time() + 60
    while time.time() < deadline and env.key.p.poll() is None:
        time.sleep(0.05)
    check("keystore killed after create commit", env.key.p.poll() is not None)
    disarm_kill_file(kp)
    env.start_key()
    eq("gen4 key exists after restart", keystore_info(env.key_url(), 4)["exists"], True)
    wait_status(cli, "job4", "done", timeout=90)
    eq("status job4 done", cli.status("job4"), {"target": 4, "state": "done"})
    eq("read after create-commit crash", cli.read("a"), "甲")
    eq("gen3 destroyed", keystore_info(env.key_url(), 3)["tombstoned"], True)
    w.stop()

    print("E. archive server killed after put commit, before reply")
    eq("rotate to 5", cli.rotate("job5"), 5)
    w = env.start_worker(job="job5")
    wait_status(cli, "job5", "done", timeout=90)
    kp = env.kill_path("put_commit")
    arm_kill_file(kp)
    env.server.stop()
    env.start_server(kill_after="put_commit")
    # First write succeeds server-side, then the process is SIGKILLed before
    # it can reply, so the client sees a transport error.
    try:
        client(env).put("crashy", "已确认")
        check("put reply was lost as intended", False)
    except Exception:
        check("put reply was lost as intended", True)
    time.sleep(0.2)
    check("archive server died at put commit",
          env.server.p.poll() is not None)
    disarm_kill_file(kp)
    env.start_server()
    cli = client(env)
    eq("read of committed-before-crash object", cli.read("crashy"), "已确认")
    eq("retry of lost reply is a no-op", cli.put("crashy", "已确认"), None)
    eq("read after retry", cli.read("crashy"), "已确认")
    eq("new upload still uses current gen 5", cli.put("z", "尾"), None)
    eq("read z", cli.read("z"), "尾")
    w.stop()

    print("F. worker killed after confirmed destroy, before done; restart")
    eq("rotate to 6", cli.rotate("job6"), 6)
    kp = env.kill_path("worker_destroy")
    arm_kill_file(kp)
    w = env.start_worker(job="job6", kill_after="worker_destroy")
    deadline = time.time() + 90
    while time.time() < deadline and w.p.poll() is None:
        time.sleep(0.05)
    check("worker killed before marking done", w.p.poll() is not None)
    disarm_kill_file(kp)
    key_url = env.key_url()
    eq("gen5 destroyed before job done", keystore_info(key_url, 5)["tombstoned"], True)
    st = cli.status("job6")
    check("job6 still pending after worker crash", st["state"] == "pending", st)
    eq("read works with done-implying old key destroyed",
       cli.read("a"), "甲")
    env.start_worker(job="job6")
    wait_status(cli, "job6", "done", timeout=90)
    eq("job6 done after restart", cli.status("job6"), {"target": 6, "state": "done"})
    eq("read all objects after final rotation",
       [cli.read(k) for k in ("a", "empty", "u", "b", "late", "crashy", "z")],
       ["甲", "", "𝕏😀\u0000é", "后", "迟到", "已确认", "尾"])

    print("G. concurrency: 20 threads uploading and reading during rotation")
    for i in range(10):
        cli.put(f"c{i}", f"并发{i}")
    eq("rotate to 7", cli.rotate("job7"), 7)
    errors: list[str] = []

    def hammer(n: int):
        c = client(env)
        try:
            for k in range(6):
                oid = f"t{n}x{k}"
                c.put(oid, f"文本{n}-{k}")
                if c.read(oid) != f"文本{n}-{k}":
                    errors.append(f"bad read {oid}")
                if c.read(f"c{k}") != f"并发{k}":
                    errors.append(f"bad read c{k}")
        except Exception as exc:
            errors.append(repr(exc))

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(10)]
    w = env.start_worker(job="job7")
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    check("no concurrency errors", not errors, errors[:3])
    wait_status(cli, "job7", "done", timeout=120)
    eq("job7 done", cli.status("job7"), {"target": 7, "state": "done"})
    eq("all concurrent objects readable",
       all(cli.read(f"t{n}x{k}") == f"文本{n}-{k}" for n in range(10) for k in range(6)),
       True)
    eq("gen6 destroyed", keystore_info(key_url, 6)["tombstoned"], True)
    eq("no object left on an old generation", archive_gens(env.arch_db), {7})
    # No plaintext anywhere on the archive's disk.
    check("no plaintext on archive disk after all rotations",
          not all_files_contain(env.arch_data, "并发0".encode()) and
          not all_files_contain(env.arch_data, "已确认".encode()), "")
    w.stop()

    print("H. worker killed in the middle of envelope migration")
    eq("rotate to 8", cli.rotate("job8"), 8)
    kp = env.kill_path("migrate_commit")
    arm_kill_file(kp)
    target_gens_before = archive_gens(env.arch_db)
    check("pre-migration objects still on gen 7",
          target_gens_before == {7}, target_gens_before)
    w = env.start_worker(job="job8", kill_after="migrate_commit")
    deadline = time.time() + 60
    while time.time() < deadline and w.p.poll() is None:
        time.sleep(0.05)
    check("worker killed after first envelope commit", w.p.poll() is not None)
    disarm_kill_file(kp)
    partial = archive_gens(env.arch_db)
    check("migration was partial when killed", 8 in partial and 7 in partial, partial)
    eq("job8 still pending", cli.status("job8")["state"], "pending")
    eq("reads work mid-migration", [cli.read(k) for k in ("a", "z")], ["甲", "尾"])
    eq("uploads work mid-migration", (cli.put("mid", "中途"), cli.read("mid")),
       (None, "中途"))
    env.start_worker(job="job8")
    wait_status(cli, "job8", "done", timeout=120)
    eq("job8 done after restart", cli.status("job8"), {"target": 8, "state": "done"})
    eq("all objects on gen8", archive_gens(env.arch_db), {8})
    eq("gen7 destroyed", keystore_info(key_url, 7)["tombstoned"], True)
    eq("read everything after interrupted migration",
       [cli.read(k) for k in ("a", "empty", "u", "z", "mid")],
       ["甲", "", "𝕏😀\u0000é", "尾", "中途"])
    w.stop()
    env.stop_all()


def main() -> int:
    root = tempfile.mkdtemp(prefix="archive-accept-")
    print(f"workdir: {root}")
    try:
        scenario_main(root)
    except Exception:
        import traceback
        traceback.print_exc()
        FAILS.append("unexpected exception")
    finally:
        pass
    print()
    if FAILS:
        print(f"FAILED {len(FAILS)} of {CHECKS} checks: {FAILS}")
        return 1
    print(f"PASSED all {CHECKS} checks")
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
