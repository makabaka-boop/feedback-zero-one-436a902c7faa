"""Archive backend: immutable encrypted objects + resumable generation rotation.

Storage invariants
------------------
Every published object exists as:

    data/objects/<id>     body: magic + nonce + AES-256-GCM ciphertext of the
                          UTF-8 text (AAD binds the id)
    SQLite index row      id, gen, wrapped data key ("envelope"), body length
                          and SHA-256

The text is never written to disk by the archive side, and the data key only
ever exists there wrapped under a per-generation master key owned by the
*independent* key service (separate process, separate SQLite database).
Publishing a body and putting the matching row in the index is ordered so that
a row is never visible without a complete body; the index commit is the
publication point.

Generation protocol
-------------------
* ``uploaded_gen`` is the generation new uploads must use.  ``put`` reads it
  inside the publication step while holding the cross-process upload lock, so
  a delayed/late upload can never publish under a retired generation.
* ``rotate(job)``:
    - an existing job name returns its original target (idempotent retry),
      even if that job is already done;
    - a *new* job is rejected while any rotation is incomplete;
    - otherwise, in one transaction: target = uploaded_gen + 1, register the
      job as pending, advance uploaded_gen to target.  The target is fixed
      forever.
* ``status(job)`` -> {"target": n, "state": "pending" | "done"}.
* A background worker (``python -m archive.worker``), which may be a separate
  process, re-wraps data keys only; body ciphertext is never modified.  When
  every published object uses the target generation, older generation keys are
  destroyed at the keystore.  ``done`` is written only after the keystore
  confirms each destruction (permanent tombstone).  All phases are idempotent,
  so a crash at any point resumes cleanly.
* A read that observes the old envelope while its key is being destroyed gets
  ``410 gen_destroyed`` from the keystore and transparently re-fetches the
  current envelope.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import sqlite3
import sys
import threading
import time

from . import crypto
from .common import Fault, KeySideError, is_valid_id, validate_text
from .faults import kill_point
from .keyclient import KeyClient

SCHEMA = """
CREATE TABLE IF NOT EXISTS objects (
    id           TEXT PRIMARY KEY,
    gen          INTEGER NOT NULL,
    wrap         BLOB NOT NULL,
    body_len     INTEGER NOT NULL,
    body_sha     TEXT NOT NULL,
    published_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
    job        TEXT PRIMARY KEY,
    target     INTEGER NOT NULL,
    prev_gen   INTEGER NOT NULL,
    state      TEXT NOT NULL,
    created_at REAL NOT NULL,
    done_at    REAL
);
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
"""

BODY_MAGIC = b"ARCHBODY1"
MIGRATION_BATCH = 64


class UnknownObject(Exception):
    pass


class _Busy(Exception):
    pass


class _Retry(Exception):
    pass


def _id_aad(obj_id: str) -> bytes:
    return b"archive-body-v1:" + obj_id.encode("ascii")


def encode_body(nonce: bytes, ct: bytes) -> bytes:
    return BODY_MAGIC + bytes([len(nonce)]) + nonce + ct


def decode_body(raw: bytes) -> tuple[bytes, bytes]:
    if not raw.startswith(BODY_MAGIC):
        raise ValueError("bad body")
    off = len(BODY_MAGIC)
    nlen = raw[off]
    nonce = raw[off + 1: off + 1 + nlen]
    ct = raw[off + 1 + nlen:]
    if len(nonce) != nlen or not ct:
        raise ValueError("bad body")
    return nonce, ct


class ArchiveStore:
    """In-process backend.  Safe for concurrent use by many threads."""

    def __init__(self, db_path: str, data_dir: str, keystore_url: str | None = None, *,
                 endpoint_file: str | None = None,
                 http_timeout: float = 10.0, key_retries: int = 8,
                 lock_timeout: float = 30.0, clean_tmp: bool = True):
        self.db_path = os.path.abspath(db_path)
        self.data_dir = os.path.abspath(data_dir)
        self.obj_dir = os.path.join(self.data_dir, "objects")
        self.tmp_dir = os.path.join(self.data_dir, "tmp")
        for d in (self.data_dir, self.obj_dir, self.tmp_dir):
            os.makedirs(d, exist_ok=True)
        if clean_tmp:
            self._clean_tmp()
        self.keyclient = KeyClient(keystore_url, endpoint_file=endpoint_file,
                                   timeout=http_timeout, retries=key_retries)
        self.lock_timeout = lock_timeout
        self._db_lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, timeout=30,
                                     isolation_level=None,
                                     check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=30000")
        with self._db_lock:
            self._conn.executescript(SCHEMA)
        with self._tx():
            for k, v in (("uploaded_gen", "0"),):
                self._conn.execute(
                    "INSERT OR IGNORE INTO meta(k, v) VALUES (?,?)", (k, v))
        self._upload_mutex = threading.Lock()
        self._worker_mutex = threading.Lock()
        self._upload_file = self._open_lock("upload")
        self._worker_file = self._open_lock("worker")

    # -- infrastructure ------------------------------------------------
    def _clean_tmp(self, older_than: float = 300.0) -> None:
        """Remove only stale temp files: another process may be writing."""
        cutoff = time.time() - older_than
        for name in os.listdir(self.tmp_dir):
            path = os.path.join(self.tmp_dir, name)
            try:
                if os.stat(path).st_mtime < cutoff:
                    os.unlink(path)
            except OSError:
                pass

    def _open_lock(self, name: str):
        return open(self.db_path + "." + name + ".lock", "a+b")

    def close(self) -> None:
        with self._db_lock:
            self._conn.close()
        for f in (self._upload_file, self._worker_file):
            try:
                f.close()
            except Exception:
                pass

    @contextlib.contextmanager
    def _db(self):
        with self._db_lock:
            yield self._conn

    @contextlib.contextmanager
    def _tx(self, conn=None):
        with self._db_lock:
            conn = conn or self._conn
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.OperationalError:
                    pass
                raise
            else:
                conn.execute("COMMIT")

    @contextlib.contextmanager
    def _guard(self, mutex: threading.Lock, file_obj, timeout):
        acquired = mutex.acquire() if timeout is None else mutex.acquire(timeout=max(0.0, timeout))
        if not acquired:
            raise _Busy()
        try:
            if timeout is None:
                fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
            else:
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise _Busy()
                        time.sleep(0.005)
            try:
                yield
            finally:
                fcntl.flock(file_obj.fileno(), fcntl.LOCK_UN)
        finally:
            mutex.release()

    def upload_guard(self, timeout=None):
        return self._guard(self._upload_mutex, self._upload_file, timeout)

    def worker_guard(self, timeout=None):
        return self._guard(self._worker_mutex, self._worker_file, timeout)

    # -- meta ----------------------------------------------------------
    def _get_meta(self, conn, key: str) -> int:
        row = conn.execute("SELECT v FROM meta WHERE k=?", (key,)).fetchone()
        return int(row[0])

    @staticmethod
    def _set_meta(conn, key: str, value: int) -> None:
        conn.execute("UPDATE meta SET v=? WHERE k=?", (str(value), key))

    # -- files ---------------------------------------------------------
    def body_path(self, obj_id: str) -> str:
        # File names are the hash of the id: ids may be long and the id
        # itself never needs to appear on the filesystem.
        return os.path.join(self.obj_dir, hashlib.sha256(obj_id.encode("ascii")).hexdigest())

    @staticmethod
    def _fsync_dir(path: str) -> None:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _store_body(self, obj_id: str, raw: bytes) -> None:
        # Caller holds the upload lock, so this id cannot be published
        # concurrently; a leftover unpublished body is safe to replace.
        digest = hashlib.sha256(obj_id.encode("ascii")).hexdigest()
        tmp = os.path.join(self.tmp_dir,
                           f"{digest}.{os.getpid()}.{threading.get_ident()}")
        with open(tmp, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.body_path(obj_id))
        self._fsync_dir(self.obj_dir)

    def _load_body(self, obj_id: str) -> bytes:
        try:
            with open(self.body_path(obj_id), "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise UnknownObject(obj_id) from None

    # -- envelope helpers ---------------------------------------------
    @staticmethod
    def _wrap_to_blob(resp: dict) -> bytes:
        return crypto.encode_wrap(resp["gen"], resp["kid"], resp["nonce"], resp["ct"])

    @staticmethod
    def _blob_to_wrap(blob: bytes) -> dict:
        gen, kid, nonce, ct = crypto.decode_wrap(blob)
        return {"gen": gen, "kid": kid, "nonce": nonce, "ct": ct}

    @staticmethod
    def _row(conn, obj_id: str):
        return conn.execute(
            "SELECT gen, wrap, body_len, body_sha FROM objects WHERE id=?",
            (obj_id,)).fetchone()

    def _decrypt_row(self, row, obj_id: str) -> str:
        gen, wrap_blob, body_len, body_sha = row
        wrap = self._blob_to_wrap(wrap_blob)
        if wrap["gen"] != gen:
            raise ValueError("envelope/gen mismatch")
        data_key = self.keyclient.unwrap(gen, wrap)
        raw = self._load_body(obj_id)
        if len(raw) != body_len or hashlib.sha256(raw).hexdigest() != body_sha:
            raise ValueError("body integrity failure")
        nonce, ct = decode_body(raw)
        return crypto.aead_decrypt(data_key, nonce, ct, _id_aad(obj_id)).decode("utf-8")

    # ------------------------------------------------------------------
    # put
    # ------------------------------------------------------------------
    def put(self, obj_id, text):
        if not is_valid_id(obj_id):
            raise Fault("id")
        text = validate_text(text)
        # Wait for the (short) publication critical section.  Rotation only
        # holds it for one SQLite transaction, so this cannot be indefinite
        # unless another upload is talking to a slow keystore.
        with self.upload_guard(None):
            return self._put_locked(obj_id, text)

    def _put_locked(self, obj_id: str, text: str):
        # Idempotent retry of an already published object.  Comparing the
        # stored plaintext is the only correct way to detect a conflict, so
        # this costs one keystore unwrap.
        with self._db() as conn:
            row = self._row(conn, obj_id)
        if row is not None:
            for attempt in range(8):
                try:
                    stored = self._decrypt_row(row, obj_id)
                    break
                except KeySideError as exc:
                    if exc.retryable:
                        raise
                    # A concurrent rotation replaced and retired the envelope
                    # between our index read and the unwrap.  Re-fetch it.
                    time.sleep(0.005 * (attempt + 1))
                    with self._db() as conn:
                        row = self._row(conn, obj_id)
                    if row is None:
                        raise Fault("id") from None
            else:
                raise KeySideError("no live envelope for id", retryable=False)
            if stored == text:
                return None
            raise Fault("text")

        plain = text.encode("utf-8")
        aad = _id_aad(obj_id)
        for _ in range(8):
            with self._db() as conn:
                gen = self._get_meta(conn, "uploaded_gen")
            self.keyclient.ensure(gen)          # idempotent per generation
            data_key = crypto.new_data_key()
            nonce, ct = crypto.aead_encrypt(data_key, plain, aad)
            wrap_resp = self.keyclient.wrap(gen, data_key)
            if wrap_resp["gen"] != gen:         # pragma: no cover - defensive
                continue
            wrap_blob = self._wrap_to_blob(wrap_resp)
            raw = encode_body(nonce, ct)
            body_sha = hashlib.sha256(raw).hexdigest()
            self._store_body(obj_id, raw)       # never visible before the row
            try:
                with self._tx() as conn:
                    # The upload generation cannot have moved: the caller holds
                    # the cross-process upload lock.  Assert anyway.
                    if self._get_meta(conn, "uploaded_gen") != gen:
                        raise _Retry()
                    if self._row(conn, obj_id) is not None:
                        raise _Retry()
                    conn.execute(
                        "INSERT INTO objects(id, gen, wrap, body_len, body_sha, "
                        "published_at) VALUES (?,?,?,?,?,?)",
                        (obj_id, gen, wrap_blob, len(raw), body_sha, time.time()))
            except _Retry:
                continue
            kill_point("put_commit")
            return None
        raise Fault("id")                       # pragma: no cover

    # ------------------------------------------------------------------
    # read
    # ------------------------------------------------------------------
    def read(self, obj_id):
        if not is_valid_id(obj_id):
            raise Fault("id")
        return self._read_with_row(obj_id, None)

    def read_with_envelope(self, obj_id, gen: int, wrap_blob: bytes):
        """Read using a *cached* (possibly stale) envelope.

        This is the path a reader takes when it captured an envelope before a
        rotation.  If that generation has been destroyed the keystore answers
        410 and the stored, current envelope is re-fetched transparently.
        """
        if not is_valid_id(obj_id):
            raise Fault("id")
        return self._read_with_row(obj_id, (gen, wrap_blob))

    def _read_with_row(self, obj_id: str, stale):
        row = None
        use_stale = stale is not None
        for attempt in range(8):
            with self._db() as conn:
                fresh = self._row(conn, obj_id)
            if fresh is None:
                raise Fault("id")
            if row is None:
                if use_stale:
                    row = (stale[0], stale[1], fresh[2], fresh[3])
                else:
                    row = fresh
            try:
                return self._decrypt_row(row, obj_id)
            except KeySideError as exc:
                if exc.retryable:
                    raise
                # 410 gen_destroyed: the envelope's generation was retired by a
                # committed rotation.  Re-fetch the current envelope and retry
                # (the stale one is only ever tried once).
                time.sleep(0.005 * (attempt + 1))
                row = None
                use_stale = False
            except UnknownObject:
                raise Fault("id") from None
        raise KeySideError("no live envelope for id", retryable=False)

    # ------------------------------------------------------------------
    # rotate / status
    # ------------------------------------------------------------------
    def rotate(self, job):
        if not is_valid_id(job):
            raise Fault("job")
        try:
            with self.upload_guard(self.lock_timeout):
                with self._tx() as conn:
                    row = conn.execute(
                        "SELECT target FROM jobs WHERE job=?", (job,)).fetchone()
                    if row is not None:
                        return int(row[0])
                    pending = conn.execute(
                        "SELECT 1 FROM jobs WHERE state<>'done' LIMIT 1").fetchone()
                    if pending is not None:
                        # Registered work is incomplete: a *new* rotation is
                        # rejected without touching any state.  The offending
                        # reference is the job parameter.
                        raise Fault("job")
                    prev = self._get_meta(conn, "uploaded_gen")
                    target = prev + 1
                    conn.execute(
                        "INSERT INTO jobs(job, target, prev_gen, state, created_at) "
                        "VALUES (?,?,?,'pending',?)",
                        (job, target, prev, time.time()))
                    self._set_meta(conn, "uploaded_gen", target)
        except _Busy:
            # Another rotation/upload holds the critical section: reject
            # without changing state.
            raise Fault("job") from None
        # Best-effort pre-creation of the target key.  If the keystore is
        # unreachable the worker and every subsequent upload retry it.  The
        # registration is already durable and the target is fixed, so this
        # must not turn a committed rotate into an error.
        try:
            self.keyclient.ensure(target)
        except KeySideError as exc:
            if not exc.retryable:
                # e.g. a tombstoned target: the job stays pending rather than
                # pretending the registration did not happen.
                print(f"warning: cannot create key for gen {target}: {exc}",
                      file=sys.stderr)
        return target

    def status(self, job):
        if not is_valid_id(job):
            raise Fault("job")
        with self._db() as conn:
            row = conn.execute(
                "SELECT target, state FROM jobs WHERE job=?", (job,)).fetchone()
        if row is None:
            raise Fault("job")
        return {"target": int(row[0]), "state": row[1]}

    # ------------------------------------------------------------------
    # background worker: drive a pending rotation to completion
    # ------------------------------------------------------------------
    def _job_row(self, job: str):
        with self._db() as conn:
            return conn.execute(
                "SELECT job, target, prev_gen, state FROM jobs WHERE job=?",
                (job,)).fetchone()

    def run_job(self, job: str, *, pause_hook=None) -> bool:
        """Drive one rotation job to done.  Idempotent and restartable."""
        row = self._job_row(job)
        if row is None:
            raise KeyError(job)
        _, target, prev_gen, state = row
        if state == "done":
            return True

        self.keyclient.ensure(target)

        # Phase 1: replace envelopes of objects that still use an *older*
        # generation.  Bodies are never touched.  A rotation only ever moves
        # forwards; an object at a newer generation would mean a newer job
        # already ran, which the registration protocol forbids.
        while True:
            with self._db() as conn:
                rows = conn.execute(
                    "SELECT id, gen, wrap FROM objects WHERE gen<? LIMIT ?",
                    (target, MIGRATION_BATCH)).fetchall()
            if not rows:
                break
            for obj_id, gen, wrap_blob in rows:
                if pause_hook is not None:
                    pause_hook()
                self._migrate_one(obj_id, gen, wrap_blob, target)

        with self._db() as conn:
            older = conn.execute(
                "SELECT COUNT(*) FROM objects WHERE gen<?", (target,)).fetchone()[0]
            newer = conn.execute(
                "SELECT COUNT(*) FROM objects WHERE gen>?", (target,)).fetchone()[0]
        if older or newer:
            raise RuntimeError("objects reference a generation other than the target")

        # Phase 2: destroy every older generation key.  No published object
        # references any generation other than the target (checked above), and
        # the target is immutable for this job, so generations < target are
        # unreachable for reads and safe to retire.  Idempotent; repeated if a
        # reply was lost.  The keystore leaves a permanent tombstone.
        # Newest first: the generation that was current until this rotation is
        # retired (and its destruction proven) before anything older.
        for g in range(target - 1, -1, -1):
            res = self.keyclient.destroy(g)
            info = self.keyclient.info(g)
            if not info.get("tombstoned"):
                raise RuntimeError(f"keystore did not confirm destruction of gen {g}")
            if res.get("existed"):
                # Crash point: a live key was provably destroyed and `done` is
                # not written yet.
                kill_point("worker_destroy")

        # Phase 3: the commit point for `done`.
        with self._tx() as conn:
            conn.execute(
                "UPDATE jobs SET state='done', done_at=? WHERE job=? AND state<>'done'",
                (time.time(), job))
        return True

    def _migrate_one(self, obj_id: str, gen: int, wrap_blob: bytes, target: int) -> None:
        if gen == target:                       # pragma: no cover - query filter
            return
        wrap = self._blob_to_wrap(wrap_blob)
        try:
            data_key = self.keyclient.unwrap(gen, wrap)
        except KeySideError as exc:
            if exc.retryable:
                raise
            # Envelope changed underneath us: verify the object now uses the
            # target generation; if so nothing to do.
            with self._db() as conn:
                row = self._row(conn, obj_id)
            if row is None or row[0] == target:
                return
            raise
        new_wrap = self._wrap_to_blob(self.keyclient.wrap(target, data_key))
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE objects SET gen=?, wrap=? WHERE id=? AND gen=?",
                (target, new_wrap, obj_id, gen))
            if cur.rowcount == 0:
                row = self._row(conn, obj_id)
                if row is None or row[0] != target:
                    raise RuntimeError("envelope migration race")
        # Crash point: this envelope is durably replaced; the job is not done.
        kill_point("migrate_commit")

    # ------------------------------------------------------------------
    # worker process helpers
    # ------------------------------------------------------------------
    def pending_jobs(self) -> list[str]:
        with self._db() as conn:
            return [r[0] for r in conn.execute(
                "SELECT job FROM jobs WHERE state<>'done' ORDER BY created_at")]

    def upload_gen(self) -> int:
        with self._db() as conn:
            return self._get_meta(conn, "uploaded_gen")
