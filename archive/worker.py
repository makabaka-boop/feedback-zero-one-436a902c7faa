"""Standalone rotation worker process.

Runs independently of the HTTP server: it shares only the SQLite index and the
data directory's cross-process locks with it.  It can be restarted at any time;
every phase is idempotent and resumes from the durable job row.

    python3 -m archive.worker --db data/archive.db --data data/archive \
        --keystore http://127.0.0.1:PORT [--job NAME] [--once] [--stop PATH]

The worker only rewrites wrapped data keys ("envelopes").  Body ciphertext is
never read or modified.  When a rotation is paused by the test hook, new
uploads and reads keep working: uploads never take the worker lock, and reads
only ever read committed SQLite rows.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .backend import ArchiveStore
from .faults import pause_point
from .common import KeySideError


def _pause_hook() -> None:
    pause_point("migration")


def run_until_idle(store: ArchiveStore, *, job: str | None = None,
                   poll: float = 5.0, stop_path: str | None = None,
                   max_seconds: float | None = None) -> int:
    start = time.monotonic()
    while True:
        if stop_path and os.path.exists(stop_path):
            return 0
        if max_seconds is not None and time.monotonic() - start > max_seconds:
            return 0
        try:
            with store.worker_guard(None):
                jobs = [job] if job else store.pending_jobs()
                for j in jobs:
                    row = store._job_row(j)
                    if row is None or row[3] == "done":
                        continue
                    store.run_job(j, pause_hook=_pause_hook)
                    print(json.dumps({"job": j, "state": "done"}), flush=True)
        except KeySideError as exc:
            print(json.dumps({"job": job, "state": "waiting",
                              "error": str(exc)}), flush=True)
        except Exception as exc:  # keep going: transient faults must heal
            print(json.dumps({"job": job, "state": "error",
                              "error": repr(exc)}), flush=True)
        if stop_path and os.path.exists(stop_path):
            return 0
        time.sleep(poll)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="archive rotation worker")
    ap.add_argument("--db", required=True)
    ap.add_argument("--data", required=True)
    ap.add_argument("--keystore", default=None)
    ap.add_argument("--endpoint-file", default=None)
    ap.add_argument("--job", default=None, help="process only this job; default: all")
    ap.add_argument("--once", action="store_true", help="run one pass then exit")
    ap.add_argument("--poll", type=float, default=1.0)
    ap.add_argument("--stop", default=None,
                    help="exit gracefully as soon as this file exists")
    ap.add_argument("--max-seconds", type=float, default=None)
    ap.add_argument("--key-retries", type=int, default=8)
    args = ap.parse_args(argv)

    store = ArchiveStore(args.db, args.data, args.keystore,
                         endpoint_file=args.endpoint_file,
                         key_retries=args.key_retries, clean_tmp=False)
    try:
        if args.once:
            with store.worker_guard(None):
                jobs = [args.job] if args.job else store.pending_jobs()
                ok = True
                for j in jobs:
                    row = store._job_row(j)
                    if row is None or row[3] == "done":
                        continue
                    try:
                        store.run_job(j, pause_hook=_pause_hook)
                        print(json.dumps({"job": j, "state": "done"}), flush=True)
                    except Exception as exc:
                        ok = False
                        print(json.dumps({"job": j, "state": "error",
                                          "error": repr(exc)}), flush=True)
            return 0 if ok else 1
        return run_until_idle(store, job=args.job, poll=args.poll,
                              stop_path=args.stop,
                              max_seconds=args.max_seconds)
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
