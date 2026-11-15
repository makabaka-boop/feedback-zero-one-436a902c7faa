"""Crash/pause injection points for the acceptance tests.

Kill points are armed by the environment variable ARCH_KILL_AFTER_<POINT>,
which holds the path of a trigger file that does not exist yet.  The process
checks it at a point where the work is durably committed but the reply has not
been written.  If the file exists the process SIGKILLs itself, so tests prove
"commit happened, reply lost" is harmless.

    ARCH_KILL_AFTER_CREATE_COMMIT    keystore: key row committed, before reply
    ARCH_KILL_AFTER_DESTROY_COMMIT   keystore: tombstone committed, before reply
    ARCH_KILL_AFTER_PUT_COMMIT       archive: object row committed, before reply
    ARCH_KILL_AFTER_MIGRATE_COMMIT   worker: envelope replacement committed
    ARCH_KILL_AFTER_WORKER_DESTROY   worker: destroy confirmed, before done

Pause points block the worker while a named file exists:

    ARCH_PAUSE_MIGRATION              inside the envelope migration phase
"""

from __future__ import annotations

import os
import signal
import sys
import time


def kill_point(name: str) -> None:
    path = os.environ.get("ARCH_KILL_AFTER_" + name.upper())
    if not path or not os.path.exists(path):
        return
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    os.kill(os.getpid(), signal.SIGKILL)


def pause_point(name: str) -> None:
    path = os.environ.get("ARCH_PAUSE_" + name.upper())
    if not path:
        return
    while os.path.exists(path):
        time.sleep(0.02)
