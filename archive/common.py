"""Small shared helpers (stdlib only).

The keystore process never imports anything from the archive backend, and the
archive side never imports keystore internals: the only link between the two
is HTTP.
"""

from __future__ import annotations

import errno
import os
import signal
import time

class Fault(Exception):
    """Protocol-level rejection, reported as {"error": <param>}."""

    def __init__(self, param: str):
        super().__init__(param)
        self.param = param


class KeySideError(Exception):
    """Keystore refused or could not serve a request.

    ``retryable`` marks ambiguous transport failures: re-issuing the same
    request is safe because every keystore operation is idempotent per
    generation.
    """

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


def is_valid_id(obj) -> bool:
    """Non-empty ASCII alphanumeric identifier (no length cap; ids are hashed
    for filenames and the HTTP layer bounds request size)."""
    if not isinstance(obj, str) or not obj:
        return False
    for ch in obj:
        if not (("a" <= ch <= "z") or ("A" <= ch <= "Z") or ("0" <= ch <= "9")):
            return False
    return True


def validate_text(obj) -> str:
    """text must be a Unicode scalar string (lone surrogates rejected)."""
    if not isinstance(obj, str):
        raise Fault("text")
    try:
        obj.encode("utf-8")
    except UnicodeEncodeError:
        raise Fault("text") from None
    return obj


# --------------------------------------------------------------------------
# Crash / kill helpers used by the acceptance scripts.
# --------------------------------------------------------------------------

def arm_kill_file(path: str) -> None:
    with open(path, "wb") as f:
        f.write(b"kill")


def disarm_kill_file(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def kill_pid(pid: int, sig=signal.SIGKILL) -> None:
    """Kill a child process and wait until it is really gone."""
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            _reap(pid)
            return
        if _reap(pid):
            return
        time.sleep(0.01)


def _reap(pid: int) -> bool:
    if not hasattr(os, "waitpid"):
        return False
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    except OSError as exc:  # pragma: no cover
        return exc.errno == errno.ECHILD
    return done == pid
