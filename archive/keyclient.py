"""HTTP transport with idempotent retries toward the key service."""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request

from .common import KeySideError


class KeyClient:
    def __init__(self, base_url: str | None = None, *, endpoint_file: str | None = None,
                 timeout: float = 10.0, retries: int = 8,
                 backoff: float = 0.02, max_backoff: float = 0.5):
        if not base_url and not endpoint_file:
            raise ValueError("keystore url required")
        if base_url is not None:
            if not isinstance(base_url, str) or not base_url.startswith("http"):
                raise ValueError("bad keystore url")
            self.base = base_url.rstrip("/")
        else:
            self.base = None
        self.endpoint_file = endpoint_file
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.max_backoff = max_backoff

    def _resolve_base(self) -> str:
        if self.endpoint_file:
            try:
                with open(self.endpoint_file, "r", encoding="utf-8") as f:
                    url = json.load(f)["url"]
                if isinstance(url, str) and url.startswith("http"):
                    self.base = url.rstrip("/")
            except (OSError, ValueError, KeyError):
                if not self.base:
                    raise KeySideError("no keystore endpoint", retryable=True) from None
        if not self.base:
            raise KeySideError("no keystore endpoint", retryable=True)
        return self.base

    def _request(self, method: str, path: str, payload=None, *,
                 retries: int | None = None) -> dict:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        attempts = self.retries if retries is None else retries
        last = KeySideError("keystore unreachable", retryable=True)
        for attempt in range(attempts + 1):
            try:
                base = self._resolve_base()
            except KeySideError as exc:
                last = exc
                time.sleep(min(self.max_backoff, self.backoff * (2 ** attempt)))
                continue
            req = urllib.request.Request(base + path, data=data,
                                         headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
            except urllib.error.HTTPError as exc:
                status = exc.code
                try:
                    obj = json.loads(exc.read().decode("utf-8"))
                    if not isinstance(obj, dict):
                        obj = {}
                except Exception:
                    obj = {}
                if status == 410:
                    raise KeySideError(obj.get("error", "gen_destroyed"),
                                       retryable=False) from None
                if status in (429, 500, 502, 503, 504):
                    last = KeySideError(f"keystore {status}", retryable=True)
                else:
                    # Definite refusal: retrying cannot change the answer.
                    raise KeySideError(obj.get("error", f"keystore {status}"),
                                       retryable=False) from None
            except (urllib.error.URLError, OSError, TimeoutError) as exc:
                last = KeySideError(f"keystore unreachable: {exc}", retryable=True)
            else:
                try:
                    obj = json.loads(body.decode("utf-8"))
                    if not isinstance(obj, dict):
                        raise ValueError
                    return obj
                except Exception:
                    last = KeySideError("malformed keystore response", retryable=True)
            if attempt < attempts:
                time.sleep(min(self.max_backoff, self.backoff * (2 ** attempt)))
        raise last

    # -- operations ----------------------------------------------------
    def ensure(self, gen: int) -> dict:
        return self._request("POST", f"/v1/keys/{gen}/create")

    def destroy(self, gen: int) -> dict:
        return self._request("POST", f"/v1/keys/{gen}/destroy")

    def info(self, gen: int) -> dict:
        return self._request("GET", f"/v1/keys/{gen}")

    def wrap(self, gen: int, data_key: bytes) -> dict:
        resp = self._request("POST", f"/v1/keys/{gen}/wrap", {
            "data_key": base64.b64encode(data_key).decode("ascii")})
        return {
            "gen": int(resp["gen"]),
            "kid": resp["key_id"],
            "nonce": _b64d(resp["nonce"]),
            "ct": _b64d(resp["wrapped"]),
        }

    def unwrap(self, gen: int, wrap: dict) -> bytes:
        resp = self._request("POST", f"/v1/keys/{gen}/unwrap", {
            "key_id": wrap["kid"],
            "nonce": _b64e(wrap["nonce"]),
            "wrapped": _b64e(wrap["ct"]),
        })
        return _b64d(resp["data_key"])


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s) -> bytes:
    if not isinstance(s, str):
        raise KeySideError("malformed keystore response", retryable=True)
    try:
        return base64.b64decode(s.encode("ascii"), validate=True)
    except Exception:
        raise KeySideError("malformed keystore response", retryable=True) from None
