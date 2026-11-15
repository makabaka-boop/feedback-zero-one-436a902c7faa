"""Command line client / scripting helper for the archive HTTP API."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


class ArchiveError(Exception):
    def __init__(self, status: int, payload):
        super().__init__(f"{status}: {payload!r}")
        self.status = status
        self.payload = payload


def _call(url: str, path: str, payload=None, *, timeout: float = 30.0):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url.rstrip("/") + path, data=data,
                                 headers=headers,
                                 method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return json.loads(body.decode("utf-8")) if body else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            obj = json.loads(raw.decode("utf-8"))
        except Exception:
            obj = raw.decode("utf-8", "replace")
        raise ArchiveError(exc.code, obj) from None


class ArchiveClient:
    def __init__(self, url: str, timeout: float = 30.0):
        self.url = url
        self.timeout = timeout

    def put(self, obj_id: str, text: str):
        return _call(self.url, "/put", {"id": obj_id, "text": text},
                     timeout=self.timeout)

    def read(self, obj_id: str) -> str:
        return _call(self.url, "/read", {"id": obj_id}, timeout=self.timeout)

    def rotate(self, job: str) -> int:
        return _call(self.url, "/rotate", {"job": job}, timeout=self.timeout)

    def status(self, job: str) -> dict:
        return _call(self.url, "/status", {"job": job}, timeout=self.timeout)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="archive client")
    ap.add_argument("--url", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("put"); p.add_argument("id"); p.add_argument("text")
    r = sub.add_parser("read"); r.add_argument("id")
    ro = sub.add_parser("rotate"); ro.add_argument("job")
    st = sub.add_parser("status"); st.add_argument("job")
    args = ap.parse_args(argv)
    c = ArchiveClient(args.url)
    try:
        if args.cmd == "put":
            out = c.put(args.id, args.text)
        elif args.cmd == "read":
            out = c.read(args.id)
        elif args.cmd == "rotate":
            out = c.rotate(args.job)
        else:
            out = c.status(args.job)
    except ArchiveError as exc:
        print(json.dumps(exc.payload, ensure_ascii=False))
        return 1
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
