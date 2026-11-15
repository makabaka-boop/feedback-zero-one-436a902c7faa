#!/usr/bin/env python3
"""Launcher for the three roles, usable with ``python3 -I``.

    python3 -I bin/run.py keyserver --db ... --endpoint-file ...
    python3 -I bin/run.py server    --db ... --data ... --endpoint-file ...
    python3 -I bin/run.py worker    --db ... --data ... --endpoint-file ...
    python3 -I bin/run.py client    --url http://... put a 甲

``-I`` removes both the script directory and the current directory from
``sys.path``, so the repository root is added explicitly here.  This keeps
process startup immune to planted ``json.py``-style modules in data dirs.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

ROLES = {
    "keyserver": ("archive.keyserver", "main"),
    "server": ("archive.server", "main"),
    "worker": ("archive.worker", "main"),
    "client": ("archive.client", "main"),
}


def main(argv):
    if len(argv) < 2 or argv[1] not in ROLES:
        print(__doc__ or "", file=sys.stderr)
        return 2
    module_name, fn_name = ROLES[argv[1]]
    module = __import__(module_name, fromlist=[fn_name])
    return getattr(module, fn_name)(argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
