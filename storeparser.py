#!/usr/bin/env python3
"""storeparser aggregate pkgtrace TSV into a per-package storage-root db.

Reads pkgtrace output (TSV columns: ts pkg pid comm path ancestry) and
collapses paths into XDG-style storage roots, counting writes per root.
Output: JSON like
    {"firefox": {"~/.cache/mozilla/firefox": 800, "~/.config/mozilla/firefox": 42}}

Only XDG-rooted paths (~/.config/X, ~/.cache/X, ~/.local/share/X,
~/.local/state/X) are aggregated.
"""
import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

XDG_TLDS = (".config", ".cache", ".local/share", ".local/state")
DEFAULT_INPUT  = "/tmp/pkgtrace.tsv"
DEFAULT_OUTPUT = "/var/lib/pkgtrace/db.json"

def storage_root(path: str, home: str) -> str | None:
    """Return ~-relative root for an XDG path, or None to skip."""
    if not path.startswith(home + "/"):
        return None
    rel = path[len(home) + 1:]
    for tld in XDG_TLDS:
        if rel.startswith(tld + "/"):
            tail = rel[len(tld) + 1:]
            first = tail.split("/", 1)[0]
            if first:
                return f"~/{tld}/{first}"
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", "-i", default=DEFAULT_INPUT,
                    help=f"pkgtrace TSV (default {DEFAULT_INPUT}, '-' for stdin)")
    ap.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                    help=f"db.json (default {DEFAULT_OUTPUT})")
    ap.add_argument("--home", default=None,
                    help="home dir for XDG normalization "
                         "(default: $SUDO_USER's or current $HOME)")
    ap.add_argument("--min-writes", type=int, default=1,
                    help="drop roots seen fewer than N times (default 1)")
    args = ap.parse_args()

    home = args.home or (
        f"/home/{os.environ['SUDO_USER']}" if os.environ.get("SUDO_USER")
        else os.path.expanduser("~")
    )

    src = sys.stdin if args.input == "-" else open(args.input)
    db: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    try:
        for line in src:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            _ts, pkg, _pid, _comm, path = parts[:5]
            if not pkg or pkg == "?" or pkg.startswith("unowned"):
                continue
            root = storage_root(path, home)
            if root is None:
                continue
            db[pkg][root] += 1
    finally:
        if src is not sys.stdin:
            src.close()

    out = {
        pkg: {root: n for root, n in roots.items() if n >= args.min_writes}
        for pkg, roots in db.items()
    }
    out = {pkg: roots for pkg, roots in out.items() if roots}

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)

    total_roots = sum(len(r) for r in out.values())
    print(f"# wrote {out_path}: {len(out)} pkgs, {total_roots} roots",
          file=sys.stderr)


if __name__ == "__main__":
    main()
