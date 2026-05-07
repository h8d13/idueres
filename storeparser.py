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
import time
from collections import defaultdict
from pathlib import Path

XDG_TLDS = (".config", ".cache", ".local/share", ".local/state")
DEFAULT_INPUT = "/tmp/pkgtrace.tsv"
DEFAULT_DB    = "/var/lib/pkgtrace/db.json"

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
    ap.add_argument("--db", default=DEFAULT_DB,
                    help=f"db.json (default {DEFAULT_DB})")
    ap.add_argument("--home", default=None,
                    help="home dir for XDG normalization "
                         "(default: $SUDO_USER's or current $HOME)")
    ap.add_argument("--min-writes", type=int, default=1,
                    help="drop roots with fewer than N writes after merge (default 1)")
    args = ap.parse_args()

    home = args.home or (
        f"/home/{os.environ['SUDO_USER']}" if os.environ.get("SUDO_USER")
        else os.path.expanduser("~")
    )

    out_path = Path(args.db)
    db: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    if out_path.exists():
        with open(out_path) as f:
            for pkg, roots in json.load(f).items():
                for root, n in roots.items():
                    db[pkg][root] = n

    if args.input == "-":
        src = sys.stdin
    else:
        try:
            src = open(args.input)
        except FileNotFoundError:
            sys.exit(f"no input at {args.input} "
                     "(already processed? look for *.processed files)")
    new_writes = 0
    try:
        for line in src:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            # Format: ts\tpkg\tpid\tcomm\tpath\tancestry. Path may itself
            # contain tabs (rare but legal), so pull ancestry off the right
            # first, then split the head with a fixed limit.
            head, _, _ancestry = line.rpartition("\t")
            if not _ancestry:
                continue
            parts = head.split("\t", 4)
            if len(parts) < 5:
                continue
            _ts, pkg, _pid, _comm, path = parts
            if not pkg or pkg == "?" or pkg.startswith("unowned"):
                continue
            root = storage_root(path, home)
            if root is None:
                continue
            db[pkg][root] += 1
            new_writes += 1
    finally:
        if src is not sys.stdin:
            src.close()

    out = {
        pkg: {root: n for root, n in roots.items() if n >= args.min_writes}
        for pkg, roots in db.items()
    }
    out = {pkg: roots for pkg, roots in out.items() if roots}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    tmp.replace(out_path)

    # Rotate consumed input so re-running storeparser doesn't double-count
    # already-merged writes. Skip for stdin and for empty runs.
    if args.input != "-" and new_writes > 0:
        rotated = f"{args.input}.{int(time.time())}.processed"
        try:
            os.rename(args.input, rotated)
            print(f"# rotated input ==> {rotated}", file=sys.stderr)
        except OSError as e:
            print(f"# warn: failed to rotate input: {e}", file=sys.stderr)

    total_roots = sum(len(r) for r in out.values())
    print(
        f"# {out_path}: {len(out)} pkgs, {total_roots} roots "
        f"(+{new_writes} writes this run)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
