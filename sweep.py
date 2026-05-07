#!/usr/bin/env python3
"""sweep remove storage roots left behind by uninstalled packages.

Usage: sudo pkgsweep <pkg> [pkg ...]
       sudo pkgsweep -n <pkg>   # dry-run (show only)

Looks each pkg up in /var/lib/pkgtrace/db.json. For each root that still
exists on disk, rm -rf it. Roots written by more than one package are
printed as conflicts and skipped.
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

DB_PATH = "/var/lib/pkgtrace/db.json"


def expand(path: str, home: str) -> str:
    return path.replace("~", home, 1) if path.startswith("~") else path


def dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def find_sharers(db, pkg, root):
    return [p for p, roots in db.items() if p != pkg and root in roots]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pkgs", nargs="+", help="package(s) to clean up")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--home", default=None,
                    help="home dir (default: $SUDO_USER's or current $HOME)")
    ap.add_argument("-n", "--dry-run", action="store_true",
                    help="show what would be removed, don't delete")
    args = ap.parse_args()

    if not Path(args.db).exists():
        sys.exit(f"no db at {args.db} — run storeparser.py first")
    with open(args.db) as f:
        db = json.load(f)
    home = args.home or (
        f"/home/{os.environ['SUDO_USER']}"
        if os.environ.get("SUDO_USER") else os.path.expanduser("~")
    )

    total_freed = 0
    for pkg in args.pkgs:
        roots = db.get(pkg)
        if not roots:
            print(f"# {pkg}: no roots in db", file=sys.stderr)
            continue
        print(f"# {pkg}", file=sys.stderr)
        for root, count in sorted(roots.items(), key=lambda kv: -kv[1]):
            real = Path(expand(root, home))
            # is_symlink first: a broken symlink fails exists(), and a
            # symlink-to-dir would crash rmtree at the top level.
            if real.is_symlink():
                if args.dry_run:
                    print(f"  would rm  {real} (symlink)")
                else:
                    try:
                        real.unlink()
                        print(f"  removed   {real} (symlink)")
                    except OSError as e:
                        print(f"  failed    {real}: {e}", file=sys.stderr)
                continue
            if not real.exists():
                print(f"  gone      {real}")
                continue
            sharers = find_sharers(db, pkg, root)
            if sharers:
                print(f"  conflict  {real} (also: {', '.join(sharers)})")
                continue
            size = dir_size(real)
            if args.dry_run:
                print(f"  would rm  {real} ({fmt_bytes(size)}, {count} writes)")
            else:
                try:
                    shutil.rmtree(real)
                    print(f"  removed   {real} ({fmt_bytes(size)})")
                    total_freed += size
                except OSError as e:
                    print(f"  failed    {real}: {e}", file=sys.stderr)

    if not args.dry_run and total_freed:
        print(f"# freed {fmt_bytes(total_freed)}", file=sys.stderr)


if __name__ == "__main__":
    main()
