#!/usr/bin/env python3
"""pkgtrace — fanotify-based file-write watcher with pacman attribution.

Run as root: sudo ./pkgtrace.py [--paths DIR ...] [--history FILE]
"""
import argparse
import ctypes
import ctypes.util
import os
import struct
import subprocess
import sys
import time
from functools import lru_cache
from pathlib import Path

FAN_CLOEXEC, FAN_CLASS_NOTIF = 0x00000001, 0x00000000
FAN_MARK_ADD, FAN_MARK_FILESYSTEM = 0x00000001, 0x00000100
FAN_CLOSE_WRITE = 0x00000008
O_RDONLY, O_LARGEFILE, O_CLOEXEC = 0, 0, 0o2000000
AT_FDCWD = -100

# struct fanotify_event_metadata: __u32 len; __u8 vers; __u8 res; __u16 mlen;
# __aligned_u64 mask; __s32 fd; __s32 pid;  (native alignment matches kernel)
EVENT_FMT = "IBBHQii"
EVENT_SIZE = struct.calcsize(EVENT_FMT)

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
libc.fanotify_init.restype = ctypes.c_int
libc.fanotify_mark.argtypes = [
    ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p
]
libc.fanotify_mark.restype = ctypes.c_int


def _check(rc, what):
    if rc < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), what)
    return rc


def fanotify_init(flags, event_f_flags):
    return _check(libc.fanotify_init(flags, event_f_flags), "fanotify_init")


def fanotify_mark(fd, flags, mask, dirfd, path):
    _check(
        libc.fanotify_mark(fd, flags, mask, dirfd, path.encode()),
        f"fanotify_mark({path})",
    )


@lru_cache(maxsize=8192)
def package_for_exe(exe: str) -> str:
    if not exe:
        return "?"
    try:
        r = subprocess.run(
            ["pacman", "-Qoq", exe],
            capture_output=True, text=True, timeout=2,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        return "?"
    return f"unowned({Path(exe).name or exe})"


def exe_for_pid(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def comm_for_pid(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paths", nargs="*", default=None,
                    help="path prefixes to keep (default: user home)")
    ap.add_argument("--mark", default="/",
                    help="any path on the filesystem to mark (default /)")
    ap.add_argument("--history", default=None,
                    help="append matching events as TSV to this file")
    ap.add_argument("--show-unowned", action="store_true",
                    help="also show writes by non-pacman processes")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("fanotify needs root — rerun with sudo")

    home = (
        f"/home/{os.environ['SUDO_USER']}"
        if os.environ.get("SUDO_USER")
        else os.path.expanduser("~")
    )
    prefixes = tuple(args.paths) if args.paths else (home,)

    fan_fd = fanotify_init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC,
        O_RDONLY | O_LARGEFILE | O_CLOEXEC,
    )
    fanotify_mark(
        fan_fd,
        FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
        FAN_CLOSE_WRITE,
        AT_FDCWD,
        args.mark,
    )

    print(f"# watching fs of {args.mark}; keeping events under {prefixes}",
          file=sys.stderr)
    print("# columns: ts\tpkg\tpid\tcomm\tpath", file=sys.stderr)

    history = open(args.history, "a") if args.history else None
    try:
        while True:
            buf = os.read(fan_fd, 4096)
            offset = 0
            while offset + EVENT_SIZE <= len(buf):
                (event_len, vers, _r, _ml, _mask, ev_fd, pid) = (
                    struct.unpack_from(EVENT_FMT, buf, offset)
                )
                offset += event_len
                if ev_fd < 0:
                    continue
                try:
                    path = os.readlink(f"/proc/self/fd/{ev_fd}")
                finally:
                    os.close(ev_fd)
                if not any(path.startswith(p) for p in prefixes):
                    continue
                exe = exe_for_pid(pid)
                pkg = package_for_exe(exe)
                if not args.show_unowned and pkg.startswith("unowned"):
                    continue
                row = (
                    f"{time.time():.3f}\t{pkg}\t{pid}\t"
                    f"{comm_for_pid(pid)}\t{path}"
                )
                print(row, flush=True)
                if history:
                    history.write(row + "\n")
                    history.flush()
    except KeyboardInterrupt:
        pass
    finally:
        os.close(fan_fd)
        if history:
            history.close()


if __name__ == "__main__":
    main()
