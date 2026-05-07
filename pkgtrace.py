#!/usr/bin/env python3
"""pkgtrace
Usage example: sudo ./pkgtrace.py [--paths DIR ...] [--exclude-glob PAT ...]
"""
import argparse
import ctypes
import ctypes.util
import fnmatch
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from functools import lru_cache
from pathlib import Path
import re

libaudit = ctypes.CDLL(
    ctypes.util.find_library("audit") or "libaudit.so.1",
    use_errno=True,
)
libaudit.audit_set_pid.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_int]
libaudit.audit_set_pid.restype = ctypes.c_int

# fanotify

FAN_CLOEXEC          = 0x00000001
FAN_CLASS_NOTIF      = 0x00000000

FAN_MARK_ADD         = 0x00000001
FAN_MARK_FILESYSTEM  = 0x00000100

FAN_CLOSE_WRITE      = 0x00000008

O_RDONLY, O_LARGEFILE, O_CLOEXEC = 0, 0, 0o2000000
AT_FDCWD = -100

EVENT_FMT = "IBBHQii"
EVENT_SIZE = struct.calcsize(EVENT_FMT)

DEFAULT_EXCLUDES = (
    "*/AlternateServices.bin",
    "*.sqlite-journal",
    "*.sqlite-wal",
)

# audit

NETLINK_AUDIT      = 9
NLM_F_REQUEST_ACK  = 0x05
AUDIT_GET          = 1000
RULE_KEY           = "pkgtrace"
WAIT_NO, WAIT_YES  = 0, 1

# libc bindings

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


# pacman / /proc helpers

@lru_cache(maxsize=8192)
def _package_for_exe_cached(exe: str) -> str:
    r = subprocess.run(
        ["pacman", "-Qoq", exe],
        capture_output=True, text=True, timeout=2,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    return f"unowned({Path(exe).name or exe})"


def package_for_exe(exe: str) -> str:
    if not exe:
        return "?"
    try:
        return _package_for_exe_cached(exe)
    except Exception:
        return "?"


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


# audit exec cache

class AuditExecCache:
    """Listens on audit netlink for execve events; maps pid -> exe.

    libaudit (ctypes) handles audit_set_pid; auditctl handles rule lifecycle;
    regex parses SYSCALL records (auparse's exe handling is broken on py3.14).
    """

    def __init__(self):
        self.sock = None
        self.cache = {}     # pid -> {"exe", "ppid", "comm"}
        self.lock = threading.Lock()
        self.thread = None
        self.stop_event = threading.Event()
        self._took_dispatcher = False

    def _audit_get_dispatcher(self):
        """Return current audit_pid (0 if free)."""
        req = struct.pack("IHHII", 16, AUDIT_GET, NLM_F_REQUEST_ACK, 1, 0)
        self.sock.send(req)
        self.sock.settimeout(1.0)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            offset = 0
            while offset + 16 <= len(data):
                nlmsg_len, nlmsg_type, *_ = struct.unpack_from(
                    "IHHII", data, offset
                )
                if nlmsg_len < 16:
                    break
                if nlmsg_type == AUDIT_GET and nlmsg_len >= 32:
                    _mask, _enabled, _fail, pid = struct.unpack_from(
                        "IIII", data, offset + 16
                    )
                    return pid
                offset += (nlmsg_len + 3) & ~3
        raise RuntimeError("no AUDIT_GET response")

    def start(self):
        self.sock = socket.socket(
            socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT
        )
        self.sock.bind((0, 0))
        current = self._audit_get_dispatcher()
        if current not in (0, os.getpid()):
            self.sock.close()
            self.sock = None
            raise RuntimeError(
                f"audit dispatcher already taken by pid {current} "
                "(stop auditd or run with --no-audit)"
            )
        if libaudit.audit_set_pid(self.sock.fileno(), os.getpid(), WAIT_YES) < 0:
            err = ctypes.get_errno()
            self.sock.close()
            self.sock = None
            raise OSError(err, os.strerror(err), "audit_set_pid")
        self._took_dispatcher = True
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2)
            self.thread = None
        if self._took_dispatcher and self.sock:
            try:
                libaudit.audit_set_pid(self.sock.fileno(), 0, WAIT_NO)
            except Exception:
                pass
            self._took_dispatcher = False
        if self.sock:
            try: self.sock.close()
            except Exception: pass
            self.sock = None

    _RE_SYSCALL    = re.compile(rb"\bsyscall=(\d+)")
    _RE_PID        = re.compile(rb"\bpid=(\d+)")
    _RE_PPID       = re.compile(rb"\bppid=(\d+)")
    _RE_COMM       = re.compile(rb'\bcomm="([^"]+)')
    # Audit text records sometimes truncate before the closing quote, so we
    # match through `"` or end-of-body, whichever comes first.
    _RE_EXE_QUOTED = re.compile(rb'\bexe="([^"]+)')
    _RE_EXE_HEX    = re.compile(rb"\bexe=([0-9a-fA-F]+)(?=\s|$)")

    @classmethod
    def _extract_exe(cls, body: bytes) -> str:
        m = cls._RE_EXE_QUOTED.search(body)
        if m:
            return m.group(1).decode("utf-8", errors="replace")
        m = cls._RE_EXE_HEX.search(body)
        if m:
            try:
                return bytes.fromhex(m.group(1).decode("ascii")).decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, UnicodeDecodeError):
                pass
        return ""

    def _listen(self):
        AUDIT_SYSCALL = 1300
        self.sock.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                data = self.sock.recv(16384)
            except socket.timeout:
                continue
            except OSError:
                break
            offset = 0
            while offset + 16 <= len(data):
                nlmsg_len, nlmsg_type, *_ = struct.unpack_from(
                    "IHHII", data, offset
                )
                if nlmsg_len < 16 or offset + nlmsg_len > len(data):
                    break
                if nlmsg_type == AUDIT_SYSCALL:
                    body = data[offset + 16 : offset + nlmsg_len]
                    sc = self._RE_SYSCALL.search(body)
                    if sc and sc.group(1) in (b"59", b"322"):
                        m_pid = self._RE_PID.search(body)
                        exe = self._extract_exe(body)
                        if m_pid and exe:
                            pid = int(m_pid.group(1))
                            m_ppid = self._RE_PPID.search(body)
                            m_comm = self._RE_COMM.search(body)
                            with self.lock:
                                self.cache[pid] = {
                                    "exe": exe,
                                    "ppid": int(m_ppid.group(1)) if m_ppid else 0,
                                    "comm": (m_comm.group(1).decode(
                                        "utf-8", errors="replace") if m_comm else ""),
                                }
                offset += (nlmsg_len + 3) & ~3

    def lookup(self, pid: int):
        with self.lock:
            rec = self.cache.get(pid)
            return dict(rec) if rec else None

    def prune(self):
        """Drop entries whose pid no longer exists in /proc.

        Long-running sessions otherwise grow unbounded and risk pid recycle
        misattributing writes to a dead process's pkg.
        """
        with self.lock:
            dead = [pid for pid in self.cache
                    if not os.path.exists(f"/proc/{pid}")]
            for pid in dead:
                del self.cache[pid]

    def lookup_chain(self, pid: int, max_depth: int = 12):
        chain = []
        seen = set()
        cur = pid
        while cur and cur > 1 and cur not in seen and len(chain) < max_depth:
            seen.add(cur)
            rec = self.lookup(cur)
            if rec:
                comm = rec.get("comm") or os.path.basename(rec.get("exe", ""))
                chain.append((cur, comm))
                cur = rec.get("ppid", 0)
                continue
            try:
                with open(f"/proc/{cur}/comm") as f:
                    comm = f.read().strip()
                ppid = 0
                with open(f"/proc/{cur}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            ppid = int(line.split()[1])
                            break
                chain.append((cur, comm))
                cur = ppid
            except (OSError, ValueError):
                break
        return chain


# mountinfo

PSEUDO_FS = frozenset({
    "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue",
    "debugfs", "tracefs", "hugetlbfs", "securityfs", "pstore",
    "autofs", "fusectl", "configfs", "ramfs", "binfmt_misc",
    "bpf", "rpc_pipefs", "nsfs", "selinuxfs", "efivarfs",
})


def _mounts_to_mark(mark: str):
    """Yield one mountpoint per real filesystem under `mark`.

    FAN_MARK_FILESYSTEM only covers the fs containing the marked path, so
    /home, /var, /tmp on separate mounts each need their own mark.
    """
    norm = mark.rstrip("/") or "/"
    seen_dev = set()
    paths = []
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split(" - ", 1)
                if len(parts) != 2:
                    continue
                left = parts[0].split()
                right = parts[1].split()
                if len(left) < 5 or not right:
                    continue
                dev = left[2]
                mp = left[4]
                fstype = right[0]
                if fstype in PSEUDO_FS:
                    continue
                if norm != "/" and not (mp == norm
                                        or mp.startswith(norm + "/")):
                    continue
                if dev in seen_dev:
                    continue
                seen_dev.add(dev)
                paths.append(mp)
    except OSError:
        return [mark]
    return paths or [mark]


# main

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
    ap.add_argument("--exclude-glob", action="append", default=[],
                    metavar="PATTERN",
                    help="fnmatch pattern to drop (repeatable)")
    ap.add_argument("--no-default-excludes", action="store_true",
                    help="don't apply the built-in noise skiplist")
    ap.add_argument("--no-audit", action="store_true",
                    help="disable audit-based exec cache (lose touch attribution)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("fanotify needs root — rerun with sudo")

    home = (
        f"/home/{os.environ['SUDO_USER']}"
        if os.environ.get("SUDO_USER")
        else os.path.expanduser("~")
    )
    prefixes = tuple(args.paths) if args.paths else (home,)
    excludes = (() if args.no_default_excludes else DEFAULT_EXCLUDES) + tuple(
        args.exclude_glob
    )

    audit_cache = None
    if not args.no_audit:
        audit_cache = AuditExecCache()
        try:
            audit_cache.start()
            print("# audit exec cache active", file=sys.stderr)
        except Exception as e:
            print(f"# audit exec cache disabled: {e}", file=sys.stderr)
            audit_cache = None

    fan_fd = fanotify_init(
        FAN_CLASS_NOTIF | FAN_CLOEXEC,
        O_RDONLY | O_LARGEFILE | O_CLOEXEC,
    )
    marked = []
    for mp in _mounts_to_mark(args.mark):
        try:
            fanotify_mark(
                fan_fd,
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                FAN_CLOSE_WRITE,
                AT_FDCWD,
                mp,
            )
            marked.append(mp)
        except OSError as e:
            print(f"# skip mark {mp}: {e}", file=sys.stderr)
    if not marked:
        sys.exit(f"no filesystems marked under {args.mark}")

    print(f"# watching {len(marked)} fs under {args.mark}: {marked}",
          file=sys.stderr)
    print(f"# keep prefixes={prefixes}", file=sys.stderr)
    print(f"# excludes={excludes}", file=sys.stderr)
    print("# columns: ts\tpkg\tpid\tcomm\tpath\tancestry", file=sys.stderr)

    history = open(args.history, "a") if args.history else None

    def keep(path):
        if not any(path.startswith(p) for p in prefixes):
            return False
        if any(fnmatch.fnmatch(path, pat) for pat in excludes):
            return False
        return True

    def emit(path, pid):
        if not keep(path):
            return
        rec = audit_cache.lookup(pid) if audit_cache else None
        exe = (rec.get("exe") if rec else "") or exe_for_pid(pid)
        pkg = package_for_exe(exe)
        if not args.show_unowned and pkg.startswith("unowned"):
            return
        comm = ((rec.get("comm") if rec else "")
                or comm_for_pid(pid) or os.path.basename(exe))
        chain = audit_cache.lookup_chain(pid) if audit_cache else []
        # writer's pid+comm already in cols 3+4; ancestry shows just the parents.
        parents = chain[1:]
        ancestry = (" ← ".join(f"{c[1]}[{c[0]}]" for c in parents)
                    if parents else "-")
        row = f"{time.time():.3f}\t{pkg}\t{pid}\t{comm}\t{path}\t{ancestry}"
        print(row, flush=True)
        if history:
            history.write(row + "\n")
            history.flush()

    event_count = 0
    PRUNE_INTERVAL = 1000
    try:
        while True:
            buf = os.read(fan_fd, 4096)
            offset = 0
            while offset + EVENT_SIZE <= len(buf):
                (event_len, _vers, _r, _ml, _mask, ev_fd, pid) = (
                    struct.unpack_from(EVENT_FMT, buf, offset)
                )
                offset += event_len
                if ev_fd < 0:
                    continue
                try:
                    path = os.readlink(f"/proc/self/fd/{ev_fd}")
                finally:
                    os.close(ev_fd)
                if path.endswith(" (deleted)"):
                    path = path[:-10]
                emit(path, pid)
                event_count += 1
                if audit_cache and event_count % PRUNE_INTERVAL == 0:
                    audit_cache.prune()
    except KeyboardInterrupt:
        pass
    finally:
        try: os.close(fan_fd)
        except OSError: pass
        if history:
            history.close()
        if audit_cache:
            audit_cache.stop()


if __name__ == "__main__":
    main()
