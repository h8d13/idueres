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
import audit

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


# audit exec cache

class AuditExecCache:
    """Listens on audit netlink for execve events; maps pid -> exe.

    libaudit (ctypes) handles audit_set_pid; auditctl handles rule lifecycle;
    regex parses SYSCALL records (auparse's exe handling is broken on py3.14).
    """

    def __init__(self):
        self.sock = None
        self.cache = {}     # pid -> {"exe", "ppid", "comm", "argv"}
        self._id_to_pid = {}  # audit serial -> pid (for SYSCALL/PROCTITLE correlation)
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
    _RE_AUDIT_ID   = re.compile(rb"audit\(\d+\.\d+:(\d+)\)")
    # Audit text records sometimes truncate before the closing quote, so we
    # match through `"` or end-of-body, whichever comes first.
    _RE_EXE_QUOTED = re.compile(rb'\bexe="([^"]+)')
    _RE_EXE_HEX    = re.compile(rb"\bexe=([0-9a-fA-F]+)(?=\s|$)")
    _RE_PT_QUOTED  = re.compile(rb'\bproctitle="([^"]+)')
    _RE_PT_HEX     = re.compile(rb"\bproctitle=([0-9a-fA-F]+)")

    @staticmethod
    def _decode_quoted_or_hex(quoted, hex_match, nul_to_space=False) -> str:
        if quoted:
            return quoted.group(1).decode("utf-8", errors="replace")
        if hex_match:
            try:
                raw = bytes.fromhex(hex_match.group(1).decode("ascii"))
                if nul_to_space:
                    raw = raw.replace(b"\x00", b" ").rstrip()
                return raw.decode("utf-8", errors="replace")
            except (ValueError, UnicodeDecodeError):
                pass
        return ""

    @classmethod
    def _extract_exe(cls, body: bytes) -> str:
        return cls._decode_quoted_or_hex(
            cls._RE_EXE_QUOTED.search(body), cls._RE_EXE_HEX.search(body),
        )

    @classmethod
    def _extract_proctitle(cls, body: bytes) -> str:
        return cls._decode_quoted_or_hex(
            cls._RE_PT_QUOTED.search(body), cls._RE_PT_HEX.search(body),
            nul_to_space=True,
        )

    def _listen(self):
        AUDIT_SYSCALL, AUDIT_PROCTITLE = 1300, 1327
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
                body = data[offset + 16 : offset + nlmsg_len]
                if nlmsg_type == AUDIT_SYSCALL:
                    sc = self._RE_SYSCALL.search(body)
                    if sc and sc.group(1) in (b"59", b"322"):
                        m_pid = self._RE_PID.search(body)
                        exe = self._extract_exe(body)
                        if m_pid and exe:
                            pid = int(m_pid.group(1))
                            m_ppid = self._RE_PPID.search(body)
                            m_comm = self._RE_COMM.search(body)
                            m_id = self._RE_AUDIT_ID.search(body)
                            with self.lock:
                                self.cache[pid] = {
                                    "exe": exe,
                                    "ppid": int(m_ppid.group(1)) if m_ppid else 0,
                                    "comm": (m_comm.group(1).decode(
                                        "utf-8", errors="replace") if m_comm else ""),
                                    "argv": "",
                                    "audit_id": m_id.group(1) if m_id else None,
                                }
                                if m_id:
                                    self._id_to_pid[m_id.group(1)] = pid
                                    if len(self._id_to_pid) > 1024:
                                        # crude bounded cleanup
                                        for k in list(self._id_to_pid)[:512]:
                                            del self._id_to_pid[k]
                elif nlmsg_type == AUDIT_PROCTITLE:
                    title = self._extract_proctitle(body)
                    m_id = self._RE_AUDIT_ID.search(body)
                    if title and m_id:
                        aid = m_id.group(1)
                        with self.lock:
                            pid = self._id_to_pid.get(aid)
                            # Only apply if this PROCTITLE matches the latest
                            # SYSCALL we saw for this pid — otherwise a late
                            # PROCTITLE for an older exec can clobber a newer
                            # exec's (empty) argv slot.
                            if (pid and pid in self.cache
                                    and self.cache[pid].get("audit_id") == aid):
                                self.cache[pid]["argv"] = title
                offset += (nlmsg_len + 3) & ~3

    def lookup(self, pid: int):
        with self.lock:
            rec = self.cache.get(pid)
            return dict(rec) if rec else None

    def lookup_chain(self, pid: int, max_depth: int = 12):
        chain = []
        seen = set()
        cur = pid
        while cur and cur > 1 and cur not in seen and len(chain) < max_depth:
            seen.add(cur)
            rec = self.lookup(cur)
            if rec:
                comm = rec.get("comm") or os.path.basename(rec.get("exe", ""))
                chain.append((cur, comm, rec.get("argv", "")))
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
                chain.append((cur, comm, ""))
                cur = ppid
            except (OSError, ValueError):
                break
        return chain


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
    fanotify_mark(
        fan_fd,
        FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
        FAN_CLOSE_WRITE,
        AT_FDCWD,
        args.mark,
    )

    print(f"# watching fs of {args.mark}; keep prefixes={prefixes}",
          file=sys.stderr)
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
        # writer's pid is already in column 3, so the chain head shows argv
        # (which begins with the binary name) or comm if argv is missing.
        if chain:
            head = chain[0][2] or chain[0][1]
            tail = " ← ".join(f"{c[1]}[{c[0]}]" for c in chain[1:])
            ancestry = f"{head} ← {tail}" if tail else head
        else:
            ancestry = "-"
        row = f"{time.time():.3f}\t{pkg}\t{pid}\t{comm}\t{path}\t{ancestry}"
        print(row, flush=True)
        if history:
            history.write(row + "\n")
            history.flush()

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
