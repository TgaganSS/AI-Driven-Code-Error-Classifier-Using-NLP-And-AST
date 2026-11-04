"""
diagnostics.py
--------------
Single source of truth for turning raw g++/clang++ output into diagnostic
dicts, and for running the compiler safely and quickly.

What changed versus the first version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Detection
  * The build now uses a security-oriented warning profile (``analysis_flags``)
    at ``-O2`` so flow-based checks fire: null dereference, out-of-bounds,
    use-after-free, format-string, uninitialised use, dangling pointers ...
    Previously the CLI passed *no* warning flags, so ``*nullptr = 1`` was
    reported as "Compilation successful".
  * ``[-Wxxx]`` option tags are parsed into ``option`` (the most reliable
    classification signal g++ offers).
  * ``note:`` lines are attached to their parent diagnostic (``notes``).
  * Diagnostics located inside system headers (template instantiation errors,
    fortified ``strcpy`` overflows ...) are *re-anchored* to the user's line via
    the ``required from here`` / ``inlined from ... at file:line`` context that
    g++ prints, instead of showing library source lines as "your" error.
  * Duplicates are removed and obvious follow-on errors are flagged
    ``cascade``.
Performance
  * One compile + one link per analysis (the old flow compiled the file up to
    four times: ``-E``, ``-c``, the real build, and the heal loop again).
  * Results are cached (see ``build_cache``).
Safety
  * Builds run under ``ulimit`` CPU/memory limits and in their own process
    group that is killed on timeout (``subprocess.run(timeout=)`` used to leave
    ``cc1plus`` running).
"""

from __future__ import annotations

import functools
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Tuple

import build_cache
from taxonomy import split_option

# ─────────────────────────────────────────────────────────────────────────────
# Parsing
# ─────────────────────────────────────────────────────────────────────────────

# file:line:col: error|warning|note: msg
_FRONTEND_RE = re.compile(
    r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s+"
    r"(?P<type>error|warning|fatal error|note):\s+(?P<msg>.*)$"
)
# file:line:col:   required from here | required from 'foo'
_REQUIRED_RE = re.compile(r"^(?P<file>.+?):(?P<line>\d+):(?P<col>\d+):\s+required from\b")
# "    inlined from 'void ovf()' at hdr.cpp:3:31:"
_INLINED_RE = re.compile(r"inlined from .* at (?P<file>[^\s:]+):(?P<line>\d+):(?P<col>\d+):?\s*$")
_INSTANTIATION_RE = re.compile(r"In (?:member )?(?:function )?.*instantiation of")

# GNU ld prefix lines, e.g.  /usr/bin/ld: cannot find -lfoo
_LD_PREFIX_RE = re.compile(r"^(?:[^\s:]*/)?ld(?:\.[a-z]+)?:\s+(?P<msg>.*)$")
_COLLECT2_RE = re.compile(r"^collect2:\s+(?:fatal )?error:\s+(?P<msg>.*)$")
_CLANG_LD_RE = re.compile(r"^clang(?:\+\+)?: error: linker command failed.*$")
_MAC_UNDEF_RE = re.compile(r"^Undefined symbols for architecture .*$")

_QUOTE_MAP = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"'})

_SYSTEM_PREFIXES = ("/usr/include", "/usr/lib", "/usr/local/include", "/usr/local/lib",
                    "/opt/", "/Library/", "/Applications/", "/System/", "/lib/", "/lib64/",
                    "/nix/store/", "/Program Files")

# Follow-on errors g++ emits once the brace structure is already broken.
_CASCADE_RE = re.compile(
    r"expected declaration before '\}' token|expected unqualified-id before '\}' token|"
    r"expected '\}' at end of input|expected declaration before end of input", re.I)

_MAX_NOTES = 6


def _is_system_path(path: str) -> bool:
    return path.replace("\\", "/").startswith(_SYSTEM_PREFIXES)


def _norm(path: Optional[str]) -> str:
    if not path:
        return ""
    try:
        return os.path.normpath(os.path.abspath(path))
    except Exception:
        return path


def _linker_diag(file_path, message, raw):
    return {
        "file": file_path,
        "line": None,
        "column": None,
        "type": "error",
        "message": message,
        "raw": raw,
        "category": "linker_error",
        "confidence": 1.0,
        "option": None,
        "notes": [],
    }


def parse_compiler_stderr(stderr: str, source_file: Optional[str] = None,
                          returncode: Optional[int] = None) -> List[dict]:
    """
    Parse raw compiler/linker stderr into a list of diagnostic dicts.

    Each dict: file, line, column, type (error|warning), message, raw, option,
    notes, instantiation, anchored_from (when re-anchored), cascade.

    Guarantee: if the toolchain failed (``returncode != 0``) this NEVER returns
    an empty list - unrecognised failures are surfaced as a generic error so a
    failed build can no longer be reported as success.
    """
    diags: List[dict] = []
    # Under UTF-8 locales g++ prints curly quotes; every downstream regex expects ASCII.
    stderr = (stderr or "").translate(_QUOTE_MAP)
    lines = stderr.splitlines()

    src_abs = _norm(source_file)
    src_dir = os.path.dirname(src_abs) if src_abs else ""

    def is_user(path: str) -> bool:
        if not path:
            return False
        n = _norm(path)
        if src_abs and n == src_abs:
            return True
        if _is_system_path(n):
            return False
        if src_dir:
            return n == src_dir or n.startswith(src_dir + os.sep)
        return True

    saw_linker = False
    pending_anchor: Optional[Tuple[str, int, int]] = None
    in_instantiation = False
    last_diag: Optional[dict] = None
    seen_keys = set()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()

        # Context lines telling us where in USER code a library diagnostic originates.
        rm = _REQUIRED_RE.match(stripped)
        if rm:
            in_instantiation = True
            if is_user(rm.group("file")):
                pending_anchor = (rm.group("file"), int(rm.group("line")), int(rm.group("col")))
            i += 1
            continue
        fm = _FRONTEND_RE.match(stripped)
        if not fm:
            im = _INLINED_RE.search(stripped)
            if im:
                if is_user(im.group("file")):
                    pending_anchor = (im.group("file"), int(im.group("line")), int(im.group("col")))
                i += 1
                continue
            if _INSTANTIATION_RE.search(stripped):
                in_instantiation = True

        m = fm
        if m:
            dtype = m.group("type")
            if dtype == "note":
                if last_diag is not None and len(last_diag["notes"]) < _MAX_NOTES:
                    last_diag["notes"].append({
                        "file": m.group("file"), "line": int(m.group("line")),
                        "column": int(m.group("col")), "message": m.group("msg")})
                i += 1
                continue
            full_msg = m.group("msg")
            _msg, option = split_option(full_msg)
            d = {
                "file": m.group("file"),
                "line": int(m.group("line")),
                "column": int(m.group("col")),
                "type": "error" if dtype == "fatal error" else dtype,
                "message": full_msg,            # tag kept for backward compatibility
                "raw": line,
                "option": option,
                "notes": [],
                "instantiation": in_instantiation,
                "cascade": False,
            }
            # Re-anchor library-located diagnostics onto the user's own line.
            if not is_user(d["file"]) and pending_anchor is not None:
                d["anchored_from"] = {"file": d["file"], "line": d["line"], "column": d["column"]}
                d["file"], d["line"], d["column"] = pending_anchor
            key = (d["file"], d["line"], d["column"], d["type"], d["message"])
            # One template misuse produces several library-internal errors that all
            # re-anchor to the same user line; keep the first, count the rest.
            if "anchored_from" in d:
                akey = (d["file"], d["line"], d["column"], d["type"], "anchored")
                if akey in seen_keys:
                    for prev in diags:
                        if (prev["file"], prev["line"], prev["column"], prev["type"]) == akey[:4] \
                                and "anchored_from" in prev:
                            prev["suppressed"] = prev.get("suppressed", 0) + 1
                            break
                    pending_anchor = None
                    in_instantiation = False
                    last_diag = None
                    i += 1
                    continue
                seen_keys.add(akey)
            pending_anchor = None
            in_instantiation = False
            if key in seen_keys:
                last_diag = None
                i += 1
                continue
            seen_keys.add(key)
            diags.append(d)
            last_diag = d
            i += 1
            continue

        # macOS multi-line block: "Undefined symbols for architecture ..."
        if _MAC_UNDEF_RE.match(stripped):
            block = [stripped]
            i += 1
            while i < len(lines):
                nxt = lines[i].strip()
                block.append(nxt)
                i += 1
                if "symbol(s) not found" in nxt:
                    break
            text = "\n".join(block)
            diags.append(_linker_diag(source_file, text, text))
            saw_linker = True
            continue

        # GNU ld: "undefined reference to ..." / "multiple definition of ..."
        um = re.search(r"(undefined reference to|multiple definition of)\s+(.+)$", stripped)
        if um:
            msg = f"{um.group(1)} {um.group(2)}"
            key = ("linker", msg)
            if key not in seen_keys:
                seen_keys.add(key)
                diags.append(_linker_diag(source_file, msg, line))
            saw_linker = True
            i += 1
            continue

        cm = _COLLECT2_RE.match(stripped)
        if cm or _CLANG_LD_RE.match(stripped):
            if not saw_linker:
                msg = cm.group("msg") if cm else stripped
                diags.append(_linker_diag(source_file, f"linker: {msg}", line))
                saw_linker = True
            i += 1
            continue

        lm = _LD_PREFIX_RE.match(stripped)
        if lm and re.search(r"cannot find|cannot open|no such file|cannot find -l",
                            lm.group("msg"), re.I):
            diags.append(_linker_diag(source_file, f"linker: {lm.group('msg')}", line))
            saw_linker = True
        i += 1

    # Flag follow-on errors that only exist because an earlier error broke structure.
    first_error_seen = False
    for d in diags:
        if d["type"] == "error":
            if first_error_seen and _CASCADE_RE.search(d["message"]):
                d["cascade"] = True
            first_error_seen = True

    # Failsafe: toolchain failed but nothing recognised.
    if returncode not in (None, 0) and not any(d["type"] == "error" for d in diags):
        tail = " ".join(l.strip() for l in lines if l.strip())[-300:]
        diags.append({
            "file": source_file,
            "line": None,
            "column": None,
            "type": "error",
            "message": f"Build failed (exit code {returncode})" + (f": {tail}" if tail else ""),
            "raw": stderr or "",
            "option": None,
            "notes": [],
        })
    return diags


# ─────────────────────────────────────────────────────────────────────────────
# Compiler capabilities / flags
# ─────────────────────────────────────────────────────────────────────────────

_COMPILER = os.environ.get("GSC_CXX", "g++")


def _compiler_key() -> Optional[str]:
    """Identity of the compiler binary (path + mtime + size) used to key the probe cache."""
    exe = shutil.which(_COMPILER)
    if not exe:
        return None
    try:
        real = os.path.realpath(exe)
        st = os.stat(real)
        return f"{real}:{st.st_mtime_ns}:{st.st_size}"
    except OSError:
        return None


def _probe_path() -> str:
    return os.path.join(build_cache.cache_dir(), "compiler_probe.json")


def _load_probe() -> dict:
    key = _compiler_key()
    try:
        import json
        with open(_probe_path(), "r", encoding="utf-8") as f:
            doc = json.load(f)
        if key and doc.get("key") == key and isinstance(doc.get("id"), str) \
                and isinstance(doc.get("warnings"), list):
            return doc
    except (OSError, ValueError):
        pass
    return {}


def _save_probe(doc: dict) -> None:
    key = _compiler_key()
    if not key or not build_cache.enabled() or not build_cache._ensure_dir():
        return
    try:
        import json
        doc = dict(doc, key=key)
        fd, tmp = tempfile.mkstemp(dir=build_cache.cache_dir(), prefix=".tmp-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        os.replace(tmp, _probe_path())
    except (OSError, TypeError, ValueError):
        pass


@functools.lru_cache(maxsize=None)
def compiler_id() -> str:
    """First line of ``g++ --version`` (cache key + flag selection); persisted across runs."""
    doc = _load_probe()
    if doc.get("id"):
        return doc["id"]
    try:
        r = subprocess.run([_COMPILER, "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=15)
        cid = (r.stdout.splitlines() or ["unknown"])[0]
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"
    _save_probe({"id": cid, "warnings": doc.get("warnings", [])})
    return cid


def is_clang() -> bool:
    return "clang" in compiler_id().lower()


@functools.lru_cache(maxsize=None)
def _supported_warnings() -> frozenset:
    """Names of all -W options this compiler understands (without the ``-W``); persisted."""
    doc = _load_probe()
    if doc.get("warnings"):
        return frozenset(doc["warnings"])
    names = set()
    try:
        r = subprocess.run([_COMPILER, "--help=warnings"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, timeout=20)
        for m in re.finditer(r"^\s+-W([\w+\-]+)", r.stdout, re.M):
            names.add(m.group(1))
    except (OSError, subprocess.TimeoutExpired):
        pass
    if names:
        _save_probe({"id": compiler_id(), "warnings": sorted(names)})
    return frozenset(names)


# Candidate warning flags.  Unsupported ones are silently dropped so the same
# profile works on older g++ and on clang.
_CANDIDATE_WARNINGS = [
    "-Wall", "-Wextra", "-Wpedantic",
    # memory safety / flow based (need -O2)
    "-Wnull-dereference", "-Warray-bounds=2", "-Wstringop-overflow=4", "-Wstringop-truncation",
    "-Wuse-after-free=3", "-Wdangling-pointer=2", "-Wfree-nonheap-object", "-Wmismatched-new-delete",
    "-Wmaybe-uninitialized", "-Walloc-size-larger-than=1073741824", "-Wformat-overflow=2",
    "-Wformat-truncation=2", "-Walloca", "-Wvla",
    # format strings
    "-Wformat=2", "-Wformat-security",
    # integer safety
    "-Wconversion", "-Wsign-conversion", "-Wfloat-conversion", "-Wdouble-promotion",
    # logic
    "-Wshadow", "-Wduplicated-cond", "-Wduplicated-branches", "-Wlogical-op",
    "-Wimplicit-fallthrough", "-Wmisleading-indentation", "-Wnon-virtual-dtor",
    "-Woverloaded-virtual", "-Wundef", "-Wcast-qual", "-Wcast-align",
    "-Wpessimizing-move", "-Wredundant-move", "-Wrange-loop-construct",
]

_BASE_FLAGS = ["-std=c++17", "-fno-diagnostics-show-caret", "-fdiagnostics-color=never",
               "-fdiagnostics-show-option", "-fmax-errors=50"]


@functools.lru_cache(maxsize=None)
def analysis_flags() -> Tuple[str, ...]:
    """Full detection profile, filtered to what the installed compiler supports."""
    flags = list(_BASE_FLAGS)
    flags += ["-O2", "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong"]
    supported = _supported_warnings()
    for w in _CANDIDATE_WARNINGS:
        base = re.sub(r"=.*$", "", w[2:])
        if is_clang() or not supported or base in supported:
            flags.append(w)
    return tuple(flags)


def basic_flags() -> Tuple[str, ...]:
    return tuple(_BASE_FLAGS)


# ─────────────────────────────────────────────────────────────────────────────
# Running the compiler
# ─────────────────────────────────────────────────────────────────────────────

_CPU_LIMIT_S = int(os.environ.get("GSC_BUILD_CPU_S", "90"))
_MEM_LIMIT_KB = int(os.environ.get("GSC_BUILD_MEM_MB", "4096")) * 1024
_ENV = dict(os.environ, LC_ALL="C", LANGUAGE="C")
_ENV.pop("GCC_COLORS", None)

_LIMIT_WRAPPER = ('ulimit -t {cpu} 2>/dev/null; ulimit -v {mem} 2>/dev/null; '
                  'ulimit -c 0 2>/dev/null; exec "$@"')


def _run_limited(cmd: List[str], timeout: int, cwd: Optional[str] = None) -> Tuple[int, str, str, bool]:
    """
    Run ``cmd`` under CPU/memory limits in its own process group.
    Returns (returncode, stdout, stderr, timed_out).  On timeout the *whole*
    group is killed so cc1plus / as / ld cannot linger.
    """
    if os.name == "posix" and shutil.which("sh"):
        full = ["sh", "-c", _LIMIT_WRAPPER.format(cpu=_CPU_LIMIT_S, mem=_MEM_LIMIT_KB), "gsc"] + cmd
        kwargs = {"start_new_session": True}
    else:                                           # pragma: no cover (Windows)
        full = cmd
        kwargs = {}
    proc = subprocess.Popen(full, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=_ENV, cwd=cwd, errors="replace", **kwargs)
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        try:
            if "start_new_session" in kwargs:
                os.killpg(proc.pid, signal.SIGKILL)
            else:                                   # pragma: no cover
                proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass
        out, err = proc.communicate()
        return 124, out or "", err or "", True


def undefined_symbols(path: str) -> Optional[List[str]]:
    """Undefined symbols of an object/binary via ``nm -u`` (None if nm is unavailable)."""
    nm = shutil.which("nm")
    if not nm:
        return None
    try:
        r = subprocess.run([nm, "-u", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    syms = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] == "U":
            syms.append(parts[-1].split("@")[0])
    return syms


@dataclass
class BuildResult:
    diagnostics: List[dict]
    stderr: str
    returncode: int
    undefined: List[str] = field(default_factory=list)   # undefined symbols of the object file
    nm_available: bool = True
    cached: bool = False
    elapsed: float = 0.0
    timed_out: bool = False

    def as_triple(self):
        return self.diagnostics, self.stderr, self.returncode


def _timeout_result(file_path: str, what: str, timeout: int, t0: float,
                    undefined=None, nm_ok=True) -> BuildResult:
    msg = f"{what} timed out after {timeout}s"
    return BuildResult([{"file": file_path, "line": None, "column": None, "type": "error",
                         "message": msg, "raw": msg, "option": None, "notes": []}],
                       msg, 124, undefined or [], nm_ok, timed_out=True, elapsed=time.time() - t0)


def build(file_path: str, extra_flags: Optional[Iterable[str]] = None, analysis: bool = False,
          timeout: int = 120, use_cache: bool = True, link: bool = True) -> BuildResult:
    """
    Compile (and link) ``file_path`` once.

    ``analysis=True``  -> full security/quality warning profile at -O2.
    ``analysis=False`` -> minimal flags (+ ``extra_flags``), the legacy behaviour.

    No a.out is ever left behind: all outputs live in a private temp directory.
    """
    t0 = time.time()
    flags = list(analysis_flags() if analysis else basic_flags()) + list(extra_flags or [])

    key = None
    if use_cache and build_cache.enabled():
        try:
            with open(file_path, "r", encoding="utf-8", errors="surrogatepass") as f:
                source = f.read()
            key = build_cache.make_key(source, flags + (["+link"] if link else []),
                                       compiler_id(), os.path.dirname(os.path.abspath(file_path)))
            hit = build_cache.get(key)
            if hit is not None:
                return BuildResult(hit["diags"], hit["stderr"], hit["rc"], hit["undefined"],
                                   nm_available=True, cached=True, elapsed=time.time() - t0)
        except OSError:
            key = None

    with tempfile.TemporaryDirectory(prefix="gsc_build_") as tmp:
        obj = os.path.join(tmp, "unit.o")
        out = os.path.join(tmp, "a.out")
        rc, _o, err, timed_out = _run_limited([_COMPILER, *flags, "-c", file_path, "-o", obj], timeout)
        if timed_out:
            return _timeout_result(file_path, "Build", timeout, t0)
        stderr = err
        undefined: List[str] = []
        nm_ok = True
        if rc == 0:
            u = undefined_symbols(obj)
            nm_ok = u is not None
            undefined = u or []
            if link:
                rc2, _o2, err2, to2 = _run_limited([_COMPILER, obj, "-o", out], timeout)
                if to2:
                    return _timeout_result(file_path, "Link", timeout, t0, undefined, nm_ok)
                if rc2 != 0:
                    rc = rc2
                    stderr = stderr + err2
    diags = parse_compiler_stderr(stderr, file_path, rc)
    result = BuildResult(diags, stderr, rc, undefined, nm_ok, cached=False, elapsed=time.time() - t0)
    if key is not None and nm_ok:
        build_cache.put(key, diags, stderr, rc, undefined)
    return result


def run_gpp(file_path: str, extra_flags=None, timeout: int = 120):
    """
    Backward-compatible wrapper: returns ``(diagnostics, raw_stderr, returncode)``
    using the minimal flag set plus ``extra_flags``.
    """
    return build(file_path, extra_flags, analysis=False, timeout=timeout).as_triple()
