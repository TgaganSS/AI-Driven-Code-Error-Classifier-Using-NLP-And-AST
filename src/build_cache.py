"""
build_cache.py
--------------
Content-addressed cache of compiler results.

Compiling is by far the most expensive step of the pipeline (0.3-1.5 s per
file).  The GUI, the CLI and the heal loop frequently re-analyse a source that
has not changed; a cache hit returns the stored diagnostics instantly.

Design / security notes
~~~~~~~~~~~~~~~~~~~~~~~
* The key is SHA-256 over: source bytes, the exact flag list, the compiler
  version string and the contents of every *local* header the source includes
  (so editing ``foo.h`` invalidates entries that depend on it).
* Entries are plain JSON (never pickle) and are schema-validated on load, so a
  corrupted or tampered file can at worst cause a cache miss.
* The directory is created with mode 0700, files are written atomically
  (temp file + ``os.replace``) and the cache is size-bounded (LRU by mtime).
* ``GSC_NO_CACHE=1`` disables it; ``GSC_CACHE_DIR`` relocates it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from typing import Iterable, List, Optional

_MAX_ENTRIES = 400
_SCHEMA = 3
_LOCAL_INCLUDE_RE = re.compile(r'^\s*#\s*include\s*"([^"\n]+)"', re.M)


def enabled() -> bool:
    return os.environ.get("GSC_NO_CACHE") != "1"


def cache_dir() -> str:
    d = os.environ.get("GSC_CACHE_DIR")
    if not d:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
        d = os.path.join(base, "gsc-build-cache")
    return d


def _ensure_dir() -> Optional[str]:
    d = cache_dir()
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d
    except OSError:
        return None


def local_header_digest(source: str, base_dir: str, _depth: int = 0, _seen: Optional[set] = None) -> str:
    """Hash of every quoted-include header reachable from ``source`` (depth <= 3)."""
    h = hashlib.sha256()
    seen = _seen if _seen is not None else set()
    if _depth > 3:
        return h.hexdigest()
    for name in sorted(set(_LOCAL_INCLUDE_RE.findall(source))):
        p = os.path.normpath(os.path.join(base_dir, name))
        if p in seen:
            continue
        seen.add(p)
        try:
            with open(p, "rb") as f:
                data = f.read(2_000_000)
        except OSError:
            h.update(b"missing:" + name.encode())
            continue
        h.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
        h.update(local_header_digest(data.decode("utf-8", "ignore"), os.path.dirname(p),
                                     _depth + 1, seen).encode())
    return h.hexdigest()


def make_key(source: str, flags: Iterable[str], compiler_id: str, base_dir: str) -> str:
    h = hashlib.sha256()
    h.update(str(_SCHEMA).encode() + b"\0")
    h.update(compiler_id.encode() + b"\0")
    h.update("\x1f".join(flags).encode() + b"\0")
    h.update(local_header_digest(source, base_dir).encode() + b"\0")
    h.update(source.encode("utf-8", "surrogatepass"))
    return h.hexdigest()


def _valid(entry) -> bool:
    return (isinstance(entry, dict)
            and entry.get("schema") == _SCHEMA
            and isinstance(entry.get("diags"), list)
            and isinstance(entry.get("stderr"), str)
            and isinstance(entry.get("rc"), int)
            and isinstance(entry.get("undefined"), list)
            and all(isinstance(d, dict) and "message" in d and "type" in d for d in entry["diags"]))


def get(key: str) -> Optional[dict]:
    if not enabled():
        return None
    d = _ensure_dir()
    if not d:
        return None
    path = os.path.join(d, key + ".json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            entry = json.load(f)
    except (OSError, ValueError):
        return None
    if not _valid(entry):
        return None
    try:
        os.utime(path)                       # LRU touch
    except OSError:
        pass
    return entry


def put(key: str, diags: List[dict], stderr: str, rc: int, undefined: List[str]) -> None:
    if not enabled():
        return
    d = _ensure_dir()
    if not d:
        return
    entry = {"schema": _SCHEMA, "diags": diags, "stderr": stderr[-200_000:], "rc": rc,
             "undefined": undefined, "ts": time.time()}
    try:
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(entry, f)
        os.replace(tmp, os.path.join(d, key + ".json"))
    except (OSError, TypeError, ValueError):
        return
    _evict(d)


def _evict(d: str) -> None:
    try:
        files = [os.path.join(d, n) for n in os.listdir(d) if n.endswith(".json") and not n.startswith(".tmp-")]
        if len(files) <= _MAX_ENTRIES:
            return
        files.sort(key=lambda p: os.path.getmtime(p))
        for p in files[:len(files) - _MAX_ENTRIES]:
            os.remove(p)
    except OSError:
        pass


def clear() -> int:
    d = cache_dir()
    n = 0
    try:
        for name in os.listdir(d):
            if name.endswith(".json"):
                os.remove(os.path.join(d, name))
                n += 1
    except OSError:
        pass
    return n
