"""
compiler_runner.py
------------------
Pre-compilation safety gate + the high-level "compile this file" entry point.

NOTE: the gate is a *best-effort guard*, not a sandbox.  Anything that must
genuinely run untrusted code still needs a real sandbox (container / seccomp /
separate user).  The tool itself never *executes* the compiled program.

Layers (all token based - see ``lexer.py`` - so comments, string/raw-string
literals and multi-line calls are handled correctly):

  L0  size / NUL-byte sanity limits (compiler-DoS and parser-confusion guard)
  L1  lexical scan: forbidden calls, address-of / qualified / value references
      (``&system``, ``::system``, ``auto p = system;``), inline assembly,
      ``<sys/...>`` includes, shellcode markers
  L1b macro-expanded scan (only when a ``#define`` could hide a call, e.g.
      ``#define RUN system`` or token pasting) via ``g++ -E``
  L1c include confinement: ``#include "/etc/passwd"`` / ``"../../secret"``
      would leak file contents through compiler diagnostics
  L2  semantic scan: undefined symbols of the *compiled object*
      (defeats ``CAT(sys,tem)("x")``).  Fused into the single analysis build -
      no second compile.
"""

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from lexer import tokenize, blank_source, IDENT, PUNCT, PREPROC, STRING

# ─────────────────────────────────────────────────────────────────────────────
_PROC_FUNCS = ("system", "popen", "fork", "vfork",
               "execl", "execlp", "execle", "execv", "execvp", "execve",
               "execvpe", "exec", "posix_spawn", "posix_spawnp")
_LOADER_FUNCS = ("dlopen", "dlsym", "syscall")
_FORBIDDEN_NAMES = frozenset(_PROC_FUNCS + _LOADER_FUNCS)
# libc symbols (``exec`` alone is not a libc symbol)
_FORBIDDEN_SYMBOLS = frozenset(_FORBIDDEN_NAMES - {"exec"})
_ASM_NAMES = frozenset({"asm", "__asm__", "__asm"})
_ASM_FOLLOW = frozenset({"(", "volatile", "__volatile__", "goto", "inline", "__inline__"})

_INCLUDE_RE = re.compile(r'^#\s*(?:include|include_next|import|embed)\s*([<"])\s*([^>"\n]+)[>"]')
_SYS_INCLUDE_RE = re.compile(r'^sys/')
_DEFINE_RE = re.compile(r'^#\s*define\b')

_MAX_SOURCE_BYTES = int(os.environ.get("GSC_MAX_SOURCE_KB", "2048")) * 1024
_SYSTEM_INCLUDE_ROOTS = ("/usr/include", "/usr/lib/gcc", "/usr/local/include", "/usr/lib/llvm")

# Kept for backwards compatibility (imported by older code/tests)
_strip_comments_and_strings = blank_source


@dataclass
class Violation:
    rule: str
    message: str
    line: Optional[int] = None

    def __str__(self):
        loc = f" (line {self.line})" if self.line else ""
        return f"{self.message}{loc}"


def _default_permissions() -> dict:
    return {
        "allow_system_calls": os.environ.get("ALLOW_SYSTEM_CALLS") == "1",
        "allow_assembly": os.environ.get("ALLOW_ASSEMBLY") == "1",
        "allow_sys_includes": os.environ.get("ALLOW_SYS_INCLUDES") == "1",
    }


def _macro_expand_user_code(source: str, include_dir: Optional[str] = None) -> str:
    """
    Preprocess and return only lines that originate from the user's own
    translation unit (system-header text is dropped so libc declarations of
    system()/popen() cannot cause false positives).
    """
    cmd = ["g++", "-E", "-std=c++17", "-x", "c++", "-"]
    if include_dir:
        cmd[1:1] = ["-I", include_dir]
    try:
        res = subprocess.run(cmd, input=source, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, timeout=15)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""
    keep, in_user = [], False
    for line in res.stdout.splitlines():
        m = re.match(r'^#\s+\d+\s+"([^"]*)"', line)
        if m:
            in_user = (m.group(1) == "<stdin>")
            continue
        if in_user:
            keep.append(line)
    return "\n".join(keep)


def _scan_tokens(tokens, permissions, out: List[Violation]) -> None:
    allow_sys = permissions.get("allow_system_calls", False)
    allow_asm = permissions.get("allow_assembly", False)
    n = len(tokens)
    for i, t in enumerate(tokens):
        if t.kind != IDENT:
            if t.kind == STRING and not allow_asm and "shellcode" in t.text.lower():
                out.append(Violation("shellcode", "shellcode marker in string literal", t.line))
            continue
        prev = tokens[i - 1] if i else None
        nxt = tokens[i + 1] if i + 1 < n else None
        member = prev is not None and prev.kind == PUNCT and prev.text in (".", "->")

        if t.text in _FORBIDDEN_NAMES and not allow_sys and not member:
            if nxt is not None and nxt.kind == PUNCT and nxt.text == "(":
                out.append(Violation("forbidden-call", f"call to '{t.text}'", t.line))
            elif prev is not None and prev.kind == PUNCT and prev.text in ("&", "::") \
                    and t.text != "exec":
                out.append(Violation("forbidden-ref", f"reference to '{t.text}'", t.line))
            elif (t.text != "exec" and nxt is not None and nxt.kind == PUNCT
                  and nxt.text in (";", ",", ")", "}")
                  and prev is not None and prev.kind == PUNCT
                  and prev.text in ("=", "(", ",", "{", "?", ":", "return")):
                out.append(Violation("forbidden-ref", f"'{t.text}' used as a value", t.line))
        if t.text in _ASM_NAMES and not allow_asm and not member:
            if nxt is not None and nxt.text in _ASM_FOLLOW:
                out.append(Violation("asm", "inline assembly", t.line))
        if t.text.lower().find("shellcode") >= 0 and not allow_asm:
            out.append(Violation("shellcode", "shellcode marker", t.line))


def _check_include(path_kind: str, path: str, include_dir: Optional[str], permissions: dict,
                   line: int, out: List[Violation]) -> None:
    if not permissions.get("allow_sys_includes", False) and _SYS_INCLUDE_RE.match(path):
        out.append(Violation("sys-include", f"system header <{path}>", line))
        return
    absolute = os.path.isabs(path)
    traversal = ".." in path.replace("\\", "/").split("/")
    if not absolute and not traversal:
        return
    root = os.path.realpath(include_dir) if include_dir else os.getcwd()
    target = os.path.realpath(path if absolute else os.path.join(root, path))
    inside_project = target == root or target.startswith(root + os.sep)
    inside_system = any(target.startswith(p + os.sep) for p in _SYSTEM_INCLUDE_ROOTS)
    if not (inside_project or inside_system):
        out.append(Violation("include-path",
                             f"include of '{path}' resolves outside the project "
                             f"(file contents would leak into compiler messages)", line))


def scan_source(source: str, permissions: Optional[dict] = None,
                include_dir: Optional[str] = None, semantic: bool = False) -> List[Violation]:
    """Run gate layers L0-L1c (and L2 when ``semantic``).  Empty list == allowed."""
    permissions = _default_permissions() if permissions is None else permissions
    out: List[Violation] = []

    if len(source.encode("utf-8", "ignore")) > _MAX_SOURCE_BYTES:
        return [Violation("size", f"source larger than {_MAX_SOURCE_BYTES // 1024} KB")]
    if "\x00" in source:
        return [Violation("nul", "NUL byte in source")]

    tokens = tokenize(source)
    macros_may_hide = False
    for t in tokens:
        if t.kind != PREPROC:
            continue
        m = _INCLUDE_RE.match(t.text)
        if m:
            _check_include(m.group(1), m.group(2).strip(), include_dir, permissions, t.line, out)
        elif _DEFINE_RE.match(t.text):
            low = t.text
            if "##" in low or any(f in low for f in _FORBIDDEN_NAMES) or "asm" in low:
                macros_may_hide = True
    _scan_tokens(tokens, permissions, out)
    if out:
        return out

    if macros_may_hide:
        expanded = _macro_expand_user_code(source, include_dir)
        if expanded:
            _scan_tokens(tokenize(expanded, keep_preproc=False), permissions, out)
            if out:
                return out

    if semantic and not permissions.get("allow_system_calls", False):
        if _object_uses_forbidden_symbols(source, include_dir):
            out.append(Violation("forbidden-symbol",
                                 "compiled object references a forbidden libc symbol"))
    return out


def forbidden_symbols_in(undefined: List[str]) -> List[str]:
    """L2 on an already-built object: which forbidden libc symbols does it import?"""
    return sorted(set(undefined) & _FORBIDDEN_SYMBOLS)


def _object_uses_forbidden_symbols(source: str, include_dir: Optional[str] = None) -> bool:
    """Stand-alone L2 (used only by ``_sanitize_code``; the pipeline fuses it into the build)."""
    from diagnostics import undefined_symbols
    with tempfile.TemporaryDirectory(prefix="gsc_scan_") as tmp:
        src = os.path.join(tmp, "scan.cpp")
        obj = os.path.join(tmp, "scan.o")
        with open(src, "w") as f:
            f.write(source)
        cmd = ["g++", "-std=c++17", "-c", src, "-o", obj]
        if include_dir:
            cmd[1:1] = ["-I", include_dir]
        try:
            if subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=60).returncode != 0:
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
        syms = undefined_symbols(obj)
    return bool(syms) and bool(forbidden_symbols_in(syms))


# ─────────────────────────────────────────────────────────────────────────────
# Public API (unchanged signatures)
# ─────────────────────────────────────────────────────────────────────────────

def _sanitize_code(source: str, permissions: dict = None, include_dir: str = None,
                   semantic: bool = True) -> bool:
    """Return True if the source is allowed, False if it is blocked."""
    return not scan_source(source, permissions, include_dir, semantic=semantic)


def _sanitize_input(file_path: str, permissions: dict = None, semantic: bool = True) -> bool:
    if not os.path.exists(file_path):
        return True
    with open(file_path, "r", errors="ignore") as f:
        return _sanitize_code(f.read(), permissions,
                              include_dir=os.path.dirname(os.path.abspath(file_path)),
                              semantic=semantic)


def security_violation_diag(file_path: str, violations: List[Violation]) -> dict:
    detail = "; ".join(str(v) for v in violations[:3])
    return {
        "file": file_path,
        "line": violations[0].line if violations and violations[0].line else 1,
        "column": 1,
        "type": "error",
        "message": "Security Error: Malicious command injection or forbidden system call detected.",
        "detail": detail,
        "raw": "error: Malicious command injection or forbidden system call detected.",
        "category": "security_violation",
        "confidence": 1.0,
        "option": None,
        "notes": [],
    }


def compile_checked(file_path: str, permissions: dict = None, analysis: bool = True,
                    extra_flags=None):
    """
    Gate + single build.  Returns ``(diagnostics, BuildResult | None)``.
    ``BuildResult`` is ``None`` when the gate blocked the source before any
    compiler ran.
    """
    from diagnostics import build
    try:
        with open(file_path, "r", errors="ignore") as f:
            source = f.read()
    except OSError:
        source = None
    perms = _default_permissions() if permissions is None else permissions
    if source is not None:
        v = scan_source(source, perms, os.path.dirname(os.path.abspath(file_path)), semantic=False)
        if v:
            return [security_violation_diag(file_path, v)], None
    try:
        res = build(file_path, extra_flags, analysis=analysis)
    except FileNotFoundError:
        msg = "g++ compiler not found. Install it (Linux: sudo apt install g++ binutils; Windows: use WSL, MSYS2 or Google Colab) and run again."
        return [{"file": None, "line": None, "column": None, "type": "error", "message": msg,
                 "raw": msg, "option": None, "notes": []}], None
    if not perms.get("allow_system_calls", False):
        bad = forbidden_symbols_in(res.undefined)
        if bad:
            v = [Violation("forbidden-symbol", f"object imports forbidden libc symbol(s): {', '.join(bad)}")]
            return [security_violation_diag(file_path, v)], res
    return res.diagnostics, res


def run_cpp_compiler(file_path, permissions=None):
    """Compile with the full detection profile; returns diagnostic dicts ([] == success)."""
    diags, _res = compile_checked(file_path, permissions, analysis=True)
    return diags
