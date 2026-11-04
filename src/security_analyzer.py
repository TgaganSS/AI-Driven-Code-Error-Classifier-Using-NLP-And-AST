"""
security_analyzer.py
--------------------
Security findings from two complementary sources, merged and de-duplicated:

  * compiler diagnostics - classified through the shared taxonomy (CWE ids,
    severities) so every ``[-Warray-bounds]``, ``[-Wformat-security]``,
    ``[-Wuse-after-free]`` ... becomes a finding;
  * a token-based static scan (built on ``lexer.py``) with per-function scope,
    compile-time constant evaluation (so ``char b[N]`` sizes are known) and a
    lightweight taint analysis (``cin >> x``, ``argv``, ``getenv``, ``fgets``,
    ``scanf``, ``recv`` ... flowing into ``system``, ``printf``, ``strcpy``,
    ``memcpy``, array indices, allocation sizes, file paths).

Compared with the first version (line-by-line regexes) this
  * understands multi-line statements and ignores comments/strings correctly;
  * **stops flagging safe code**: ``strcpy(buf8, "hi")`` into an 8-byte array,
    ``malloc`` that is freed / returned, arithmetic that merely mentions "size";
  * finds *more*: definite out-of-bounds, off-by-one loops, unbounded
    ``cin >> char[]``, tainted array indices / sizes / format strings / commands /
    paths, ``new[]``/``delete`` mismatches, double free & use-after-free
    **per function**, missing NULL checks, ``malloc(strlen(s))`` off-by-one,
    hard-coded credentials & API keys, weak hashes/ciphers, weak RNG in
    security contexts, insecure temp files, TOCTOU, 0777 permissions;
  * attaches CWE ids, rule ids and a confidence to every finding.

The public API (``SecurityFinding``, ``analyze``, ``format_security_report``)
is backward compatible; new fields have defaults.
"""

from __future__ import annotations

import functools
import hashlib
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional, Set, Tuple

from lexer import (Token, tokenize, split_statements, find_calls, IDENT, NUMBER, STRING, CHAR,
                   PUNCT, PREPROC)
from taxonomy import classify_rules, info as category_info, CWE_NAMES

Severity = Literal["Critical", "High", "Medium", "Low"]

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_SEVERITY_WEIGHT = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
_CONF_FACTOR = {"High": 1.0, "Medium": 0.6, "Low": 0.3}


@dataclass(frozen=True)
class SecurityFinding:
    file: str
    line: Optional[int]
    column: Optional[int]
    severity: str
    vulnerability_type: str
    description: str
    recommendation: str
    source: str                         # "compiler_diagnostic" | "static_scan"
    cwe: Tuple[int, ...] = ()
    rule_id: str = ""
    confidence: str = "High"           # High | Medium | Low
    snippet: str = ""

    def to_dict(self):
        d = asdict(self)
        d["cwe"] = [f"CWE-{c}" for c in self.cwe]
        return d


# ─────────────────────────────────────────────────────────────────────────────
# Compiler-diagnostic findings (via the shared taxonomy)
# ─────────────────────────────────────────────────────────────────────────────

# (category -> vulnerability_type label used in reports)
_CATEGORY_LABEL = {
    "buffer_overflow": "Buffer Overflow", "string_truncation": "String Truncation",
    "format_string": "Format String Vulnerability", "null_dereference": "Null Pointer Dereference",
    "use_after_free": "Use After Free", "memory_mismatch": "Mismatched Memory Management",
    "dangling_pointer": "Dangling Pointer", "uninitialized_memory": "Uninitialized Memory",
    "integer_overflow": "Integer Overflow", "sign_conversion": "Signed/Unsigned Mismatch",
    "division_by_zero": "Division By Zero", "unchecked_return": "Unchecked Return Value",
    "insecure_function": "Use of Deprecated/Dangerous API", "cast_safety": "Unsafe Cast",
    "logic_error": "Logic Error", "unused_variable": "Unused Variable / Dead Code",
    "implicit_fallthrough": "Switch Fall-through",
}
# categories that are reported as security findings (security group + a few correctness ones
# the original tool already surfaced)
_REPORTED = set(_CATEGORY_LABEL)


def _get(err, name, default=None):
    if isinstance(err, dict):
        return err.get(name, default)
    return getattr(err, name, default)


def _diagnostic_findings(error) -> List[SecurityFinding]:
    message = _get(error, "message") or ""
    option = _get(error, "option")
    dtype = _get(error, "type", None) or _get(error, "error_type", "warning")
    res = classify_rules(message, option, dtype)
    if not res:
        return []
    cat = res[0]
    if cat not in _REPORTED:
        return []
    c = category_info(cat)
    sev = c.severity
    low = message.lower()
    # refinements: provable out-of-bounds is Critical, truncation/compare noise is lower
    if cat == "sign_conversion" and "may change the sign" not in low and "different signedness" not in low:
        sev = "Low" if "float" in low or "double" in low else "Medium"
    if cat == "use_after_free" and "free" in low and "used after" not in low:
        sev = "High"
    path = _get(error, "file") or ""
    return [SecurityFinding(
        file=_normalize_path(path), line=_get(error, "line"), column=_get(error, "column"),
        severity=sev, vulnerability_type=_CATEGORY_LABEL[cat],
        description=c.what or message, recommendation=c.fix or c.how,
        source="compiler_diagnostic", cwe=c.cwe, rule_id=f"GCC-{option or cat}".upper()[:40],
        confidence="High" if res[1] >= 0.95 else "Medium")]


# ─────────────────────────────────────────────────────────────────────────────
# Static scan
# ─────────────────────────────────────────────────────────────────────────────

_CONTROL = {"if", "for", "while", "switch", "catch", "else", "do", "return", "sizeof", "defined"}
_TYPE_WORDS = {"const", "static", "unsigned", "signed", "long", "short", "int", "char", "float",
               "double", "bool", "void", "auto", "size_t", "ssize_t", "volatile", "register",
               "struct", "class", "enum", "wchar_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
               "int8_t", "int16_t", "int32_t", "int64_t", "constexpr", "extern", "typename", "std"}
_STREAM_TYPES = {"ifstream", "fstream", "istream", "istringstream", "stringstream", "cin"}

_PRINTF_FAMILY = {  # name -> index of the format argument
    "printf": 0, "vprintf": 0, "fprintf": 1, "vfprintf": 1, "sprintf": 1, "vsprintf": 1,
    "snprintf": 2, "vsnprintf": 2, "dprintf": 1, "syslog": 1, "wprintf": 0, "asprintf": 1,
    "err": 1, "warn": 0, "errx": 1, "warnx": 0,
}
_EXEC_FUNCS = {"system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
               "execvpe", "ShellExecute", "ShellExecuteA", "WinExec", "_popen"}
_PATH_OPENERS = {"fopen": 0, "open": 0, "freopen": 0, "creat": 0, "remove": 0, "unlink": 0,
                 "rename": 0, "opendir": 0, "stat": 0, "lstat": 0, "access": 0, "chmod": 0,
                 "ifstream": -1, "ofstream": -1, "fstream": -1}
_ALLOC = {"malloc", "calloc", "realloc", "aligned_alloc", "strdup", "strndup"}
_SENS = re.compile(r"(?i)(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|"
                   r"session|nonce|salt|\bkey\b|\biv\b|\bkeys?\b|credential|otp|csrf|auth)")
_CRED_NAME = re.compile(r"(?i)^(?:.*_)?(pass(?:word|wd)?|pwd|secret|api_?key|apikey|"
                        r"private_?key|auth_?token|access_?token|token|passphrase|credentials?)(?:_.*)?$")
_CRED_SKIP = re.compile(r"(?i)(prompt|label|hint|name|field|text|msg|message|placeholder|"
                        r"regex|pattern|format|len|size|count|file|path|dir|type|policy|enabled|"
                        r"required|min|max)")
_KEY_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "private key block"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "GitHub token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "API secret key"),
]
_WEAK_CRYPTO = re.compile(r"^(?:MD2|MD4|MD5|MD5_Init|SHA1|SHA1_Init|DES_\w+|DES_ecb_encrypt|RC4|RC4_set_key|"
                          r"EVP_md5|EVP_sha1|EVP_des_\w+|EVP_rc4\w*|EVP_aes_\d+_ecb|crypt|CryptGenRandom_weak)$")
_RNG_ENGINES = {"mt19937", "mt19937_64", "default_random_engine", "minstd_rand", "minstd_rand0",
                "ranlux24", "ranlux48", "knuth_b"}


class _Eval:
    """Tiny safe integer-expression evaluator for array sizes (no eval())."""

    def __init__(self, consts: Dict[str, int]):
        self.consts = consts

    def value(self, toks: List[Token]) -> Optional[int]:
        self.t = [x for x in toks]
        self.i = 0
        try:
            v = self._expr()
            return v if self.i == len(self.t) else None
        except (ValueError, ZeroDivisionError, IndexError):
            return None

    def _peek(self):
        return self.t[self.i].text if self.i < len(self.t) else None

    def _expr(self):
        v = self._term()
        while self._peek() in ("+", "-"):
            op = self.t[self.i].text
            self.i += 1
            r = self._term()
            v = v + r if op == "+" else v - r
        return v

    def _term(self):
        v = self._atom()
        while self._peek() in ("*", "/", "%", "<<", ">>"):
            op = self.t[self.i].text
            self.i += 1
            r = self._atom()
            v = {"*": lambda: v * r, "/": lambda: v // r, "%": lambda: v % r,
                 "<<": lambda: v << r, ">>": lambda: v >> r}[op]()
        return v

    def _atom(self):
        tok = self.t[self.i]
        if tok.text == "(":
            self.i += 1
            v = self._expr()
            if self._peek() != ")":
                raise ValueError
            self.i += 1
            return v
        if tok.text == "sizeof":
            self.i += 1
            # sizeof(char) / sizeof(int)...
            if self._peek() == "(" and self.i + 2 < len(self.t) and self.t[self.i + 2].text == ")":
                name = self.t[self.i + 1].text
                self.i += 3
                sizes = {"char": 1, "short": 2, "int": 4, "long": 8, "float": 4, "double": 8,
                         "bool": 1, "size_t": 8}
                if name in sizes:
                    return sizes[name]
            raise ValueError
        if tok.kind == NUMBER:
            self.i += 1
            m = re.match(r"^(0[xX][0-9a-fA-F']+|0[bB][01']+|\d[\d']*)[uUlL]*$", tok.text)
            if not m:
                raise ValueError
            return int(m.group(1).replace("'", ""), 0)
        if tok.kind == IDENT and tok.text in self.consts:
            self.i += 1
            return self.consts[tok.text]
        raise ValueError


@dataclass
class _Var:
    name: str
    size: Optional[int] = None         # element count for arrays
    elem: str = ""                     # element type word (char, int ...)
    is_array: bool = False
    is_ptr: bool = False
    alloc: Optional[str] = None        # malloc | new | new[] | strdup
    alloc_line: int = 0
    alloc_toks: Optional[List[Token]] = None
    alloc_stmt: int = -1
    freed_stmt: int = -1
    freed_line: int = 0
    freed_by: str = ""
    checked: bool = False              # NULL-checked
    escaped: bool = False              # returned / stored / passed on


class _Scanner:
    def __init__(self, source: str, path: str):
        self.path = path
        self.source = source
        self.lines = source.splitlines()
        self.tokens = tokenize(source)
        self.findings: List[SecurityFinding] = []
        self.consts: Dict[str, int] = {}
        self.str_consts: Dict[str, int] = {}
        self._collect_consts()
        self.ev = _Eval(self.consts)
        self.debug_guard = any(t.kind == PREPROC and re.match(r"#\s*(?:if|ifdef|ifndef)\b.*NDEBUG", t.text)
                               for t in self.tokens)

    # -- helpers ---------------------------------------------------------------
    def emit(self, rule: str, line: int, col: Optional[int], sev: str, vtype: str, desc: str,
             rec: str, cwe: Tuple[int, ...], conf: str = "High"):
        snippet = self.lines[line - 1].strip()[:160] if line and 0 < line <= len(self.lines) else ""
        self.findings.append(SecurityFinding(
            file=_normalize_path(self.path), line=line, column=col, severity=sev,
            vulnerability_type=vtype, description=desc, recommendation=rec,
            source="static_scan", cwe=cwe, rule_id=rule, confidence=conf, snippet=snippet))

    def _collect_consts(self):
        toks = self.tokens
        for i, t in enumerate(toks):                      # const char* NAME = "literal";
            if t.kind == IDENT and t.text == "char" and i >= 1 and "const" in (
                    toks[i - 1].text, toks[i - 2].text if i >= 2 else ""):
                j = i + 1
                while j < len(toks) and toks[j].text in ("*", "const"):
                    j += 1
                if j + 2 < len(toks) and toks[j].kind == IDENT:
                    k = j + 1
                    if toks[k].text == "[" and toks[k + 1].text == "]":
                        k += 2
                    if toks[k].text == "=" and toks[k + 1].kind == STRING:
                        body = toks[k + 1].text
                        m = re.match(r'^(?:u8|u|U|L)?"(.*)"$', body, re.S)
                        if m:
                            self.str_consts[toks[j].text] = len(re.sub(
                                r"\\(?:x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", "x", m.group(1)))
        for t in toks:
            if t.kind == PREPROC:
                m = re.match(r"#\s*define\s+([A-Za-z_]\w*)\s+(\(?[\w\s+\-*/%<>()']+\)?)\s*$", t.text)
                if m:
                    vt = [x for x in tokenize(m.group(2))]
                    v = _Eval(self.consts).value(vt)
                    if v is not None:
                        self.consts[m.group(1)] = v
        for i, t in enumerate(toks):
            if t.kind == IDENT and t.text in ("const", "constexpr") and i + 3 < len(toks):
                j = i + 1
                while j < len(toks) and toks[j].kind == IDENT and toks[j].text in _TYPE_WORDS:
                    j += 1
                if j + 2 < len(toks) and toks[j].kind == IDENT and toks[j + 1].text == "=":
                    k = j + 2
                    expr = []
                    while k < len(toks) and toks[k].text not in (";", ","):
                        expr.append(toks[k])
                        k += 1
                    v = _Eval(self.consts).value(expr)
                    if v is not None:
                        self.consts[toks[j].text] = v

    # -- function discovery ------------------------------------------------------
    def functions(self) -> List[Tuple[str, List[Token], int, int]]:
        toks = self.tokens
        n = len(toks)
        out = []
        stack: List[Tuple[int, bool]] = []     # (open index, is_function)
        in_func = 0
        for i, t in enumerate(toks):
            if t.kind != PUNCT:
                continue
            if t.text == "{":
                is_fn = False
                if not in_func:
                    j = i - 1
                    while j >= 0 and toks[j].kind == IDENT and toks[j].text in (
                            "const", "noexcept", "override", "final", "mutable", "volatile"):
                        j -= 1
                    if j >= 0 and toks[j].text == ")":
                        depth = 0
                        k = j
                        while k >= 0:
                            if toks[k].text == ")":
                                depth += 1
                            elif toks[k].text == "(":
                                depth -= 1
                                if depth == 0:
                                    break
                            k -= 1
                        if k >= 1 and toks[k - 1].kind == IDENT and toks[k - 1].text not in _CONTROL:
                            is_fn = True
                            name = toks[k - 1].text
                            params = toks[k + 1:j]
                            stack.append((i, True))
                            in_func += 1
                            out.append([name, params, i, -1])
                            continue
                stack.append((i, False))
            elif t.text == "}":
                if stack:
                    _, was_fn = stack.pop()
                    if was_fn:
                        in_func -= 1
                        for rec in reversed(out):
                            if rec[3] == -1:
                                rec[3] = i
                                break
        return [(a, b, c, d) for a, b, c, d in out if d != -1]

    # -- main --------------------------------------------------------------------
    def run(self):
        self._file_level()
        for name, params, s, e in self.functions():
            _FunctionAnalysis(self, name, params, s, e).run()
        return self.findings

    def _file_level(self):
        toks = self.tokens
        for i, t in enumerate(toks):
            if t.kind == STRING:
                body = t.text
                for rx, label in _KEY_PATTERNS:
                    if rx.search(body):
                        self.emit("GSC-CRED-002", t.line, t.col, "Critical", "Hard-coded Secret",
                                  f"A literal that looks like a {label} is embedded in the source.",
                                  "Remove the secret from source control, rotate it, and load it from "
                                  "the environment or a secrets manager.", (798,))
                        break
            if t.kind == IDENT and _WEAK_CRYPTO.match(t.text) and i + 1 < len(toks) \
                    and toks[i + 1].text == "(":
                self.emit("GSC-CRYPTO-001", t.line, t.col, "Medium", "Weak Cryptography",
                          f"'{t.text}' uses a broken or weak algorithm (MD5/SHA-1/DES/RC4/ECB).",
                          "Use SHA-256/SHA-3 for hashing, AES-GCM / ChaCha20-Poly1305 for encryption, "
                          "and a password KDF (Argon2/bcrypt/scrypt) for passwords.", (327,))
            if t.kind == IDENT and t.text in ("tmpnam", "tempnam", "mktemp", "tmpnam_r") \
                    and i + 1 < len(toks) and toks[i + 1].text == "(":
                self.emit("GSC-TMP-001", t.line, t.col, "Medium", "Insecure Temporary File",
                          f"{t.text}() returns a predictable name and is vulnerable to race conditions.",
                          "Use mkstemp()/std::filesystem with exclusive creation.", (377,))
            if t.kind == IDENT and t.text == "alloca" and i + 1 < len(toks) and toks[i + 1].text == "(":
                self.emit("GSC-STACK-001", t.line, t.col, "Medium", "Unbounded Stack Allocation",
                          "alloca() can exhaust the stack and has no failure indication.",
                          "Use a fixed-size buffer or heap/std::vector with an explicit upper bound.", (770,))
            if t.kind == IDENT and t.text == "gets" and i + 1 < len(toks) and toks[i + 1].text == "(":
                self.emit("GSC-BOF-001", t.line, t.col, "Critical", "Buffer Overflow",
                          "gets() reads input without any bounds checking and cannot be used safely.",
                          "Replace gets() with fgets(), std::getline, or another bounded routine.",
                          (242, 120))
            if t.kind == IDENT and t.text == "assert" and i + 1 < len(toks) and toks[i + 1].text == "(" \
                    and not self.debug_guard:
                self.emit("GSC-ASSERT-001", t.line, t.col, "Low", "Disabled Safety Check",
                          "assert() is compiled out with NDEBUG and must not be the only validation.",
                          "Keep runtime checks explicit; do not rely on assert() in production.", (617,),
                          "Low")


@functools.lru_cache(maxsize=64)
def _scan_cached(digest: str, path: str, source: str) -> Tuple[SecurityFinding, ...]:
    return tuple(_Scanner(source, path).run())


def _normalize_path(source_path: str) -> str:
    try:
        return str(Path(source_path).resolve())
    except Exception:
        return source_path


class _FunctionAnalysis:
    """Straight-line, per-function analysis with taint, sizes and allocation tracking."""

    def __init__(self, sc: _Scanner, name: str, params: List[Token], start: int, end: int):
        self.sc = sc
        self.name = name
        self.params = params
        self.toks = sc.tokens[start + 1:end]
        self.vars: Dict[str, _Var] = {}
        self.tainted: Set[str] = set()
        self.validated: Set[str] = set()
        self.zero_checked: Set[str] = set()
        self.streams: Set[str] = set(["cin"])
        self.rd_vars: Set[str] = set()
        self.size_calc: Dict[str, List[Token]] = {}
        self.stmt_no = 0
        self.bounded: Set[str] = set()
        self.emitted: Set[Tuple] = set()

    # -- util -------------------------------------------------------------------
    def emit(self, rule, tok_or_line, sev, vtype, desc, rec, cwe, conf="High"):
        line = tok_or_line.line if isinstance(tok_or_line, Token) else tok_or_line
        col = tok_or_line.col if isinstance(tok_or_line, Token) else None
        key = (rule, line)
        if key in self.emitted:
            return
        self.emitted.add(key)
        self.sc.emit(rule, line, col, sev, vtype, desc, rec, cwe, conf)

    @staticmethod
    def idents(toks: Iterable[Token]) -> Set[str]:
        return {t.text for t in toks if t.kind == IDENT}

    def is_literal(self, toks: List[Token]) -> bool:
        return bool(toks) and all(t.kind == STRING for t in toks)

    def literal_len(self, toks: List[Token]) -> Optional[int]:
        if not self.is_literal(toks):
            return None
        n = 0
        for t in toks:
            body = t.text
            m = re.match(r'^(?:u8|u|U|L)?"(.*)"$', body, re.S)
            if not m:
                return None
            n += len(re.sub(r"\\(?:x[0-9a-fA-F]{1,2}|[0-7]{1,3}|.)", "x", m.group(1)))
        return n

    def tainted_in(self, toks: Iterable[Token]) -> Set[str]:
        ids = self.idents(toks)
        hit = (ids & self.tainted)
        if "argv" in ids:
            hit.add("argv")
        for t in toks:
            if t.kind == IDENT and t.text == "getenv":
                hit.add("getenv()")
        return hit

    def unvalidated(self, toks: Iterable[Token]) -> Set[str]:
        return {x for x in self.tainted_in(toks) if x not in self.validated}

    def int_value(self, toks: List[Token]) -> Optional[int]:
        return _Eval(self.sc.consts).value(toks)

    # -- parameters --------------------------------------------------------------
    def _params(self):
        cur: List[Token] = []
        parts: List[List[Token]] = []
        depth = 0
        for t in self.params:
            if t.text in "([<":
                depth += 1
            elif t.text in ")]>":
                depth -= 1
            if t.text == "," and depth <= 0:
                parts.append(cur)
                cur = []
                continue
            cur.append(t)
        if cur:
            parts.append(cur)
        for p in parts:
            ids = [t for t in p if t.kind == IDENT]
            if not ids:
                continue
            name = ids[-1].text
            ptr = any(t.text in ("*",) for t in p) or any(t.text == "[" for t in p)
            # main's 2nd/3rd parameters (argv/envp) are attacker-controlled whatever they are called
            if name == "argv" or (self.name == "main" and parts.index(p) in (1, 2) and ptr):
                self.tainted.add(name)
            self.vars[name] = _Var(name, is_ptr=ptr)

    # -- declarations ---------------------------------------------------------------
    def _declarations(self, st: List[Token]):
        """Record local arrays / pointers declared in statement ``st``."""
        if not st or st[0].kind != IDENT:
            return
        if st[0].text in _CONTROL or st[0].text in ("delete", "free", "goto", "throw", "case"):
            return
        # type words then declarators
        i = 0
        while i < len(st) and st[i].kind == IDENT and (st[i].text in _TYPE_WORDS or st[i].text == "::"):
            i += 1
        # simple "Type name" or "Type* name" or "Type name[N]"
        j = 0
        elem = ""
        for t in st:
            if t.kind == IDENT and t.text in ("char", "int", "long", "short", "float", "double",
                                              "wchar_t", "uint8_t", "unsigned", "bool"):
                elem = t.text
                break
        for k, t in enumerate(st):
            if t.kind == IDENT and k + 1 < len(st) and st[k + 1].text == "[" and k >= 1 \
                    and (st[k - 1].kind == IDENT or st[k - 1].text in ("*", "&")) \
                    and st[k - 1].text != "new" and t.text not in _TYPE_WORDS \
                    and st[0].text not in _CONTROL:
                # find closing bracket
                depth = 0
                m = k + 1
                expr: List[Token] = []
                while m < len(st):
                    if st[m].text == "[":
                        depth += 1
                        if depth == 1:
                            m += 1
                            continue
                    elif st[m].text == "]":
                        depth -= 1
                        if depth == 0:
                            break
                    expr.append(st[m])
                    m += 1
                # must be followed by ; = , ) { to be a declaration (not an index expression)
                nxt = st[m + 1].text if m + 1 < len(st) else ";"
                before_type = st[k - 1].kind == IDENT and st[k - 1].text not in _CONTROL
                if nxt in (";", "=", ",", "[", "{") and before_type and st[0].kind == IDENT:
                    size = self.int_value(expr) if expr else None
                    v = _Var(t.text, size=size, elem=elem, is_array=True)
                    if expr and size is None and all(x.kind == IDENT for x in expr):
                        v.size = None
                        self._vla(t, expr)
                    self.vars[t.text] = v
            # pointer declarations "T * name"
        for k, t in enumerate(st):
            if t.kind == IDENT and k >= 1 and st[k - 1].text == "*" and (
                    k + 1 >= len(st) or st[k + 1].text in ("=", ";", ",", "(")) \
                    and k >= 2 and (st[k - 2].kind == IDENT) and st[0].text not in _CONTROL \
                    and st[0].kind == IDENT:
                self.vars.setdefault(t.text, _Var(t.text, is_ptr=True, elem=elem))
        # stream objects
        for k, t in enumerate(st):
            if t.kind == IDENT and t.text in _STREAM_TYPES and k + 1 < len(st) and st[k + 1].kind == IDENT:
                self.streams.add(st[k + 1].text)

    def _vla(self, name_tok: Token, expr: List[Token]):
        if self.tainted_in(expr):
            self.emit("GSC-STACK-002", name_tok, "High", "Unbounded Stack Allocation",
                      "A variable-length array is sized from external input.",
                      "Validate the size against a fixed maximum, or use std::vector.", (770,))

    # -- taint sources / propagation -------------------------------------------------
    def _taint_sources(self, st: List[Token]):
        calls = list(find_calls(st))
        for c in calls:
            nm = c.name
            args = c.args
            if nm in ("scanf", "fscanf", "sscanf", "wscanf"):
                skip = 1 if nm == "scanf" else 2
                for a in args[skip:]:
                    ids = [t.text for t in a if t.kind == IDENT]
                    if ids:
                        self.tainted.add(ids[0] if a[0].text != "&" else (ids[0]))
            elif nm in ("fgets", "gets", "fread", "read", "recv", "recvfrom", "pread", "getline") and args:
                tgt = args[0] if nm in ("fgets", "gets", "fread") else (args[1] if len(args) > 1 else [])
                if nm == "getline" and len(args) >= 1:
                    tgt = args[0]
                ids = [t.text for t in tgt if t.kind == IDENT]
                if ids:
                    self.tainted.add(ids[0])
        # std::getline(cin, s) / cin.getline(buf, n) / cin.get(buf, n)
        for k, t in enumerate(st):
            if t.kind == IDENT and t.text in ("getline", "get") and k >= 2 and st[k - 1].text in (".", "::"):
                base = st[k - 2].text
                if base in self.streams or base == "std":
                    args = next(iter([c for c in calls if c.name == t.text]), None)
                    if args and args.args:
                        ids = [x.text for x in args.args[0] if x.kind == IDENT]
                        if ids:
                            self.tainted.add(ids[0])
            if t.kind == IDENT and t.text == "getline" and k + 2 < len(st) and st[k + 1].text == "(":
                c = next((x for x in calls if x.name == "getline"), None)
                if c and len(c.args) >= 2 and c.args[0] and c.args[0][0].text in self.streams | {"std"}:
                    ids = [x.text for x in c.args[1] if x.kind == IDENT]
                    if ids:
                        self.tainted.add(ids[0])
        # cin >> a >> b[0]
        for k, t in enumerate(st):
            if t.text == ">>" and k >= 1:
                # find the stream at the start of the chain
                j = k - 1
                while j >= 0 and st[j].text != ">>" and st[j].text != "=":
                    j -= 1
                head = [x for x in st[j + 1:k] if x.kind == IDENT]
                chain_start = st[:k]
                if any(x.kind == IDENT and x.text in self.streams for x in chain_start[:3]) or \
                        any(x.text in self.streams for x in chain_start if x.kind == IDENT):
                    if k + 1 < len(st) and st[k + 1].kind == IDENT:
                        self.tainted.add(st[k + 1].text)
        # remember arithmetic assigned to a variable (used later as an allocation size)
        for k, t in enumerate(st):
            if t.text == "=" and k >= 1 and st[k - 1].kind == IDENT:
                rhs = st[k + 1:]
                if any(x.text in ("*", "<<") for x in rhs) and any(x.kind == IDENT for x in rhs):
                    self.size_calc[st[k - 1].text] = rhs
                break
        # assignment / declaration propagation
        eq = None
        depth = 0
        for k, t in enumerate(st):
            if t.text in "([{":
                depth += 1
            elif t.text in ")]}":
                depth -= 1
            elif depth == 0 and t.text in ("=", "+=", "-=", "*=", "|=", "&=") :
                eq = k
                break
        if eq is not None:
            lhs = [x for x in st[:eq] if x.kind == IDENT and x.text not in _TYPE_WORDS]
            rhs = st[eq + 1:]
            if lhs and self.tainted_in(rhs):
                self.tainted.add(lhs[-1].text)
        # constructor-style declaration:  std::string s(argv[1]);
        if len(st) >= 4 and st[0].kind == IDENT and st[0].text not in _CONTROL:
            for k in range(1, len(st) - 1):
                if st[k].kind == IDENT and st[k + 1].text == "(" and st[k - 1].kind == IDENT \
                        and st[k - 1].text not in _CONTROL and st[k].text not in self.sc.consts:
                    # find matching paren content
                    inner = []
                    d = 0
                    for x in st[k + 1:]:
                        if x.text == "(":
                            d += 1
                            if d == 1:
                                continue
                        if x.text == ")":
                            d -= 1
                            if d == 0:
                                break
                        inner.append(x)
                    if self.tainted_in(inner) and (st[k - 1].text in _TYPE_WORDS or
                                                   st[k - 1].text in ("string", "vector", "path", "ifstream")
                                                   or st[k - 1].text == ">"):
                        self.tainted.add(st[k].text)
                    break
        # copy functions taint their destination
        for c in calls:
            if c.name in ("strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove", "sprintf",
                          "snprintf", "stpcpy") and c.args:
                tgt_i = 0
                rest = c.args[1:]
                if self.tainted_in([x for a in rest for x in a]):
                    ids = [x.text for x in c.args[tgt_i] if x.kind == IDENT]
                    if ids:
                        self.tainted.add(ids[0])

    def _validation(self, st: List[Token]):
        """An if/while/assert/for condition comparing a tainted value counts as validation."""
        if not st or st[0].text not in ("if", "while", "assert", "for") and st[0].text != "}":
            return
        text_ids = self.idents(st)
        has_cmp = any(t.text in ("<", ">", "<=", ">=", "==", "!=", "&&", "||") for t in st) or \
            any(t.text in ("empty", "size", "length", "strlen") for t in st)
        if has_cmp:
            self.validated |= (text_ids & self.tainted)
        if any(t.text in ("==", "!=", "!") for t in st) or True:
            self.zero_checked |= text_ids

    # -- sinks --------------------------------------------------------------------------
    def _sinks(self, st: List[Token]):
        for c in find_calls(st):
            nm = c.name
            a = c.args
            tok = st[c.start]
            # --- command execution
            if nm in _EXEC_FUNCS and a:
                tainted = self.unvalidated(a[0]) if True else set()
                lit = self.is_literal(a[0])
                if tainted:
                    self.emit("GSC-CMD-001", tok, "Critical", "Command Injection",
                              f"{nm}() runs a command built from external input ({', '.join(sorted(tainted))}).",
                              "Never pass user input to a shell. Use execve-style APIs with an argument "
                              "vector and a strict allow-list.", (78,))
                elif lit:
                    self.emit("GSC-CMD-002", tok, "Medium", "Shell Execution",
                              f"{nm}() launches a shell command; a constant string is safe today but fragile.",
                              "Prefer library APIs over spawning a shell.", (78,), "Medium")
                else:
                    self.emit("GSC-CMD-003", tok, "High", "Command Injection",
                              f"{nm}() executes a non-constant command string.",
                              "Avoid shell execution. Use exec-style APIs with a fixed argument vector.", (78,))
            # --- format strings
            if nm in _PRINTF_FAMILY and len(a) > _PRINTF_FAMILY[nm]:
                fmt = a[_PRINTF_FAMILY[nm]]
                if fmt and not self.is_literal(fmt) and not (fmt[0].kind == IDENT and fmt[0].text in
                                                            ("L", "u8")):
                    tainted = self.unvalidated(fmt)
                    only_fmt = len(a) == _PRINTF_FAMILY[nm] + 1
                    if tainted:
                        self.emit("GSC-FMT-001", tok, "High", "Format String Vulnerability",
                                  f"{nm}() uses an externally controlled format string ({', '.join(sorted(tainted))}).",
                                  f"Use {nm}(\"%s\", data) - never pass user data as the format.", (134,))
                    elif only_fmt:
                        self.emit("GSC-FMT-002", tok, "High", "Format String Vulnerability",
                                  f"{nm}() is given a non-literal format string and no arguments.",
                                  f"Use {nm}(\"%s\", text).", (134,), "Medium")
            # --- strcpy family
            if nm in ("strcpy", "stpcpy", "wcscpy", "strcat", "wcscat") and len(a) >= 2:
                self._strcpy(nm, c, a, tok)
            if nm in ("sprintf", "vsprintf") and len(a) >= 2:
                dst = a[0][0].text if a[0] and a[0][0].kind == IDENT else ""
                v = self.vars.get(dst)
                fmt = a[1]
                has_s = bool(fmt and fmt[0].kind == STRING and re.search(r"%[^a-zA-Z%]*s", fmt[0].text))
                tainted = self.unvalidated([x for z in a[2:] for x in z])
                sev = "High" if tainted else "Medium"
                self.emit("GSC-BOF-003", tok, sev, "Unbounded sprintf",
                          f"{nm}() writes without a length limit" +
                          (" and formats external input." if tainted else "."),
                          "Use snprintf(dst, sizeof dst, ...) or std::string / std::format.", (120, 787),
                          "High" if tainted or has_s else "Medium")
            # --- scanf %s without width
            if nm in ("scanf", "fscanf", "sscanf") and a:
                fi = 0 if nm == "scanf" else 1
                if len(a) > fi and a[fi] and a[fi][0].kind == STRING:
                    f = a[fi][0].text
                    if re.search(r"%(?!\d)[*]?(?:[lh]*)s|%(?!\d)\[", f) and not re.search(r"%\d+(s|\[)", f):
                        self.emit("GSC-BOF-004", tok, "High", "Unbounded Input",
                                  f"{nm}() reads a string with %s and no field width.",
                                  "Add a width (e.g. %63s for a 64-byte buffer) or read into std::string.",
                                  (120,))
            # --- bounded copy / read functions with sizes
            if nm in ("memcpy", "memmove", "memset", "strncpy", "strncat", "read", "fread", "recv",
                      "fgets", "snprintf", "memccpy", "pread"):
                self._sized(nm, c, a, tok)
            # --- allocation sizes
            if nm in ("malloc", "alloca", "realloc") and a:
                szi = 0 if nm != "realloc" else 1
                if len(a) > szi:
                    self._alloc_size(nm, a[szi], tok)
            if nm == "calloc":
                pass
            # --- path traversal
            if nm in _PATH_OPENERS and _PATH_OPENERS[nm] >= 0 and a:
                tainted = self.unvalidated(a[_PATH_OPENERS[nm]])
                if tainted:
                    self.emit("GSC-PATH-001", tok, "High", "Path Traversal",
                              f"{nm}() opens a path derived from external input ({', '.join(sorted(tainted))}).",
                              "Canonicalise the path (realpath/std::filesystem::weakly_canonical) and verify "
                              "it stays inside an allowed directory.", (22,))
            # --- permissions
            if nm in ("chmod", "fchmod") and len(a) >= 2 and a[1] and a[1][0].kind == NUMBER \
                    and re.match(r"^0*(777|666|776|766)$", a[1][0].text.lstrip("0") or "0"):
                self.emit("GSC-PERM-001", tok, "Medium", "Insecure File Permissions",
                          "The file is made world-writable.",
                          "Use the least privilege needed (e.g. 0600 / 0644).", (732,))
            if nm == "umask" and a and a[0] and a[0][0].text in ("0", "000", "0000"):
                self.emit("GSC-PERM-002", tok, "Medium", "Insecure File Permissions",
                          "umask(0) lets newly created files be world-writable.",
                          "Use a restrictive umask such as 077.", (732,))
            # --- atoi family
            if nm in ("atoi", "atol", "atoll", "atof") and a and self.unvalidated(a[0]):
                self.emit("GSC-INT-001", tok, "Low", "Unchecked Numeric Conversion",
                          f"{nm}() has no error reporting and is fed external input.",
                          "Use strtol/std::from_chars/std::stoi with range and error checks.", (20, 190), "Medium")
            # --- random numbers
            if nm == "rand" and self._sensitive_context(st):
                self.emit("GSC-RNG-001", tok, "High", "Weak Randomness",
                          "rand() is not cryptographically secure and is used for a secret/token.",
                          "Use std::random_device / getrandom() / a CSPRNG.", (338,))
            if nm == "srand" and a and any(x.text in ("time", "clock") for x in a[0]) \
                    and self._sensitive_context(st):
                self.emit("GSC-RNG-002", tok, "High", "Predictable PRNG Seed",
                          "The PRNG is seeded from the clock in a security-sensitive context.",
                          "Seed from std::random_device or use a CSPRNG.", (337,))
            # --- sizeof(pointer) used as a size
            if nm in ("memset", "memcpy", "strncpy", "strncat", "fgets", "snprintf", "read", "fread"):
                for arg in a:
                    for k, x in enumerate(arg):
                        if x.text == "sizeof" and k + 2 < len(arg):
                            nm_tok = [y for y in arg[k + 1:] if y.kind == IDENT]
                            if nm_tok:
                                v = self.vars.get(nm_tok[0].text)
                                if v and v.is_ptr and not v.is_array and len(arg) <= k + 4:
                                    self.emit("GSC-SIZEOF-001", tok, "Medium", "sizeof() on a Pointer",
                                              f"sizeof({v.name}) is the pointer size, not the buffer size.",
                                              "Pass the real buffer length explicitly.", (467,))
        # random engines: flag *predictable seeding* in a security-sensitive context
        # (time/clock/constant/default seed).  Seeding from std::random_device is accepted.
        for k, x in enumerate(st):
            if x.kind == IDENT and x.text == "random_device":
                for y in st[k + 1:k + 3]:
                    if y.kind == IDENT:
                        self.rd_vars.add(y.text)
        for k, x in enumerate(st):
            if x.kind == IDENT and x.text in _RNG_ENGINES and self._sensitive_context(st):
                ids = self.idents(st)
                if "random_device" in ids or (ids & self.rd_vars):
                    continue
                self.emit("GSC-RNG-003", x, "High", "Predictable PRNG Seed",
                          f"{x.text} is a non-cryptographic PRNG seeded predictably (clock, constant or "
                          "default seed) for a secret/token.",
                          "Use std::random_device / getrandom() or a CSPRNG for secrets.", (337, 338))
        # ifstream f(path) / f.open(path)
        for c in find_calls(st):
            prev = st[c.start - 1].text if c.start >= 1 else ""
            if (prev in ("ifstream", "ofstream", "fstream") or (c.name == "open" and prev in (".", "->"))) \
                    and c.args and c.args[0]:
                tainted = self.unvalidated(c.args[0])
                if tainted:
                    self.emit("GSC-PATH-001", st[c.start], "High", "Path Traversal",
                              f"A file stream is opened with a path from external input ({', '.join(sorted(tainted))}).",
                              "Canonicalise the path and verify it stays inside an allowed directory.", (22,))
        # unbounded counter write:  buf[n++] = c   with n never compared to a limit
        for k, x in enumerate(st):
            if x.kind == IDENT and k + 4 < len(st) and st[k + 1].text == "[" and st[k + 2].kind == IDENT \
                    and st[k + 3].text == "++" and st[k + 4].text == "]":
                v = self.vars.get(x.text)
                if v and v.is_array and v.size and st[k + 2].text not in self.bounded:
                    self.emit("GSC-IDX-004", x, "High", "Unbounded Buffer Write",
                              f"'{x.text}[{st[k + 2].text}++]' writes into a {v.size}-element array and "
                              f"'{st[k + 2].text}' is never compared with a limit.",
                              f"Stop when {st[k + 2].text} reaches {v.size - 1}, or use std::string/vector.",
                              (787, 120, 129), "Medium")
        # cin >> char array
        for k, x in enumerate(st):
            if x.text == ">>" and k + 1 < len(st) and st[k + 1].kind == IDENT:
                head_ok = any(y.kind == IDENT and y.text in self.streams for y in st[:k])
                v = self.vars.get(st[k + 1].text)
                nxt = st[k + 2].text if k + 2 < len(st) else ";"
                bounded = any(y.text in ("setw", "width") for y in st[:k + 1])
                if head_ok and v and v.is_array and v.elem in ("char", "wchar_t") and nxt in (">>", ";") and not bounded:
                    self.emit("GSC-BOF-005", x, "High", "Buffer Overflow",
                              f"'cin >> {v.name}' extracts an unbounded string into a fixed char array"
                              + (f" of {v.size} bytes." if v.size else "."),
                              "Use std::string, or std::cin >> std::setw(sizeof buf) >> buf.", (120, 787))
        # cin.getline(buf, N) with N larger than buf
        for c in find_calls(st):
            if c.name in ("getline", "get") and len(c.args) >= 2:
                idx = st[c.start - 2].text if c.start >= 2 else ""
                if idx in self.streams and c.args[0] and c.args[0][0].kind == IDENT:
                    v = self.vars.get(c.args[0][0].text)
                    n = self.int_value(c.args[1]) if c.args[1] else None
                    if v and v.size and n is not None and n > v.size:
                        self.emit("GSC-BOF-006", st[c.start], "Critical", "Buffer Overflow",
                                  f"getline() may write {n} bytes into '{v.name}' which holds {v.size}.",
                                  "Pass sizeof(buffer) as the limit.", (120, 787))
        self._indexing(st)
        self._division(st)
        self._weak_cred(st)

    def _sensitive_context(self, st: List[Token]) -> bool:
        ids = " ".join(t.text for t in st)
        if _SENS.search(ids):
            return True
        # function name itself
        return bool(_SENS.search(self.name))

    def _weak_cred(self, st: List[Token]):
        # NAME = "literal"   /  NAME("literal")  /  NAME{"literal"}
        for k, t in enumerate(st):
            if t.kind != IDENT or not _CRED_NAME.match(t.text) or _CRED_SKIP.search(t.text):
                continue
            if t.text.lower() in ("token",) and False:
                continue
            j = k + 1
            if j < len(st) and st[j].text in ("=", "(", "{") and j + 1 < len(st) and st[j + 1].kind == STRING:
                lit = st[j + 1].text
                body = re.sub(r'^(?:u8|u|U|L)?"|"$', "", lit)
                if len(body) >= 3 and body.lower() not in ("", "password", "enter password", "none"):
                    self.emit("GSC-CRED-001", t, "High", "Hard-coded Credentials",
                              f"'{t.text}' is initialised with a string literal.",
                              "Load secrets from the environment, a vault, or protected configuration - "
                              "never from source.", (798,), "Medium")

    def _strcpy(self, nm, c, a, tok):
        dst_t, src = a[0], a[1]
        dst = dst_t[0].text if dst_t and dst_t[0].kind == IDENT else ""
        v = self.vars.get(dst)
        lit = self.literal_len(src)
        if lit is None and len(src) == 1 and src[0].kind == IDENT and src[0].text in self.sc.str_consts:
            lit = self.sc.str_consts[src[0].text]
        cat = nm.endswith("cat")
        tainted = self.unvalidated(src)
        if v and v.is_array and v.size and lit is not None and not cat:
            if lit + 1 > v.size:
                self.emit("GSC-BOF-002", tok, "Critical", "Buffer Overflow",
                          f"{nm}() copies {lit + 1} bytes (including NUL) into '{dst}' which holds {v.size}.",
                          "Enlarge the buffer or use snprintf / std::string.", (120, 787))
            return                      # literal that fits: provably safe
        if v and v.is_array and v.size and lit is not None and cat:
            self.emit("GSC-BOF-002", tok, "Medium", "Unsafe String Function",
                      f"{nm}() appends {lit} bytes to '{dst}' ({v.size} bytes) without checking remaining space.",
                      "Use strncat with the remaining length, snprintf or std::string.", (120,), "Medium")
            return
        if tainted:
            self.emit("GSC-BOF-002", tok, "High", "Buffer Overflow",
                      f"{nm}() copies external input ({', '.join(sorted(tainted))}) with no length check.",
                      "Check the length first, or use snprintf / std::string.", (120, 787))
        elif lit is None:
            self.emit("GSC-BOF-002", tok, "Medium", "Unsafe String Function",
                      f"{nm}() has no bounds control; the source length is not known at compile time.",
                      "Use bounded alternatives (snprintf, strlcpy) or std::string.", (120, 676), "Medium")

    def _sized(self, nm, c, a, tok):
        # (dst_index, size_index)
        spec = {"memcpy": (0, 2), "memmove": (0, 2), "memset": (0, 2), "strncpy": (0, 2),
                "strncat": (0, 2), "read": (1, 2), "fread": (0, None), "recv": (1, 2),
                "fgets": (0, 1), "snprintf": (0, 1), "memccpy": (0, 3), "pread": (1, 2)}[nm]
        di, si = spec
        if nm == "fread" and len(a) >= 3:
            sz = self._mul_value(a[1], a[2])
            size_toks = a[1] + a[2]
        elif si is not None and len(a) > si:
            sz = self.int_value(a[si])
            size_toks = a[si]
        else:
            return
        if len(a) <= di or not a[di]:
            return
        dst = a[di][0].text if a[di][0].kind == IDENT else ""
        v = self.vars.get(dst)
        if v and v.is_array and v.size is not None and sz is not None:
            esz = {"char": 1, "short": 2, "int": 4, "long": 8, "float": 4, "double": 8, "bool": 1,
                   "uint8_t": 1, "wchar_t": 4}.get(v.elem, 1)
            cap = v.size * esz
            if sz > cap:
                self.emit("GSC-BOF-007", tok, "Critical", "Buffer Overflow",
                          f"{nm}() may write {sz} bytes into '{dst}' which holds {cap}.",
                          "Use sizeof(destination) as the limit.", (120, 787))
                return
        tainted = self.unvalidated(size_toks) if sz is None else set()
        if tainted and nm not in ("fgets", "snprintf", "memset"):
            self.emit("GSC-BOF-008", tok, "High", "Buffer Overflow",
                      f"{nm}() uses a length derived from external input ({', '.join(sorted(tainted))}) "
                      "without validating it.",
                      "Clamp the length to the destination size before copying.", (119, 129))
        if nm == "strncpy" and v and v.is_array:
            # NUL termination
            terminated = False
            for t2 in self.toks:
                pass
            if not self._nul_terminated(dst, tok.line):
                self.emit("GSC-STR-001", tok, "Medium", "Missing NUL Terminator",
                          f"strncpy() does not NUL-terminate '{dst}' when the source is as long as the limit.",
                          f"Set {dst}[sizeof {dst} - 1] = '\\0' after the copy, or use snprintf.", (170,),
                          "Medium")

    def _nul_terminated(self, name: str, from_line: int) -> bool:
        toks = self.toks
        for i, t in enumerate(toks):
            if t.kind == IDENT and t.text == name and t.line >= from_line and i + 1 < len(toks) \
                    and toks[i + 1].text == "[":
                j = i
                while j < len(toks) and toks[j].text != "=" and toks[j].text != ";":
                    j += 1
                if j + 1 < len(toks) and toks[j].text == "=" and toks[j + 1].text in ("0", "'\\0'"):
                    return True
        return False

    def _mul_value(self, a, b):
        x, y = self.int_value(a), self.int_value(b)
        return x * y if x is not None and y is not None else None

    def _alloc_size(self, nm, size_toks, tok):
        if len(size_toks) == 1 and size_toks[0].kind == IDENT and size_toks[0].text in self.size_calc:
            size_toks = self.size_calc[size_toks[0].text]       # resolve 'size_t n = a * b; malloc(n)'
        ops = [t for t in size_toks if t.text in ("*", "+", "<<")]
        ids = self.idents(size_toks) - {"sizeof"} - set(_TYPE_WORDS)
        nonconst = {i for i in ids if i not in self.sc.consts}
        tainted = self.unvalidated(size_toks)
        if tainted and ops:
            self.emit("GSC-ALLOC-001", tok, "High", "Integer Overflow in Allocation",
                      f"{nm}() size is computed from external input ({', '.join(sorted(tainted))}) with "
                      "arithmetic that can wrap.",
                      "Validate operands and use checked multiplication (__builtin_mul_overflow) or calloc.",
                      (190, 789))
        elif tainted:
            self.emit("GSC-ALLOC-002", tok, "Medium", "Uncontrolled Allocation Size",
                      f"{nm}() size comes straight from external input ({', '.join(sorted(tainted))}).",
                      "Enforce an upper bound before allocating.", (789, 770))
        elif ops and any(t.text in ("*", "<<") for t in ops) and len(nonconst) >= 1:
            self.emit("GSC-ALLOC-003", tok, "Medium", "Integer Overflow in Allocation",
                      f"{nm}() size is computed by multiplying a runtime value; the product can wrap "
                      "before allocation.",
                      "Use calloc(n, size) or checked multiplication.", (190, 789), "Medium")
        # malloc(strlen(x)) off-by-one
        s = [t.text for t in size_toks]
        if "strlen" in s and "+" not in s:
            self.emit("GSC-ALLOC-004", tok, "High", "Off-by-one Allocation",
                      f"{nm}(strlen(...)) leaves no room for the terminating NUL.",
                      "Allocate strlen(x) + 1 bytes.", (131, 193))

    def _indexing(self, st: List[Token]):
        for k, t in enumerate(st):
            if t.kind != IDENT or k + 1 >= len(st) or st[k + 1].text != "[":
                continue
            if t.text in _TYPE_WORDS or (k >= 1 and st[k - 1].text == "new"):
                continue                                  # 'new int[64]' is an allocation
            # skip declarations
            if k >= 1 and st[k - 1].kind == IDENT and st[k - 1].text not in _CONTROL \
                    and st[0].kind == IDENT and st[0].text in _TYPE_WORDS | {"unsigned"}:
                continue
            depth = 0
            m = k + 1
            expr: List[Token] = []
            while m < len(st):
                if st[m].text == "[":
                    depth += 1
                    if depth == 1:
                        m += 1
                        continue
                elif st[m].text == "]":
                    depth -= 1
                    if depth == 0:
                        break
                expr.append(st[m])
                m += 1
            if not expr:
                continue
            v = self.vars.get(t.text)
            val = self.int_value(expr)
            if v and v.is_array and v.size is not None and val is not None:
                if val >= v.size or val < 0:
                    self.emit("GSC-IDX-001", t, "Critical", "Buffer Overflow",
                              f"Index {val} is outside '{t.text}' which has {v.size} elements.",
                              "Keep indices in [0, size); prefer std::array::at() / std::vector::at().",
                              (787, 125))
                    continue
            tainted = self.unvalidated(expr)
            if tainted and not (v and v.size and val is not None):
                self.emit("GSC-IDX-002", t, "High", "Unvalidated Array Index",
                          f"'{t.text}[...]' is indexed by external input ({', '.join(sorted(tainted))}) "
                          "with no bounds check.",
                          "Check 0 <= index < size before indexing, or use .at().", (129, 787))

    def _division(self, st: List[Token]):
        for k, t in enumerate(st):
            if t.text in ("/", "%", "/=", "%=") and k + 1 < len(st) and st[k + 1].kind == IDENT:
                d = st[k + 1].text
                if d in self.tainted and d not in self.zero_checked:
                    self.emit("GSC-DIV-001", t, "Medium", "Division By Zero",
                              f"Division by '{d}' which comes from external input and is not checked for zero.",
                              f"Guard with if ({d} != 0) before dividing.", (369,), "Medium")

    # -- allocation / free lifecycle -----------------------------------------------------
    def _lifecycle(self, st: List[Token]):
        if not st:
            return
        text = [t.text for t in st]
        # p = malloc(...) / new T / new T[n]
        eq = next((i for i, t in enumerate(st) if t.text == "=" and i > 0), None)
        if eq is not None:
            lhs = [x for x in st[:eq] if x.kind == IDENT and x.text not in _TYPE_WORDS]
            rhs = st[eq + 1:]
            kind = None
            for r_i, x in enumerate(rhs):
                if x.kind == IDENT and x.text in _ALLOC and r_i + 1 < len(rhs) and rhs[r_i + 1].text == "(":
                    kind = "malloc"
                    break
                if x.kind == IDENT and x.text == "new":
                    kind = "new[]" if any(y.text == "[" for y in rhs[r_i:]) else "new"
                    if "nothrow" in [y.text for y in rhs]:
                        kind = "malloc"
                    break
            if lhs and kind:
                name = lhs[-1].text
                known_local = name in self.vars
                is_decl = len(lhs) >= 2 or any(x.text == "*" for x in st[:eq])
                v = self.vars.get(name) or _Var(name, is_ptr=True)
                v.alloc, v.alloc_line, v.alloc_toks, v.checked, v.freed_line, v.escaped = \
                    kind, st[0].line, st, False, 0, False
                v.alloc_stmt = self.stmt_no
                if not known_local and not is_decl:
                    v.escaped = True            # member / global pointer: its owner releases it
                v.is_ptr = True
                self.vars[name] = v
            elif lhs and not kind:
                # reassignment: pointer 'p = other' or 'p = nullptr' clears freed state; 'q = p' escapes p
                # (but '*p = x', 'p[i] = x', 'p->m = x' are writes THROUGH p, not reassignments)
                name = lhs[-1].text
                v = self.vars.get(name)
                through = st[0].text == "*" or any(y.text in ("[", "->", ".") for y in st[:eq])
                if v and not through:
                    v.freed_line = 0
                for x in rhs:
                    if x.kind == IDENT and x.text in self.vars and self.vars[x.text].alloc:
                        self.vars[x.text].escaped = True
                if v and len(lhs) >= 1 and (len(st) > eq + 1) and any(
                        tt.text == name for tt in st[:eq]) and v.alloc and False:
                    pass
            # member / global store: obj->p = ptr, this->p = ptr
            for x in rhs:
                if x.kind == IDENT and x.text in self.vars and self.vars[x.text].alloc and \
                        any(y.text in ("->", ".") for y in st[:eq]):
                    self.vars[x.text].escaped = True
        # NULL check
        if st[0].text in ("if", "while", "assert") or "?" in text:
            for x in st:
                if x.kind == IDENT and x.text in self.vars:
                    self.vars[x.text].checked = True
        # escapes: return p; passed as call argument; pushed
        if st[0].text == "return" or st[0].text == "throw":
            for x in st:
                if x.kind == IDENT and x.text in self.vars:
                    self.vars[x.text].escaped = True
        for c in find_calls(st):
            if c.name in _CONTROL:
                continue
            for arg in c.args:
                for x in arg:
                    if x.kind == IDENT and x.text in self.vars and self.vars[x.text].alloc \
                            and c.name not in ("free", "strcpy", "strncpy", "memcpy", "memset", "printf",
                                               "puts", "strlen", "strcmp", "fprintf", "sprintf", "snprintf",
                                               "strcat", "memmove", "fgets", "scanf", "fread", "fwrite",
                                               "read", "write", "sizeof", "getline", "cin", "cout",
                                               "strncmp", "strncat", "memcmp") \
                            and not (c.name in _ALLOC):
                        self.vars[x.text].escaped = True
        # delete / free
        if st[0].text == "delete":
            arr = len(st) > 1 and st[1].text == "["
            nm_tok = [x for x in st if x.kind == IDENT and x.text != "delete"]
            if nm_tok:
                self._release(nm_tok[0], "delete[]" if arr else "delete")
        for c in find_calls(st):
            if c.name == "free" and c.args and c.args[0] and c.args[0][-1].kind == IDENT:
                self._release(st[c.start], "free", c.args[0][-1].text)
        # pointer nulling after release:  p = nullptr / NULL / 0
        if eq is not None and len(st) > eq + 1:
            rhs_txt = [t.text for t in st[eq + 1:]]
            lhs_ids = [x for x in st[:eq] if x.kind == IDENT]
            if lhs_ids and rhs_txt and rhs_txt[0] in ("nullptr", "NULL", "0") and len(rhs_txt) <= 2:
                v = self.vars.get(lhs_ids[-1].text)
                if v:
                    v.freed_line = 0
        # use after free
        for k, x in enumerate(st):
            if x.kind == IDENT and x.text in self.vars and self.vars[x.text].freed_line:
                v = self.vars[x.text]
                if v.freed_stmt == self.stmt_no:
                    continue
                used = (k + 1 < len(st) and st[k + 1].text in ("->", "[")) or \
                       (k >= 1 and st[k - 1].text == "*")
                call_arg = any(c.name not in ("free",) and any(y is x for arg in c.args for y in arg)
                               for c in find_calls(st))
                is_assign_target = k + 1 < len(st) and st[k + 1].text == "=" and k == 0
                if (used or call_arg) and not is_assign_target and st[0].text != "delete":
                    self.emit("GSC-MEM-004", x, "High", "Use After Free",
                              f"'{x.text}' is used after it was released at line {v.freed_line}.",
                              "Do not touch a pointer after delete/free; set it to nullptr or use "
                              "std::unique_ptr.", (416,))
                    v.freed_line = 0

    def _release(self, tok, how, name=None):
        name = name or tok.text
        v = self.vars.get(name)
        if not v:
            return
        if v.freed_line and v.freed_stmt != self.stmt_no:
            self.emit("GSC-MEM-003", tok, "High", "Double Free",
                      f"'{name}' is released again (first released at line {v.freed_line}).",
                      "Set the pointer to nullptr after releasing it, or use std::unique_ptr.", (415,))
        if v.alloc:
            ok = {"malloc": "free", "new": "delete", "new[]": "delete[]"}[v.alloc]
            if how != ok:
                self.emit("GSC-MEM-002", tok, "High", "Mismatched Memory Management",
                          f"'{name}' was allocated with {v.alloc} (line {v.alloc_line}) but released "
                          f"with {how}.",
                          f"Release memory with the matching routine ({ok}); better, use RAII containers.",
                          (762, 590))
        v.freed_line = tok.line
        v.freed_stmt = self.stmt_no
        v.freed_by = how
        v.escaped = True if False else v.escaped

    def _unchecked_malloc(self, st: List[Token]):
        # use of a malloc'd pointer before any NULL check
        for k, x in enumerate(st):
            if x.kind == IDENT and x.text in self.vars:
                v = self.vars[x.text]
                if v.alloc == "malloc" and not v.checked and v.alloc_stmt != self.stmt_no:
                    use = (k + 1 < len(st) and st[k + 1].text in ("->", "[")) or (k and st[k - 1].text == "*")
                    callarg = any(c.name in ("strcpy", "memcpy", "memset", "strncpy", "sprintf", "snprintf",
                                             "strcat", "fgets", "fread", "read", "memmove", "scanf")
                                  and c.args and c.args[0] and c.args[0][0] is x
                                  for c in find_calls(st))
                    if (use or callarg) and st[0].text not in ("if", "while"):
                        self.emit("GSC-MEM-005", x, "Medium", "Unchecked Allocation",
                                  f"'{x.text}' (allocated at line {v.alloc_line}) is used without a NULL check.",
                                  "Test the result of malloc/calloc/realloc before dereferencing it.", (476,),
                                  "Medium")
                        v.checked = True

    def _loops(self, st: List[Token]):
        # for (T i = a; i <= LIMIT; ...) { ... arr[i] ... } with LIMIT == size(arr)
        if not st or st[0].text != "for":
            return
        cond = []
        semis = 0
        depth = 0
        for x in st[1:]:
            if x.text == "(":
                depth += 1
                continue
            if x.text == ")":
                depth -= 1
                if depth == 0:
                    break
            if x.text == ";" and depth == 1:
                semis += 1
                continue
            if semis == 1:
                cond.append(x)
        if len(cond) >= 3 and cond[0].kind == IDENT and cond[1].text == "<=":
            idx = cond[0].text
            lim = self.int_value(cond[2:])
            sz_of = None
            if lim is None:
                # i <= sizeof(a)/sizeof(a[0])
                txt = [t.text for t in cond[2:]]
                if "sizeof" in txt:
                    nm_t = [t.text for t in cond[2:] if t.kind == IDENT and t.text != "sizeof"]
                    if nm_t and nm_t[0] in self.vars:
                        sz_of = self.vars[nm_t[0]]
            self._loop_idx, self._loop_lim, self._loop_sz = idx, lim, sz_of
            self._loop_line = st[0].line
        else:
            self._loop_idx = None

    def _loop_body_check(self, st: List[Token]):
        idx = getattr(self, "_loop_idx", None)
        if not idx:
            return
        for k, x in enumerate(st):
            if x.kind == IDENT and k + 3 < len(st) and st[k + 1].text == "[" and st[k + 2].text == idx \
                    and st[k + 3].text == "]":
                v = self.vars.get(x.text)
                lim = getattr(self, "_loop_lim", None)
                if v and v.is_array and v.size is not None and lim is not None and lim >= v.size:
                    self.emit("GSC-IDX-003", self._loop_line, "High", "Off-by-one Error",
                              f"Loop runs while {idx} <= {lim} but '{x.text}' has only {v.size} elements "
                              f"(valid indices 0..{v.size - 1}).",
                              f"Use {idx} < {v.size}.", (193, 787))
                    self._loop_idx = None
                    return

    # -- driver -------------------------------------------------------------------------------
    def run(self):
        self._params()
        stmts = split_statements(self.toks)
        for st0 in stmts:
            if st0 and st0[0].text in ("if", "while", "for", "do", "assert", "switch") and any(
                    t.text in ("<", "<=", ">", ">=", "==") for t in st0):
                self.bounded |= {t.text for t in st0 if t.kind == IDENT}
        self._loop_idx = None
        for st in stmts:
            if len(st) == 1 and st[0].text in ("{", "}"):
                continue
            if st[0].kind == PREPROC:
                continue
            self.stmt_no += 1
            self._declarations(st)
            self._taint_sources(st)
            self._validation(st)
            self._sinks(st)
            self._lifecycle(st)
            self._unchecked_malloc(st)
            self._loops(st)
            self._loop_body_check(st)
        # leaks: allocated, never released, never escaped, never returned
        for name, v in self.vars.items():
            if v.alloc and not v.freed_line and not v.escaped:
                self.emit("GSC-MEM-001", v.alloc_line, "Medium", "Potential Memory Leak",
                          f"'{name}' is allocated with {v.alloc} but never released in {self.name}().",
                          "Release it on every path, or use std::unique_ptr / std::vector.", (401,), "Medium")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _scan_source_findings(source_path: str) -> List[SecurityFinding]:
    path = Path(source_path)
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    return list(analyze_source(text, str(path), []))


def analyze_source(source: str, path: str = "<source>", compiler_errors=None) -> List[SecurityFinding]:
    """Analyse source *text* (no re-reading of the file) and merge with compiler diagnostics."""
    findings: List[SecurityFinding] = []
    for err in compiler_errors or []:
        findings.extend(_diagnostic_findings(err))
    digest = hashlib.sha1(source.encode("utf-8", "ignore")).hexdigest()
    findings.extend(_scan_cached(digest, path, source))
    return _dedupe_findings(findings)


def analyze(source_path: str, compiler_errors=None) -> List[SecurityFinding]:
    findings: List[SecurityFinding] = []
    for error in compiler_errors or []:
        findings.extend(_diagnostic_findings(error))
    findings.extend(_scan_source_findings(source_path))
    return _dedupe_findings(findings)


def _dedupe_findings(findings: List[SecurityFinding]) -> List[SecurityFinding]:
    seen: Set[Tuple] = set()
    uniq: List[SecurityFinding] = []
    for f in findings:
        key = (f.file, f.line, f.column, f.vulnerability_type, f.description, f.source)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)
    # a compiler finding and a static finding on the same line sharing a CWE are the same bug
    comp = [(f.file, f.line, set(f.cwe)) for f in uniq if f.source == "compiler_diagnostic" and f.cwe]
    out: List[SecurityFinding] = []
    for f in uniq:
        if f.source == "static_scan" and f.cwe and any(
                cf == f.file and cl == f.line and (cc & set(f.cwe)) for cf, cl, cc in comp):
            # keep the static one only if it carries a higher severity (definite overflow etc.)
            better = any(c.file == f.file and c.line == f.line and set(c.cwe) & set(f.cwe)
                         and _SEVERITY_ORDER[c.severity] > _SEVERITY_ORDER[f.severity]
                         for c in uniq if c.source == "compiler_diagnostic")
            if not better:
                continue
        out.append(f)
    out.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.file or "",
                            f.line if f.line is not None else 10 ** 9,
                            f.column if f.column is not None else 10 ** 9, f.vulnerability_type))
    return out


def risk_score(findings: List[SecurityFinding]) -> int:
    return int(round(sum(_SEVERITY_WEIGHT[f.severity] * _CONF_FACTOR.get(f.confidence, 1.0)
                         for f in findings)))


def _severity_counts(findings: List[SecurityFinding]) -> Dict[str, int]:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _risk_label(score: int) -> str:
    if score == 0:
        return "Clean"
    if score <= 10:
        return "Low Risk"
    if score <= 30:
        return "Moderate"
    return "High Risk"


def format_security_report(findings: List[SecurityFinding]) -> str:
    findings = _dedupe_findings(list(findings))
    counts = _severity_counts(findings)
    score = risk_score(findings)
    lines = [f"{counts['Critical']} critical, {counts['High']} high, {counts['Medium']} medium, "
             f"{counts['Low']} low findings", ""]
    for severity in ("Critical", "High", "Medium", "Low"):
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        lines.append(severity.upper())
        for f in group:
            location = f.file or ""
            if f.line is not None:
                location += f":{f.line}"
            cwe = (" " + "/".join(f"CWE-{c}" for c in f.cwe)) if f.cwe else ""
            conf = "" if f.confidence == "High" else f" ({f.confidence.lower()} confidence)"
            lines.append(f"[{f.severity.upper()}] {f.vulnerability_type}{cwe} - {location}{conf}")
            lines.append(f"  Description: {f.description}")
            lines.append(f"  Recommendation: {f.recommendation}")
            lines.append("")
    lines.append(f"Risk score: {score} ({_risk_label(score)})")
    return "\n".join(lines).strip() + "\n"
