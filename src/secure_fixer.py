"""
secure_fixer.py
---------------
Verified automatic hardening of C++ source.

Every fix is a small, token-precise edit with a known-safe replacement:

  gets(b)               -> fgets(b, sizeof(b), stdin)           (CWE-242/120)
  strcpy(d, s)          -> snprintf(d, sizeof(d), "%s", s)      (CWE-120)
  strcat(d, s)          -> strncat(d, s, sizeof(d)-strlen(d)-1) (CWE-120)
  sprintf(d, ...)       -> snprintf(d, sizeof(d), ...)          (CWE-120)
  printf(x)             -> printf("%s", x)                      (CWE-134)
  scanf("%s", b)        -> scanf("%<N-1>s", b)                  (CWE-120)
  cin >> b              -> cin >> std::setw(N) >> b             (CWE-120)
  delete p / free(p)    -> the routine matching the allocation  (CWE-762)
  double delete/free    -> p = nullptr; after the first release (CWE-415)
  strncpy(d, s, n)      -> + d[sizeof(d)-1] = '\\0';            (CWE-170)
  for (...; i <= N; ..) -> i < N when N == array size           (CWE-193)
  malloc(strlen(s))     -> malloc(strlen(s) + 1)                (CWE-131)
  chmod(.., 0777)       -> 0755  (0666 -> 0644)                 (CWE-732)

A fix is **kept only if verified**: the patched program must still compile
without errors and the finding it targets must have disappeared from a
re-analysis.  Anything that fails verification is reverted and reported.
Nothing is ever applied silently to the user's file - the CLI writes a
``*.hardened.cpp`` copy and prints a diff unless ``--in-place`` is given.
"""

from __future__ import annotations

import difflib
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from lexer import Token, tokenize, find_calls, IDENT, NUMBER, STRING, PUNCT, PREPROC
from security_analyzer import (_Scanner, _Eval, SecurityFinding, analyze_source)


@dataclass
class Edit:
    start: int
    end: int
    text: str
    rule: str
    line: int
    description: str
    needs: Tuple[str, ...] = ()


@dataclass
class Fix:
    rule: str
    line: int
    description: str
    before: str
    after: str


@dataclass
class HardenResult:
    original: str
    hardened: str
    applied: List[Fix] = field(default_factory=list)
    skipped: List[Tuple[str, int, str]] = field(default_factory=list)   # (rule, line, reason)
    remaining: List[SecurityFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def changed(self) -> bool:
        return self.original != self.hardened


_HEADERS = {"cstdio": ("snprintf", "fgets", "printf"), "cstring": ("strncat", "strlen"),
            "iomanip": ("setw",)}


def _array_decls(tokens: List[Token], consts: Dict[str, int]):
    """name -> list of (token_index, element_count, element_type)."""
    out: Dict[str, List[Tuple[int, int, str]]] = {}
    ev = _Eval(consts)
    n = len(tokens)
    for i in range(1, n - 3):
        t = tokens[i]
        if t.kind != IDENT or tokens[i + 1].text != "[" or tokens[i - 1].kind != IDENT:
            continue
        j = i + 2
        expr = []
        while j < n and tokens[j].text != "]":
            expr.append(tokens[j])
            j += 1
        if j + 1 >= n or tokens[j + 1].text not in (";", "=", ",", "{"):
            continue
        size = ev.value(expr) if expr else None
        if size is None:
            continue
        k = i - 1
        elem = ""
        while k >= 0 and tokens[k].kind == IDENT and tokens[k].text not in ("return", "else", "delete"):
            elem = tokens[k].text if tokens[k].text in ("char", "wchar_t", "int", "long", "short",
                                                         "float", "double") else elem
            k -= 1
        out.setdefault(t.text, []).append((i, size, elem))
    return out


def _size_at(decls, name: str, idx: int) -> Optional[Tuple[int, str]]:
    best = None
    for (i, size, elem) in decls.get(name, []):
        if i < idx and (best is None or i > best[0]):
            best = (i, size, elem)
    return (best[1], best[2]) if best else None


def _src(source: str, toks: List[Token]) -> str:
    if not toks:
        return ""
    return source[toks[0].pos: toks[-1].pos + len(toks[-1].text)]


def _stmt_start_ok(tokens: List[Token], idx: int) -> bool:
    """Is tokens[idx] (the callee) at statement start, so its return value is unused?"""
    k = idx - 1
    while k >= 1 and tokens[k].text == "::" and tokens[k - 1].kind == IDENT:
        k -= 2
    return k < 0 or tokens[k].text in (";", "{", "}", ")", "else", ":")


def propose(source: str, findings: List[SecurityFinding]) -> List[Edit]:
    sc = _Scanner(source, "<fix>")
    toks = sc.tokens
    decls = _array_decls(toks, sc.consts)
    by_rule: Dict[str, set] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, set()).add(f.line)
    edits: List[Edit] = []

    def qual(c) -> str:             # keep a leading 'std::' if the user wrote it
        return "std::" if c.start >= 2 and toks[c.start - 1].text == "::" and \
            toks[c.start - 2].text == "std" else ""

    def start_pos(c) -> int:
        return toks[c.start - 2].pos if qual(c) else toks[c.start].pos

    def end_pos(c) -> int:
        t = toks[c.end - 1]
        return t.pos + len(t.text)

    calls = list(find_calls(toks))
    for c in calls:
        line = toks[c.start].line
        a = c.args
        q = qual(c)
        if not a:
            continue
        first = a[0][0].text if a[0] and a[0][0].kind == IDENT and len(a[0]) == 1 else None
        sz = _size_at(decls, first, c.start) if first else None
        # gets
        if c.name == "gets" and line in by_rule.get("GSC-BOF-001", ()) and first and sz \
                and len(a) == 1 and _stmt_start_ok(toks, c.start) | True:
            edits.append(Edit(start_pos(c), end_pos(c), f"{q}fgets({first}, sizeof({first}), stdin)",
                              "GSC-BOF-001", line, "gets() -> bounded fgets()", ("cstdio",)))
        # strcpy / strcat / sprintf
        elif c.name == "strcpy" and line in by_rule.get("GSC-BOF-002", ()) and first and sz and len(a) == 2 \
                and _stmt_start_ok(toks, c.start):
            edits.append(Edit(start_pos(c), end_pos(c),
                              f'{q}snprintf({first}, sizeof({first}), "%s", {_src(source, a[1])})',
                              "GSC-BOF-002", line, "strcpy() -> bounded snprintf()", ("cstdio",)))
        elif c.name == "strcat" and line in by_rule.get("GSC-BOF-002", ()) and first and sz and len(a) == 2 \
                and _stmt_start_ok(toks, c.start):
            edits.append(Edit(start_pos(c), end_pos(c),
                              f"{q}strncat({first}, {_src(source, a[1])}, sizeof({first}) - {q}strlen({first}) - 1)",
                              "GSC-BOF-002", line, "strcat() -> bounded strncat()", ("cstring",)))
        elif c.name == "sprintf" and line in by_rule.get("GSC-BOF-003", ()) and first and sz and len(a) >= 2 \
                and _stmt_start_ok(toks, c.start):
            rest = source[toks[c.start + 2].pos + len(first): end_pos(c) - 1]
            edits.append(Edit(start_pos(c), end_pos(c),
                              f"{q}snprintf({first}, sizeof({first}){rest})",
                              "GSC-BOF-003", line, "sprintf() -> bounded snprintf()", ("cstdio",)))
        # printf(x) / fprintf(f, x)
        elif c.name in ("printf", "fprintf", "sprintf", "snprintf", "syslog", "dprintf") and \
                (line in by_rule.get("GSC-FMT-001", ()) or line in by_rule.get("GSC-FMT-002", ())):
            fi = {"printf": 0, "fprintf": 1, "dprintf": 1, "syslog": 1, "sprintf": 1, "snprintf": 2}[c.name]
            if len(a) == fi + 1 and a[fi] and a[fi][0].kind != STRING:
                edits.append(Edit(a[fi][0].pos, a[fi][0].pos, '"%s", ', "GSC-FMT-002", line,
                                  "format string made constant: printf(x) -> printf(\"%s\", x)"))
        # scanf("%s", b)
        elif c.name == "scanf" and line in by_rule.get("GSC-BOF-004", ()) and len(a) == 2 and a[0] \
                and a[0][0].kind == STRING and a[1] and a[1][-1].kind == IDENT:
            nm = a[1][-1].text
            sz2 = _size_at(decls, nm, c.start)
            lit = a[0][0].text
            if sz2 and lit.count("%s") == 1 and sz2[0] >= 2:
                edits.append(Edit(a[0][0].pos, a[0][0].pos + len(lit), lit.replace("%s", f"%{sz2[0] - 1}s"),
                                  "GSC-BOF-004", line, f"scanf %s bounded to {sz2[0] - 1} chars"))
        # strncpy without NUL
        elif c.name == "strncpy" and line in by_rule.get("GSC-STR-001", ()) and first and sz and len(a) == 3:
            semi = c.end
            if semi < len(toks) and toks[semi].text == ";":
                pos = toks[semi].pos + 1
                edits.append(Edit(pos, pos, f" {first}[sizeof({first}) - 1] = '\\0';", "GSC-STR-001", line,
                                  "NUL-terminate after strncpy"))
        # chmod
        elif c.name == "chmod" and line in by_rule.get("GSC-PERM-001", ()) and len(a) == 2 and a[1] \
                and a[1][0].kind == NUMBER:
            lit = a[1][0].text
            new = {"0777": "0755", "0666": "0644", "0776": "0755", "0766": "0755"}.get(lit)
            if new:
                edits.append(Edit(a[1][0].pos, a[1][0].pos + len(lit), new, "GSC-PERM-001", line,
                                  f"world-writable {lit} -> {new}"))
        # malloc(strlen(x))
        elif c.name in ("malloc",) and line in by_rule.get("GSC-ALLOC-004", ()) and len(a) == 1:
            sl = list(find_calls(a[0], {"strlen"}))
            if sl and not any(t.text == "+" for t in a[0]):
                inner = a[0]
                endt = inner[sl[0].end - 1]
                edits.append(Edit(endt.pos + 1, endt.pos + 1, " + 1", "GSC-ALLOC-004", line,
                                  "allocate strlen()+1 bytes for the NUL"))

    # cin >> char_array
    for i, t in enumerate(toks):
        if t.text == ">>" and i + 1 < len(toks) and toks[i + 1].kind == IDENT \
                and t.line in by_rule.get("GSC-BOF-005", ()):
            sz = _size_at(decls, toks[i + 1].text, i)
            if sz and sz[1] in ("char", "wchar_t"):
                edits.append(Edit(t.pos, t.pos + 2, f">> std::setw({sz[0]}) >>", "GSC-BOF-005", t.line,
                                  "cin >> char[] bounded with setw", ("iomanip",)))

    # for (...; i <= N; ...)  with N == array size
    for i, t in enumerate(toks):
        if t.text == "for" and t.line in by_rule.get("GSC-IDX-003", ()) and toks[i + 1].text == "(":
            depth = 0
            semis = 0
            for j in range(i + 1, len(toks)):
                x = toks[j]
                if x.text == "(":
                    depth += 1
                elif x.text == ")":
                    depth -= 1
                    if depth == 0:
                        break
                elif x.text == ";" and depth == 1:
                    semis += 1
                elif x.text == "<=" and semis == 1:
                    edits.append(Edit(x.pos, x.pos + 2, "<", "GSC-IDX-003", t.line,
                                      "loop bound '<=' -> '<' (off-by-one)"))
                    break

    # release mismatches / double free
    rel_stmt = re.compile(r"")
    for f in findings:
        if f.rule_id not in ("GSC-MEM-002", "GSC-MEM-003"):
            continue
        m = re.match(r"'(\w+)'", f.description)
        if not m:
            continue
        name = m.group(1)
        releases = []   # (stmt_start_idx, kind, end_idx_of_semicolon)
        for i, t in enumerate(toks):
            if t.text == "delete" and t.kind == IDENT:
                j = i + 1
                arr = False
                if toks[j].text == "[" and toks[j + 1].text == "]":
                    arr = True
                    j += 2
                if toks[j].kind == IDENT and toks[j].text == name:
                    releases.append((i, "delete[]" if arr else "delete", j))
            elif t.text == "free" and i + 3 < len(toks) and toks[i + 1].text == "(" \
                    and toks[i + 2].text == name and toks[i + 3].text == ")":
                releases.append((i, "free", i + 3))
        alloc = None
        for i, t in enumerate(toks):
            if t.text == name and i + 1 < len(toks) and toks[i + 1].text == "=":
                kind = None
                for x in toks[i + 2:i + 12]:
                    if x.text == ";":
                        break
                    if x.text == "new":
                        kind = "new[]" if any(y.text == "[" for y in toks[i + 2:i + 12]) else "new"
                        break
                    if x.text in ("malloc", "calloc", "realloc"):
                        kind = "malloc"
                        break
                if kind:
                    alloc = kind
        if f.rule_id == "GSC-MEM-002" and alloc:
            want = {"malloc": "free", "new": "delete", "new[]": "delete[]"}[alloc]
            for (i, kind, j) in releases:
                if toks[i].line == f.line and kind != want:
                    s0, e0 = toks[i].pos, toks[j].pos + len(toks[j].text) + (1 if kind == "free" else 0)
                    repl = {"free": f"free({name})", "delete": f"delete {name}",
                            "delete[]": f"delete[] {name}"}[want]
                    edits.append(Edit(s0, e0, repl, "GSC-MEM-002", f.line,
                                      f"{kind} -> {want} (matches {alloc})",
                                      ("cstdlib",) if want == "free" else ()))
        if f.rule_id == "GSC-MEM-003" and len(releases) >= 2:
            i, kind, j = releases[0]
            k = j
            while k < len(toks) and toks[k].text != ";":
                k += 1
            if k < len(toks):
                pos = toks[k].pos + 1
                edits.append(Edit(pos, pos, f" {name} = nullptr;", "GSC-MEM-003", f.line,
                                  f"null '{name}' after first release (double free)"))
    return edits


def _apply(source: str, edits: List[Edit]) -> str:
    out = source
    for e in sorted(edits, key=lambda e: (e.start, e.end), reverse=True):
        out = out[:e.start] + e.text + out[e.end:]
    return out


def _non_overlapping(edits: List[Edit]) -> List[Edit]:
    keep: List[Edit] = []
    for e in sorted(edits, key=lambda e: (e.start, e.end)):
        if keep and e.start < keep[-1].end:
            continue
        if keep and e.start == keep[-1].start and e.end == keep[-1].end:
            continue
        keep.append(e)
    return keep


def _ensure_includes(source: str, needed: set) -> str:
    present = set(re.findall(r"#\s*include\s*<([^>]+)>", source))
    if "bits/stdc++.h" in present:
        return source
    missing = [h for h in sorted(needed) if h not in present and f"{h[1:]}.h" not in present
               and f"{h}" not in present]
    if not missing:
        return source
    inc = "".join(f"#include <{h}>\n" for h in missing)
    last = None
    for m in re.finditer(r"^[ \t]*#\s*include[^\n]*\n", source, re.M):
        last = m
    if last:
        return source[:last.end()] + inc + source[last.end():]
    return inc + source


def _compiles(source: str, base_dir: str) -> Tuple[bool, str]:
    from diagnostics import build
    d = base_dir if os.access(base_dir, os.W_OK) else tempfile.gettempdir()
    fd, tmp = tempfile.mkstemp(suffix=".cpp", prefix=".gsc_harden_", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(source)
        res = build(tmp, ["-Wall", "-I", base_dir], analysis=False, use_cache=False, link=False)
        errs = [x for x in res.diagnostics if x["type"] == "error"]
        return (not errs), (errs[0]["message"] if errs else "")
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass


def harden_source(source: str, path: str = "<source>", verify: bool = True) -> HardenResult:
    base_dir = os.path.dirname(os.path.abspath(path)) if path and path != "<source>" else os.getcwd()
    res = HardenResult(original=source, hardened=source)
    if verify:
        ok, msg = _compiles(source, base_dir)
        if not ok:
            res.error = f"The source does not compile ({msg}); fix compile errors before hardening."
            return res
    before = analyze_source(source, path)
    res.remaining = before
    edits = _non_overlapping(propose(source, before))
    if not edits:
        return res
    rule_before = Counter(f.rule_id for f in before)

    def verified(candidate_src: str, rules: set) -> Tuple[bool, str]:
        if verify:
            ok, msg = _compiles(candidate_src, base_dir)
            if not ok:
                return False, f"no longer compiles: {msg}"
        after = Counter(f.rule_id for f in analyze_source(candidate_src, path))
        for r in rules:
            # GSC-FMT-001/002 share a fix; compare family totals
            fam = [k for k in rule_before if k.rsplit("-", 1)[0] == r.rsplit("-", 1)[0] and k in rules | {r}]
            if after[r] >= rule_before[r]:
                return False, "finding still present after the edit"
        return True, ""

    # try everything at once first (fast path)...
    needs = set(h for e in edits for h in e.needs)
    candidate = _ensure_includes(_apply(source, edits), needs)
    ok, why = verified(candidate, {e.rule for e in edits})
    chosen: List[Edit] = []
    if ok:
        chosen = edits
        current = candidate
    else:
        # ...otherwise add edits one by one, keeping only the verified ones
        current = source
        for e in edits:
            trial_edits = chosen + [e]
            trial = _ensure_includes(_apply(source, trial_edits),
                                     set(h for x in trial_edits for h in x.needs))
            ok1, why1 = verified(trial, {x.rule for x in trial_edits})
            if ok1:
                chosen = trial_edits
                current = trial
            else:
                res.skipped.append((e.rule, e.line, why1))
    res.hardened = current
    for e in chosen:
        res.applied.append(Fix(e.rule, e.line, e.description,
                               source[e.start:e.end] if e.end > e.start else "",
                               e.text))
    res.remaining = analyze_source(current, path)
    return res


def unified_diff(original: str, hardened: str, path: str = "source.cpp") -> str:
    return "".join(difflib.unified_diff(original.splitlines(True), hardened.splitlines(True),
                                        fromfile=path, tofile=path + " (hardened)"))
