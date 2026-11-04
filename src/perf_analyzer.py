"""
perf_analyzer.py
----------------
Code-optimization advice, built on the shared lexer.  Findings are *advice*
(never blocking) ranked by expected impact:

  High    algorithmic: exponential recursion, O(n^2) hidden in loops
          (``strlen`` in a loop condition, ``erase(begin())``, ``find`` in a loop,
          string re-concatenation), allocation inside hot loops
  Medium  heavy objects passed by value, ``std::endl`` flushing in loops,
          unsynchronised iostreams in loop-heavy I/O programs, by-value range-for
          over heavy elements
  Low     ``push_back`` in a counted loop without ``reserve``

The compiler's own performance diagnostics (``-Wpessimizing-move``,
``-Wrange-loop-construct``, ``-Wredundant-move`` ...) are merged in via the
taxonomy ``performance`` category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple

from lexer import Token, tokenize, find_calls, split_statements, IDENT, PUNCT, PREPROC, STRING
from security_analyzer import _Scanner, _normalize_path
from taxonomy import classify_rules

_IMPACT_ORDER = {"High": 0, "Medium": 1, "Low": 2}
_HEAVY = {"string", "vector", "map", "set", "unordered_map", "unordered_set", "list", "deque",
          "multimap", "multiset", "array", "function", "wstring", "ostringstream", "stringstream",
          "priority_queue", "queue", "stack", "bitset"}


@dataclass(frozen=True)
class OptimizationFinding:
    file: str
    line: Optional[int]
    column: Optional[int]
    impact: str
    kind: str
    description: str
    suggestion: str
    rule_id: str
    source: str = "static_scan"

    def to_dict(self):
        return asdict(self)


def _match(tokens: List[Token], i: int, open_t="(", close_t=")") -> int:
    """Index of the token closing the bracket that opens at ``i`` (or len-1)."""
    d = 0
    for k in range(i, len(tokens)):
        if tokens[k].text == open_t:
            d += 1
        elif tokens[k].text == close_t:
            d -= 1
            if d == 0:
                return k
    return len(tokens) - 1


def _loops(tokens: List[Token]) -> List[Tuple[int, int, int, int]]:
    """(keyword_index, header_open, body_start, body_end) for every for/while/do loop."""
    out = []
    n = len(tokens)
    for i, t in enumerate(tokens):
        if t.kind != IDENT or t.text not in ("for", "while", "do"):
            continue
        if t.text == "do":
            if i + 1 < n and tokens[i + 1].text == "{":
                e = _match(tokens, i + 1, "{", "}")
                out.append((i, -1, i + 2, e))
            continue
        if i + 1 >= n or tokens[i + 1].text != "(":
            continue
        close = _match(tokens, i + 1)
        j = close + 1
        if j < n and tokens[j].text == "{":
            out.append((i, i + 1, j + 1, _match(tokens, j, "{", "}")))
        elif j < n and tokens[j].text == ";":
            continue                                  # empty body / do-while tail
        else:                                         # single statement body
            k = j
            d = 0
            while k < n:
                if tokens[k].text in "([{":
                    d += 1
                elif tokens[k].text in ")]}":
                    d -= 1
                elif tokens[k].text == ";" and d <= 0:
                    break
                k += 1
            out.append((i, i + 1, j, k))
    return out


def analyze_performance(source: str, path: str = "<source>",
                        compiler_errors=None) -> List[OptimizationFinding]:
    sc = _Scanner(source, path)
    toks = sc.tokens
    fpath = _normalize_path(path)
    out: List[OptimizationFinding] = []
    seen: Set[Tuple] = set()

    def add(rule, tok_or_line, impact, kind, desc, sug):
        line = tok_or_line.line if isinstance(tok_or_line, Token) else tok_or_line
        col = tok_or_line.col if isinstance(tok_or_line, Token) else None
        key = (rule, line, col)
        if key in seen:
            return
        seen.add(key)
        out.append(OptimizationFinding(fpath, line, col, impact, kind, desc, sug, rule))

    loops = _loops(toks)

    def in_loop(i: int) -> Optional[Tuple[int, int, int, int]]:
        best = None
        for L in loops:
            if L[2] <= i <= L[3] and (best is None or L[2] >= best[2]):
                best = L
        return best

    # declared container/string types (function-insensitive, last declaration wins)
    decl_type: Dict[str, str] = {}
    for st in split_statements(toks):
        if not st or st[0].kind != IDENT:
            continue
        ids = [t for t in st if t.kind == IDENT]
        for k, t in enumerate(st):
            if t.kind == IDENT and t.text in _HEAVY and k + 1 < len(st):
                # name follows the (possibly templated) type
                j = k + 1
                if st[j].text == "<":
                    depth = 0
                    while j < len(st):
                        if st[j].text == "<":
                            depth += 1
                        elif st[j].text == ">":
                            depth -= 1
                        elif st[j].text == ">>":
                            depth -= 2
                        j += 1
                        if depth <= 0:
                            break
                if j < len(st) and st[j].kind == IDENT and j + 1 <= len(st):
                    decl_type[st[j].text] = t.text
                break

    # ---- P01: heavy parameter passed by value ---------------------------------
    for name, params, s, e in sc.functions():
        cur: List[Token] = []
        parts: List[List[Token]] = []
        depth = 0
        for t in params:
            if t.text in "(<[":
                depth += 1
            elif t.text in ")>]":
                depth -= 1
            if t.text == "," and depth <= 0:
                parts.append(cur)
                cur = []
                continue
            cur.append(t)
        if cur:
            parts.append(cur)
        for p in parts:
            texts = [t.text for t in p]
            if not any(t in _HEAVY for t in texts):
                continue
            heavy = next(t for t in p if t.text in _HEAVY)
            pname = [t for t in p if t.kind == IDENT][-1]
            if pname.text in _HEAVY or pname is heavy:
                continue
            decl_type[pname.text] = heavy.text          # parameters count as declarations too
            if "&" in texts or "*" in texts or "&&" in texts:
                continue
            add("PERF-001", heavy, "Medium", "Pass by value",
                f"Parameter '{pname.text}' ({heavy.text}) is copied on every call to {name}().",
                f"Take it by const reference: 'const {heavy.text}& {pname.text}'.")

        # ---- P14: exponential recursion --------------------------------------------
        body = toks[s + 1:e]
        selfcalls = [c for c in find_calls(body, {name})]
        if len(selfcalls) >= 2 and not any(t.text in ("static", "memo", "cache", "dp", "unordered_map",
                                                      "map") for t in body):
            for st in split_statements(body):
                cnt = [c for c in find_calls(st, {name})]
                if len(cnt) >= 2 and any(t.text in ("+", "*") for t in st):
                    add("PERF-002", st[0], "High", "Exponential recursion",
                        f"{name}() calls itself {len(cnt)} times in one expression without memoization "
                        "(O(2^n) work).",
                        "Memoize results (unordered_map / array) or rewrite iteratively.")
                    break

    # ---- loop-based rules -------------------------------------------------------------
    for L in loops:
        kw, hdr, bs, be = L
        header = toks[hdr:bs] if hdr >= 0 else []
        # P03: strlen in the loop condition
        if header:
            for c in find_calls(header, {"strlen", "wcslen"}):
                add("PERF-003", header[c.start], "High", "Hidden O(n^2)",
                    f"{c.name}() in the loop condition is re-evaluated every iteration (O(n) each).",
                    f"Compute it once before the loop: size_t n = {c.name}(...);")
        body = toks[bs:be]
        for k, t in enumerate(body):
            if t.kind != IDENT:
                continue
            nxt = body[k + 1].text if k + 1 < len(body) else ""
            if t.text == "endl":
                add("PERF-004", t, "Medium", "Stream flush in loop",
                    "std::endl flushes the stream on every iteration.",
                    "Use '\\n' and flush once after the loop.")
            if t.text in ("new", "malloc", "calloc") and (t.text == "new" or nxt == "("):
                add("PERF-005", t, "High", "Allocation in loop",
                    "Heap allocation inside a loop body is expensive and fragments memory.",
                    "Hoist the allocation out of the loop, reuse a buffer, or use a container.")
            if t.text in ("find", "count") and nxt == "(" and k >= 1 and body[k - 1].text in ("::", "."):
                is_algo = body[k - 1].text == "::"
                recv = body[k - 2].text if k >= 2 else ""
                if is_algo or decl_type.get(recv) in ("vector", "list", "deque", "string"):
                    add("PERF-006", t, "High", "Hidden O(n^2)",
                        f"Linear {t.text}() inside a loop makes the loop O(n*m).",
                        "Use an unordered_set / unordered_map (or sort once + binary_search).")
            if t.text in ("erase", "insert") and nxt == "(" and k >= 2 and body[k - 1].text == ".":
                arg = body[k + 2:k + 6]
                if arg and arg[0].text == recv_begin(body, k) and decl_type.get(body[k - 2].text) in ("vector", "string"):
                    add("PERF-007", t, "High", "Hidden O(n^2)",
                        f"{t.text}() at the front of a vector shifts every element each iteration.",
                        "Use std::deque / std::list, iterate with an index, or erase once with the "
                        "erase-remove idiom.")
            if t.text == "push_back" and k >= 2 and body[k - 1].text == ".":
                v = body[k - 2].text
                if decl_type.get(v) == "vector" and "reserve" not in {x.text for x in toks}:
                    add("PERF-008", t, "Low", "Missing reserve",
                        f"'{v}.push_back' in a loop reallocates repeatedly as '{v}' grows.",
                        f"Call {v}.reserve(n) before the loop when the final size is known.")
        # P04b: s = s + x  (string re-concatenation)
        for st in split_statements(body):
            if len(st) >= 4 and st[0].kind == IDENT and st[1].text == "=" and st[2].text == st[0].text \
                    and st[3].text == "+" and decl_type.get(st[0].text) in ("string", "wstring"):
                add("PERF-009", st[0], "High", "Hidden O(n^2)",
                    f"'{st[0].text} = {st[0].text} + ...' copies the whole string every iteration.",
                    f"Use '{st[0].text} += ...' (amortised O(1)) and reserve() if the size is known.")
        # range-for by value over heavy elements
        if header and toks[kw].text == "for" and ":" in [h.text for h in header]:
            colon = next(i for i, h in enumerate(header) if h.text == ":")
            lhs = header[1:colon]
            rhs = [h for h in header[colon + 1:] if h.kind == IDENT]
            if lhs and not any(h.text in ("&", "&&", "*") for h in lhs) and rhs and \
                    decl_type.get(rhs[0].text) and not any(h.text == "const" for h in lhs[:1]):
                elem_heavy = any(h.text in _HEAVY for h in lhs) or (
                    lhs[0].text == "auto" and _elem_heavy(toks, rhs[0].text))
                if elem_heavy:
                    add("PERF-010", toks[kw], "Medium", "Copy in range-for",
                        "The loop variable copies every element.",
                        "Bind by reference: 'for (const auto& x : container)'.")

    # ---- P19: iostream sync -----------------------------------------------------------------
    uses_cin = any(t.text == "cin" for t in toks)
    uses_cout = any(t.text == "cout" for t in toks)
    has_sync = any(t.text == "sync_with_stdio" for t in toks)
    if (uses_cin or uses_cout) and not has_sync:
        for L in loops:
            seg = toks[L[2]:L[3]]
            if any(t.text in ("cin", "cout") for t in seg):
                first = next(t for t in seg if t.text in ("cin", "cout"))
                add("PERF-011", first, "Medium", "Synchronised iostream",
                    "cin/cout are synchronised with C stdio by default, which can make loop-heavy "
                    "I/O several times slower.",
                    "Add 'std::ios::sync_with_stdio(false); std::cin.tie(nullptr);' at the start of main().")
                break

    # ---- compiler-reported performance diagnostics ---------------------------------------------
    for err in compiler_errors or []:
        msg = err.get("message") if isinstance(err, dict) else getattr(err, "message", "")
        opt = err.get("option") if isinstance(err, dict) else getattr(err, "option", None)
        res = classify_rules(msg or "", opt, "warning")
        if res and res[0] == "performance":
            line = err.get("line") if isinstance(err, dict) else getattr(err, "line", None)
            out.append(OptimizationFinding(fpath, line, None, "Medium", "Compiler performance warning",
                                           re.sub(r"\s*\[-W[^\]]+\]$", "", msg or ""),
                                           "Apply the compiler's suggestion (remove std::move / bind by reference).",
                                           f"GCC-{opt or 'perf'}".upper(), "compiler_diagnostic"))
    out.sort(key=lambda f: (_IMPACT_ORDER[f.impact], f.line if f.line is not None else 10 ** 9))
    return out


def recv_begin(body: List[Token], k: int) -> str:
    """For 'x.erase(x.begin())' return the text of the receiver ('x') when begin() follows."""
    j = k + 2
    if j + 2 < len(body) and body[j + 1].text == "." and body[j + 2].text == "begin":
        return body[j].text
    return "\0"


def _elem_heavy(toks: List[Token], name: str) -> bool:
    """Does container ``name`` hold heavy elements (vector<string>, vector<vector<..>> ...)?"""
    for i, t in enumerate(toks[:-4]):
        if t.text in ("vector", "list", "deque", "set", "map", "unordered_map", "array") \
                and toks[i + 1].text == "<":
            j = i + 2
            window = []
            depth = 1
            while j < len(toks) and depth > 0:
                if toks[j].text == "<":
                    depth += 1
                elif toks[j].text == ">":
                    depth -= 1
                elif toks[j].text == ">>":
                    depth -= 2
                window.append(toks[j])
                j += 1
            if j < len(toks) and toks[j].kind == IDENT and toks[j].text == name and \
                    any(w.text in _HEAVY for w in window):
                return True
    return False


def format_optimization_report(findings: List[OptimizationFinding]) -> str:
    if not findings:
        return "No optimization opportunities found.\n"
    c = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        c[f.impact] += 1
    lines = [f"{c['High']} high-impact, {c['Medium']} medium-impact, {c['Low']} low-impact "
             f"optimization opportunities", ""]
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"[{f.impact.upper()}] {f.kind} - {loc}")
        lines.append(f"  Why: {f.description}")
        lines.append(f"  Fix: {f.suggestion}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
