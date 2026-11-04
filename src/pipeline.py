"""
pipeline.py
-----------
One orchestrated analysis shared by the CLI, tests and any front-end:

    read source once
      -> lexer pre-flight (unclosed / mismatched delimiters, pointed at the OPENING token)
      -> safety gate (token based)  +  ONE cached, resource-limited build
      -> parse diagnostics (option tags, notes, re-anchoring)
      -> hybrid classification + explanation (rules first, ML only when needed)
      -> security analysis ONCE per file (compiler findings + static/taint scan)
      -> optimization analysis ONCE per file
      -> feedback logging of rule-confirmed labels

The previous CLI ran the compiler up to four times per file, re-scanned the whole
source once per reported error, and loaded a 37 MB model on every start.
"""

from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass, field
from typing import List, Optional

from compiler_runner import compile_checked
from dataset_logger import log_example
from error_explainer import enrich_error
from error_parser import parse_errors
from lexer import tokenize, check_delimiters
from perf_analyzer import analyze_performance, OptimizationFinding
from security_analyzer import analyze_source, SecurityFinding, risk_score
from taxonomy import info as category_info

# warning groups shown by default (everything else needs --all)
_DEFAULT_VISIBLE_GROUPS = {"error", "security"}
_DEFAULT_VISIBLE_CATEGORIES = {"logic_error", "uninitialized_memory", "return_type_error",
                               "implicit_fallthrough"}


@dataclass
class AnalysisResult:
    file: str
    errors: list = field(default_factory=list)                 # CompilerError objects (enriched)
    security_findings: List[SecurityFinding] = field(default_factory=list)
    optimization_findings: List[OptimizationFinding] = field(default_factory=list)
    blocked: bool = False
    preflight: List[dict] = field(default_factory=list)
    timings: dict = field(default_factory=dict)
    cached: bool = False

    @property
    def error_count(self) -> int:
        return sum(1 for e in self.errors if e.error_type == "error" and not e.cascade)

    def visible(self, show_all: bool = False) -> list:
        if show_all:
            return list(self.errors)
        out = []
        for e in self.errors:
            if e.cascade:
                continue
            if e.error_type == "error":
                out.append(e)
            elif (e.group in _DEFAULT_VISIBLE_GROUPS) or (e.category in _DEFAULT_VISIBLE_CATEGORIES):
                out.append(e)
        return out

    @property
    def risk(self) -> int:
        return risk_score(self.security_findings)


_clang_ok: Optional[bool] = None


def _have_clang() -> bool:
    global _clang_ok
    if _clang_ok is None:
        _clang_ok = shutil.which("clang++") is not None or shutil.which("clang") is not None
    return _clang_ok


def _attach_preflight_hints(errors, problems: List[dict]) -> None:
    """g++ reports a missing '}' at end of file; point at the real opening brace instead."""
    unclosed = [p for p in problems if p["kind"] == "unclosed"]
    if not unclosed:
        return
    for e in errors:
        msg = e.message or ""
        if e.category in ("missing_closing_brace",) or "expected '}' at end of input" in msg \
                or "a function-definition is not allowed here" in msg:
            p = unclosed[0]
            hint = f"Pre-flight scan: '{p['message'].split(' ')[0]}' opened at line {p['line']} is never closed."
            e.notes = list(e.notes or []) + [{"file": e.file, "line": p["line"],
                                              "column": p["col"], "message": hint}]
            if e.explanation:
                e.explanation += f"\n\nLikely cause: {hint}"
            break


def analyze_file(path: str, permissions: dict = None, optimize: bool = True, log: bool = True,
                 use_ast: bool = True) -> AnalysisResult:
    t0 = time.time()
    res = AnalysisResult(file=path)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except OSError:
        source = ""

    # 1. pre-flight (microseconds)
    t = time.time()
    problems = check_delimiters(tokenize(source, keep_preproc=False)) if source else []
    res.preflight = problems
    res.timings["preflight"] = time.time() - t

    # 2. gate + single build
    t = time.time()
    diags, build = compile_checked(path, permissions, analysis=True)
    res.blocked = build is None and bool(diags) and diags[0].get("category") == "security_violation"
    res.cached = bool(build and build.cached)
    res.timings["build"] = time.time() - t

    # 3. parse + (optional) AST + classify/explain
    t = time.time()
    errors = parse_errors(diags)
    ast_text = None
    has_hard_error = any(e.error_type == "error" for e in errors)
    if use_ast and has_hard_error and _have_clang() and not res.blocked:
        try:
            from ast_extractor import extract_ast
            ast_text = extract_ast(path)
        except Exception:
            ast_text = None
    for e in errors:
        e.ast_node = None
        if ast_text and e.line:
            try:
                from ast_extractor import extract_node_near_line
                e.ast_node = extract_node_near_line(ast_text, e.line)
            except Exception:
                e.ast_node = None
        enrich_error(e)
        if getattr(e, "detail", None):
            e.explanation = (e.explanation or "") + f"\n\nBlocked because: {e.detail}"
    _attach_preflight_hints(errors, problems)
    res.errors = errors
    res.timings["classify"] = time.time() - t

    # 4. security (once)
    t = time.time()
    # Static analysis is pure text processing (nothing is compiled or run), so it is safe -
    # and most useful - exactly when the safety gate blocked the build.
    res.security_findings = analyze_source(source, path, errors)
    for e in errors:
        if not e.security_findings:
            e.security_findings = [f for f in res.security_findings
                                   if f.source == "compiler_diagnostic" and f.line == e.line]
    res.timings["security"] = time.time() - t

    # 5. optimization (once)
    t = time.time()
    if optimize and not res.blocked and not any(e.error_type == "error" for e in errors):
        try:
            res.optimization_findings = analyze_performance(source, path, diags)
        except Exception:
            res.optimization_findings = []
    res.timings["optimize"] = time.time() - t

    # 6. feedback
    if log:
        for e in errors:
            try:
                log_example(e)
            except Exception:
                pass
    res.timings["total"] = time.time() - t0
    return res
