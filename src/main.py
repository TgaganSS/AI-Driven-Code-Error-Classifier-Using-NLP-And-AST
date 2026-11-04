#!/usr/bin/env python3
"""
Self-Healing C++ Compiler - command line interface.

  python src/main.py file.cpp                    analyse (errors, security, optimisation)
  python src/main.py file.cpp -v                 + code context, timings, compiler notes
  python src/main.py file.cpp --format json      machine readable
  python src/main.py file.cpp --format sarif     SARIF 2.1.0 for CI / code scanning
  python src/main.py file.cpp --fail-on high     exit code 2 when a finding >= severity exists
  python src/main.py file.cpp --harden           verified secure rewrite -> file.hardened.cpp (+ diff)
  python src/main.py file.cpp --harden --in-place
"""

import argparse
import json
import os
import sys
import textwrap

from pipeline import analyze_file
from security_analyzer import format_security_report, risk_score
from perf_analyzer import format_optimization_report

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def parse_arguments(argv=None):
    p = argparse.ArgumentParser(description="C++ Error Explanation, Security & Optimization Tool")
    p.add_argument("source_file", help="C++ source file to analyse")
    p.add_argument("-j", "--json", action="store_true", help="shortcut for --format json")
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("-v", "--verbose", action="store_true", help="show code context, notes and timings")
    p.add_argument("-c", "--context", type=int, default=2, help="number of context lines")
    p.add_argument("--all", action="store_true",
                   help="also show style / quality / performance warnings and cascading errors")
    p.add_argument("--no-optimize", action="store_true", help="skip optimisation advice")
    p.add_argument("--fail-on", choices=tuple(_SEV_RANK), default=None,
                   help="exit with status 2 if a security finding of at least this severity exists")
    p.add_argument("--harden", action="store_true",
                   help="apply verified secure-code fixes (writes <file>.hardened.cpp and prints a diff)")
    p.add_argument("--in-place", action="store_true", help="with --harden: overwrite the source file")
    p.add_argument("--no-cache", action="store_true", help="disable the build cache for this run")
    p.add_argument("--clear-cache", action="store_true", help="empty the build cache and exit")
    return p.parse_args(argv)


def print_error(error, verbose=False):
    etype = error.error_type.lower()
    color = RED if etype == "error" else YELLOW if etype == "warning" else BLUE
    print(f"\n{color}{BOLD}{etype.upper()}:{error.message}{RESET}")

    if error.file:
        location = f"{error.file}"
        if error.line is not None:
            location += f" (line {error.line}"
            if error.column is not None:
                location += f", column {error.column}"
            location += ")"
        print(f"  {BLUE}Location:{RESET} {location}")
    if error.category:
        cwe = (" " + "/".join(f"CWE-{c}" for c in error.cwe[:3])) if error.cwe else ""
        unc = " (uncertain)" if error.uncertain else ""
        print(f"  {BLUE}Category:{RESET} {error.category}{cwe}  "
              f"[{error.confidence:.0%} via {error.source or 'n/a'}]{unc}")

    if error.explanation:
        print(f"\n  {BLUE}{BOLD}Explanation:{RESET}")
        for block in error.explanation.split("\n\n"):
            print(f"  {BLUE}{textwrap.fill(block, width=80)}{RESET}\n")

    if error.suggestion:
        print(f"\n  {GREEN}{BOLD}Suggestion:{RESET}")
        for line in textwrap.fill(error.suggestion, width=80).split("\n"):
            print(f"  {GREEN}{line}{RESET}")

    if error.security_risk and error.security_risk not in ("None",) and \
            (error.security_risk != "Low" or error.group == "security" or verbose):
        print(f"\n  {YELLOW}{BOLD}Security Assessment:{RESET}")
        print(f"  {YELLOW}Risk Level: {error.security_risk}{RESET}")
        if error.risk_reason:
            print(f"  {YELLOW}{error.risk_reason}{RESET}")

    if verbose and error.notes:
        print(f"\n  {BOLD}Compiler notes:{RESET}")
        for n in error.notes[:4]:
            print(f"    - line {n.get('line')}: {n['message']}")
    if verbose and error.context and "lines" in error.context:
        print(f"\n  {BOLD}Code Context:{RESET}")
        start = error.context["start_line"]
        for i, line in enumerate(error.context["lines"], start=start):
            marker = "→" if i == error.line else " "
            print(f"  {marker} {i}: {line.rstrip()}")
    print()


def _result_dict(res, visible):
    errs = [e for e in visible if e.error_type == "error"]
    warns = [e for e in visible if e.error_type == "warning"]
    return {
        "status": "error" if errs else "success",
        "file": res.file,
        "blocked": res.blocked,
        "error_count": len(errs),
        "warning_count": len(warns),
        "errors": [e.to_dict() for e in visible],
        "security_findings": [f.to_dict() for f in res.security_findings],
        "security_report": format_security_report(res.security_findings),
        "risk_score": risk_score(res.security_findings),
        "optimization_findings": [o.to_dict() for o in res.optimization_findings],
        "preflight": res.preflight,
        "cached": res.cached,
        "timings": {k: round(v, 4) for k, v in res.timings.items()},
    }


def _fail_code(res, threshold):
    if not threshold:
        return 0
    limit = _SEV_RANK[threshold]
    return 2 if any(_SEV_RANK[f.severity.lower()] <= limit for f in res.security_findings) else 0


def run_harden(args):
    from secure_fixer import harden_source, unified_diff
    path = args.source_file
    with open(path, "rb") as fb:
        had_crlf = b"\r\n" in fb.read()           # keep the file's original line endings
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        source = f.read()
    r = harden_source(source, path)
    if r.error:
        print(f"{RED}{r.error}{RESET}")
        return 1
    if not r.applied:
        print("No verified automatic fixes available.")
        for rule, line, why in r.skipped:
            print(f"  skipped {rule} (line {line}): {why}")
        print()
        print(format_security_report(r.remaining), end="")
        return 0
    print(f"{GREEN}{BOLD}{len(r.applied)} verified fix(es) applied:{RESET}")
    for fx in r.applied:
        print(f"  line {fx.line:<4} {fx.rule:<14} {fx.description}")
    for rule, line, why in r.skipped:
        print(f"  {YELLOW}skipped{RESET} {rule} (line {line}): {why}")
    print("\n" + unified_diff(r.original, r.hardened, os.path.basename(path)))
    out = path if args.in_place else os.path.splitext(path)[0] + ".hardened.cpp"
    with open(out, "w", encoding="utf-8", newline="\r\n" if had_crlf else None) as f:
        f.write(r.hardened)
    print(f"{GREEN}Written: {out}{RESET}")
    print(f"\nRemaining findings: {len(r.remaining)}")
    print(format_security_report(r.remaining), end="")
    return 0


def main(argv=None):
    args = parse_arguments(argv)
    if args.no_cache:
        os.environ["GSC_NO_CACHE"] = "1"
    if args.clear_cache:
        import build_cache
        print(f"Removed {build_cache.clear()} cached build result(s).")
        return 0
    if args.harden:
        return run_harden(args)

    fmt = "json" if args.json else args.format
    res = analyze_file(args.source_file, optimize=not args.no_optimize)
    visible = res.visible(show_all=args.all)
    hidden = len(res.errors) - len(visible)
    code = 1 if res.error_count > 0 else 0
    if code == 0:
        code = _fail_code(res, args.fail_on)

    if fmt == "sarif":
        import sarif
        print(sarif.dumps(res.security_findings, res.optimization_findings))
        return code
    if fmt == "json":
        print(json.dumps(_result_dict(res, visible), indent=2))
        return code

    # ---- human readable ----
    if res.blocked:
        for e in visible:
            print_error(e, verbose=args.verbose)
        return 1
    if not visible:
        print("Compilation successful")
        print()
    else:
        print(f"\n{len(visible)} issue(s) found:\n")
        error_count = warning_count = 0
        for e in visible:
            if e.error_type == "error":
                error_count += 1
            elif e.error_type == "warning":
                warning_count += 1
            print_error(e, verbose=args.verbose)
        print(f"{error_count} error(s), {warning_count} warning(s)")
        if hidden > 0:
            print(f"({hidden} style/quality/follow-on diagnostic(s) hidden; use --all to show)")
        print()
    if res.preflight and args.verbose:
        for p in res.preflight[:5]:
            print(f"{YELLOW}Pre-flight:{RESET} line {p['line']}: {p['message']}")
        print()
    print(format_security_report(res.security_findings), end="")
    if res.optimization_findings:
        print(f"\n{BOLD}Optimization advice{RESET}")
        print(format_optimization_report(res.optimization_findings), end="")
    if args.verbose:
        t = res.timings
        print(f"\n[timing] total {t['total']:.2f}s | build {t['build']:.2f}s"
              f"{' (cached)' if res.cached else ''} | classify {t['classify']:.2f}s | "
              f"security {t['security']:.3f}s | optimize {t['optimize']:.3f}s")
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:                       # e.g. `main.py f.cpp | head` - exit quietly
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except OSError:
            pass
        sys.exit(0)
