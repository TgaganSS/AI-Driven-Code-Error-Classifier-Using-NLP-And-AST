"""Headless demo of the self-healing loop (the same engine the GUI uses).

    python tools/heal_demo.py demo/06_heal_semicolons.cpp

Loop: compile -> classify -> apply ONE rule-based fix -> recompile, until clean
or MAX_ATTEMPTS.  The original file is never modified; the result is written
next to it as <name>.healed.cpp.
"""
import difflib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
os.environ.setdefault("GSC_DISABLE_DATASET_LOGGING", "1")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import auto_healer as A                      # noqa: E402
import heal_loop as H                        # noqa: E402
from error_classifier import ErrorClassifier  # noqa: E402

MAX_ATTEMPTS = 10


def main(path: str) -> int:
    clf = ErrorClassifier()
    out = os.path.splitext(path)[0] + ".healed.cpp"
    with open(path, encoding="utf-8", errors="ignore") as f:
        original = f.read()
    with open(out, "w", encoding="utf-8") as f:
        f.write(original)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        errors = [e for e in H._compile(out)[0] if e.get("type") == "error"]
        if not errors:
            print(f"attempt {attempt}: recompile -> CLEAN  (healed)")
            break
        H._classify_errors(errors, clf)
        src = open(out, encoding="utf-8", errors="ignore").read()
        for e in errors:
            fixed = A.attempt_fix(src, e)
            if fixed and fixed != src:
                print(f"attempt {attempt}: [{e.get('category')}] {e['message'][:60]} (line {e['line']}) -> fixed")
                open(out, "w", encoding="utf-8").write(fixed)
                break
        else:
            print(f"attempt {attempt}: no safe automatic fix for: "
                  + "; ".join(f"{e['message'][:40]} (line {e['line']})" for e in errors[:3]))
            print("-> stopped, a human decision is needed")
            break

    healed = open(out, encoding="utf-8", errors="ignore").read()
    print("\n--- changes ---")
    diff = list(difflib.unified_diff(original.splitlines(), healed.splitlines(),
                                     os.path.basename(path), os.path.basename(out) , lineterm="", n=1))
    print("\n".join(diff) if diff else "(no changes)")
    print(f"\nWritten: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) > 1 else print(__doc__) or 1)
