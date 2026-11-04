#!/usr/bin/env python3
"""
Reproduces the numbers quoted in PBL_Report.md (Tables 3 and 4 context).

  python3 tests/evaluate.py

For every file in test_cases/ the auto-heal loop is run on a private copy and
the result is verified by an independent real g++ build+link (so a wrong
"compile_clean" signal cannot inflate the score).  It also runs the security
analyzer on the clean baseline and on the deliberately vulnerable fixtures.
Requires g++ and PyQt6 (QtCore only; runs headless).
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import warnings

warnings.filterwarnings("ignore")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from heal_loop import HealWorker            # noqa: E402
from error_classifier import ErrorClassifier  # noqa: E402
from security_analyzer import analyze       # noqa: E402


def builds(path):
    r = subprocess.run(["g++", "-std=c++17", path, "-o", os.devnull],
                       capture_output=True, text=True,
                       env=dict(os.environ, LC_ALL="C"))
    return r.returncode == 0


def heal_eval():
    clf = ErrorClassifier()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for src in sorted(glob.glob(os.path.join(ROOT, "test_cases", "*.cpp"))):
            name = os.path.basename(src)
            dst = os.path.join(tmp, name)
            shutil.copy(src, dst)
            was_ok = builds(dst)
            w = HealWorker(dst, clf)
            sig, patches = [], []
            w.compile_clean.connect(lambda: sig.append("clean"))
            w.give_up.connect(lambda h: sig.append("give_up"))
            w.diff_ready.connect(lambda n, d: patches.append(n))
            w._heal()
            rows.append((name, was_ok, builds(dst), sig[-1] if sig else "none", len(patches)))
    return rows


def main():
    rows = heal_eval()
    buggy = [r for r in rows if not r[1]]
    healed = [r for r in buggy if r[2]]
    print("== Auto-heal (verified by real g++ build + link) ==")
    print(f"{'file':30} {'initially builds':>16} {'builds after':>13} {'signal':>9} {'patches':>8}")
    for n, a, b, s, p in rows:
        print(f"{n:30} {str(a):>16} {str(b):>13} {s:>9} {p:>8}")
    print(f"\nInitially-broken files : {len(buggy)}")
    print(f"Healed to a real build : {len(healed)}")
    if healed:
        print(f"Mean patches (healed)  : {sum(r[4] for r in healed)/len(healed):.1f}")
    lies = [r for r in rows if r[3] == 'clean' and not r[2]]
    print(f"False 'clean' signals  : {len(lies)}")

    print("\n== Security analyzer ==")
    for fname in ("test_clean.cpp", "test_secure.cpp", "test_all_security.cpp"):
        f = analyze(os.path.join(ROOT, fname), [])
        print(f"{fname:24} findings: {len(f)}")


if __name__ == "__main__":
    main()
