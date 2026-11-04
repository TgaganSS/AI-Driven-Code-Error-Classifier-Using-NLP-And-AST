"""Recall / false-positive measurement of the security analyzer on the labelled corpora."""
import os, sys, tempfile
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src")); sys.path.insert(0, os.path.join(ROOT, "tests")); sys.path.insert(0, os.path.dirname(__file__))
import security_analyzer as SA, security_corpus as C, blind_set as B

def recall_fp(vuln, safe, wrap):
    hit = sum(any(set(f.cwe) & exp for f in SA.analyze_source(wrap(body), "/tmp/x.cpp")) for _i, exp, body in vuln)
    fp = [i for i, body in safe if SA.analyze_source(wrap(body), "/tmp/x.cpp")]
    return hit, len(vuln), fp, len(safe)

v = [(i, e, b) for i, e, nc, b in C.VULN if not nc]
h, n, fp, ns = recall_fp(v, C.SAFE, C.source_of)
print(f"tuned corpus : recall {h}/{n}  false positives {len(fp)}/{ns} {fp}")
h, n, fp, ns = recall_fp(B.VULN, B.SAFE, lambda b: B.H + b + "\n")
print(f"blind set    : recall {h}/{n}  false positives {len(fp)}/{ns} {fp}")
