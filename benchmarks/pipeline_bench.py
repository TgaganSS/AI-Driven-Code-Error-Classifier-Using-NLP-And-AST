"""Per-file wall time + number of g++ driver invocations over test_cases/ (uses a PATH shim).

Usage: python benchmarks/pipeline_bench.py [project_root] [label]
"""
"""Run the CLI over every test case; report wall time + number of g++ invocations."""
import glob, os, subprocess, sys, time, json, tempfile
root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), ".."))
label = sys.argv[2] if len(sys.argv) > 2 else "RUN"
files = sorted(glob.glob(os.path.join(root, "test_cases", "*.cpp")))[:24] + [os.path.join(root,"test_clean.cpp"), os.path.join(root,"test_all_security.cpp")]
env = dict(os.environ, PATH=os.path.join(os.path.dirname(os.path.abspath(__file__)), "shim")+":"+os.environ["PATH"], GSC_DISABLE_DATASET_LOGGING="1",
           QT_QPA_PLATFORM="offscreen", PYTHONWARNINGS="ignore")
tot_t = tot_c = 0; rows = []
for f in files:
    log = tempfile.mktemp(); env["GSC_SHIM_LOG"] = log
    t = time.time()
    r = subprocess.run([sys.executable, "-W", "ignore", os.path.join(root,"src","main.py"), "-j", f],
                       capture_output=True, text=True, env=env, cwd=root)
    dt = time.time() - t
    n = len(open(log).read().splitlines()) if os.path.exists(log) else 0
    try:
        j = json.loads(r.stdout); ne = j.get("error_count"); nw = j.get("warning_count"); ns = len(j.get("security_findings", []))
    except Exception: ne = nw = ns = "?"
    rows.append((os.path.basename(f), dt, n, ne, nw, ns)); tot_t += dt; tot_c += n
print(f"== {label}: {len(files)} files | total {tot_t:.1f}s | avg {tot_t/len(files):.2f}s/file | g++ calls {tot_c} ({tot_c/len(files):.1f}/file)")
for r in rows: print(f"  {r[0]:<34} {r[1]:5.2f}s  g++x{r[2]}  err={r[3]} warn={r[4]} sec={r[5]}")
