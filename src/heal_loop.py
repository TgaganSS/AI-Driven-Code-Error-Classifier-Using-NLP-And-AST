"""
heal_loop.py
------------
Orchestrates the auto-healing pipeline.

Flow:
  1. Compile  → parse errors
  2. Classify each error
  3. Call auto_healer.attempt_fix() for the first fixable error
  4. Write patched source  →  show diff
  5. Recompile  →  if clean, done ✅
  6. After MAX_ATTEMPTS failures  →  emit give_up signal

Signals emitted (for the GUI):
  - attempt_started(attempt_no: int, error: dict)
  - diff_ready(attempt_no: int, diff_html: str)
  - compile_clean()
  - give_up(history: list[dict])
  - error_signal(message: str)
"""

import json
import os
import sys
import re
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal

from auto_healer import attempt_fix, UNFIXABLE_CATEGORIES
from diff_viewer import compute_diff, format_diff_html, has_changes
from healing_suggester import suggest_failed_heal
import time
try:
    from codecarbon import EmissionsTracker
    HAS_CODECARBON = True
except ImportError:
    HAS_CODECARBON = False

MAX_ATTEMPTS = 10

def _compile(file_path: str) -> tuple[list[dict], str]:
    """
    Safety gate + ONE build (cached, resource-limited) and return (error_list, raw_stderr).
    Each error dict has: file, line, column, type, message, raw (+ option/notes).

    The healer deliberately keeps the focused ``-Wall`` profile: the full
    security/quality warning profile is for *reporting*, not for patching, and
    would make the loop chase hundreds of style warnings.
    """
    from compiler_runner import compile_checked
    diags, res = compile_checked(file_path, analysis=False, extra_flags=["-Wall"])
    if res is None and diags and diags[0].get("category") == "security_violation":
        return diags, "error: Malicious code blocked"
    return diags, (res.stderr if res is not None else "")


def _pre_scan(source: str) -> list[dict]:
    """
    Catch a small set of obvious issues before compile diagnostics.
    Returns synthetic diagnostics in the same shape as compiler errors.
    """
    errors = []
    lines = source.splitlines()

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        if re.search(r"\bint\b.*=\s*2147483647\b", stripped):
            errors.append({
                "file": "source",
                "line": i,
                "column": 0,
                "type": "warning",
                "message": "integer overflow: value at INT_MAX, addition will overflow",
                "raw": line,
                "category": "integer_overflow",
                "confidence": 1.0,
            })

        if re.search(r"if\s*\([^=!<>]*(?<![=!<>])=(?!=)[^)]*\)", stripped):
            if not re.search(r"if\s*\(.*==.*\)", stripped):
                errors.append({
                    "file": "source",
                    "line": i,
                    "column": 0,
                    "type": "warning",
                    "message": "assignment used as truth value in if condition",
                    "raw": line,
                    "category": "syntax_error",
                    "confidence": 1.0,
                })

        if re.search(r"/\s*0\b", stripped):
            errors.append({
                "file": "source",
                "line": i,
                "column": 0,
                "type": "warning",
                "message": "division by zero: literal 0 used as divisor",
                "raw": line,
                "category": "division_by_zero",
                "confidence": 1.0,
            })

        zero_assign = re.search(r"\bint\s+([A-Za-z_]\w*)\s*=\s*0\s*;", stripped)
        if zero_assign:
            var = zero_assign.group(1)
            guard_pattern = re.compile(rf"if\s*\(\s*{re.escape(var)}\s*==\s*0\s*\)")
            if guard_pattern.search(source):
                continue
            for j, future_line in enumerate(lines[i:], start=i + 1):
                future_stripped = future_line.strip()
                if future_stripped.startswith("//"):
                    continue
                if re.search(rf"/\s*{re.escape(var)}\b", future_line):
                    errors.append({
                        "file": "source",
                        "line": j,
                        "column": 0,
                        "type": "warning",
                        "message": f"division by zero: '{var}' is 0",
                        "raw": future_line,
                        "category": "division_by_zero",
                        "confidence": 0.9,
                    })
                    break

    return errors


def _classify_errors(errors: list[dict], classifier) -> list[dict]:
    """Attach 'category' to each error using the ML classifier."""
    for e in errors:
        if e.get("category"):
            e["confidence"] = round(float(e.get("confidence", 1.0)), 3)
            continue
        cat, conf = classifier.predict(e["message"])
        e["category"] = cat or "other"
        e["confidence"] = round(conf, 3)
    return errors


def _pick_fix_target(issues: list[dict]) -> Optional[dict]:
    """
    Prefer real errors, but allow fixable warnings such as uninitialized
    variables when there are no patchable hard errors.
    """
    for issue_type in ("error", "warning"):
        for issue in issues:
            if issue["type"] != issue_type:
                continue
            if issue.get("category") in UNFIXABLE_CATEGORIES:
                continue
            return issue
    return None


class HealWorker(QThread):
    """
    QThread that runs the full heal loop asynchronously.
    Connect to its signals to receive live updates.
    """
    attempt_started = pyqtSignal(int, dict)          # (attempt_no, error)
    diff_ready      = pyqtSignal(int, str)            # (attempt_no, diff_html)
    compile_clean   = pyqtSignal()
    give_up         = pyqtSignal(list)                # history list
    error_signal    = pyqtSignal(str)                 # fatal/internal errors
    hint_required   = pyqtSignal(int, dict, list)     # (attempt_no, error, history)
    lines_fixed     = pyqtSignal(list)                # [line_no, ...]
    telemetry_ready = pyqtSignal(list)                # list[dict]

    def __init__(self, file_path: str, classifier, hint: Optional[str] = None):
        super().__init__()
        self.file_path  = file_path
        self.classifier = classifier
        self.hint       = hint          # optional user guidance from previous round

    def run(self):
        project_dir = os.path.dirname(os.path.abspath(self.file_path))
        main_tracker = None
        if HAS_CODECARBON:
            try:
                main_tracker = EmissionsTracker(
                    project_name="self_healing_compiler",
                    measure_power_secs=1,
                    log_level="error",
                    save_to_file=True,
                    output_dir=project_dir,
                    output_file="emissions.csv"
                )
                main_tracker.start()
            except Exception:
                main_tracker = None

        try:
            telemetry = self._heal()
            self.telemetry_ready.emit(telemetry)
        except Exception as exc:
            self.error_signal.emit(str(exc))
        finally:
            if main_tracker:
                try:
                    main_tracker.stop()
                except:
                    pass

    def _attach_failure_suggestion(self, history: list[dict], error: dict, source: str) -> None:
        if not error:
            return
        error["suggestion"] = suggest_failed_heal(error, source, history)

    def _heal(self) -> list[dict]:
        history = []
        telemetry = []
        seen_errors = set()
        project_dir = os.path.dirname(os.path.abspath(self.file_path))

        # Read current source
        with open(self.file_path, "r", encoding="utf-8") as f:
            source = f.read()

        if self.hint:
            history.append({"type": "hint", "text": self.hint})

        for attempt in range(1, MAX_ATTEMPTS + 1):
            attempt_start_time = time.time()
            attempt_tracker = None
            if HAS_CODECARBON:
                try:
                    attempt_tracker = EmissionsTracker(
                        project_name="self_healing_compiler",
                        measure_power_secs=1,
                        log_level="error",
                        save_to_file=True,
                        output_dir=project_dir,
                        output_file="emissions.csv"
                    )
                    attempt_tracker.start()
                except:
                    attempt_tracker = None

            # 1. Compile
            errors, raw_stderr = _compile(self.file_path)
            pre_errors = _pre_scan(source)
            all_errors = pre_errors + errors

            if not all_errors:
                if attempt_tracker: attempt_tracker.stop()
                self.compile_clean.emit()
                return telemetry

            # 2. Classify
            _classify_errors(all_errors, self.classifier)

            # 3. Pick target
            target = _pick_fix_target(all_errors)
            if target is None:
                if attempt_tracker: attempt_tracker.stop()
                hard_errors = [e for e in all_errors if e["type"] == "error"]
                if not hard_errors:
                    self.compile_clean.emit()
                    return telemetry
                history.append({
                    "attempt": attempt, "error": hard_errors[0], "patch": None, "reason": "unfixable_category"
                })
                self._attach_failure_suggestion(history, hard_errors[0], source)
                self.give_up.emit(history)
                return telemetry

            self.attempt_started.emit(attempt, target)

            error_key = target.get("message")
            if error_key in seen_errors:
                if attempt_tracker: attempt_tracker.stop()
                self._attach_failure_suggestion(history, target, source)
                self.give_up.emit(history)
                return telemetry
            seen_errors.add(error_key)

            # 4. Patch
            patched = attempt_fix(source, target)
            if patched is None or patched == source:
                if attempt_tracker: attempt_tracker.stop()
                history.append({
                    "attempt": attempt, "error": target, "patch": None, "reason": "no_patch_available"
                })
                if attempt == MAX_ATTEMPTS:
                    self._attach_failure_suggestion(history, target, source)
                    self.give_up.emit(history)
                    return telemetry
                continue

            # 5. Diff & Notify
            diff = compute_diff(source, patched)
            diff_html = format_diff_html(diff) if has_changes(diff) else "<i>No visible changes.</i>"
            self.diff_ready.emit(attempt, diff_html)

            fixed_line_nos = [d.line_no_new for d in diff if d.kind == "+" and d.line_no_new is not None]
            self.lines_fixed.emit(fixed_line_nos)

            history.append({
                "attempt": attempt, "error": target, "patch": patched, "diff_html": diff_html
            })

            # 6. Save
            with open(self.file_path, "w", encoding="utf-8") as f:
                f.write(patched)
            source = patched

            # Telemetry logic
            attempt_duration = time.time() - attempt_start_time
            attempt_emissions = 0.0
            if attempt_tracker:
                try:
                    attempt_emissions = attempt_tracker.stop()
                except:
                    pass
            
            telemetry.append({
                "attempt": attempt,
                "category": target.get("category", "unknown"),
                "success": True,
                "duration": round(attempt_duration, 3),
                "emissions": attempt_emissions
            })

        # Exhaust
        last_error = next((item.get("error") for item in reversed(history) if item.get("error")), None)
        self._attach_failure_suggestion(history, last_error, source)
        self.give_up.emit(history)
        return telemetry
