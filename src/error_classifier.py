"""
error_classifier.py
-------------------
Hybrid diagnostic classifier.

    1. RULES  (taxonomy.classify_rules)   - keyed on the ``[-Wxxx]`` tag and on
       message templates.  ~96 % of real messages, ~99 % precise, zero ML cost.
    2. ML     (compact linear text model) - only for messages no rule recognises.
       It abstains (returns ``other`` with ``uncertain=True``) when its
       probability is below ``ABSTAIN_BELOW`` instead of being confidently wrong.

Why this replaces the previous scikit-learn pickle
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* The old model was trained on 67 k near-duplicate rows (only ~5.8 k distinct
  message *templates*), 37 % of them labelled ``other`` (mostly mislabelled -
  ``'import' does not name a type`` is plainly a name-resolution error), and
  had no security classes.  Every real warning such as ``[-Wformat-security]``
  came out as ``other`` with 64-94 % confidence.
* The model is now trained on identifier-masked, de-duplicated, rule-relabelled
  templates, so it generalises and is ~10x smaller.
* It is exported to JSON + ``.npz`` and evaluated with plain numpy.  **No
  pickle is ever loaded** (a swapped ``.joblib`` was a code-execution vector),
  the artifact carries a SHA-256, and scikit-learn is only needed for
  *training* - inference starts in milliseconds and is independent of the
  installed scikit-learn version.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from taxonomy import (CATEGORIES, classify_rules, normalize_template, split_option, legacy_of)

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
_DEFAULT_TRAINING_DATA_FILE = os.path.join(_DEFAULT_DATA_DIR, "training_data.json")
_DEFAULT_MODEL_FILE = os.path.join(_DEFAULT_DATA_DIR, "error_classifier.model.json")

ABSTAIN_BELOW = float(os.environ.get("GSC_ABSTAIN_BELOW", "0.70"))
_MODEL_SCHEMA = 2

# ── Legacy label handling (training data uses the old coarse names) ──────────
CATEGORY_ALIASES = {
    "name_resolution": "name_resolution",
    "function_error": "type_error",
    "linker_error": "linker_error",
    "warning": "other",
    "syntax_error": "syntax_error",
    "type_error": "type_error",
    "missing_include": "missing_include",
    "redefinition": "redefinition",
    "access_error": "access_error",
    "return_type_error": "return_type_error",
    "unused_variable": "unused_variable",
    "other": "other",
}
ALL_CATEGORIES = list(CATEGORIES.keys())


def _normalize_category(cat: str) -> str:
    c = (cat or "").strip().lower()
    if c in CATEGORIES:
        return c
    return CATEGORY_ALIASES.get(c, "other")


# ─────────────────────────────────────────────────────────────────────────────
# Pure-numpy linear text model (TF-IDF word + char_wb n-grams, softmax)
# ─────────────────────────────────────────────────────────────────────────────

_WORD_TOKEN_RE = re.compile(r"(?u)\b\w+\b|[;{}()\[\]+\-/*=<>,.:&|!?~^%]")
_WS_RE = re.compile(r"\s\s+")


def _word_terms(text: str, ngram=(1, 2)) -> List[str]:
    toks = _WORD_TOKEN_RE.findall(text)
    terms = list(toks)
    for n in range(max(ngram[0], 2), ngram[1] + 1):
        terms.extend(" ".join(toks[i:i + n]) for i in range(len(toks) - n + 1))
    return terms


def _char_wb_terms(text: str, ngram=(3, 5)) -> List[str]:
    out: List[str] = []
    text = _WS_RE.sub(" ", text)
    for w in text.split():
        w = " " + w + " "
        wl = len(w)
        for n in range(ngram[0], ngram[1] + 1):
            off = 0
            out.append(w[off:off + n])
            while off + n < wl:
                off += 1
                out.append(w[off:off + n])
            if off == 0:
                break
    return out


class LinearTextModel:
    """TF-IDF (word 1-2 + char_wb 3-5, each L2-normalised) -> multinomial logistic regression."""

    def __init__(self, classes, word_vocab, word_idf, char_vocab, char_idf, coef, intercept):
        import numpy as np
        self.np = np
        self.classes = list(classes)
        self.word_vocab = word_vocab
        self.char_vocab = char_vocab
        self.word_idf = np.asarray(word_idf, dtype=np.float32)
        self.char_idf = np.asarray(char_idf, dtype=np.float32)
        self.coef = np.asarray(coef, dtype=np.float32)          # (n_classes, n_features)
        self.intercept = np.asarray(intercept, dtype=np.float32)
        self._nw = len(word_vocab)

    # -- features ------------------------------------------------------------
    def _block(self, terms, vocab, idf, offset, idx, val):
        counts = Counter(t for t in terms if t in vocab)
        if not counts:
            return
        items = [(vocab[t], c * float(idf[vocab[t]])) for t, c in counts.items()]
        norm = math.sqrt(sum(v * v for _, v in items)) or 1.0
        for j, v in items:
            idx.append(offset + j)
            val.append(v / norm)

    def predict_proba(self, texts: Sequence[str]):
        np = self.np
        out = np.zeros((len(texts), len(self.classes)), dtype=np.float32)
        for r, text in enumerate(texts):
            low = text.lower()
            idx: List[int] = []
            val: List[float] = []
            self._block(_word_terms(low), self.word_vocab, self.word_idf, 0, idx, val)
            self._block(_char_wb_terms(low), self.char_vocab, self.char_idf, self._nw, idx, val)
            logits = self.intercept.copy()
            if idx:
                logits += self.coef[:, idx] @ np.asarray(val, dtype=np.float32)
            logits -= logits.max()
            e = np.exp(logits)
            out[r] = e / e.sum()
        return out

    # -- (de)serialisation: JSON + npz, never pickle ----------------------------
    def save(self, json_path: str, meta: dict) -> None:
        np = self.np
        base = json_path[:-len(".json")] if json_path.endswith(".json") else json_path
        npz_path = base + ".npz"
        os.makedirs(os.path.dirname(json_path) or ".", exist_ok=True)
        tmp_npz = npz_path + ".tmp"
        with open(tmp_npz, "wb") as f:
            np.savez_compressed(f, coef=self.coef, intercept=self.intercept,
                                word_idf=self.word_idf, char_idf=self.char_idf)
        with open(tmp_npz, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        os.replace(tmp_npz, npz_path)
        doc = {"schema": _MODEL_SCHEMA, "classes": self.classes, "word_vocab": self.word_vocab,
               "char_vocab": self.char_vocab, "npz": os.path.basename(npz_path),
               "npz_sha256": digest, "meta": meta}
        tmp_json = json_path + ".tmp"
        with open(tmp_json, "w", encoding="utf-8") as f:
            json.dump(doc, f, separators=(",", ":"))
        os.replace(tmp_json, json_path)

    @classmethod
    def load(cls, json_path: str) -> Optional["LinearTextModel"]:
        import numpy as np
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            if doc.get("schema") != _MODEL_SCHEMA:
                return None
            npz_path = os.path.join(os.path.dirname(json_path), os.path.basename(doc["npz"]))
            with open(npz_path, "rb") as f:
                raw = f.read()
            if hashlib.sha256(raw).hexdigest() != doc["npz_sha256"]:
                return None                                   # tampered / corrupt
            import io
            arrs = np.load(io.BytesIO(raw), allow_pickle=False)
            m = cls(doc["classes"], doc["word_vocab"], arrs["word_idf"], doc["char_vocab"],
                    arrs["char_idf"], arrs["coef"], arrs["intercept"])
            m.meta = doc.get("meta", {})
            if m.coef.shape != (len(m.classes), len(m.word_vocab) + len(m.char_vocab)):
                return None
            return m
        except (OSError, ValueError, KeyError, TypeError):
            return None


# ─────────────────────────────────────────────────────────────────────────────
# Training data preparation
# ─────────────────────────────────────────────────────────────────────────────

# Seed examples for classes the legacy corpus never contained (all security /
# correctness warning classes) including clang phrasing, so the ML fallback can
# generalise beyond g++ wording.  Rules already handle the g++ originals.
_SEEDS: List[Tuple[str, str]] = [
    ("variable 'x' is uninitialized when used here", "uninitialized_memory"),
    ("'x' is used uninitialized in this function", "uninitialized_memory"),
    ("variable 'x' is used uninitialized whenever 'if' condition is false", "uninitialized_memory"),
    ("format string is not a string literal (potentially insecure)", "format_string"),
    ("format string argument is not a string literal", "format_string"),
    ("array index 10 is past the end of the array (which contains 10 elements)", "buffer_overflow"),
    ("array index -1 is before the beginning of the array", "buffer_overflow"),
    ("writing 28 bytes into a region of size 8 overflows the destination", "buffer_overflow"),
    ("'memcpy' will always overflow; destination buffer has size 4, but size argument is 16", "buffer_overflow"),
    ("'strcpy' will always overflow; destination buffer has size 8, but the source string has length 28", "buffer_overflow"),
    ("indirection of non-volatile null pointer will be deleted, not trap", "null_dereference"),
    ("null passed to a callee that requires a non-null argument", "null_dereference"),
    ("dereference of a null pointer", "null_dereference"),
    ("'free' called on pointer 'p' after it was already freed", "use_after_free"),
    ("memory 'p' used after being deleted", "use_after_free"),
    ("returning address of local variable or temporary: x", "dangling_pointer"),
    ("reference to stack memory associated with local variable 'x' returned", "dangling_pointer"),
    ("address of stack memory associated with local variable 'x' returned", "dangling_pointer"),
    ("'delete' applied to a pointer that was allocated with 'new[]'", "memory_mismatch"),
    ("'delete[]' applied to a pointer that was allocated with 'malloc'", "memory_mismatch"),
    ("implicit conversion loses integer precision: 'long' to 'int'", "narrowing_conversion"),
    ("implicit conversion changes signedness: 'int' to 'unsigned int'", "sign_conversion"),
    ("comparison of integers of different signs: 'int' and 'unsigned int'", "sign_conversion"),
    ("implicit conversion from 'double' to 'int' changes value", "narrowing_conversion"),
    ("integer overflow in expression of type 'int' results in a constant", "integer_overflow"),
    ("arithmetic on a pointer to an incomplete type may overflow", "integer_overflow"),
    ("remainder by zero is undefined", "division_by_zero"),
    ("division by zero is undefined", "division_by_zero"),
    ("ignoring return value of function declared with 'warn_unused_result' attribute", "unchecked_return"),
    ("ignoring return value of 'fread', declared with attribute warn_unused_result", "unchecked_return"),
    ("'gets' is deprecated: This function is provided for compatibility reasons only", "insecure_function"),
    ("'sprintf' is deprecated: This function is provided for compatibility reasons only", "insecure_function"),
    ("using the result of an assignment as a condition without parentheses", "logic_error"),
    ("misleading indentation; statement is not part of the previous 'if'", "logic_error"),
    ("self-comparison always evaluates to true", "logic_error"),
    ("unannotated fall-through between switch labels", "implicit_fallthrough"),
    ("declaration shadows a local variable", "shadowing"),
    ("unused variable 'x'", "unused_variable"),
    ("unused parameter 'argc'", "unused_variable"),
    ("moving a local object in a return statement prevents copy elision", "performance"),
    ("loop variable 'x' creates a copy from type 'const std::string'", "performance"),
    ("cast from 'const char *' to 'char *' drops const qualifier", "cast_safety"),
    ("cast from 'char *' to 'int *' increases required alignment from 1 to 4", "cast_safety"),
    ("use of undeclared identifier 'x'", "name_resolution"),
    ("unknown type name 'string'", "name_resolution"),
    ("no member named 'foo' in 'Bar'", "name_resolution"),
    ("expected ';' after expression", "syntax_error"),
    ("expected ')'", "syntax_error"),
    ("expected expression", "syntax_error"),
    ("extraneous closing brace ('}')", "syntax_error"),
    ("no matching function for call to 'f'", "type_error"),
    ("cannot initialize a variable of type 'int *' with an rvalue of type 'const char *'", "type_error"),
    ("invalid operands to binary expression ('S' and 'S')", "type_error"),
    ("assigning to 'int' from incompatible type 'const char [4]'", "type_error"),
    ("'iostream.h' file not found", "missing_include"),
    ("redefinition of 'x'", "redefinition"),
    ("cannot assign to variable 'x' with const-qualified type 'const int'", "access_error"),
    ("'x' is a private member of 'Foo'", "access_error"),
    ("non-void function does not return a value", "return_type_error"),
    ("control may reach end of non-void function", "return_type_error"),
    ("'break' statement not in loop or switch statement", "control_flow_error"),
    ("undefined reference to 'foo'", "linker_error"),
]


def _load_rows(training_data_file: str) -> List[Tuple[str, str]]:
    with open(training_data_file, "r", encoding="utf-8") as f:
        raw = json.load(f)
    rows: List[Tuple[str, str]] = []
    # feedback log written by dataset_logger (JSON Lines, rule-labelled only)
    log_path = os.path.join(os.path.dirname(training_data_file), "logged_diagnostics.jsonl")
    if os.path.exists(log_path):
        try:
            with open(log_path, "r", encoding="utf-8") as lf:
                for line in lf:
                    try:
                        r = json.loads(line)
                        if r.get("message") and r.get("category"):
                            rows.append((str(r["message"]), _normalize_category(str(r["category"]))))
                    except ValueError:
                        continue
        except OSError:
            pass
    if not isinstance(raw, list):
        return rows
    for row in raw:
        if not isinstance(row, dict):
            continue
        msg = row.get("raw_message") or row.get("message")
        cat = row.get("category")
        if not msg or not cat or not isinstance(msg, str):
            continue
        rows.append((msg, _normalize_category(str(cat))))
    return rows


def build_training_set(training_data_file: str, seeds: bool = True):
    """
    De-duplicate by identifier-masked template and *relabel with the rules*.

    Returns ``(templates, labels, stats)``.  A template's label is the rule
    label when a rule fires with confidence >= 0.9, otherwise the majority
    dataset label; the many mislabelled ``other`` rows therefore become their
    true class instead of poisoning the model.
    """
    rows = _load_rows(training_data_file)
    votes: Dict[str, Counter] = defaultdict(Counter)
    relabeled = 0
    for msg, ds_label in rows:
        tmpl = normalize_template(msg)
        if not tmpl:
            continue
        rule = classify_rules(msg, dtype="error")
        if rule and rule[1] >= 0.9:
            label = rule[0]
            if label != ds_label and legacy_of(label) != ds_label:
                relabeled += 1
        else:
            label = ds_label
        votes[tmpl][label] += 1
    if seeds:
        for msg, label in _SEEDS:
            votes[normalize_template(msg)][label] += 3
    templates, labels = [], []
    for tmpl, c in votes.items():
        templates.append(tmpl)
        labels.append(c.most_common(1)[0][0])
    stats = {"rows": len(rows), "templates": len(templates), "relabeled_rows": relabeled,
             "classes": dict(Counter(labels))}
    return templates, labels, stats


def _fit_sklearn(templates: List[str], labels: List[str]):
    """Train with scikit-learn and convert into the pickle-free ``LinearTextModel``."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    import numpy as np

    wv = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1, token_pattern=_WORD_TOKEN_RE.pattern,
                         dtype=np.float32)
    cv = TfidfVectorizer(lowercase=True, analyzer="char_wb", ngram_range=(3, 5), min_df=2,
                         dtype=np.float32)
    import scipy.sparse as sp
    Xw = wv.fit_transform(templates)
    Xc = cv.fit_transform(templates)
    X = sp.hstack([Xw, Xc]).tocsr()
    clf = LogisticRegression(max_iter=3000, C=20.0, class_weight="balanced")
    clf.fit(X, labels)
    return LinearTextModel(clf.classes_, {k: int(v) for k, v in wv.vocabulary_.items()}, wv.idf_,
                           {k: int(v) for k, v in cv.vocabulary_.items()}, cv.idf_,
                           clf.coef_, clf.intercept_)


# ─────────────────────────────────────────────────────────────────────────────
# Public classifier
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Classification:
    category: str
    confidence: float
    source: str                 # "rule:-Wxxx" | "rule:message" | "ml" | "ml:uncertain" | "none"
    uncertain: bool = False

    @property
    def legacy(self) -> str:
        return legacy_of(self.category)


class ErrorClassifier:
    def __init__(self, model_file: str = _DEFAULT_MODEL_FILE,
                 training_data_file: str = _DEFAULT_TRAINING_DATA_FILE) -> None:
        self.model_file = model_file
        self.training_data_file = training_data_file
        self._model: Optional[LinearTextModel] = None
        self._tried_load = False
        self._cache: Dict[Tuple, Classification] = {}
        self.last_report: dict = {}

    # -- lifecycle -------------------------------------------------------------
    def is_trained(self) -> bool:
        return self._model is not None or os.path.exists(self.model_file)

    def train(self) -> dict:
        if not os.path.exists(self.training_data_file):
            raise FileNotFoundError(f"Training data not found: {self.training_data_file}")
        t0 = time.time()
        templates, labels, stats = build_training_set(self.training_data_file)
        if len(templates) < 2:
            raise ValueError("Not enough training examples to train classifier.")
        self._model = _fit_sklearn(templates, labels)
        stats["train_seconds"] = round(time.time() - t0, 2)
        stats["trained_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._model.meta = stats
        self.last_report = stats
        self._cache.clear()
        print(f"[Classifier] Trained on {stats['templates']} distinct templates "
              f"({stats['rows']} rows, {stats['relabeled_rows']} relabelled) across "
              f"{len(stats['classes'])} categories in {stats['train_seconds']}s.")
        return stats

    def save(self) -> None:
        if self._model is None:
            raise ValueError("No trained model in memory to save.")
        meta = getattr(self._model, "meta", {}) or {}
        try:
            self._model.save(self.model_file, meta)
        except OSError:                                     # read-only install dir
            alt = os.path.join(os.path.expanduser("~"), ".cache", "gsc-model", "error_classifier.model.json")
            self._model.save(alt, meta)
            self.model_file = alt
        print(f"[Classifier] Model saved -> {self.model_file}")

    def load(self) -> bool:
        if self._model is not None:
            return True
        if self._tried_load and not os.path.exists(self.model_file):
            return False
        self._tried_load = True
        m = LinearTextModel.load(self.model_file) if os.path.exists(self.model_file) else None
        if m is None:
            alt = os.path.join(os.path.expanduser("~"), ".cache", "gsc-model", "error_classifier.model.json")
            m = LinearTextModel.load(alt) if os.path.exists(alt) else None
        self._model = m
        return m is not None

    def train_and_save(self) -> None:
        self.train()
        self.save()

    def _ensure_model(self) -> bool:
        if self.load():
            return True
        if os.path.exists(self.training_data_file):
            try:
                self.train_and_save()
            except Exception:                              # sklearn missing, etc.
                return False
        return self.load() or self._model is not None

    # -- inference -------------------------------------------------------------
    def classify(self, message: str, option: Optional[str] = None, dtype: str = "error",
                 instantiation: bool = False, ast_node: str = "") -> Classification:
        if not message:
            return Classification("other", 0.0, "none", True)
        key = (message, option, dtype, instantiation, ast_node)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        res = classify_rules(message, option, dtype)
        if res:
            cat, conf, src = res
            if cat == "type_error" and instantiation:
                cat = "template_error"
            out = Classification(cat, conf, src)
        else:
            out = self._ml(message, ast_node)
        if len(self._cache) > 4096:
            self._cache.clear()
        self._cache[key] = out
        return out

    def _ml(self, message: str, ast_node: str = "") -> Classification:
        if not self._ensure_model():
            return Classification("other", 0.0, "none", True)
        text = normalize_template(message)
        if ast_node:
            text = f"{ast_node} {text}"
        proba = self._model.predict_proba([text])[0]
        i = int(proba.argmax())
        conf = float(proba[i])
        if conf < ABSTAIN_BELOW:
            return Classification("other", conf, "ml:uncertain", True)
        return Classification(self._model.classes[i], conf, "ml")

    def predict(self, message: str, ast_node: str = "") -> Tuple[Optional[str], float]:
        """Backward-compatible ``(category, confidence)`` API."""
        if not message:
            return None, 0.0
        c = self.classify(message, ast_node=ast_node)
        return c.category, c.confidence

    def predict_many(self, messages: Sequence[str]) -> List[Tuple[str, float]]:
        return [self.predict(m) or ("other", 0.0) for m in messages]

    # -- evaluation (kept for the old CLI) ----------------------------------------
    def evaluate_on_tests(self, test_dir: str) -> dict:
        import subprocess
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from build_dataset_from_tests import FILE_LABELS  # type: ignore
        results: dict = {}
        detail = []
        for fname, expected_cat in FILE_LABELS.items():
            if expected_cat is None:
                continue
            fpath = os.path.join(test_dir, fname)
            if not os.path.exists(fpath):
                continue
            r = subprocess.run(["g++", "-std=c++17", "-Wall", fpath, "-o", os.devnull],
                               capture_output=True, text=True)
            cats = []
            for line in r.stderr.splitlines():
                m = re.match(r"^.+?:\d+(?::\d+)?:\s*(error|warning):\s*(.*)$", line.strip())
                if m:
                    c = self.classify(m.group(2).strip(), dtype=m.group(1))
                    cats.append(legacy_of(c.category))
            predicted = Counter(cats).most_common(1)[0][0] if cats else "other"
            ok = predicted == legacy_of(expected_cat)
            results.setdefault(expected_cat, {"correct": 0, "total": 0})
            results[expected_cat]["total"] += 1
            results[expected_cat]["correct"] += int(ok)
            detail.append((fname, expected_cat, predicted, "ok" if ok else "XX"))
        for fname, exp, pred, mark in detail:
            print(f"  {fname:<35} {exp:<22} {pred:<22} {mark}")
        tot = sum(v["total"] for v in results.values())
        cor = sum(v["correct"] for v in results.values())
        print(f"  OVERALL {cor}/{tot} ({100 * cor / tot if tot else 0:.0f}%)")
        return results


_default_classifier: Optional[ErrorClassifier] = None


def get_default_classifier() -> ErrorClassifier:
    global _default_classifier
    if _default_classifier is None:
        _default_classifier = ErrorClassifier()
    return _default_classifier


def predict_error_category(error_message: str) -> str:
    """Legacy helper kept for compatibility."""
    return get_default_classifier().classify(error_message).category


if __name__ == "__main__":
    import sys
    clf = ErrorClassifier()
    if "--evaluate" in sys.argv:
        clf.evaluate_on_tests(os.path.join(_PROJECT_ROOT, "test_cases"))
    else:
        clf.train_and_save()
