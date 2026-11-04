"""
dataset_logger.py
-----------------
Feeds *new, trustworthy* diagnostics back into the training corpus.

The first version parsed and rewrote the whole 14.7 MB ``training_data.json``
on **every error** (non-atomically, so a crash or two parallel runs could
corrupt it) and stored the model's *own prediction* as the ground-truth label,
which lets mistakes reinforce themselves and lets an attacker poison the
training set with crafted messages.

Now:
  * append-only JSON Lines file (``data/logged_diagnostics.jsonl``): O(1) per
    error, a torn write can lose at most one line;
  * only diagnostics whose category was decided by a deterministic **rule**
    are logged - never ML guesses or uncertain results;
  * de-duplicated by identifier-masked template (in-memory set, loaded once);
  * messages are length-capped and stripped of control characters;
  * ``GSC_DISABLE_DATASET_LOGGING=1`` still turns it off completely.
"""

import json
import os
import re
from typing import Optional, Set

from taxonomy import normalize_template

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DATA_FILE = os.path.join(DATA_DIR, "training_data.json")          # curated corpus (read-only here)
LOG_FILE = os.path.join(DATA_DIR, "logged_diagnostics.jsonl")      # append-only feedback log

_seen: Optional[Set[str]] = None
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_MAX_LEN = 400


def _load_seen() -> Set[str]:
    global _seen
    if _seen is None:
        _seen = set()
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        _seen.add(normalize_template(json.loads(line).get("message", "")))
                    except ValueError:
                        continue
        except OSError:
            pass
    return _seen


def log_example(error) -> None:
    if os.environ.get("GSC_DISABLE_DATASET_LOGGING") == "1":
        return
    source = getattr(error, "source", None) or ""
    category = getattr(error, "category", None)
    if not category or not source.startswith("rule:"):
        return                                   # never learn from ML guesses
    raw = _CTRL.sub("", (getattr(error, "message", "") or ""))[:_MAX_LEN]
    if not raw:
        return
    tmpl = normalize_template(raw)
    seen = _load_seen()
    if not tmpl or tmpl in seen:
        return
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        entry = {"message": raw, "category": category, "source": source,
                 "ast_node": getattr(error, "ast_node", "") or ""}
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        seen.add(tmpl)
    except OSError:
        pass
