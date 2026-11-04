"""
error_normalizer.py
====================
Compiler Error Normalization and Explanation Engine.

Produces TWO distinct outputs from a raw compiler error message:

1. DATASET OUTPUT  — abstract, semantic, consistent (for ML training)
2. USER OUTPUT     — concrete, readable, friendly (for GUI/CLI display)

Rules:
  - NEVER store raw compiler-specific tokens in the dataset if they can be generalized.
  - ALWAYS preserve meaning, not surface syntax.
  - Dataset = abstract + consistent
  - UI     = concrete + readable
"""

import re
from typing import Tuple

# ---------------------------------------------------------------------------
# Token normalization table
# Maps raw compiler tokens → abstract semantic labels (for dataset storage)
# ---------------------------------------------------------------------------
_TOKEN_MAP = [
    # Punctuation / syntax tokens
    (r"';'",              "statement terminator"),
    (r"'}'",              "closing brace"),
    (r"'{'",              "opening brace"),
    (r"'\)'",             "closing parenthesis"),
    (r"'\('",             "opening parenthesis"),
    (r"'\]'",             "closing bracket"),
    (r"'\['",             "opening bracket"),
    (r"':'",              "colon"),
    (r"','",              "comma"),
    (r"'>>'",             "right shift / closing template bracket"),

    # Type tokens
    (r"'(int|float|double|char|bool|long|short|unsigned|signed|void|auto)'",
                          "type"),

    # Identifier-class tokens
    (r"'[a-zA-Z_][a-zA-Z0-9_]*'",   "identifier"),

    # Operator tokens
    (r"'[+\-\*/%=<>!&|^~]+='?",     "operator"),
]


def _ui_token(token: str) -> str:
    """Return a readable article+name for a raw token, e.g. ';' → 'a ;'"""
    clean = token.strip("'\"")
    vowels = "aeiouAEIOU"
    article = "an" if clean and clean[0] in vowels else "a"
    return f"{article} '{clean}'"


def normalize_for_dataset(raw_message: str) -> str:
    """
    Convert a raw compiler error message into a generalized, semantic form
    suitable for dataset storage and ML training.

    Example:
        "expected ';' after expression"
        → "expected statement terminator after expression"
    """
    result = raw_message
    for pattern, replacement in _TOKEN_MAP:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    # Collapse extra whitespace
    result = re.sub(r" {2,}", " ", result).strip()
    return result


def build_ui_message(raw_message: str) -> str:
    """
    Convert a raw compiler error message into a human-readable sentence
    for display in the GUI or CLI.

    Example:
        "expected ';' after expression"
        → "The compiler expected a ';' after the expression."
    """
    msg = raw_message.strip()

    # ── pattern: expected '<token>' [after/before] <context> ──
    m = re.match(
        r"expected\s+('.*?')\s*(after|before)?\s*(.*)",
        msg,
        re.IGNORECASE,
    )
    if m:
        token_raw, prep, context = m.group(1), m.group(2), m.group(3).strip()
        token_ui = _ui_token(token_raw)
        if prep and context:
            return f"The compiler expected {token_ui} {prep} {context}."
        elif context:
            return f"The compiler expected {token_ui} ({context})."
        else:
            return f"The compiler expected {token_ui}."

    # ── pattern: '<token>' was not declared in this scope ──
    m = re.match(r"'(.+?)'\s+was not declared in this scope", msg, re.IGNORECASE)
    if m:
        return f"'{m.group(1)}' was used but has not been declared in this scope."

    # ── pattern: use of undeclared identifier ──
    m = re.match(r"use of undeclared identifier '(.+?)'", msg, re.IGNORECASE)
    if m:
        return f"The identifier '{m.group(1)}' was used before it was declared."

    # ── pattern: cannot convert / invalid conversion ──
    m = re.match(
        r"(cannot convert|invalid conversion)\s+(?:from\s+)?'(.+?)'\s+to\s+'(.+?)'",
        msg,
        re.IGNORECASE,
    )
    if m:
        return (
            f"A value of type '{m.group(2)}' cannot be used where "
            f"'{m.group(3)}' is required."
        )

    # ── pattern: no matching function for call to '<fn>' ──
    m = re.match(r"no matching function for call to '(.+?)'", msg, re.IGNORECASE)
    if m:
        return (
            f"No overload of '{m.group(1)}' matches the arguments you provided. "
            f"Check the function signature and argument types."
        )

    # ── pattern: redeclaration / redefinition ──
    m = re.match(r"(redeclaration|redefinition) of '(.+?)'", msg, re.IGNORECASE)
    if m:
        action = "declared again" if "redeclaration" in m.group(1).lower() else "defined again"
        return f"'{m.group(2)}' has already been {action} in this scope."

    # ── pattern: '<token>' has not been declared ──
    m = re.match(r"'(.+?)' has not been declared", msg, re.IGNORECASE)
    if m:
        return f"'{m.group(1)}' is referenced but has not been declared."

    # ── pattern: return-type mismatch ──
    if re.search(r"return.*type|cannot.*return", msg, re.IGNORECASE):
        return f"The return value does not match the function's declared return type."

    # ── fallback: capitalize and append period ──
    sentence = msg[0].upper() + msg[1:] if msg else msg
    if not sentence.endswith("."):
        sentence += "."
    return sentence


# ---------------------------------------------------------------------------
# Public entry-point
# ---------------------------------------------------------------------------

def normalize_error(raw_message: str) -> Tuple[str, str]:
    """
    Main entry point.

    Returns:
        (dataset_message, ui_message)

        dataset_message — abstract, semantic, suitable for training_data.json
        ui_message      — readable, friendly, suitable for GUI/CLI display
    """
    dataset_msg = normalize_for_dataset(raw_message)
    ui_msg = build_ui_message(raw_message)
    return dataset_msg, ui_msg
