"""
auto_healer.py
--------------
Takes a structured error dict (category + line number + source code) and
returns a patched version of the source, or None if the error cannot be
auto-fixed.

Each public function follows the signature:
    fix_<category>(source: str, error: dict) -> str | None
"""

import re
from typing import Optional

# ── Symbol → header mapping ──────────────────────────────────────────────────
_SYMBOL_TO_HEADER = {
    # I/O
    "cout": "iostream", "cin": "iostream", "cerr": "iostream",
    "endl": "iostream", "ostream": "iostream", "istream": "iostream",
    "printf": "cstdio",  "scanf": "cstdio",  "fprintf": "cstdio",
    # strings
    "string": "string",  "getline": "string",
    # containers
    "vector": "vector",  "map": "map",       "set": "set",
    "unordered_map": "unordered_map",         "unordered_set": "unordered_set",
    "list": "list",      "queue": "queue",   "stack": "stack",
    "deque": "deque",    "array": "array",   "pair": "utility",
    "tuple": "tuple",    "optional": "optional",
    # algorithms
    "sort": "algorithm", "find": "algorithm", "max": "algorithm",
    "min": "algorithm",  "reverse": "algorithm", "count": "algorithm",
    "fill": "algorithm", "copy": "algorithm",
    # math
    "abs": "cmath",  "sqrt": "cmath",  "pow": "cmath",
    "ceil": "cmath", "floor": "cmath",
    # memory
    "unique_ptr": "memory", "shared_ptr": "memory", "make_unique": "memory",
    "make_shared": "memory",
    # misc
    "assert": "cassert",  "INT_MAX": "climits",  "INT_MIN": "climits",
    "size_t": "cstddef",  "nullptr": "",          "NULL": "cstdlib",
}

# std:: symbols most commonly needing prefix
_STD_SYMBOLS = {
    "cout", "cin", "cerr", "endl", "string", "vector", "map", "set",
    "pair", "tuple", "sort", "find", "max", "min", "reverse", "count",
    "make_unique", "make_shared", "unique_ptr", "shared_ptr",
    "list", "queue", "stack", "deque", "array",
    "unordered_map", "unordered_set", "optional",
}

_CPP_KEYWORDS = [
    "int", "float", "double", "char", "bool", "void", "return", "if", "else",
    "while", "for", "do", "switch", "case", "break", "continue", "class",
    "struct", "public", "private", "protected", "new", "delete", "true",
    "false", "const", "static", "namespace", "include", "template", "virtual",
]
_VALID_KEYWORDS = set(_CPP_KEYWORDS)


def _build_keyword_variant_map() -> dict[str, str]:
    """
    Map common typo variants back to canonical keywords.
    Includes the exact keyword plus single adjacent transpositions.
    """
    variants: dict[str, str] = {}
    for keyword in _CPP_KEYWORDS:
        variants[keyword] = keyword
        chars = list(keyword)
        for i in range(len(chars) - 1):
            swapped = chars.copy()
            swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
            variants["".join(swapped)] = keyword
    return variants


_KEYWORD_VARIANTS = _build_keyword_variant_map()


def _keyword_edit_distance(a: str, b: str, limit: int = 2) -> int:
    """Compute a bounded Levenshtein distance."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    if a == b:
        return 0

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        row_min = curr[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(
                prev[j] + 1,      # deletion
                curr[j - 1] + 1,   # insertion
                prev[j - 1] + cost # substitution
            ))
            row_min = min(row_min, curr[-1])
        if row_min > limit:
            return limit + 1
        prev = curr
    return prev[-1]


# ── Helper utilities ─────────────────────────────────────────────────────────

def _lines(source: str):
    return source.splitlines(keepends=True)


def _join(lines: list) -> str:
    return "".join(lines)


def _extract_symbol(message: str) -> Optional[str]:
    """Pull the first quoted identifier out of a GCC error message."""
    m = re.search(r"'([a-zA-Z_][a-zA-Z0-9_:]*)'", message)
    return m.group(1).split("::")[-1] if m else None


def _fix_keyword_typo(line: str, target_token: Optional[str] = None) -> Optional[str]:
    """
    Replace a misspelled C++ keyword if the token matches one of the keyword
    permutation variants or is close by edit distance.
    """
    if not target_token:
        return None
    if len(target_token) < 3:
        return None
    # Standard-library names (cout, cin, endl, ...) are never keyword typos.
    # Without this guard `cout` (edit distance 2 from `const`) was "healed"
    # into `const`, corrupting the user's code.
    if target_token in _STD_SYMBOLS or target_token in _SYMBOL_TO_HEADER:
        return None

    for match in re.finditer(r"\b[A-Za-z_]\w*\b", line):
        token = match.group(0)
        if token != target_token:
            continue
        if line[:match.start()].rstrip().endswith("::"):
            continue          # qualified name, not a bare keyword typo
        # Real keywords are never candidates for healing.
        if token in _VALID_KEYWORDS:
            continue

        canonical = _KEYWORD_VARIANTS.get(token)
        if canonical and canonical != token:
            return line[:match.start()] + canonical + line[match.end():]

        best_keyword = None
        best_distance = 3
        for keyword in _CPP_KEYWORDS:
            if token == keyword:
                continue
            if token[0].lower() != keyword[0].lower():
                continue
            if abs(len(token) - len(keyword)) > 2:
                continue
            distance = _keyword_edit_distance(token.lower(), keyword.lower(), limit=2)
            if distance < best_distance:
                best_distance = distance
                best_keyword = keyword
                if distance == 1:
                    break

        if best_keyword is not None and best_distance <= 2:
            return line[:match.start()] + best_keyword + line[match.end():]
    return None


def _append_missing_semicolon(line: str) -> Optional[str]:
    stripped = line.rstrip("\n\r")
    content = stripped.strip()
    if not content:
        return None
    if re.search(r"[;{},:]\s*$", stripped):
        return None
    if content.startswith(("#", "//")):
        return None
    if re.match(r"^(if|else|for|while|switch|case|do|class|struct|namespace|template|public|private|protected)\b", content):
        return None
    if re.search(r"\)\s*$", stripped) and re.match(r"^(if|for|while|switch)\b", content):
        return None
    return stripped + ";\n"


def _has_include(source: str, header: str) -> bool:
    return bool(re.search(rf'#include\s*[<"]{re.escape(header)}[>"]', source))


def _insert_include(source: str, header: str) -> str:
    """Insert #include at top, after any existing #include block."""
    inc_line = f"#include <{header}>\n"
    lines = _lines(source)
    last_inc = -1
    for i, line in enumerate(lines):
        if line.strip().startswith("#include"):
            last_inc = i
    insert_pos = last_inc + 1 if last_inc >= 0 else 0
    lines.insert(insert_pos, inc_line)
    return _join(lines)


_RAW_STRING_START = re.compile(r'(?:u8|u|U|L)?R"([^\s()\\]{0,16})\(')
_UNINIT_MESSAGE_RE = re.compile(
    r"used uninitialized"
    r"|may be used uninitialized"
    r"|is uninitialized when used"
    r"|uninitialized when used here"
    r"|wuninitialized"
    r"|uninitialized variable",
    re.IGNORECASE,
)
_UNDECLARED_IDENTIFIER_PHRASES = (
    "was not declared in this scope",
    "use of undeclared identifier",
    "undeclared identifier",
    "identifier not found",
    "is undefined",
)
_INTEGER_OVERFLOW_PHRASES = (
    "integer overflow",
    "overflow in expression",
    "result is undefined",
)
_DIVISION_BY_ZERO_PHRASES = (
    "division by zero",
    "divide by zero",
)
_STREAM_OPERATOR_PHRASES = (
    "no match for 'operator<<'",
    "no match for 'operator>>'",
    "operand types are 'std::istream'",
    "operand types are 'std::ostream'",
    "invalid operands to binary expression",
)
_UNUSED_VARIABLE_PHRASES = (
    "set but not used",
    "unused variable",
    "unused but set variable",
    "declared but never used",
)


def _is_undeclared_identifier_error(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in _UNDECLARED_IDENTIFIER_PHRASES)


def _is_integer_overflow_error(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in _INTEGER_OVERFLOW_PHRASES)


def _is_division_by_zero_error(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in _DIVISION_BY_ZERO_PHRASES)


def _is_stream_operator_error(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in _STREAM_OPERATOR_PHRASES)


def _is_unused_variable_error(message: str) -> bool:
    lowered = message.lower()
    return any(phrase in lowered for phrase in _UNUSED_VARIABLE_PHRASES)


def _infer_undeclared_initializer(line: str, var: str) -> Optional[str]:
    stripped = line.strip()
    assign_match = re.match(
        rf"^[A-Za-z_]\w*\s*$", stripped
    )
    if assign_match:
        return None

    direct_assign = re.match(
        rf"^\s*{re.escape(var)}\s*=\s*(.+?)\s*;\s*$",
        line,
    )
    if direct_assign:
        return direct_assign.group(1).strip()

    compound_assign = re.match(
        rf"^\s*{re.escape(var)}\s*([+\-*/%&|^]|<<|>>)=\s*(.+?)\s*;\s*$",
        line,
    )
    if compound_assign:
        return "0"

    increment = re.match(rf"^\s*(\+\+|--){re.escape(var)}\s*;\s*$", line)
    if increment:
        return "0"

    postfix = re.match(rf"^\s*{re.escape(var)}(\+\+|--)\s*;\s*$", line)
    if postfix:
        return "0"

    return None


def _brace_context(prefix_text: str, previous_text: str) -> str:
    """Best-effort label for an opening brace."""
    text = f"{previous_text} {prefix_text}".strip()
    if not text:
        return "anonymous"

    if re.search(r"\b(?:class|struct|enum|namespace)\b", text):
        return "class"
    if re.search(r"\bif\s*\(", text) or re.search(r"\belse\b", text):
        return "if"
    if re.search(r"\bfor\s*\(", text):
        return "for"
    if re.search(r"\bwhile\s*\(", text):
        return "while"

    func_like = re.search(
        r"\b(?:[A-Za-z_]\w*::)*[A-Za-z_]\w*\s*\([^;{}]*\)\s*"
        r"(?:const\b|noexcept\b|override\b|final\b|\->[^{};]+)?\s*$",
        text,
    )
    if func_like:
        return "function"

    return "anonymous"


def fix_missing_closing_braces(source: str, _error: dict = None) -> Optional[str]:
    """
    Repair missing trailing closing braces by tracking open blocks in LIFO
    order and appending the required braces at EOF.
    """
    lines = [
        line for line in _lines(source)
        if not re.search(r"}\s*//\s*closes\s+\w+\s+opened at line\s+\d+", line)
    ]
    if not lines:
        return source

    stack = []
    in_block_comment = False
    raw_delim = None
    previous_code_text = ""
    last_code_line_idx = None

    for line_idx, line in enumerate(lines):
        # Scan for function definition inside another unclosed function
        if stack:
            stripped = line.strip()
            # A sign is finding int main() or any return-type function signature at brace depth > 0
            # We look for something that looks like 'type name(args) {'
            is_func_sig = re.match(r'^(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*\s+)+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{', stripped)
            if is_func_sig and not re.match(r'^(if|for|while|switch|catch|return)\b', stripped):
                # Insert a } on the line immediately before that function definition
                lines.insert(line_idx, "}\n")
                return _join(lines)

        i = 0
        code_prefix = []
        while i < len(line):
            if raw_delim is not None:
                raw_end = line.find(")" + raw_delim + '"', i)
                if raw_end == -1:
                    i = len(line)
                    break
                i = raw_end + len(raw_delim) + 2
                raw_delim = None
                continue

            if in_block_comment:
                comment_end = line.find("*/", i)
                if comment_end == -1:
                    i = len(line)
                    break
                i = comment_end + 2
                in_block_comment = False
                continue

            if line.startswith("//", i):
                break
            if line.startswith("/*", i):
                in_block_comment = True
                i += 2
                continue

            raw_match = _RAW_STRING_START.match(line, i)
            if raw_match:
                raw_delim = raw_match.group(1)
                i = raw_match.end()
                continue

            ch = line[i]
            if ch in ("'", '"'):
                quote = ch
                i += 1
                while i < len(line):
                    if line[i] == "\\":
                        i += 2
                        continue
                    if line[i] == quote:
                        i += 1
                        break
                    i += 1
                continue

            if ch == "{":
                indent = re.match(r"[ \t]*", line).group(0)
                prefix_text = "".join(code_prefix).strip()
                context = _brace_context(prefix_text, previous_code_text)
                stack.append({
                    "line": line_idx + 1,
                    "indent": indent,
                    "context": context,
                })
                code_prefix.append(ch)
                i += 1
                continue

            if ch == "}":
                if stack:
                    stack.pop()
                code_prefix.append(ch)
                i += 1
                continue

            code_prefix.append(ch)
            i += 1

        code_text = "".join(code_prefix).strip()
        if code_text:
            previous_code_text = code_text
            last_code_line_idx = line_idx

    if not stack:
        return source

    insert_at = (last_code_line_idx + 1) if last_code_line_idx is not None else len(lines)
    closing_lines = [
        f"{entry['indent']}}} // closes {entry['context']} opened at line {entry['line']}\n"
        for entry in reversed(stack)
    ]
    lines[insert_at:insert_at] = closing_lines
    return _join(lines)


_PRIMITIVE_DEFAULTS = [
    (re.compile(r"\bbool\b"), " = false"),
    (re.compile(r"\bchar\b"), " = '\\0'"),
    (re.compile(r"\bfloat\b"), " = 0.0f"),
    (re.compile(r"\b(double|long double)\b"), " = 0.0"),
    (re.compile(r"\b(?:short|int|long|long long|unsigned|signed|size_t|ptrdiff_t|ssize_t)\b"), " = 0"),
]


def _initializer_for_declaration(line: str) -> Optional[str]:
    stripped = line.strip()
    if "=" in stripped or not stripped.endswith(";") or "(" in stripped:
        return None

    if re.search(r"\[[^\]]*\]\s*;$", stripped):
        return " = {}"

    if "*" in stripped:
        return " = nullptr"

    lhs = stripped[:-1].strip()
    for pattern, initializer in _PRIMITIVE_DEFAULTS:
        if pattern.search(lhs):
            return initializer

    if re.search(r"\bstruct\b|\bclass\b|\benum\b", lhs) or re.match(r"^[A-Z]\w*(?:::\w+)*\s+\w+$", lhs):
        return " = {}"

    return " = {}"


def fix_uninitialized_variable(source: str, error: dict) -> Optional[str]:
    """
    Initialize the variable reported as uninitialized at its declaration.
    This keeps the fix local and avoids adding an assignment at the use site.
    """
    msg = error.get("message", "")
    if not _UNINIT_MESSAGE_RE.search(msg):
        return None

    var = _extract_symbol(msg)
    if not var:
        return None

    lines = _lines(source)
    if not lines:
        return None

    start_idx = int(error.get("line") or len(lines)) - 1
    start_idx = max(0, min(start_idx, len(lines) - 1))

    decl_idx = None
    for i in range(start_idx, -1, -1):
        line = lines[i]
        if var not in line:
            continue
        stripped = line.strip()
        bare_init = re.match(r"^(?P<indent>\s*)(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+);\s*$", line)
        if not stripped.endswith(";") or "(" in line or ")" in line:
            continue
        if "=" in line and not bare_init:
            continue
        if re.match(r"^(return|if|for|while|switch|case|do|else|goto|throw|printf|fprintf|scanf|cout|cin|cerr)\b", stripped):
            continue
        match = re.search(rf"\b{re.escape(var)}\b", line)
        if not match:
            continue

        decl_idx = i
        break

    if decl_idx is None:
        return None

    line = lines[decl_idx]
    stripped = line.strip()
    bare_init = re.match(r"^(?P<indent>\s*)(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+);\s*$", line)
    if bare_init and bare_init.group("name") == var:
        fixed = f"{bare_init.group('indent')}auto {var} = {bare_init.group('rhs').strip()};\n"
        if fixed != line:
            lines[decl_idx] = fixed
            return _join(lines)

    if re.search(rf"\b{re.escape(var)}\s*\[", line):
        fixed = re.sub(
            rf"^(\s*.*?\b{re.escape(var)}\b(?:\s*(?:\[[^\]]*\]\s*)+))\s*;\s*$",
            rf"\1 = {{}};",
            line,
            count=1,
        )
    elif "*" in stripped:
        fixed = re.sub(
            rf"^(\s*)(?:[\w:<>*&\s]+?)\b{re.escape(var)}\b\s*;\s*$",
            rf"\1auto {var} = nullptr;",
            line,
            count=1,
        )
    else:
        init = _initializer_for_declaration(line)
        if init is None:
            return None
        fixed = re.sub(
            rf"^(\s*)(?:[\w:<>*&\s]+?)\b{re.escape(var)}\b\s*;\s*$",
            rf"\1auto {var}{init};",
            line,
            count=1,
        )

    if fixed == line:
        return None

    if not fixed.endswith(("\n", "\r")):
        fixed += "\n"

    lines[decl_idx] = fixed
    return _join(lines)


# ── Fix handlers ─────────────────────────────────────────────────────────────

def fix_missing_include(source: str, error: dict) -> Optional[str]:
    """Detect the missing symbol and insert the correct #include."""
    msg = error.get("message", "")
    sym = _extract_symbol(msg)
    if not sym:
        return None
    header = _SYMBOL_TO_HEADER.get(sym)
    if not header:
        return None
    if _has_include(source, header):
        return None  # already present
    return _insert_include(source, header)


def fix_syntax_error(source: str, error: dict) -> Optional[str]:
    """
    Attempt common syntax fixes:
      - Missing semicolon at end of a statement line
      - Assignment in condition (= → ==)
      - Broken main() signature
    """
    msg = error.get("message", "").lower()
    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx]
    stripped = line.rstrip("\n\r")
    target_token = _extract_symbol(error.get("message", ""))

    stream_fixed = fix_stream_operator(source, error)
    if stream_fixed is not None and stream_fixed != source:
        return stream_fixed

    typo_fixed = _fix_keyword_typo(line, target_token=target_token)
    if typo_fixed and typo_fixed != line:
        lines[idx] = _append_missing_semicolon(typo_fixed) or typo_fixed
        return _join(lines)

    # Fix: missing closing brace at end of input
    if "expected '}' at end of input" in msg or "expected '}'" in msg:
        patched = fix_missing_closing_braces(source, error)
        if patched is not None and patched != source:
            return patched
        lines.append("}\n")
        return _join(lines)

    # Fix: missing parenthesis
    if "expected ')'" in msg:
        stripped = line.rstrip("\n\r")
        if stripped.endswith(";"):
            lines[idx] = stripped[:-1] + ");\n"
        else:
            lines[idx] = stripped + ")\n"
        return _join(lines)

    # Fix: missing semicolon (skip lines ending with { } , or already ;)
    if re.search(r"expected\s+(?:['\"],['\"]\s+or\s+)?['\"]?;['\"]?", msg):
        # g++ often reports "expected ';' before 'X'" on the line that holds
        # X, i.e. the line AFTER the statement that lacks its semicolon.
        before = re.search(r"before\s+['\"]([^'\"]+)['\"]", error.get("message", ""))
        if before and stripped.lstrip().startswith(before.group(1)):
            prev = idx - 1
            while prev >= 0 and (not lines[prev].strip()
                                 or lines[prev].strip().startswith("//")):
                prev -= 1
            if prev >= 0:
                prev_fixed = _append_missing_semicolon(lines[prev])
                if prev_fixed:
                    lines[prev] = prev_fixed
                    return _join(lines)
        semicolon_fixed = _append_missing_semicolon(line)
        if semicolon_fixed:
            lines[idx] = semicolon_fixed
            return _join(lines)

    # Fix: assignment in boolean condition
    if "suggest parentheses" in msg or "assignment used as truth value" in msg:
        fixed = re.sub(
            r'(if\s*\()([^)]*?)(?<![=!<>])=(?!=)([^)]*?)(\))',
            r'\1\2==\3\4',
            stripped,
        )
        if fixed != stripped:
            lines[idx] = fixed + "\n"
            return _join(lines)

    # Fix: broken int main signature
    if "main" in stripped and "int main" not in stripped and "void main" not in stripped:
        lines[idx] = re.sub(r'\bmain\s*\(', 'int main(', stripped) + "\n"
        return _join(lines)

    # Fix: missing quotes (unterminated string/char)
    if "missing terminating" in msg:
        quote = '"' if '\"' in msg or '" character' in msg else "'"
        stripped = line.rstrip("\n\r;")
        lines[idx] = stripped + quote + ";\n"
        return _join(lines)

    return None


def fix_name_resolution(source: str, error: dict) -> Optional[str]:
    """
    Add std:: prefix to unresolved std symbols, or inject
    'using namespace std;' if multiple are missing.
    """
    msg = error.get("message", "")
    if _is_undeclared_identifier_error(msg):
        line_no = error.get("line")
        sym = _extract_symbol(msg)
        if line_no and sym:
            lines = _lines(source)
            idx = int(line_no) - 1
            if 0 <= idx < len(lines):
                typo_fixed = _fix_keyword_typo(lines[idx], target_token=sym)
                if typo_fixed and typo_fixed != lines[idx]:
                    lines[idx] = _append_missing_semicolon(typo_fixed) or typo_fixed
                    return _join(lines)
        return fix_undeclared_variable(source, error)

    sym = _extract_symbol(msg)
    if not sym:
        return None

    # "'cout' is not a member of 'std'" almost always means a missing header.
    if "is not a member of" in msg and sym in _SYMBOL_TO_HEADER:
        patched = fix_missing_include(source, error)
        if patched is not None and patched != source:
            return patched

    line_no = error.get("line")
    if line_no:
        lines = _lines(source)
        idx = int(line_no) - 1
        if 0 <= idx < len(lines):
            typo_fixed = _fix_keyword_typo(lines[idx], target_token=sym)
            if typo_fixed and typo_fixed != lines[idx]:
                lines[idx] = _append_missing_semicolon(typo_fixed) or typo_fixed
                return _join(lines)

    # Fix typo 'end1' or 'endI' -> 'endl'
    if sym in ("end1", "endI"):
        patched = re.sub(rf'\b{sym}\b', 'endl', source)
        return patched

    if sym not in _STD_SYMBOLS:
        return None

    # Count how many std symbols are bare (no prefix)
    bare_count = sum(
        1 for s in _STD_SYMBOLS
        if re.search(rf'(?<!:)\b{re.escape(s)}\b', source)
        and f"std::{s}" not in source
    )

    if bare_count >= 3 and "using namespace std;" not in source:
        # Insert 'using namespace std;' after the last #include
        lines = _lines(source)
        last_inc = -1
        for i, l in enumerate(lines):
            if l.strip().startswith("#include"):
                last_inc = i
        insert_pos = last_inc + 1 if last_inc >= 0 else 0
        lines.insert(insert_pos, "using namespace std;\n")
        return _join(lines)

    # Otherwise prefix just this symbol
    patched = re.sub(rf'(?<!:)\b{re.escape(sym)}\b', f"std::{sym}", source)
    if patched == source:
        return None
    return patched


def fix_undeclared_variable(source: str, error: dict) -> Optional[str]:
    """
    If a variable is used but never declared, insert a local auto declaration
    before the first reported use, reusing the current line's initializer
    when that intent is clear.
    """
    msg = error.get("message", "")
    if not _is_undeclared_identifier_error(msg):
        return None

    var = _extract_symbol(msg)
    if not var or var in _VALID_KEYWORDS:
        return None

    lines = _lines(source)
    line_no = error.get("line")
    if not line_no:
        return None

    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    # Don't add a duplicate declaration if the symbol already exists earlier.
    decl_pattern = re.compile(
        rf"\b(?:auto|bool|char|double|float|int|long|short|signed|unsigned|size_t|const|static|[\w:<>]+[*&\s]+)\b\s*\**\b{re.escape(var)}\b"
    )
    for existing in lines[:idx]:
        if decl_pattern.search(existing):
            return None

    indent = re.match(r"^(\s*)", lines[idx]).group(1)
    initializer = _infer_undeclared_initializer(lines[idx], var)
    if initializer is None:
        return None

    lines.insert(idx, f"{indent}auto {var} = {initializer};\n")
    return _join(lines)


def fix_integer_overflow(source: str, error: dict) -> Optional[str]:
    """
    Widen obvious overflowing arithmetic so the expression is evaluated in a
    larger integer type.
    """
    msg = error.get("message", "")
    if not _is_integer_overflow_error(msg):
        return None

    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx]

    fixed = re.sub(r"\bint\b", "long long", line, count=1)
    if fixed != line:
        lines[idx] = fixed
        return _join(lines)

    expr = re.search(r"(\b\w+\b)\s*(\+|\-|\*)\s*(\w+)", line)
    if expr:
        fixed = (
            line[:expr.start()] +
            f"(long long){expr.group(1)} {expr.group(2)} {expr.group(3)}" +
            line[expr.end():]
        )
        lines[idx] = fixed
        return _join(lines)

    return None


def inject_division_guard(source: str, error: dict) -> Optional[str]:
    """
    Insert a runtime zero check before a division whose divisor is a variable.
    """
    msg = error.get("message", "")
    if not _is_division_by_zero_error(msg):
        return None

    lines = _lines(source)
    var_match = re.search(r"'([A-Za-z_]\w*)'\s+is\s+0", msg)
    divisor = var_match.group(1) if var_match else None

    line_no = error.get("line")
    if divisor is None and line_no:
        idx = int(line_no) - 1
        if 0 <= idx < len(lines):
            line = lines[idx]
            match = re.search(r"/\s*([a-zA-Z_]\w*)", line)
            if match:
                divisor = match.group(1)

    if not divisor:
        return None

    guard_pattern = re.compile(rf"if\s*\(\s*{re.escape(divisor)}\s*==\s*0\s*\)")
    if guard_pattern.search(source):
        return None

    div_idx = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        if re.search(rf"/\s*{re.escape(divisor)}\b", line):
            div_idx = i
            break

    if div_idx is None:
        return None

    indent = re.match(r"^(\s*)", lines[div_idx]).group(1)
    guard = (
        f"{indent}if ({divisor} == 0) {{\n"
        f"{indent}    std::cerr << \"Error: division by zero\\n\";\n"
        f"{indent}    return 1;\n"
        f"{indent}}}\n"
    )
    lines.insert(div_idx, guard)
    return _join(lines)


def fix_division_by_zero(source: str, error: dict) -> Optional[str]:
    """
    Replace literal /0 with /1 as a safe placeholder, otherwise inject a guard
    for variable divisors.
    """
    msg = error.get("message", "")
    if not _is_division_by_zero_error(msg):
        return None

    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx]
    fixed = re.sub(r"/\s*0\b", "/ 1 /* FIX: was /0 */", line)
    if fixed != line:
        lines[idx] = fixed
        return _join(lines)

    return inject_division_guard(source, error)


def fix_stream_operator(source: str, error: dict) -> Optional[str]:
    """
    Repair flipped stream operators:
    std::cin << x  -> std::cin >> x
    std::cout >> x -> std::cout << x
    """
    msg = error.get("message", "")
    if not _is_stream_operator_error(msg):
        return None

    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx]
    if re.search(r"(?:std::)?cin\s*<<", line):
        fixed = re.sub(r"((?:std::)?cin\s*)<<", r"\1>>", line)
        if fixed != line:
            lines[idx] = fixed
            return _join(lines)

    if re.search(r"(?:std::)?cout\s*>>", line):
        fixed = re.sub(r"((?:std::)?cout\s*)>>", r"\1<<", line)
        if fixed != line:
            lines[idx] = fixed
            return _join(lines)

    return None


def _initializer_is_side_effect_free(init: str) -> bool:
    """True when deleting `T x = <init>;` cannot drop a call/assignment."""
    if re.search(r"\w\s*\(", init):             # function call / ctor call
        return False
    if re.search(r"\+\+|--|\bnew\b|\bdelete\b", init):
        return False
    if re.search(r"(?<![=!<>])=(?!=)", init):    # nested assignment
        return False
    return True


def fix_unused_variable(source: str, error: dict) -> Optional[str]:
    """
    Remove a trivially unused declaration, or suppress the warning with a
    void cast when deleting the line is not clearly safe (initializer has
    side effects, or the variable is assigned elsewhere: "set but not used").
    """
    msg = error.get("message", "")
    if not _is_unused_variable_error(msg):
        return None

    var = _extract_symbol(msg)
    if not var or var in _VALID_KEYWORDS:
        return None

    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx]
    is_set_but_unused = "set but not used" in msg.lower() or "unused but set" in msg.lower()

    if not is_set_but_unused:
        simple_decl = re.match(
            rf"^\s*(?:auto|int|float|double|char|bool|long|short)\s+{re.escape(var)}\s*=\s*(.+);\s*$",
            line,
        )
        if simple_decl and _initializer_is_side_effect_free(simple_decl.group(1)):
            lines.pop(idx)
            return _join(lines)

        bare_decl = re.match(
            rf"^\s*(?:auto|int|float|double|char|bool|long|short)\s+{re.escape(var)}\s*;\s*$",
            line,
        )
        if bare_decl:
            lines.pop(idx)
            return _join(lines)

    indent = re.match(r"^(\s*)", line).group(1)
    if idx + 1 < len(lines) and re.match(rf"^\s*\(void\){re.escape(var)}\s*;\s*$", lines[idx + 1]):
        return None
    lines.insert(idx + 1, f"{indent}(void){var};\n")
    return _join(lines)


def fix_type_error(source: str, error: dict) -> Optional[str]:
    """
    Insert static_cast where an implicit narrowing/widening conversion is
    the culprit, or add & to fix a pointer mismatch.
    """
    msg = error.get("message", "").lower()
    stream_fixed = fix_stream_operator(source, error)
    if stream_fixed is not None and stream_fixed != source:
        return stream_fixed

    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None
    line = lines[idx]

    # Fix: quote mismatch (char vs string)
    if "invalid conversion from 'const char*' to 'char'" in msg:
        # Used double quotes for a char: char c = "A"; -> 'A'
        fixed = re.sub(r'"([^"])"', r"'\1'", line)
        if fixed != line:
            lines[idx] = fixed
            return _join(lines)
    if "invalid conversion from 'int' to 'const char*'" in msg or "invalid conversion from 'char' to 'const char*'" in msg:
        # Used single quotes for a string: string s = 'A'; -> "A"
        fixed = re.sub(r"'([^']+)'", r'"\1"', line)
        if fixed != line:
            lines[idx] = fixed
            return _join(lines)

    # Fix: dot vs arrow for pointers
    if "maybe you meant to use '->'" in msg or ("request for member" in msg and "pointer type" in msg):
        m = re.search(r'([a-zA-Z0-9_]+)\.([a-zA-Z0-9_]+)', line)
        if m:
            fixed = line[:m.start()] + f"{m.group(1)}->{m.group(2)}" + line[m.end():]
            lines[idx] = fixed
            return _join(lines)

    # Fix: expression cannot be used as a function
    if "cannot be used as a function" in msg:
        m = re.search(r'([a-zA-Z_]\w*)\s*\(([^)]+)\)', line)
        if m:
            fixed = line[:m.start()] + f"{m.group(1)}[{m.group(2)}]" + line[m.end():]
            lines[idx] = fixed
            return _join(lines)

    # Fix: cannot convert from type to type
    conv = re.search(r"cannot convert '([^']+)' to '([^']+)'", error.get("message", ""))
    if conv:
        from_t, to_t = conv.group(1), conv.group(2)
        
        # Missing dereference: assigning pointer to value
        if from_t.endswith("*") and not to_t.endswith("*"):
            m = re.search(r'=\s*([a-zA-Z0-9_]+)', line)
            if m:
                var = m.group(1)
                lines[idx] = line[:m.start()] + f"= *{var}" + line[m.end():]
                return _join(lines)
        
        # Missing pointer pass (passing local by value instead of pointer)
        if "pointer" in msg or "address" in msg:
            m = re.search(r'\b([a-zA-Z_]\w*)\b\s*\)', line)
            if m:
                var = m.group(1)
                lines[idx] = line[:m.start()] + f"&{var})" + line[m.end():]
                return _join(lines)

        # Wrap RHS of assignment with static_cast
        m = re.search(r'=\s*(.+);', line)
        if m:
            rhs = m.group(1).strip()
            fixed_line = line[: m.start()] + f"= static_cast<{to_t}>({rhs});\n"
            lines[idx] = fixed_line
            return _join(lines)

    # Fix: taking address of variable for pointer param
    if "pointer" in msg or "address" in msg:
        m = re.search(r'\b([a-zA-Z_]\w*)\b\s*\)', line)
        if m:
            var = m.group(1)
            lines[idx] = line.replace(var + ")", f"&{var})", 1)
            return _join(lines)

    return None


def fix_return_type_error(source: str, error: dict) -> Optional[str]:
    """
    Insert a default 'return 0;' before the closing brace of a non-void
    function that is missing a return statement.
    """
    msg = error.get("message", "").lower()
    if "no return" not in msg and "return" not in msg:
        return None

    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    # Insert return 0; before the closing brace of the function
    for i in range(idx, -1, -1):
        if lines[i].strip() == "}":
            lines.insert(i, "    return 0;\n")
            return _join(lines)

    return None


def fix_redefinition(source: str, error: dict) -> Optional[str]:
    """
    Remove a duplicate variable declaration on the error line.
    Strips the type qualifier to turn it into an assignment.
    """
    line_no = error.get("line")
    if not line_no:
        return None

    lines = _lines(source)
    idx = int(line_no) - 1
    if idx < 0 or idx >= len(lines):
        return None

    line = lines[idx]
    # Match: int x = ...; → x = ...;
    m = re.match(r'^(\s*)(int|float|double|char|bool|auto|long|short|unsigned)\s+', line)
    if m:
        lines[idx] = m.group(1) + line[m.end():]
        return _join(lines)

    return None


# ── Cannot auto-fix categories ───────────────────────────────────────────────

def fix_linker_error(_source: str, _error: dict) -> None:
    """Linker errors require multi-file context — cannot auto-fix."""
    return None


def fix_access_error(_source: str, _error: dict) -> None:
    """Access control errors require design-level changes — cannot auto-fix."""
    return None


# ── Dispatch table ────────────────────────────────────────────────────────────

_HANDLERS = {
    "missing_include":  fix_missing_include,
    "missing_closing_brace": fix_missing_closing_braces,
    "uninitialized_memory": fix_uninitialized_variable,
    "syntax_error":     fix_syntax_error,
    "name_resolution":  fix_name_resolution,
    "type_error":       fix_type_error,
    "return_type_error": fix_return_type_error,
    "redefinition":     fix_redefinition,
    "integer_overflow": fix_integer_overflow,
    "division_by_zero": fix_division_by_zero,
    "stream_operator":  fix_stream_operator,
    "unused_variable":  fix_unused_variable,
    "linker_error":     fix_linker_error,
    "access_error":     fix_access_error,
}

# Categories where we skip directly to user guidance (no point retrying).
# NOTE: "unused_variable" used to be listed here even though a working
# fix_unused_variable handler exists; the loop therefore never selected it.
# It is now fixable.  ("undeclared_variable" is not a category anything emits;
# fix_undeclared_variable is reached via fix_name_resolution.)
UNFIXABLE_CATEGORIES = {"linker_error", "access_error"}


def attempt_fix(source: str, error: dict) -> Optional[str]:
    """
    Main entry point.
    Returns patched source string, or None if no fix could be applied.
    """
    category = error.get("category", "other")
    msg = error.get("message", "").lower()

    # Rule: Treat "function definition not allowed here" as missing_closing_brace
    if "not allowed here" in msg or category == "missing_closing_brace":
        patched = fix_missing_closing_braces(source, error)
        if patched is not None and patched != source:
            return patched

    # Fine-grained categories (e.g. template_error, control_flow_error) fall back to
    # their legacy parent so existing fixers keep working.
    from taxonomy import legacy_of
    handler = _HANDLERS.get(category) or _HANDLERS.get(legacy_of(category))
    if handler is not None:
        patched = handler(source, error)
        if patched is not None and patched != source:
            return patched

    if _is_stream_operator_error(msg):
        return fix_stream_operator(source, error)
    if _is_unused_variable_error(msg):
        return fix_unused_variable(source, error)
    if _is_integer_overflow_error(msg):
        return fix_integer_overflow(source, error)
    if _is_division_by_zero_error(msg):
        return fix_division_by_zero(source, error)
    if _is_undeclared_identifier_error(msg):
        return fix_name_resolution(source, error)
    if _UNINIT_MESSAGE_RE.search(msg):
        return fix_uninitialized_variable(source, error)

    return None
