import re
from typing import Optional


CPP_KEYWORDS = {
    "int", "float", "double", "char", "bool", "void", "return", "if", "else",
    "while", "for", "do", "switch", "case", "break", "continue", "class",
    "struct", "public", "private", "protected", "new", "delete", "true",
    "false", "const", "static", "namespace", "include", "template", "virtual",
}
UNDECLARED_IDENTIFIER_PHRASES = (
    "was not declared in this scope",
    "use of undeclared identifier",
    "undeclared identifier",
    "identifier not found",
    "is undefined",
)
INTEGER_OVERFLOW_PHRASES = (
    "integer overflow",
    "overflow in expression",
    "result is undefined",
)
DIVISION_BY_ZERO_PHRASES = (
    "division by zero",
    "divide by zero",
)
STREAM_OPERATOR_PHRASES = (
    "no match for 'operator<<'",
    "no match for 'operator>>'",
    "operand types are 'std::istream'",
    "operand types are 'std::ostream'",
    "invalid operands to binary expression",
)
UNUSED_VARIABLE_PHRASES = (
    "set but not used",
    "unused variable",
    "unused but set variable",
    "declared but never used",
    "-wunused-but-set-variable",
    "-wunused-variable",
)


def _extract_symbol(message: str) -> Optional[str]:
    match = re.search(r"'([a-zA-Z_][a-zA-Z0-9_:]*)'", message)
    return match.group(1).split("::")[-1] if match else None


def _format_error(line: str, fix: str, why: str, error: str) -> str:
    return (
        f"ERROR: {error}\n"
        f"LINE:  {line.rstrip()}\n"
        f"FIX:   {fix}\n"
        f"WHY:   {why}"
    )


def _format_ask(error: str, reason: str, question: str) -> str:
    return (
        f"ERROR: {error}\n"
        f"FIX:   Cannot auto-fix — {reason}\n"
        f"ASK:   {question}"
    )


def _classify(message: str) -> str:
    lowered = message.lower()
    if any(phrase in lowered for phrase in UNDECLARED_IDENTIFIER_PHRASES):
        return "undeclared variable"
    if any(phrase in lowered for phrase in INTEGER_OVERFLOW_PHRASES):
        return "integer overflow"
    if any(phrase in lowered for phrase in DIVISION_BY_ZERO_PHRASES):
        return "division by zero"
    if any(phrase in lowered for phrase in STREAM_OPERATOR_PHRASES):
        return "stream operator"
    if any(phrase in lowered for phrase in UNUSED_VARIABLE_PHRASES):
        return "unused variable"
    if "expected" in lowered and ";" in lowered:
        return "missing semicolon"
    if "cannot convert" in lowered or "invalid conversion" in lowered:
        return "wrong type"
    if "no return statement" in lowered or "control reaches end of non-void function" in lowered:
        return "missing return"
    if any(phrase in lowered for phrase in UNDECLARED_IDENTIFIER_PHRASES) and any(sym in lowered for sym in ("cout", "cin", "cerr", "endl")):
        return "missing include"
    return "other"


def _attempted_categories(history: list[dict]) -> set[str]:
    attempted = set()
    for item in history:
        error = item.get("error") or {}
        category = error.get("category")
        if category:
            attempted.add(category)
    return attempted


def _nearest_keyword(token: str) -> Optional[str]:
    if len(token) < 3:
        return None
    best = None
    best_score = 3
    for keyword in CPP_KEYWORDS:
        if token[0].lower() != keyword[0].lower():
            continue
        if abs(len(token) - len(keyword)) > 2:
            continue
        score = _bounded_distance(token.lower(), keyword.lower(), 2)
        if score < best_score:
            best = keyword
            best_score = score
    return best if best_score <= 2 else None


def _bounded_distance(a: str, b: str, limit: int) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        row_min = curr[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
            row_min = min(row_min, curr[-1])
        if row_min > limit:
            return limit + 1
        prev = curr
    return prev[-1]


def _infer_undeclared_initializer(line: str, symbol: str) -> Optional[str]:
    direct_assign = re.match(rf"^\s*{re.escape(symbol)}\s*=\s*(.+?)\s*;\s*$", line)
    if direct_assign:
        return direct_assign.group(1).strip()

    compound_assign = re.match(
        rf"^\s*{re.escape(symbol)}\s*([+\-*/%&|^]|<<|>>)=\s*(.+?)\s*;\s*$",
        line,
    )
    if compound_assign:
        return "0"

    if re.match(rf"^\s*(\+\+|--){re.escape(symbol)}\s*;\s*$", line):
        return "0"
    if re.match(rf"^\s*{re.escape(symbol)}(\+\+|--)\s*;\s*$", line):
        return "0"
    return None


def suggest_failed_heal(error: dict, source: str, history: list[dict]) -> str:
    message = error.get("message", "")
    line_no = int(error.get("line") or 0)
    lines = source.splitlines()
    line = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
    category = _classify(message)
    attempted = _attempted_categories(history)

    if category == "undeclared variable":
        symbol = _extract_symbol(message)
        if not symbol:
            return _format_ask(
                "The compiler reports an undeclared identifier.",
                "the missing name could not be identified from the error text",
                "What variable or function name did you intend to use here?",
            )
        keyword_guess = _nearest_keyword(symbol)
        if keyword_guess:
            return _format_error(
                line,
                line.replace(symbol, keyword_guess, 1).rstrip(),
                f"This fixes the misspelled C++ keyword so the compiler can parse the statement correctly.",
                f"The token '{symbol}' is not a declared name here.",
            )
        if symbol in CPP_KEYWORDS:
            return _format_ask(
                f"The compiler reports '{symbol}' as undeclared on this line.",
                "the token is already a valid C++ keyword, so the intended code is unclear",
                "Did you mean a variable name, or is there a typo elsewhere on this line?",
            )
        initializer = _infer_undeclared_initializer(line, symbol)
        if initializer is None:
            return _format_ask(
                f"The variable '{symbol}' is used before it is declared.",
                "the reported line does not show a safe initializer to infer its type from",
                f"What initial value should '{symbol}' have before this line runs?",
            )
        return _format_error(
            line,
            f"auto {symbol} = {initializer};",
            "This declares the variable with the same value used on the reported line so the compiler can infer the intended type.",
            f"The variable '{symbol}' is used before it is declared.",
        )

    if category == "missing semicolon":
        fixed = line.rstrip()
        if not fixed.endswith(";"):
            fixed += ";"
        return _format_error(
            line,
            fixed,
            "C++ statements must end with a semicolon so the compiler knows where the statement stops.",
            "The compiler reached the next token before it found the statement terminator.",
        )

    if category == "missing return":
        return _format_error(
            line,
            "return 0;",
            "A non-void function must return a value on every control path.",
            "The function can reach its end without returning the required value.",
        )

    if category == "wrong type":
        conv = re.search(r"cannot convert '([^']+)' to '([^']+)'", message)
        assign = re.search(r'=\s*(.+?);?\s*$', line)
        if conv and assign:
            target_type = conv.group(2)
            value = assign.group(1).rstrip(";")
            fixed = re.sub(r'=\s*.+?;?\s*$', f"= static_cast<{target_type}>({value});", line.rstrip())
            return _format_error(
                line,
                fixed,
                "This makes the conversion explicit on the reported line so the assigned value matches the expected type.",
                "The value on this line has the wrong type for the target expression.",
            )
        return _format_ask(
            "The compiler found a type mismatch on this line.",
            "the exact conversion intent is unclear from the current code",
            "What type should this expression evaluate to?",
        )

    if category == "integer overflow":
        widened = re.sub(r"\bint\b", "long long", line.rstrip(), count=1)
        if widened != line.rstrip():
            return _format_error(
                line,
                widened,
                "This widens the arithmetic on the reported line so the value can fit without overflowing int.",
                "The arithmetic on this line overflows the range of int.",
            )
        expr = re.search(r"(\b\w+\b)\s*(\+|\-|\*)\s*(\w+)", line)
        if expr:
            fixed = (
                line[:expr.start()] +
                f"(long long){expr.group(1)} {expr.group(2)} {expr.group(3)}" +
                line[expr.end():]
            ).rstrip()
            return _format_error(
                line,
                fixed,
                "This forces the expression to be evaluated in a wider type before the arithmetic happens.",
                "The arithmetic on this line overflows the range of int.",
            )

    if category == "division by zero":
        literal_fix = re.sub(r"/\s*0\b", "/ 1 /* FIX: was /0 */", line.rstrip())
        if literal_fix != line.rstrip():
            return _format_error(
                line,
                literal_fix,
                "This removes the literal zero divisor so the expression is no longer undefined.",
                "This line divides by a literal zero.",
            )
        divisor = re.search(r"/\s*([A-Za-z_]\w*)", line)
        if divisor:
            var = divisor.group(1)
            return _format_error(
                line,
                f"if ({var} == 0) return 1;",
                "This guards the divisor before the division runs so the program can avoid undefined behavior.",
                "This line may divide by zero at runtime.",
            )

    if category == "stream operator":
        if re.search(r"cin\s*<<", line):
            fixed = re.sub(r"(cin\s*)<<", r"\1>>", line.rstrip())
            return _format_error(
                line,
                fixed,
                "std::cin reads input, so it must use >> rather than << on this line.",
                "This line uses the wrong stream operator for an input stream.",
            )
        if re.search(r"cout\s*>>", line):
            fixed = re.sub(r"(cout\s*)>>", r"\1<<", line.rstrip())
            return _format_error(
                line,
                fixed,
                "std::cout writes output, so it must use << rather than >> on this line.",
                "This line uses the wrong stream operator for an output stream.",
            )

    if category == "unused variable":
        symbol = _extract_symbol(message)
        if symbol:
            if re.match(
                rf"^\s*(?:auto|int|float|double|char|bool|long|short)\s+{re.escape(symbol)}\s*(?:=\s*.+)?;\s*$",
                line,
            ):
                return _format_error(
                    line,
                    "(remove this line)",
                    "The variable is never read, so deleting the declaration line removes dead code without changing later behavior.",
                    f"The variable '{symbol}' is assigned but never used.",
                )
            return _format_error(
                line,
                f"(void){symbol};",
                "Casting the variable to void marks it as intentionally unused and suppresses the warning.",
                f"The variable '{symbol}' is assigned but never used.",
            )

    lowered_message = message.lower()
    if "cout" in lowered_message and any(phrase in lowered_message for phrase in UNDECLARED_IDENTIFIER_PHRASES):
        fixed = re.sub(r'(?<!:)\bcout\b', 'std::cout', line.rstrip(), count=1)
        return _format_error(
            line,
            fixed,
            "This qualifies the stream with the standard namespace so the compiler can resolve it.",
            "The standard output stream is being used without a visible declaration.",
        )

    if "missing_include" in attempted:
        return _format_ask(
            "The previous automatic include fix did not resolve the compiler error.",
            "the intended library symbol still is not clear from the current source",
            "Which header or library is this symbol supposed to come from?",
        )

    return _format_ask(
        "The compiler error could not be mapped to a safe single-line fix.",
        "the intended correction is unclear after the automatic healing attempts already failed",
        "What behavior do you want on this line so the fix can be chosen safely?",
    )
