"""
lexer.py
--------
A small, fast, dependency-free C++ lexer shared by every static-analysis
component (pre-compile sanitizer, security analyzer, performance analyzer,
delimiter pre-flight).

Why it exists
~~~~~~~~~~~~~
Before this module the project had three independent "strip comments and
strings" implementations, all line-oriented regex hacks.  They disagreed with
each other and broke on multi-line statements, raw strings and C++14 digit
separators (``1'000'000``).  This lexer is the single source of truth:

* comments are dropped, string/char/raw-string literals are single tokens;
* every token carries ``line`` / ``col`` (1-based) and an absolute offset;
* preprocessor directives (with ``\\`` continuations) are single tokens;
* ``blank_source()`` returns the source with comments/literal *contents*
  blanked but with identical length and line structure, so offsets computed on
  the blanked text map 1:1 onto the original file.

The lexer never raises: malformed input degrades into ``other`` tokens.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Optional, Sequence

# Token kinds
IDENT, NUMBER, STRING, CHAR, PUNCT, PREPROC, OTHER = (
    "ident", "number", "string", "char", "punct", "preproc", "other")

_ENC = r"(?:u8|u|U|L)?"

_TOKEN_RE = re.compile(
    rf"""
      (?P<pp>^[ \t]*\#(?:[^\n\\]|\\\n|\\.)*)
    | (?P<ws>[ \t\r\f\v\n]+)
    | (?P<lcom>//(?:[^\n\\]|\\\n|\\.)*)
    | (?P<bcom>/\*.*?(?:\*/|\Z))
    | (?P<raw>{_ENC}R"(?P<rd>[^\s()\\]{{0,16}})\(.*?\)(?P=rd)")
    | (?P<str>{_ENC}"(?:\\.|[^"\\\n])*"?)
    | (?P<chr>{_ENC}'(?:\\.|[^'\\\n])+'?)
    | (?P<num>\.?\d(?:[eEpP][+-]|[\w.]|'(?=\w))*)
    | (?P<id>[A-Za-z_]\w*)
    | (?P<punct>->\*|\.\.\.|<<=|>>=|<=>|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||::
               |\+=|-=|\*=|/=|%=|&=|\|=|\^=|\.\*|[-+*/%&|^~!<>=?:;,.(){{}}\[\]\#])
    | (?P<other>.)
    """,
    re.X | re.S | re.M,
)


@dataclass(slots=True)
class Token:
    kind: str
    text: str
    line: int
    col: int
    pos: int          # absolute character offset of the first char

    def __repr__(self) -> str:                      # pragma: no cover
        return f"{self.kind}:{self.text!r}@{self.line}:{self.col}"


def tokenize(source: str, keep_preproc: bool = True) -> List[Token]:
    """Tokenize ``source``.  Comments and whitespace are discarded."""
    tokens: List[Token] = []
    append = tokens.append
    line = 1
    line_start = 0
    for m in _TOKEN_RE.finditer(source):
        kind = m.lastgroup
        text = m.group(0)
        start = m.start()
        if kind in ("ws", "lcom", "bcom"):
            nl = text.count("\n")
            if nl:
                line += nl
                line_start = start + text.rfind("\n") + 1
            continue
        if kind == "rd":                       # inner group name leaked
            kind = "raw"
        col = start - line_start + 1
        if kind == "pp":
            col += len(text) - len(text.lstrip(" \t"))
            if keep_preproc:
                append(Token(PREPROC, text.strip(), line, col, start))
        elif kind == "id":
            append(Token(IDENT, text, line, col, start))
        elif kind == "num":
            append(Token(NUMBER, text, line, col, start))
        elif kind in ("str", "raw"):
            append(Token(STRING, text, line, col, start))
        elif kind == "chr":
            append(Token(CHAR, text, line, col, start))
        elif kind == "punct":
            append(Token(PUNCT, text, line, col, start))
        else:
            append(Token(OTHER, text, line, col, start))
        nl = text.count("\n")
        if nl:
            line += nl
            line_start = start + text.rfind("\n") + 1
    return tokens


def blank_source(source: str) -> str:
    """
    Return ``source`` with comments and the *contents* of string/char
    literals replaced by spaces.  Length and newline positions are preserved.
    Preprocessor lines are kept verbatim (callers need ``#include`` targets).
    """
    out: List[str] = []
    last = 0
    for m in _TOKEN_RE.finditer(source):
        kind = m.lastgroup
        if kind == "rd":
            kind = "raw"
        if kind in ("lcom", "bcom"):
            out.append(source[last:m.start()])
            out.append(re.sub(r"[^\n]", " ", m.group(0)))
            last = m.end()
        elif kind in ("str", "raw", "chr"):
            text = m.group(0)
            out.append(source[last:m.start()])
            # keep the quotes so '"" ' stays a literal, blank the middle
            q = text[:1] if text[:1] in "\"'" else None
            if q is None:                     # prefixed / raw literal
                idx = min([i for i in (text.find('"'), text.find("'")) if i >= 0] or [0])
                head, body = text[:idx + 1], text[idx + 1:]
            else:
                head, body = q, text[1:]
            out.append(head + re.sub(r"[^\n]", " ", body))
            last = m.end()
    out.append(source[last:])
    return "".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# Structure helpers
# ─────────────────────────────────────────────────────────────────────────────

_OPEN = {"(": ")", "[": "]", "{": "}"}
_CLOSE = {v: k for k, v in _OPEN.items()}


def check_delimiters(tokens: Sequence[Token]) -> List[dict]:
    """
    Detect unbalanced ``() [] {}``.  Returns a list of problems, each a dict
    ``{line, col, message, kind}``.  g++ typically reports these far away from
    the real cause (e.g. a missing ``}`` is reported at EOF), so pointing at
    the *opening* delimiter that was never closed is far more useful.
    """
    stack: List[Token] = []
    problems: List[dict] = []
    for t in tokens:
        if t.kind != PUNCT:
            continue
        if t.text in _OPEN:
            stack.append(t)
        elif t.text in _CLOSE:
            if stack and stack[-1].text == _CLOSE[t.text]:
                stack.pop()
            elif stack:
                top = stack[-1]
                problems.append({
                    "line": t.line, "col": t.col, "kind": "mismatch",
                    "message": f"'{t.text}' does not match '{top.text}' opened at line {top.line}"})
                # resynchronise: drop the offending opener if it matches deeper
                for i in range(len(stack) - 1, -1, -1):
                    if stack[i].text == _CLOSE[t.text]:
                        del stack[i:]
                        break
            else:
                problems.append({
                    "line": t.line, "col": t.col, "kind": "stray",
                    "message": f"unmatched '{t.text}' with no opening delimiter"})
    for t in stack:
        problems.append({
            "line": t.line, "col": t.col, "kind": "unclosed",
            "message": f"'{t.text}' opened here is never closed"})
    return problems


@dataclass(slots=True)
class Call:
    name: str                    # last identifier, e.g. "strcpy"
    qualified: str               # e.g. "std::strcpy"
    args: List[List[Token]]      # tokens of each top-level argument
    line: int
    col: int
    start: int                   # token index of the callee identifier
    end: int                     # token index one past the closing ')'

    def arg_text(self, i: int) -> str:
        if i >= len(self.args):
            return ""
        return " ".join(t.text for t in self.args[i])


def find_calls(tokens: Sequence[Token], names: Optional[set] = None,
               start: int = 0, stop: Optional[int] = None) -> Iterator[Call]:
    """
    Yield every ``identifier ( ... )`` call expression in ``tokens`` (optionally
    restricted to ``names``).  Spans multiple lines; argument splitting honours
    nested (), [], {} and template angle brackets are *not* guessed at.
    """
    n = len(tokens) if stop is None else stop
    i = start
    while i < n - 1:
        t = tokens[i]
        if (t.kind == IDENT and tokens[i + 1].kind == PUNCT and tokens[i + 1].text == "("
                and (names is None or t.text in names)):
            # skip declarations like "void foo(" is handled by callers; here we
            # simply return the syntactic call.
            j = i + 2
            depth = 1
            args: List[List[Token]] = []
            cur: List[Token] = []
            while j < n and depth:
                u = tokens[j]
                if u.kind == PUNCT:
                    if u.text in "([{":
                        depth += 1
                    elif u.text in ")]}":
                        depth -= 1
                        if depth == 0:
                            break
                    elif u.text == "," and depth == 1:
                        args.append(cur)
                        cur = []
                        j += 1
                        continue
                cur.append(u)
                j += 1
            if cur or args:
                args.append(cur)
            # qualified name
            q = t.text
            k = i - 1
            while k >= 1 and tokens[k].kind == PUNCT and tokens[k].text == "::" \
                    and tokens[k - 1].kind == IDENT:
                q = tokens[k - 1].text + "::" + q
                k -= 2
            yield Call(t.text, q, args, t.line, t.col, i, j + 1)
        i += 1


def split_statements(tokens: Sequence[Token]) -> List[List[Token]]:
    """
    Split a token stream into statements on top-level ``;``, ``{`` and ``}``
    (parentheses are tracked so ``for(;;)`` stays together).  Brace tokens are
    emitted as one-token pseudo-statements so callers can follow scope.
    """
    out: List[List[Token]] = []
    cur: List[Token] = []
    paren = 0
    for t in tokens:
        if t.kind == PREPROC:
            if cur:
                out.append(cur)
                cur = []
            out.append([t])
            continue
        if t.kind == PUNCT:
            if t.text in "([":
                paren += 1
            elif t.text in ")]":
                paren = max(0, paren - 1)
            elif paren == 0 and t.text in ("{", "}"):
                if cur:
                    out.append(cur)
                    cur = []
                out.append([t])
                continue
            elif paren == 0 and t.text == ";":
                cur.append(t)
                out.append(cur)
                cur = []
                continue
        cur.append(t)
    if cur:
        out.append(cur)
    return out


def text_of(tokens: Sequence[Token]) -> str:
    return " ".join(t.text for t in tokens)
