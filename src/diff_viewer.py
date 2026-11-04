"""
diff_viewer.py
--------------
Generates a clean, structured line-by-line diff between two source strings.
Returns a list of DiffLine objects suitable for both terminal printing and
rich GUI rendering.
"""

import difflib
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class DiffLine:
    line_no_old: Optional[int]   # line number in original  (None for additions)
    line_no_new: Optional[int]   # line number in patched   (None for deletions)
    kind: str                    # '+' | '-' | ' '
    content: str                 # raw text of the line (no newline)


def compute_diff(original: str, patched: str, context: int = 3) -> List[DiffLine]:
    """
    Compare two source strings and return a list of DiffLine objects.
    Lines with no changes are included only within `context` lines of a change.
    """
    orig_lines = original.splitlines()
    new_lines  = patched.splitlines()

    result: List[DiffLine] = []
    matcher = difflib.SequenceMatcher(None, orig_lines, new_lines, autojunk=False)

    for group in matcher.get_grouped_opcodes(context):
        for tag, i1, i2, j1, j2 in group:
            if tag == "equal":
                for k, (o, n) in enumerate(zip(orig_lines[i1:i2], new_lines[j1:j2])):
                    result.append(DiffLine(i1 + k + 1, j1 + k + 1, " ", o))

            elif tag in ("replace", "delete"):
                for k, line in enumerate(orig_lines[i1:i2]):
                    result.append(DiffLine(i1 + k + 1, None, "-", line))

            if tag in ("replace", "insert"):
                for k, line in enumerate(new_lines[j1:j2]):
                    result.append(DiffLine(None, j1 + k + 1, "+", line))

    return result


def format_diff_text(diff: List[DiffLine]) -> str:
    """
    Plain-text representation of the diff, suitable for the terminal pane.
    Example:
        Line  3  -  cout << "Hello";
        Line  3  +  std::cout << "Hello";
    """
    lines = []
    for d in diff:
        if d.kind == "-":
            label = f"Line {d.line_no_old:>4}"
        elif d.kind == "+":
            label = f"Line {d.line_no_new:>4}"
        else:
            label = f"Line {d.line_no_new:>4}"
        lines.append(f"  {label}  {d.kind}  {d.content}")
    return "\n".join(lines)


def format_diff_html(diff: List[DiffLine],
                     font_family: str = "JetBrains Mono",
                     color_add: str = "#3fb950",
                     color_del: str = "#f85149",
                     color_ctx: str = "#8b949e") -> str:
    """
    HTML representation of the diff for embedding in a QTextEdit / QLabel.
    """
    rows = []
    for d in diff:
        if d.kind == "-":
            color = color_del
            line_label = str(d.line_no_old)
            prefix = "−"
        elif d.kind == "+":
            color = color_add
            line_label = str(d.line_no_new)
            prefix = "+"
        else:
            color = color_ctx
            line_label = str(d.line_no_new)
            prefix = " "

        safe_content = (
            d.content
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace(" ", "&nbsp;")
        )

        row = (
            f"<span style='color:{color}; font-family:{font_family}; font-size:12px;'>"
            f"<b>{prefix}</b>&nbsp;"
            f"<span style='color:#555e6a;'>Line&nbsp;{line_label:>4}&nbsp;&nbsp;</span>"
            f"{safe_content}"
            f"</span><br>"
        )
        rows.append(row)

    return "".join(rows)


def has_changes(diff: List[DiffLine]) -> bool:
    """Return True if the diff contains any additions or deletions."""
    return any(d.kind in ("+", "-") for d in diff)
