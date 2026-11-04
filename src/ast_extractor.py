import os
import re
import subprocess


ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
NODE_RE = re.compile(r"^(?:[|` -]*)?([A-Za-z_][A-Za-z0-9_]*)(?:\s+(.*))?$")
ADDRESS_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")

MAX_TREE_DEPTH = 9
MAX_DETAIL_LENGTH = 220

VISIBLE_NODES = {
    "TranslationUnitDecl",
    "NamespaceDecl",
    "UsingDecl",
    "UsingDirectiveDecl",
    "TypedefDecl",
    "TypeAliasDecl",
    "CXXRecordDecl",
    "ClassTemplateDecl",
    "FunctionTemplateDecl",
    "FunctionDecl",
    "CXXMethodDecl",
    "CXXConstructorDecl",
    "CXXDestructorDecl",
    "FieldDecl",
    "VarDecl",
    "ParmVarDecl",
    "EnumDecl",
    "EnumConstantDecl",
    "CompoundStmt",
    "DeclStmt",
    "IfStmt",
    "ForStmt",
    "CXXForRangeStmt",
    "WhileStmt",
    "DoStmt",
    "SwitchStmt",
    "CaseStmt",
    "DefaultStmt",
    "ReturnStmt",
    "BreakStmt",
    "ContinueStmt",
    "BinaryOperator",
    "CompoundAssignOperator",
    "UnaryOperator",
    "ConditionalOperator",
    "CallExpr",
    "CXXOperatorCallExpr",
    "CXXMemberCallExpr",
    "CXXConstructExpr",
    "CXXNewExpr",
    "CXXDeleteExpr",
    "ArraySubscriptExpr",
    "MemberExpr",
    "DeclRefExpr",
    "RecoveryExpr",
    "IntegerLiteral",
    "FloatingLiteral",
    "CharacterLiteral",
    "StringLiteral",
    "CXXBoolLiteralExpr",
    "CXXNullPtrLiteralExpr",
}


def _ast_depth(line):
    marker = re.search(r"(?:\|-|`-)", line)
    if not marker:
        return 0
    return marker.start() // 2 + 1


def _node_parts(line):
    stripped = line.lstrip(" |`-")
    match = NODE_RE.match(stripped)
    if not match:
        return None, ""
    return match.group(1), match.group(2) or ""


def _is_user_location(line, file_path):
    filename = os.path.basename(file_path)
    absolute = os.path.abspath(file_path)
    return f"<{filename}:" in line or f"<{absolute}:" in line or f", {filename}:" in line


def _has_explicit_external_location(line, file_path):
    if _is_user_location(line, file_path):
        return False
    return bool(re.search(r"</|, /|<[A-Za-z]:", line))


def _has_relative_location(line):
    return "<line:" in line or "<col:" in line


def _trim_details(details):
    details = ADDRESS_RE.sub("", details)
    details = " ".join(details.split())
    if len(details) > MAX_DETAIL_LENGTH:
        details = details[: MAX_DETAIL_LENGTH - 3].rstrip() + "..."
    return details


def extract_ast(file_path):
    """Return a compact clang AST dump containing only user-file subtrees."""
    cmd = [
        "clang++",
        "-Xclang",
        "-ast-dump",
        "-fsyntax-only",
        "-fno-color-diagnostics",
        file_path,
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except OSError:
        return None

    filtered = []
    active_depth = None
    user_file_context = False

    try:
        for raw_line in process.stdout:
            line = ANSI_RE.sub("", raw_line.rstrip("\n"))
            if not line.strip():
                continue

            depth = _ast_depth(line)
            if active_depth is not None and depth <= active_depth:
                active_depth = None

            if _has_explicit_external_location(line, file_path):
                user_file_context = False

            if _is_user_location(line, file_path):
                user_file_context = True

            starts_user_subtree = _is_user_location(line, file_path) or (
                user_file_context and _has_relative_location(line)
            )

            if active_depth is None and starts_user_subtree:
                active_depth = depth

            if active_depth is not None:
                filtered.append(line)
    finally:
        process.wait()

    return "\n".join(filtered) if filtered else None


def parse_ast_to_tree(ast_text, file_path=None):
    if not ast_text:
        return []

    root_nodes = []
    stack = []

    for line in ast_text.splitlines():
        if not line.strip():
            continue

        depth = _ast_depth(line)
        node_type, details = _node_parts(line)
        if not node_type:
            continue

        while stack and stack[-1][0] >= depth:
            stack.pop()

        if depth > MAX_TREE_DEPTH or node_type not in VISIBLE_NODES:
            continue

        node = {
            "type": node_type,
            "details": _trim_details(details),
            "children": [],
        }

        if stack:
            stack[-1][1]["children"].append(node)
        else:
            root_nodes.append(node)

        stack.append((depth, node))

    return root_nodes


def extract_node_near_line(ast_text, line_number):
    if not ast_text or line_number is None:
        return None

    fallback = None

    for line in ast_text.splitlines():
        node_type, _ = _node_parts(line)
        if not node_type or node_type not in VISIBLE_NODES:
            continue

        if f":{line_number}:" in line or f"line:{line_number}" in line:
            if "Expr" in node_type or "Stmt" in node_type or "Decl" in node_type:
                return node_type
            fallback = fallback or node_type

    return fallback
