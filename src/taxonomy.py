"""
taxonomy.py
-----------
Single source of truth for *what kind of problem a diagnostic is*.

The original project had 8 coarse categories (``other`` alone was 37 % of the
training data) and *no* notion of security.  Every real-world g++ warning such
as ``[-Wformat-security]`` or ``[-Warray-bounds]`` was classified ``other``,
frequently with high confidence.

This module provides:

* ``CATEGORIES``  - ~30 fine-grained categories, each with a group
  (``error`` / ``security`` / ``correctness`` / ``quality`` / ``performance``),
  default severity, CWE identifiers and explanation text;
* ``legacy_of(cat)`` - maps a fine category back to the original coarse set so
  the healer / explainer / GUI keep working unchanged;
* ``classify_rules(message, option)`` - deterministic, high-precision rules
  keyed on the ``[-Wxxx]`` option tag g++ prints and on message templates.
  Rules are tried before any ML model, so the common cases never need to load
  scikit-learn at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Categories
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Category:
    name: str
    group: str                     # error | security | correctness | quality | performance
    severity: str                  # Critical | High | Medium | Low | Info
    legacy: str                    # coarse category understood by older modules
    title: str
    cwe: Tuple[int, ...] = ()
    what: str = ""
    why: str = ""
    how: str = ""
    fix: str = ""


def _c(name, group, severity, legacy, title, cwe=(), what="", why="", how="", fix=""):
    return Category(name, group, severity, legacy, title, tuple(cwe), what, why, how, fix)


_CATEGORY_LIST = [
    # ── hard compile / link errors (legacy names preserved) ──────────────────
    _c("syntax_error", "error", "High", "syntax_error", "Syntax error"),
    _c("missing_closing_brace", "error", "High", "syntax_error", "Missing closing brace",
       what="A '{' was opened but never closed, so a following function or block appears nested inside it.",
       why="g++ only notices at the next function definition or at end of file, which is far from the real cause.",
       how="Find the block that is missing its '}' (the pre-flight scan points at the opening brace).",
       fix="Add the missing '}' where the block should end."),
    _c("control_flow_error", "error", "High", "syntax_error", "Invalid control flow",
       what="A 'break' or 'continue' (or similar) is used where it has no enclosing loop or switch.",
       why="These statements are only meaningful inside a loop or switch.",
       how="Move the statement inside a loop/switch or replace it with 'return'.",
       fix="Place the statement inside a loop or switch, or use 'return'."),
    _c("name_resolution", "error", "High", "name_resolution", "Undeclared identifier"),
    _c("missing_include", "error", "High", "missing_include", "Missing header"),
    _c("type_error", "error", "High", "type_error", "Type error"),
    _c("template_error", "error", "High", "type_error", "Template instantiation error",
       what="A template could not be instantiated with the supplied arguments.",
       why="The type used does not provide an operation or member the template requires.",
       how="Read the innermost 'required from here' note: it names the failing instantiation.",
       fix="Provide the missing operation for the type, or use a compatible type."),
    _c("redefinition", "error", "High", "redefinition", "Redefinition"),
    _c("access_error", "error", "High", "access_error", "Access / const violation"),
    _c("return_type_error", "error", "High", "return_type_error", "Return type / missing return",
       cwe=(758,)),
    _c("linker_error", "error", "High", "linker_error", "Linker error"),
    _c("security_violation", "security", "Critical", "other", "Blocked by safety gate", cwe=(78,),
       what="The source uses a forbidden system / process / loader call or inline assembly.",
       why="Such calls can execute arbitrary commands and are blocked before any build runs.",
       how="Remove the call, or run with the explicit permission flag inside a real sandbox.",
       fix="Replace shell-outs with library APIs."),

    # ── security-relevant compiler diagnostics ───────────────────────────────
    _c("buffer_overflow", "security", "Critical", "other", "Out-of-bounds memory access",
       cwe=(119, 120, 121, 122, 787),
       what="Code reads or writes memory outside the bounds of an array or buffer.",
       why="Out-of-bounds writes corrupt neighbouring data or the return address and are the classic route to code execution.",
       how="Check the index / copy length against the real buffer size before every access.",
       fix="Bound every index and copy length, or use std::array / std::vector / std::string."),
    _c("string_truncation", "security", "Medium", "other", "String truncation / missing terminator",
       cwe=(170, 193),
       what="A bounded string copy may leave the destination without a terminating NUL.",
       why="Later C-string operations then read past the end of the buffer.",
       how="Copy at most size-1 bytes and set the last byte to '\\0', or use snprintf / std::string.",
       fix="Use snprintf(dst, sizeof dst, \"%s\", src) or std::string."),
    _c("format_string", "security", "High", "other", "Format-string vulnerability", cwe=(134,),
       what="A printf-style function receives a format string that is not a constant.",
       why="If any part of it is attacker-controlled, %n / %s specifiers can read or overwrite memory.",
       how="Always pass a literal format and give user data as an argument.",
       fix="printf(\"%s\", text) instead of printf(text)."),
    _c("null_dereference", "security", "High", "other", "Null-pointer dereference", cwe=(476,),
       what="A pointer that can be null is dereferenced.",
       why="Dereferencing null is undefined behaviour: it usually crashes and can be exploitable.",
       how="Check the pointer (or the allocation result) before using it.",
       fix="Add 'if (!p) { /* handle */ }' before the dereference."),
    _c("use_after_free", "security", "Critical", "other", "Use after free / double free",
       cwe=(415, 416, 825),
       what="Memory is used (or released again) after it was already freed.",
       why="The allocator may have reused the block, so reads/writes hit unrelated live data.",
       how="Set pointers to nullptr after free/delete and prefer smart pointers.",
       fix="Use std::unique_ptr, or null the pointer immediately after release."),
    _c("memory_mismatch", "security", "High", "other", "Mismatched allocation / deallocation",
       cwe=(590, 762),
       what="Memory is released with a routine that does not match the one that allocated it.",
       why="new[] must pair with delete[], new with delete, malloc with free; anything else is undefined.",
       how="Match each allocation with its own deallocation, or use RAII containers.",
       fix="Use delete[] for new[], delete for new, free for malloc."),
    _c("dangling_pointer", "security", "High", "other", "Dangling pointer / reference",
       cwe=(562, 825),
       what="A pointer or reference to a local object outlives that object.",
       why="The stack slot is reused after the function returns, so the caller reads garbage.",
       how="Return by value, or return a pointer to storage that outlives the call.",
       fix="Return by value / std::string / std::vector instead of a pointer to a local."),
    _c("uninitialized_memory", "security", "High", "other", "Uninitialized variable", cwe=(457, 665),
       what="A variable is read before it has been assigned a value.",
       why="The value is whatever was in that memory before - unpredictable and sometimes a data leak.",
       how="Initialize at declaration, and make sure every path assigns before use.",
       fix="Initialize the variable where it is declared (e.g. 'int x = 0;')."),
    _c("integer_overflow", "security", "High", "other", "Integer overflow / wraparound",
       cwe=(190, 789),
       what="An arithmetic expression can exceed the range of its type.",
       why="Signed overflow is undefined behaviour; unsigned wraps silently. Both corrupt size and index calculations.",
       how="Validate operands first, use wider types, or checked arithmetic.",
       fix="Check bounds before arithmetic; use __builtin_*_overflow or a wider type."),
    _c("sign_conversion", "security", "Medium", "other", "Signed/unsigned or narrowing conversion",
       cwe=(195, 196, 197),
       what="A value is converted between signed/unsigned or to a narrower type.",
       why="Negative numbers become huge unsigned values (bypassing length checks) and narrowing loses data.",
       how="Use one signedness for sizes (size_t), or range-check before an explicit cast.",
       fix="Use size_t / std::size_t for sizes and indices, or cast after a range check."),
    _c("narrowing_conversion", "quality", "Info", "other", "Narrowing numeric conversion", cwe=(197,),
       what="A value is implicitly converted to a narrower or less precise numeric type.",
       why="High bits or the fractional part are dropped; harmless when the value provably fits, dangerous for sizes and indices.",
       how="Check the range, or make the conversion explicit with a comment/static_cast after validation.",
       fix="static_cast<T>(value) after confirming the value fits."),
    _c("division_by_zero", "security", "Medium", "other", "Division by zero", cwe=(369,),
       what="A division or modulo has a divisor that is (or can be) zero.",
       why="Integer division by zero traps (crash); it is a ready-made denial-of-service.",
       how="Guard the divisor with a non-zero check.",
       fix="if (d != 0) { ... } before dividing."),
    _c("unchecked_return", "security", "Medium", "other", "Unchecked return value", cwe=(252,),
       what="The result of a function that can fail is ignored.",
       why="Failure goes unnoticed and later code runs on invalid state (e.g. a variable scanf never filled).",
       how="Test the return value and handle failure.",
       fix="if (scanf(\"%d\", &x) != 1) { /* error */ }"),
    _c("insecure_function", "security", "Medium", "other", "Use of dangerous / deprecated API", cwe=(676, 242),
       what="The code calls an API that is deprecated or known to be unsafe.",
       why="Such APIs have no bounds or error handling and are routinely exploited.",
       how="Switch to the modern bounded replacement.",
       fix="Replace with the safe alternative named in the message."),
    _c("cast_safety", "security", "Low", "other", "Unsafe cast", cwe=(704,),
       what="A cast discards const, or increases pointer alignment requirements.",
       why="Writing through a const-stripped pointer is undefined; misaligned access can fault.",
       how="Avoid the cast; redesign const-correctness.",
       fix="Remove the cast or make the object non-const."),

    # ── correctness (non-security logic bugs) ────────────────────────────────
    _c("logic_error", "correctness", "Medium", "other", "Suspicious logic",
       cwe=(483, 561, 570, 571),
       what="The compiler found code that is almost certainly not what was intended.",
       why="Examples: '=' inside a condition, always-true comparisons, misleading indentation, duplicate conditions.",
       how="Re-read the flagged expression and compare with the intent.",
       fix="Fix the condition / add braces to make the intended structure explicit."),
    _c("implicit_fallthrough", "correctness", "Low", "other", "Switch fall-through", cwe=(484,),
       what="A switch case runs into the next case without a break.",
       why="Usually a forgotten 'break'; the next case's code runs by accident.",
       how="Add 'break;' or mark intentional fall-through with [[fallthrough]];",
       fix="Add 'break;' or [[fallthrough]];"),
    _c("unused_variable", "correctness", "Low", "other", "Unused variable / parameter", cwe=(563,),
       what="A variable or parameter is declared but never used.",
       why="It can indicate dead code or a forgotten check.",
       how="Remove it, or use it.",
       fix="Delete the variable or reference it."),
    _c("shadowing", "correctness", "Low", "other", "Shadowed declaration", cwe=(1109,),
       what="A local declaration hides another variable of the same name.",
       why="Edits intended for the outer variable silently hit the inner one.",
       how="Rename one of them.",
       fix="Rename the inner variable."),
    _c("style_warning", "quality", "Info", "other", "Style / pedantic warning",
       what="The code is valid but non-portable or unidiomatic.", why="It may not compile on other toolchains.",
       how="Follow the standard form.", fix="Adjust to standard C++."),

    # ── performance ──────────────────────────────────────────────────────────
    _c("performance", "performance", "Info", "other", "Performance issue",
       what="The compiler found a construct that costs more than necessary.",
       why="Typically an unneeded copy or a move that inhibits copy elision.",
       how="Use references / remove the redundant std::move.",
       fix="Bind by const reference ('const auto&') or drop the std::move."),

    _c("other", "error", "Low", "other", "Other diagnostic",
       what="The compiler reported an issue that does not fit a standard category.",
       why="This may be a warning, a platform-specific issue, or an uncommon language rule.",
       how="Read the full compiler message carefully and check the indicated line.",
       fix="Fix the construct the message points at."),
]

CATEGORIES: Dict[str, Category] = {c.name: c for c in _CATEGORY_LIST}

# Legacy 8 + names used by older code paths
LEGACY_CATEGORIES = ("syntax_error", "name_resolution", "type_error", "missing_include",
                     "linker_error", "redefinition", "access_error", "return_type_error", "other")


def legacy_of(category: Optional[str]) -> str:
    """Coarse category understood by auto_healer / GUI / explainer."""
    if not category:
        return "other"
    c = CATEGORIES.get(category)
    return c.legacy if c else "other"


def info(category: str) -> Category:
    return CATEGORIES.get(category, CATEGORIES["other"])


# Names the healer dispatches on; keep the *specific* name (the healer has
# handlers for these) rather than collapsing to ``legacy``.
HEALER_NATIVE = {"missing_closing_brace", "uninitialized_memory", "unused_variable",
                 "integer_overflow", "division_by_zero"}

CWE_NAMES: Dict[int, str] = {
    14: "Compiler Removal of Code to Clear Buffers",
    20: "Improper Input Validation",
    22: "Path Traversal",
    78: "OS Command Injection",
    119: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    120: "Buffer Copy without Checking Size of Input",
    121: "Stack-based Buffer Overflow",
    122: "Heap-based Buffer Overflow",
    129: "Improper Validation of Array Index",
    131: "Incorrect Calculation of Buffer Size",
    134: "Use of Externally-Controlled Format String",
    170: "Improper Null Termination",
    190: "Integer Overflow or Wraparound",
    193: "Off-by-one Error",
    195: "Signed to Unsigned Conversion Error",
    196: "Unsigned to Signed Conversion Error",
    197: "Numeric Truncation Error",
    242: "Use of Inherently Dangerous Function",
    252: "Unchecked Return Value",
    327: "Use of a Broken or Risky Cryptographic Algorithm",
    337: "Predictable Seed in Pseudo-Random Number Generator",
    338: "Use of Cryptographically Weak PRNG",
    367: "Time-of-check Time-of-use (TOCTOU) Race Condition",
    369: "Divide By Zero",
    377: "Insecure Temporary File",
    401: "Missing Release of Memory after Effective Lifetime",
    415: "Double Free",
    416: "Use After Free",
    457: "Use of Uninitialized Variable",
    467: "Use of sizeof() on a Pointer Type",
    476: "NULL Pointer Dereference",
    483: "Incorrect Block Delimitation",
    484: "Omitted Break Statement in Switch",
    561: "Dead Code",
    562: "Return of Stack Variable Address",
    563: "Assignment to Variable without Use",
    570: "Expression is Always False",
    571: "Expression is Always True",
    590: "Free of Memory not on the Heap",
    665: "Improper Initialization",
    676: "Use of Potentially Dangerous Function",
    704: "Incorrect Type Conversion or Cast",
    732: "Incorrect Permission Assignment for Critical Resource",
    758: "Reliance on Undefined, Unspecified, or Implementation-Defined Behavior",
    762: "Mismatched Memory Management Routines",
    770: "Allocation of Resources Without Limits or Throttling",
    787: "Out-of-bounds Write",
    789: "Memory Allocation with Excessive Size Value",
    798: "Use of Hard-coded Credentials",
    825: "Expired Pointer Dereference",
    1109: "Use of Same Variable for Multiple Purposes",
    1335: "Incorrect Bitwise Shift of Integer Operand",
}

# ─────────────────────────────────────────────────────────────────────────────
# Rules: [-Wxxx] option -> category.  Highest precision signal g++ offers.
# Keys have the leading "-W" and any trailing "=" / "=N" removed.
# ─────────────────────────────────────────────────────────────────────────────

OPTION_RULES: Dict[str, str] = {
    # memory safety
    "array-bounds": "buffer_overflow",
    "stringop-overflow": "buffer_overflow",
    "stringop-overread": "buffer_overflow",
    "restrict": "buffer_overflow",
    "builtin-memcpy-chk-size": "buffer_overflow",
    "aggressive-loop-optimizations": "buffer_overflow",
    "vla": "buffer_overflow",
    "alloca": "buffer_overflow",
    "stack-protector": "buffer_overflow",
    "stringop-truncation": "string_truncation",
    "format-security": "format_string",
    "format-nonliteral": "format_string",
    "format-overflow": "buffer_overflow",
    "format-truncation": "string_truncation",
    "format": "format_string",
    "format-extra-args": "format_string",
    "format-zero-length": "format_string",
    "null-dereference": "null_dereference",
    "nonnull": "null_dereference",
    "nonnull-compare": "null_dereference",
    "address": "logic_error",
    "use-after-free": "use_after_free",
    "free-nonheap-object": "memory_mismatch",
    "mismatched-new-delete": "memory_mismatch",
    "mismatched-dealloc": "memory_mismatch",
    "delete-non-virtual-dtor": "memory_mismatch",
    "return-local-addr": "dangling_pointer",
    "dangling-pointer": "dangling_pointer",
    "dangling-reference": "dangling_pointer",
    "dangling-else": "logic_error",
    "uninitialized": "uninitialized_memory",
    "maybe-uninitialized": "uninitialized_memory",
    "init-self": "uninitialized_memory",
    "sizeof-pointer-memaccess": "buffer_overflow",
    "sizeof-pointer-div": "buffer_overflow",
    "sizeof-array-argument": "buffer_overflow",
    "memset-transposed-args": "buffer_overflow",
    "memset-elt-size": "buffer_overflow",
    "class-memaccess": "memory_mismatch",
    # arithmetic
    "overflow": "integer_overflow",
    "integer-overflow": "integer_overflow",
    "alloc-size-larger-than": "integer_overflow",
    "alloc-size": "integer_overflow",
    "alloc-zero": "integer_overflow",
    "shift-count-overflow": "integer_overflow",
    "shift-count-negative": "integer_overflow",
    "shift-negative-value": "integer_overflow",
    "shift-overflow": "integer_overflow",
    "div-by-zero": "division_by_zero",
    "sign-compare": "sign_conversion",
    "sign-conversion": "sign_conversion",
    "conversion": "narrowing_conversion",
    "float-conversion": "narrowing_conversion",
    "narrowing": "narrowing_conversion",
    "conversion-null": "narrowing_conversion",
    "int-to-pointer-cast": "cast_safety",
    "pointer-to-int-cast": "cast_safety",
    "double-promotion": "narrowing_conversion",
    "float-equal": "logic_error",
    # error handling / dangerous API
    "unused-result": "unchecked_return",
    "deprecated-declarations": "insecure_function",
    "deprecated": "insecure_function",
    "cpp": "style_warning",
    "cast-qual": "cast_safety",
    "cast-align": "cast_safety",
    "old-style-cast": "cast_safety",
    "strict-aliasing": "cast_safety",
    "invalid-memory-model": "cast_safety",
    # logic
    "parentheses": "logic_error",
    "misleading-indentation": "logic_error",
    "tautological-compare": "logic_error",
    "logical-op": "logic_error",
    "logical-not-parentheses": "logic_error",
    "duplicated-cond": "logic_error",
    "duplicated-branches": "logic_error",
    "bool-compare": "logic_error",
    "bool-operation": "logic_error",
    "self-assign-overloaded": "logic_error",
    "self-move": "logic_error",
    "self-assign": "logic_error",
    "type-limits": "logic_error",
    "empty-body": "logic_error",
    "comment": "logic_error",
    "switch": "logic_error",
    "switch-bool": "logic_error",
    "switch-unreachable": "logic_error",
    "sequence-point": "logic_error",
    "unsequenced": "logic_error",
    "strict-overflow": "integer_overflow",
    "enum-compare": "logic_error",
    "unused-value": "logic_error",
    "unused-label": "unused_variable",
    "unused-but-set-variable": "unused_variable",
    "unused-variable": "unused_variable",
    "unused-parameter": "unused_variable",
    "unused-function": "unused_variable",
    "unused-local-typedefs": "unused_variable",
    "unused-const-variable": "unused_variable",
    "implicit-fallthrough": "implicit_fallthrough",
    "shadow": "shadowing",
    "shadow-ivar": "shadowing",
    "return-type": "return_type_error",
    "missing-field-initializers": "uninitialized_memory",
    "reorder": "logic_error",
    "non-virtual-dtor": "memory_mismatch",
    "virtual-move-assign": "memory_mismatch",
    "overloaded-virtual": "logic_error",
    "catch-value": "performance",
    "terminate": "logic_error",
    # performance
    "pessimizing-move": "performance",
    "redundant-move": "performance",
    "range-loop-construct": "performance",
    "deprecated-copy": "performance",
    "deprecated-copy-dtor": "performance",
    "inefficient-move": "performance",
    # pedantic / style
    "pedantic": "style_warning",
    "vla-extension": "style_warning",
    "variadic-macros": "style_warning",
    "extra-semi": "style_warning",
    "missing-braces": "style_warning",
    "write-strings": "style_warning",
    "ignored-qualifiers": "style_warning",
    "attributes": "style_warning",
    "register": "style_warning",
    "volatile": "style_warning",
    "pragmas": "style_warning",
    "unknown-pragmas": "style_warning",
    "c++11-compat": "style_warning",
    "narrowing-conversion": "narrowing_conversion",
    # hard errors that carry an option tag
    "fpermissive": "type_error",
    "template-body": "template_error",
    "changes-meaning": "name_resolution",
    "expansion-to-defined": "style_warning",
    "mismatched-tags": "style_warning",
    "subobject-linkage": "linker_error",
    "odr": "redefinition",
}

# ─────────────────────────────────────────────────────────────────────────────
# Message-template rules (errors normally carry no [-W...] tag).  Order matters;
# first match wins.  Each is high-precision; anything unmatched falls through
# to the ML model.
# ─────────────────────────────────────────────────────────────────────────────

_R = re.compile
MESSAGE_RULES = [
    # linker
    (_R(r"undefined reference to|multiple definition of|undefined symbols for architecture|"
        r"linker command failed|ld returned|^linker:|cannot find -l|duplicate symbol", re.I),
     "linker_error", 1.0),
    # blocked by the safety gate
    (_R(r"^security error:|malicious command injection|forbidden system call", re.I),
     "security_violation", 1.0),
    # brace structure
    (_R(r"a function-definition is not allowed here|expected '\}' at end of input|"
        r"expected declaration before '\}' token", re.I),
     "missing_closing_brace", 0.97),
    # control flow
    (_R(r"(break|continue) statement not within|case label .* not within a switch|"
        r"'default' label not within a switch", re.I),
     "control_flow_error", 1.0),
    # missing header
    (_R(r"no such file or directory|cannot open source file|file not found", re.I),
     "missing_include", 1.0),
    # templates
    (_R(r"required from here|in instantiation of|template argument .* (?:is invalid|deduction)|"
        r"no type named .* in|couldn't deduce template|wrong number of template arguments|"
        r"template placeholder|constraints? .* not satisfied|invalid template", re.I),
     "template_error", 0.92),
    # redefinition (after linker so 'multiple definition of' stays linker)
    (_R(r"redefinition of|redeclaration of|previous definition|conflicting declaration|"
        r"has already been defined|was already declared|previously (?:defined|declared)|"
        r"redeclared as different kind of entity|ambiguating new declaration|"
        r"conflicts with a previous declaration", re.I),
     "redefinition", 0.98),
    # access / const
    (_R(r"is (?:private|protected) within this context|read-only (?:location|variable|member|reference)|"
        r"discards qualifiers|assignment of (?:member|variable) .* in read-only|"
        r"cannot assign to (?:variable|non-static data member) .*const|passing .* discards", re.I),
     "access_error", 0.97),
    # return type
    (_R(r"no return statement|control reaches end of non-void|return-statement with (?:a )?(?:value|no value)|"
        r"forbids declaration of .* with no type|must return 'int'|'main' must return|"
        r"returning .* from a function with|void function", re.I),
     "return_type_error", 0.95),
    # name resolution
    (_R(r"was not declared in this scope|has not been declared|use of undeclared identifier|"
        r"does not name a type|is not a member of|has no member named|"
        r"not declared in this scope|undeclared \(first use|unknown type name|"
        r"'.*' is not a class, namespace, or enumeration|"
        r"class .* does not have any field named|label .* used but not defined|"
        r"is not a namespace-name|no declaration matches|"
        r"there are no arguments to .* that depend on", re.I),
     "name_resolution", 0.97),
    # type errors
    (_R(r"cannot convert|invalid conversion|invalid operands (?:of types|to)|no match for|cannot be used as a function|"
        r"no matching function|could not convert|incompatible|void value not ignored|invalid cast|"
        r"cannot bind|call of overloaded .* is ambiguous|request for member .* in .* which is of non-class|"
        r"lvalue required|invalid initialization|too (?:many|few) arguments|invalid use of|"
        r"array bound is not an integer|size of array .* is|cannot be overloaded|"
        r"invalid types|base operand of '->'|expression cannot be used as a function|"
        r"invalid static_cast|invalid reinterpret_cast|ambiguous overload|"
        r"narrowing conversion|conversion from .* to .* (?:is ambiguous|requires)|no viable|"
        r"reference to .* is ambiguous|use of deleted function|conversion from .* to non-scalar|"
        r"request for member .* of pointer type|size of array .* has non-integral|"
        r"scalar object .* requires one element|too many initializers|"
        r"variable or field .* declared void|storage size of .* isn't known|"
        r"incomplete type|unable to find (?:numeric|string|character) literal operator|"
        r"not usable in a constant expression|is not captured|is not a type\b|"
        r"has no initializer|initializer fails to determine size|"
        r"must have exactly one argument|multidimensional array must have bounds|"
        r"inlining failed in call", re.I),
     "type_error", 0.95),
    # syntax
    (_R(r"expected .* (?:before|after|at end of input)|expected primary-expression|stray '.*' in program|"
        r"expected unqualified-id|expected declaration|expected [';,(){}\[\]]|"
        r"expected (?:identifier|type-specifier|constructor|class-name|initializer|expression)|"
        r"missing terminating|unterminated|invalid preprocessing directive|extra tokens at end|"
        r"stray '\\\\|invalid suffix|unbalanced|'else' without a previous 'if'|"
        r"unexpected (?:token|end)|a template declaration cannot appear|"
        r"invalid declarator before|two or more data types in declaration|"
        r"multi-character literal|expected nested-name-specifier|jump to label", re.I),
     "syntax_error", 0.97),
]

# A few message-level security / logic patterns for diagnostics that carry no
# option tag (older compilers, clang, or messages with the tag stripped).
UNTAGGED_WARNING_RULES = [
    (_R(r"may be used uninitialized|is used uninitialized|uninitialized when used|"
        r"uninitialized variable", re.I), "uninitialized_memory", 0.98),
    (_R(r"set but not used|unused variable|unused parameter|declared but never used|"
        r"unused but set", re.I), "unused_variable", 0.98),
    (_R(r"format not a string literal|format string is not a string literal|not a string literal and no format",
        re.I), "format_string", 0.97),
    (_R(r"array subscript .* (?:above|below|is outside) .*bounds|out of bounds|"
        r"offset \[.*\] (?:is|are) out of the bounds|writing .* bytes into a region|"
        r"overflows the destination|forming offset", re.I), "buffer_overflow", 0.97),
    (_R(r"null pointer dereference|dereferenc\w+ null|nullptr dereference", re.I),
     "null_dereference", 0.97),
    (_R(r"used after|use after free|double free|pointer .* used after", re.I), "use_after_free", 0.95),
    (_R(r"mismatched allocation|mismatched dealloc|called on pointer returned from a mismatched|"
        r"attempt to free a non-heap object", re.I), "memory_mismatch", 0.97),
    (_R(r"address of local variable .* returned|returning address of local|"
        r"reference to local|dangling", re.I), "dangling_pointer", 0.97),
    (_R(r"division by zero|divide by zero|remainder by zero", re.I), "division_by_zero", 0.98),
    (_R(r"integer overflow|overflow in (?:conversion|expression)|wraps around|"
        r"shift count (?:is negative|>= width)", re.I), "integer_overflow", 0.95),
    (_R(r"comparison of integer expressions of different signedness|may change the sign|"
        r"changes signedness|comparison of integers of different signs", re.I),
     "sign_conversion", 0.95),
    (_R(r"may change value|loses integer precision|conversion .* from .* to .* (?:may|changes)|"
        r"implicit conversion (?:changes|loses)", re.I), "narrowing_conversion", 0.93),
    (_R(r"ignoring return value", re.I), "unchecked_return", 0.97),
    (_R(r"is deprecated|dangerous|\bgets\b.*(?:is|may)", re.I), "insecure_function", 0.8),
    (_R(r"this 'if' clause does not guard|suggest parentheses around|"
        r"comparison is always (?:true|false)|self-assign|always evaluates", re.I),
     "logic_error", 0.9),
    (_R(r"this statement may fall through", re.I), "implicit_fallthrough", 0.98),
    (_R(r"shadows a (?:previous|parameter|member|global)|shadows", re.I), "shadowing", 0.9),
    (_R(r"pessimizing|redundant move|loop variable .* creates a copy|"
        r"implicitly-declared .* is deprecated", re.I), "performance", 0.9),
]

# These options are *warnings* in general but g++ promotes them to hard errors
# in some contexts (e.g. narrowing inside braces); then they are type errors.
_ERROR_OPTION_OVERRIDE = {"narrowing": "type_error", "narrowing-conversion": "type_error",
                          "overflow": "type_error", "conversion-null": "type_error",
                          "return-type": "return_type_error"}

_WEAK_OPTIONS = frozenset({"fpermissive", "pedantic", "changes-meaning"})

_OPTION_RE = re.compile(r"\[(-[Wf][\w+\-]*)(?:=[^\]]*)?\]\s*$")


def split_option(message: str) -> Tuple[str, Optional[str]]:
    """
    Split a trailing ``[-Wxxx]`` tag off ``message``.
    Returns ``(message_without_tag, option_base)`` where ``option_base`` has the
    leading ``-W`` and any ``=N`` stripped (``None`` if there is no tag).
    """
    m = _OPTION_RE.search(message or "")
    if not m:
        return message, None
    opt = m.group(1)
    base = opt[2:] if opt.startswith("-W") else opt[1:]
    return message[:m.start()].rstrip(), base


def classify_rules(message: str, option: Optional[str] = None,
                   dtype: str = "error") -> Optional[Tuple[str, float, str]]:
    """
    Deterministic classification.  Returns ``(category, confidence, source)`` or
    ``None`` when no rule fires (caller then falls back to the ML model).
    """
    if not message:
        return None
    if option is None:
        message, option = split_option(message)
    # 1. option tag - near-perfect precision
    if option:
        if dtype == "error" and option in _ERROR_OPTION_OVERRIDE:
            return _ERROR_OPTION_OVERRIDE[option], 0.97, f"rule:-W{option}"
        cat = OPTION_RULES.get(option)
        if cat and option in _WEAK_OPTIONS:
            # umbrella tags (-fpermissive, -Wpedantic): a specific message rule wins,
            # the tag is only the fallback.
            for rx, mcat, conf in MESSAGE_RULES:
                if rx.search(message):
                    return mcat, conf, "rule:message"
            return cat, 0.9, f"rule:-W{option}"
        if cat:
            # refine a few options using the message text
            low = message.lower()
            if option in ("use-after-free",) and "free" not in low and "delete" not in low:
                pass
            return cat, 1.0, f"rule:-W{option}"
    # 2. message templates (errors)
    for rx, cat, conf in MESSAGE_RULES:
        if rx.search(message):
            return cat, conf, "rule:message"
    # 3. untagged warning-ish text
    for rx, cat, conf in UNTAGGED_WARNING_RULES:
        if rx.search(message):
            return cat, conf, "rule:message"
    return None


def severity_for(category: str, dtype: str = "error") -> str:
    """Default severity for a category (errors are at least High if blocking)."""
    c = info(category)
    return c.severity


# ─────────────────────────────────────────────────────────────────────────────
# Template normalisation (shared by the classifier's training and inference)
# ─────────────────────────────────────────────────────────────────────────────

_KEEP_QUOTED = frozenset(
    "int char float double bool void long short unsigned signed auto const return class struct "
    "namespace template else if for while do switch case default public private protected break "
    "continue using typedef new delete this nullptr main std".split())


def normalize_template(message: str) -> str:
    """
    Mask identifiers / numbers so that ``'foo' was not declared`` and
    ``'bar' was not declared`` become the *same* sample.  Punctuation tokens
    (``';'``, ``')'``) and core keywords are kept because they carry meaning.
    The ``[-Wxxx]`` tag and any "did you mean" suffix are removed.
    """
    msg, _opt = split_option(message or "")
    msg = re.sub(r";?\s*did you mean.*$", "", msg)
    msg = re.sub(r"'([^']*)'",
                 lambda m: m.group(0) if (m.group(1) in _KEEP_QUOTED
                                          or not re.search(r"[A-Za-z0-9_]", m.group(1)))
                 else "'<ID>'", msg)
    msg = re.sub(r"\b\d+(?:\.\d+)?\b", "<NUM>", msg)
    return msg.strip()[:300]
