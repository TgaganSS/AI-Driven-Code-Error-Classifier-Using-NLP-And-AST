import re
from typing import Dict, Any, Optional
from error_classifier import get_default_classifier
from error_normalizer import normalize_error
from common_errors import COMMON_ERRORS
from security_analyzer import _diagnostic_findings
from taxonomy import CATEGORIES, info as _cat_info, legacy_of

EXPLANATIONS = {
    "syntax_error": {
        "what": "The compiler found an unexpected token or character in your code.",
        "why": "C++ has strict syntax rules. A missing semicolon, bracket, or parenthesis causes the parser to lose track of where one statement ends and another begins.",
        "how": "Check the line reported and the line just before it. Look for a missing ';', unmatched '(' or '{', or a stray character.",
        "suggestion": "Fix the syntax error near the reported location."
    },
    "name_resolution": {
        "what": "The compiler encountered an identifier that has not been declared.",
        "why": "In C++, every variable, function, or class must be declared before it is used. It may also be in a different scope or namespace.",
        "how": "Declare the variable before using it, check your spelling, or add the missing #include or 'using namespace std;'.",
        "suggestion": "Declare the identifier before use or add the missing #include."
    },
    "type_error": {
        "what": "A value of one type is being used where an incompatible type is expected.",
        "why": "C++ is strongly typed. Operations between incompatible types are not allowed without an explicit cast.",
        "how": "Check the types of the values involved. Add an explicit cast, change the variable type, or use the correct operator.",
        "suggestion": "Ensure both operands are compatible types or add an explicit cast."
    },
    "missing_include": {
        "what": "A required header file could not be found.",
        "why": "The function or class you are using is defined in a header file that has not been included in your source file.",
        "how": "Add the appropriate #include at the top of your file. For standard library features use angle brackets e.g. #include <iostream>.",
        "suggestion": "Add the missing #include directive at the top of your file."
    },
    "linker_error": {
        "what": "The linker could not find the definition of a function or variable.",
        "why": "The compiler found a declaration but no matching definition was compiled into the project.",
        "how": "Make sure the .cpp file containing the definition is being compiled. Check for typos in the function name or missing library flags.",
        "suggestion": "Ensure the function is defined and all source files are being compiled."
    },
    "redefinition": {
        "what": "The same identifier is defined more than once.",
        "why": "C++ does not allow two definitions of the same variable or function in the same scope.",
        "how": "Remove the duplicate definition. If it is coming from a header file, add #pragma once or include guards.",
        "suggestion": "Remove the duplicate definition or add include guards to your header."
    },
    "access_error": {
        "what": "A private or protected member is being accessed from outside its class.",
        "why": "C++ enforces access control. Private members can only be accessed from within the class itself.",
        "how": "Use a public getter/setter method, declare the accessing code as a friend, or change the member's access level.",
        "suggestion": "Use a public method to access the member or change its access level."
    },
    "return_type_error": {
        "what": "A function is missing a return statement or returns the wrong type.",
        "why": "In C++, non-void functions must return a value that matches their declared return type. main() must always return int.",
        "how": "Add a return statement with the correct type. For main(), use 'return 0;' at the end.",
        "suggestion": "Add a return statement matching the function's declared return type."
    },
    "other": {
        "what": "The compiler reported an issue that does not fit a standard category.",
        "why": "This may be a warning treated as an error, a platform-specific issue, or an uncommon language rule violation.",
        "how": "Read the full compiler message carefully and check the indicated line for the root cause.",
        "suggestion": "Read the compiler message carefully and correct the highlighted code."
    }
}

def lookup_common_error(message: str) -> Optional[Dict[str, Any]]:
    """
    Check if the error message matches any of the pre-defined common errors.
    Uses substring matching to handle variations while maintaining specificity.
    """
    lowered_msg = message.lower()
    for common in COMMON_ERRORS:
        # Check if the common error message (or a major part of it) is in the actual message
        # We strip surrounding quotes if they exist in the template to match more flexibly
        template_msg = common["message"].lower().strip("'\"")
        if template_msg in lowered_msg:
            return common
    return None

def format_error(what: str, why: str, how: str) -> str:
    return (
        f"What happened:\n"
        f" {what}\n\n"
        f"Why it happened:\n"
        f" {why}\n\n"
        f"How to fix it:\n"
        f" {how}"
    )

def explain_category(category: str, message: str) -> Optional[Dict[str, str]]:
    if category not in EXPLANATIONS:
        return None
    
    template = EXPLANATIONS[category]
    
    # Use normalizer to get a specific readable sentence for the 'what' part
    _, specific_what = normalize_error(message)
    
    explanation = format_error(
        what=specific_what,
        why=template["why"],
        how=template["how"]
    )
    
    return {
        "explanation": explanation,
        "suggestion": template["suggestion"]
    }

SECURITY_RULES = [
    {
        "pattern": r"unused variable|variable .+ set but not used",
        "risk": "Low",
        "reason": "Unused variables can indicate dead code, abandoned checks, or incomplete security logic."
    },
    {
        "pattern": r"may be used uninitialized",
        "risk": "High",
        "reason": "Uninitialized variables may cause undefined behavior or memory corruption."
    },
    {
        "pattern": r"division by zero",
        "risk": "High",
        "reason": "Division by zero can crash the program or cause undefined behavior."
    },
    {
        "pattern": r"invalid conversion",
        "risk": "Medium",
        "reason": "Incorrect type conversion may lead to memory or logic errors."
    },
    {
        "pattern": r"assignment of read-only location",
        "risk": "Medium",
        "reason": "Modifying const-qualified data may indicate unsafe design."
    },
    {
        "pattern": r"undefined reference",
        "risk": "Low",
        "reason": "Linker errors typically do not introduce runtime vulnerabilities."
    }
]

_RISK_BY_SEVERITY = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low", "Info": "Low"}


def analyze_security_risk(error):
    """Risk level for one diagnostic, driven by the shared taxonomy (CWE-aware)."""
    if not error or not error.message:
        return "None", None
    from taxonomy import classify_rules
    res = classify_rules(error.message, getattr(error, "option", None),
                         getattr(error, "error_type", "error"))
    if res:
        c = _cat_info(res[0])
        if c.group == "security":
            cwe = (" (" + ", ".join(f"CWE-{x}" for x in c.cwe[:3]) + ")") if c.cwe else ""
            return _RISK_BY_SEVERITY.get(c.severity, "Low"), f"{c.title}{cwe}: {c.why or c.what}"
    for rule in SECURITY_RULES:
        if re.search(rule["pattern"], error.message, re.IGNORECASE):
            return rule["risk"], rule["reason"]
    return "Low", "No immediate security risk detected."


def explain_error(error) -> Dict[str, Any]:
    if not error or not error.message:
        return {
            "explanation": "No error message provided.",
            "suggestion": "Check the compilation command and input files.",
            "category": "Unknown",
            "confidence": 0.0
        }

    # 2. Hybrid classification (rules keyed on [-Wxxx] + message templates, ML fallback)
    classifier = get_default_classifier()
    ast_node = getattr(error, "ast_node", "")
    cls = classifier.classify(error.message, option=getattr(error, "option", None),
                              dtype=getattr(error, "error_type", "error"),
                              instantiation=getattr(error, "instantiation", False),
                              ast_node=ast_node or "")
    category, confidence = cls.category, cls.confidence
    error.source = cls.source
    error.uncertain = cls.uncertain

    # Curated glossary wording wins for the explanation text, rules win for the category.
    common = lookup_common_error(error.message)
    template_category = category
    fine = explain_category(template_category, error.message) if template_category in EXPLANATIONS else None
    if not fine:
        c = _cat_info(template_category)
        if c.what:
            fine = {"explanation": format_error(what=c.what, why=c.why, how=c.how),
                    "suggestion": c.fix or c.how}
    if not fine:
        fine = explain_category("other", error.message)

    explanation = fine["explanation"]
    suggestion = fine["suggestion"]
    if common:
        explanation = format_error(what=common["explanation"], why=_cat_info(template_category).why or
                                   EXPLANATIONS.get(common["category"], EXPLANATIONS["other"])["why"],
                                   how=_cat_info(template_category).how or
                                   EXPLANATIONS.get(common["category"], EXPLANATIONS["other"])["how"])
        suggestion = common["suggestion"]
        if cls.source in ("ml", "ml:uncertain", "none"):
            template_category, confidence = common["category"], common["confidence"]

    # Compiler notes frequently contain the exact hint ("candidate: ...", "declared here").
    notes = getattr(error, "notes", None) or []
    if notes:
        explanation += "\n\nCompiler notes:\n" + "\n".join(
            f"  - {n['message']} ({n.get('line')})" for n in notes[:3])
    if cls.uncertain:
        explanation += ("\n\n(The classifier is not confident about this message; treat the category "
                        "as a hint and read the compiler text.)")

    node = getattr(error, "ast_node", None)
    if node:
        explanation += f"\n\nThis error occurred inside a {node} statement."
        confidence = min(1.0, confidence + 0.05)

    return {
        "explanation": explanation,
        "suggestion": suggestion,
        "category": template_category,
        "confidence": confidence,
    }


def enrich_error(error: 'CompilerError') -> None:
    if not error:
        return
    result = explain_error(error)

    error.explanation = result["explanation"]
    error.suggestion = result["suggestion"]
    error.category = result["category"]
    error.confidence = result["confidence"]

    risk, reason = analyze_security_risk(error)
    error.security_risk = risk
    error.risk_reason = reason

    if error.file and error.line and not error.context:
        from error_parser import get_source_context
        error.context = get_source_context(error.file, error.line)

    c = _cat_info(error.category or "other")
    error.group = c.group
    error.severity = c.severity
    error.cwe = list(c.cwe)

    # Compiler-diagnostic findings only.  (The static source scan runs ONCE per
    # file in the pipeline; it used to re-scan the whole file for every error.)
    try:
        error.security_findings = _diagnostic_findings(error)
    except Exception:
        error.security_findings = []
