"""
sarif.py
--------
Export findings as SARIF 2.1.0, the interchange format understood by GitHub
code scanning, VS Code (SARIF Viewer), Azure DevOps and most CI systems, so the
analyzer can gate pull requests.
"""

from __future__ import annotations

import json
import os
from typing import Iterable, List

_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note"}
_SECURITY_SEVERITY = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0"}


def _uri(path: str) -> str:
    try:
        return os.path.relpath(path) if path and os.path.isabs(path) else (path or "")
    except ValueError:
        return path or ""


def to_sarif(security_findings: Iterable, optimization_findings: Iterable = (),
             tool_version: str = "2.0") -> dict:
    rules = {}
    results: List[dict] = []
    for f in security_findings:
        rid = f.rule_id or f"GSC-{f.vulnerability_type.upper().replace(' ', '-')}"
        if rid not in rules:
            rules[rid] = {
                "id": rid, "name": f.vulnerability_type.replace(" ", ""),
                "shortDescription": {"text": f.vulnerability_type},
                "fullDescription": {"text": f.description},
                "help": {"text": f.recommendation},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {"tags": ["security"] + [f"external/cwe/cwe-{c}" for c in f.cwe],
                               "security-severity": _SECURITY_SEVERITY[f.severity]},
            }
        loc = {"physicalLocation": {"artifactLocation": {"uri": _uri(f.file)},
                                    "region": {"startLine": f.line or 1,
                                               **({"startColumn": f.column} if f.column else {})}}}
        results.append({"ruleId": rid, "level": _LEVEL[f.severity],
                        "message": {"text": f"{f.description} Fix: {f.recommendation}"},
                        "locations": [loc],
                        "properties": {"confidence": f.confidence, "source": f.source,
                                       "cwe": [f"CWE-{c}" for c in f.cwe]}})
    for o in optimization_findings:
        rid = o.rule_id
        if rid not in rules:
            rules[rid] = {"id": rid, "name": o.kind.replace(" ", ""),
                          "shortDescription": {"text": o.kind},
                          "help": {"text": o.suggestion},
                          "defaultConfiguration": {"level": "note"},
                          "properties": {"tags": ["performance"]}}
        results.append({"ruleId": rid, "level": "note",
                        "message": {"text": f"{o.description} Fix: {o.suggestion}"},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": _uri(o.file)},
                            "region": {"startLine": o.line or 1}}}]})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Self-Healing C++ Analyzer", "version": tool_version,
                                      "informationUri": "https://cwe.mitre.org/",
                                      "rules": list(rules.values())}},
                  "results": results}],
    }


def dumps(security_findings, optimization_findings=()) -> str:
    return json.dumps(to_sarif(security_findings, optimization_findings), indent=2)
