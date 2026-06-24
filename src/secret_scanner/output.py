from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from .detectors import Finding

ANSI_RED = "\x1b[1;31m"
ANSI_PATH = "\x1b[1;36m"
ANSI_RULE = "\x1b[33m"
ANSI_RESET = "\x1b[0m"


def _finding_to_dict(f: Finding, root: Path | None) -> dict:
    return {
        "rule": f.rule,
        "path": str(f.path.relative_to(root)) if root else str(f.path),
        "line": f.line,
        "snippet": f.snippet,
    }


def render_text(
    findings: Iterable[Finding],
    *,
    root: Path | None = None,
    color: bool = True,
) -> str:
    fs = list(findings)
    if not fs:
        return "No secrets found."

    grouped: dict[Path, list[Finding]] = defaultdict(list)
    for f in fs:
        grouped[f.path].append(f)

    lines: list[str] = []
    for path in sorted(grouped, key=lambda p: str(p)):
        display = str(path.relative_to(root)) if root else str(path)
        header = f"{ANSI_PATH}{display}{ANSI_RESET}" if color else display
        lines.append(header)
        for f in sorted(grouped[path], key=lambda f: (f.line, f.rule)):
            rule = f"{ANSI_RULE}{f.rule}{ANSI_RESET}" if color else f.rule
            marker = f"{ANSI_RED}![ {ANSI_RESET}" if color else "! "
            lines.append(f"  {marker}line {f.line}  {rule}  {f.snippet}")
        lines.append("")
    return "\n".join(lines).rstrip("\n")


def render_json(findings: Iterable[Finding], *, root: Path | None = None) -> str:
    fs = sorted(findings, key=lambda f: (str(f.path), f.line, f.rule))
    return json.dumps({"findings": [_finding_to_dict(f, root) for f in fs]}, indent=2)


def render_sarif(findings: Iterable[Finding], *, root: Path | None = None) -> str:
    fs = list(findings)
    rules_by_id: dict[str, dict] = {}
    results: list[dict] = []
    for f in fs:
        rules_by_id.setdefault(
            f.rule,
            {"id": f.rule, "shortDescription": {"text": f.rule}},
        )
        rel = str(f.path.relative_to(root)) if root else str(f.path)
        results.append({
            "ruleId": f.rule,
            "level": "error",
            "message": {"text": f.snippet},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": {"startLine": f.line},
                }
            }],
        })
    return json.dumps(
        {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "secret-scanner",
                            "informationUri": "https://github.com/victor0302/secret-scanner",
                            "rules": list(rules_by_id.values()),
                        }
                    },
                    "results": results,
                }
            ],
        },
        indent=2,
    )
