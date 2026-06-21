from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from . import Finding


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]


BUILTIN_RULES: tuple[Rule, ...] = (
    Rule("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule(
        "aws-secret-access-key",
        re.compile(
            r"""(?ix)
            aws[_\-]?(?:secret|sk)[_\-]?(?:access[_\-]?)?key
            \s*[:=]\s*
            ["']?(?P<value>[A-Za-z0-9/+=]{40})["']?
            """
        ),
    ),
    Rule("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    Rule("github-fine-grained-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    Rule(
        "private-key-header",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    Rule(
        "generic-api-token",
        re.compile(
            r"""(?ix)
            \b(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|secret[_\-]?token)
            \s*[:=]\s*
            ["'](?P<value>[A-Za-z0-9_\-]{20,})["']
            """
        ),
    ),
)


def _snippet(line: str, max_len: int = 200) -> str:
    line = line.rstrip("\n")
    return line if len(line) <= max_len else line[: max_len - 1] + "…"


def scan_text(text: str, path: Path, rules: tuple[Rule, ...] = BUILTIN_RULES) -> Iterator[Finding]:
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule in rules:
            if rule.pattern.search(line):
                yield Finding(rule=rule.name, path=path, line=lineno, snippet=_snippet(line))


def scan_file(path: Path, rules: tuple[Rule, ...] = BUILTIN_RULES) -> Iterator[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return iter(())
    return scan_text(text, path, rules)
