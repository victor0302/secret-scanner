from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterator
from pathlib import Path

from . import Finding

DEFAULT_THRESHOLD = 4.5
DEFAULT_MIN_LENGTH = 20

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{12,}")
_URL_RE = re.compile(r"https?://\S+")
_BASE64_IMAGE_RE = re.compile(r"data:image/[a-zA-Z]+;base64,")
_HASH_PREFIX_RE = re.compile(r"\b(?:sha(?:256|512|1)|md5|integrity)[=:]")
_HEX_HASH_RE = re.compile(r"^[A-Fa-f0-9]{32,128}$")
_KNOWN_HASH_LENGTHS = {32, 40, 56, 64, 96, 128}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_likely_noise(token: str, line: str) -> bool:
    if _BASE64_IMAGE_RE.search(line):
        return True
    if _HASH_PREFIX_RE.search(line):
        return True
    if _HEX_HASH_RE.match(token) and len(token) in _KNOWN_HASH_LENGTHS:
        return True
    for url in _URL_RE.findall(line):
        if token in url:
            return True
    return False


def scan_text(
    text: str,
    path: Path,
    threshold: float = DEFAULT_THRESHOLD,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> Iterator[Finding]:
    seen_in_line: set[tuple[int, str]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        for token in _TOKEN_RE.findall(line):
            if len(token) < min_length:
                continue
            if (lineno, token) in seen_in_line:
                continue
            seen_in_line.add((lineno, token))
            if _is_likely_noise(token, line):
                continue
            if shannon_entropy(token) < threshold:
                continue
            yield Finding(
                rule="high-entropy",
                path=path,
                line=lineno,
                snippet=_redact(line, token),
            )


def _redact(line: str, token: str) -> str:
    if len(token) <= 8:
        masked = "*" * len(token)
    else:
        digest = hashlib.sha256(token.encode()).hexdigest()[:6]
        masked = f"{token[:2]}…{token[-2:]} ({digest})"
    return line.replace(token, masked, 1)


def scan_file(
    path: Path,
    threshold: float = DEFAULT_THRESHOLD,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> Iterator[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return iter(())
    return scan_text(text, path, threshold, min_length)
