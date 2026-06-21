from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    rule: str
    path: Path
    line: int
    snippet: str
