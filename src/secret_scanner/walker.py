from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pathspec

DEFAULT_MAX_BYTES = 10 * 1024 * 1024
_GITIGNORE = ".gitignore"
_VCS_DIRS = {".git", ".hg", ".svn"}


@dataclass(frozen=True)
class WalkConfig:
    max_bytes: int = DEFAULT_MAX_BYTES
    respect_gitignore: bool = True


def _load_gitignore(root: Path) -> pathspec.PathSpec | None:
    gitignore = root / _GITIGNORE
    if not gitignore.is_file():
        return None
    return pathspec.GitIgnoreSpec.from_lines(gitignore.read_text().splitlines())


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(8192)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    try:
        chunk.decode("utf-8")
    except UnicodeDecodeError:
        try:
            chunk.decode("latin-1")
        except UnicodeDecodeError:
            return True
        printable = sum(b >= 0x20 or b in (0x09, 0x0A, 0x0D) for b in chunk)
        if chunk and printable / len(chunk) < 0.85:
            return True
    return False


def walk(root: Path, config: WalkConfig | None = None) -> Iterator[Path]:
    cfg = config or WalkConfig()
    if not root.is_dir():
        return
    spec = _load_gitignore(root) if cfg.respect_gitignore else None

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _VCS_DIRS for part in path.relative_to(root).parts):
            continue
        if spec is not None:
            rel = str(path.relative_to(root))
            if spec.match_file(rel):
                continue
        try:
            if path.stat().st_size > cfg.max_bytes:
                continue
        except OSError:
            continue
        if _is_binary(path):
            continue
        yield path
