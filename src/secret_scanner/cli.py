from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .detectors import Finding
from .detectors import entropy as entropy_detector
from .detectors import regex as regex_detector
from .output import render_json, render_sarif, render_text
from .walker import WalkConfig, walk

OUTPUT_CHOICES: tuple[str, ...] = ("text", "json", "sarif")
DETECTOR_CHOICES: tuple[str, ...] = ("all", "regex", "entropy")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a filesystem path for leaked secrets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a directory tree for secrets.")
    scan.add_argument("path", help="Path to scan.")
    scan.add_argument("--output", choices=OUTPUT_CHOICES, default="text")
    scan.add_argument(
        "--detectors",
        choices=DETECTOR_CHOICES,
        default="all",
        help="Which detectors to run (default: all).",
    )
    scan.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in text output."
    )
    scan.add_argument(
        "--no-gitignore",
        action="store_true",
        help="Scan files even if .gitignore excludes them.",
    )
    scan.add_argument(
        "--max-bytes",
        type=int,
        default=WalkConfig().max_bytes,
        help="Skip files larger than this many bytes (default 10 MB).",
    )
    return parser


def _emit(findings: list[Finding], output: str, *, root: Path, color: bool) -> str:
    if output == "json":
        return render_json(findings, root=root)
    if output == "sarif":
        return render_sarif(findings, root=root)
    return render_text(findings, root=root, color=color)


def _collect_findings(root: Path, detectors: str, walk_config: WalkConfig) -> list[Finding]:
    findings: list[Finding] = []
    for path in walk(root, walk_config):
        if detectors in ("all", "regex"):
            findings.extend(regex_detector.scan_file(path))
        if detectors in ("all", "entropy"):
            findings.extend(entropy_detector.scan_file(path))
    return findings


def run_scan(
    path: Path,
    output: str,
    detectors: str,
    *,
    color: bool,
    respect_gitignore: bool,
    max_bytes: int,
) -> int:
    if not path.is_dir():
        print(f"error: {path} is not a directory", file=sys.stderr)
        return 2
    walk_config = WalkConfig(max_bytes=max_bytes, respect_gitignore=respect_gitignore)
    findings = _collect_findings(path, detectors, walk_config)
    print(_emit(findings, output, root=path, color=color))
    return 1 if findings else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return run_scan(
            Path(args.path),
            args.output,
            args.detectors,
            color=not args.no_color,
            respect_gitignore=not args.no_gitignore,
            max_bytes=args.max_bytes,
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
