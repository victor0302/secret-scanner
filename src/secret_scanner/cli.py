from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

OUTPUT_CHOICES: tuple[str, ...] = ("text", "json", "sarif")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a filesystem path for leaked secrets.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a directory tree for secrets.")
    scan.add_argument("path", help="Path to scan.")
    scan.add_argument("--output", choices=OUTPUT_CHOICES, default="text")
    return parser


def _emit(findings: list[dict], output: str) -> str:
    if output == "json":
        return json.dumps({"findings": findings}, indent=2)
    if output == "sarif":
        return json.dumps(
            {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "secret-scanner"}}, "results": findings}],
            },
            indent=2,
        )
    if not findings:
        return "No secrets found."
    return "\n".join(f"- {f}" for f in findings)


def run_scan(path: Path, output: str) -> int:
    if not path.is_dir():
        print(f"error: {path} is not a directory", file=sys.stderr)
        return 2
    findings: list[dict] = []
    print(_emit(findings, output))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return run_scan(Path(args.path), args.output)
    return 2


if __name__ == "__main__":
    sys.exit(main())
