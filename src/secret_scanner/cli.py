import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan a filesystem path for leaked secrets.",
    )
    parser.add_argument("path", nargs="?", default=".", help="Path to scan.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(f"secret-scanner: scaffolding only; nothing to scan yet at {args.path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
