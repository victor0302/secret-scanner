# secret-scanner — progress notes

Running log of what's been built and why. Append-only.

## 2026-06-17 — Issue #1: scaffolding

Laid down the project skeleton so the rest of the tickets have somewhere to land.

- `pyproject.toml` with PEP 621 metadata, a `secret-scanner` console script entry point
- `src/` layout: `src/secret_scanner/` package, version string, `cli.py`
- `tests/` with a passing smoke test
- ruff + pytest pinned via the `[dev]` extra

Decisions:
- **`src/` layout over flat layout.** Tests import the installed package — catches "works in-tree, breaks on install" early.
- **setuptools, not hatch/poetry.** Stdlib-adjacent, zero ceremony for a CLI with no exotic build needs.
- **ruff rules: `E, F, I, UP, B`.** Lint + import sort + modernizers + bugbear. No `D` (docstrings) — overkill on a CLI this small.

## 2026-06-17 — Issue #2: `scan` subcommand

Built out the CLI surface. Detection itself is still stubbed — regex and entropy detectors come in #4 and #5.

- `secret-scanner scan <path>` subcommand
- `--output {text,json,sarif}` wired through (SARIF emits a minimal 2.1.0 envelope)
- `--help` shows usage
- Empty / arbitrary directory exits 0 cleanly
- Exit `2` reserved for bad input (e.g. path is a file, not a directory)

Decisions:
- **Subcommand from day one.** Cheap to add now, expensive to retrofit. Leaves room for `list-rules`, `bench`, etc. later.
- **argparse over click.** Stdlib, no extra dep, and the surface is small enough that click's ergonomics aren't worth it yet.
- **SARIF stub now, fill later.** Wiring the format string through the pipeline is the hard part; emitting an empty `runs` array is trivial and lets CI tooling start consuming it.
- **Exit codes match grep-style convention.** `0` clean, `1` reserved for "found a secret" (once detectors land), `2` for bad input.

## Open follow-ups (tracked as issues)

- #3 file walker: respect `.gitignore`, skip binaries
- #4 regex-based detector with built-in rule set
- #5 entropy-based detector for high-entropy strings
- #6 output formats: fill in real text / JSON / SARIF bodies
- #7 GitHub Actions: lint + test workflow
