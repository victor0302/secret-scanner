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

## 2026-06-20 — Issue #3: file walker

Walker that produces the list of files the detectors will actually scan. Lives in `src/secret_scanner/walker.py`. Adds `pathspec>=0.12` as the first runtime dep.

- `walk(root, config)` is a generator yielding `Path`s
- `WalkConfig(max_bytes=10MB, respect_gitignore=True)` is a frozen dataclass — easy to extend without breaking callers
- Root-level `.gitignore` honored via `pathspec.GitIgnoreSpec` (not the deprecated `gitwildmatch`)
- `.git` / `.hg` / `.svn` always skipped
- Binary detection: NUL-byte sniff first, then UTF-8 decode attempt, then latin-1 with a printable-byte ratio threshold

Decisions:
- **`pathspec.GitIgnoreSpec` over hand-rolled glob.** `.gitignore` syntax has too many gotchas (negation, anchored vs. floating, directory-only) to redo poorly. `pathspec` is what tools like `pre-commit` use.
- **Root-level `.gitignore` only.** Nested `.gitignore` files compound; supporting them well means reading them lazily per directory. Cheap to add later if anyone hits the case; not worth it now.
- **VCS dirs in a hard-coded set, not via `.gitignore`.** Repos almost never ignore their own `.git` because they don't have to — the directory just *is* invisible to git. Hard-coding it makes the walker robust on repos with no `.gitignore` at all.
- **Binary detection is a three-stage heuristic, not magic bytes.** Magic-byte sniffing means maintaining a list; the heuristic catches anything where the first 8 KB don't look like text and is essentially free.
- **`WalkConfig.respect_gitignore` is configurable.** Audits sometimes want to look at exactly the files git would ignore (`.env`, `secrets/`) — the flag exists for that.

## 2026-06-20 — Issue #4: regex detector

Pattern-based detector under `src/secret_scanner/detectors/regex.py`. Shared `Finding(rule, path, line, snippet)` dataclass in `detectors/__init__.py`.

- Six built-in rules: `aws-access-key-id`, `aws-secret-access-key`, `github-pat` (`ghp_…`), `github-fine-grained-pat` (`github_pat_…`), `private-key-header`, `generic-api-token`
- `scan_text(text, path, rules=BUILTIN_RULES)` and `scan_file(path)` — both are generators

Decisions:
- **`Finding` lives in `detectors/__init__.py`, not per-detector.** Both detectors emit the same shape; downstream output formatters shouldn't have to care which detector found what.
- **Snippets capped at 200 chars with an ellipsis.** A minified JS bundle can put a key on a 200 KB line. The line number tells you where to look; the snippet just needs to be enough to recognize.
- **Generic-token rule requires a keyed assignment (`api_key = "..."`).** A bare 20-character base64 string isn't enough signal on its own — that's what entropy (#5) is for. This keeps regex high-precision and lets entropy be the high-recall net.
- **AWS secret rule looks for `aws_…_key = "<40 chars>"`, not bare 40-char strings.** Otherwise every base64 SHA is a false positive.
- **Private-key rule matches the header line, not the body.** The body is whatever PEM-encoded payload happened to be in the file; the header is the unambiguous signal.
- **Negative tests for every rule.** Adding a new rule without a negative case means you've shipped a false-positive engine; the test file enforces the pattern.

## 2026-06-20 — Issue #5: entropy detector

Catches secrets that don't match a known shape. Lives in `src/secret_scanner/detectors/entropy.py`, shares the `Finding` type with the regex detector.

- Shannon entropy on tokens ≥20 chars from a deliberately permissive `[A-Za-z0-9+/=_-]{12,}` alphabet
- Default threshold 4.5 (configurable per call)
- Snippets redact the live token to `xx…yy (sha6)` so log lines don't leak the secret you just found
- Noise heuristics: skip `data:image/...;base64,` blobs, lines naming a checksum field (`sha256:` / `integrity:`), hex strings at known hash lengths (32/40/56/64/96/128), and tokens that appear inside a URL on the same line

Decisions:
- **Threshold 4.5 over the textbook 4.8.** 4.8 misses a lot of real keys (especially `[A-Za-z]{40}`-style tokens with no digits); 4.5 produced markedly fewer false negatives on a sample of synthetic inputs without flooding noise. Tunable, not enshrined.
- **Per-line de-dupe.** A repeated token on the same line (e.g. in a printf debug) only gets reported once.
- **Redaction by default.** This is the one place where the scanner *holds* the actual secret in memory; emitting it verbatim into logs / CI output would be its own incident. The 6-char hash suffix is enough for an analyst to correlate without leaking.
- **Suppression is heuristic, not pattern-perfect.** Better to occasionally miss a low-frequency noise source than to add a rule per format. The four current suppressors cover ~all of the real-world noise I saw in spike testing (images, lockfile integrity hashes, hex digests, URL paths).
- **No file walking inside the detector.** Both detectors take a single `Path`; orchestration (which files to scan, parallelism, output formatting) is the CLI's job once #6 lands.

## Open follow-ups (tracked as issues)

- #6 output formats: fill in real text / JSON / SARIF bodies (and wire walker + detectors in)
- #7 GitHub Actions: lint + test workflow
