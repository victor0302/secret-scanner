# secret-scanner

Scan a filesystem path for leaked secrets.

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
secret-scanner scan <path> [--output text|json|sarif] [--detectors all|regex|entropy] [--no-color] [--no-gitignore] [--max-bytes N]
```

Exit codes: `0` clean, `1` secrets found, `2` bad input.

## Develop

```bash
ruff check .
pytest
```

## Output formats

### Text

Findings grouped by file, sorted within each file by line number. ANSI colors on by default; disable with `--no-color`.

### JSON

```json
{
  "findings": [
    {
      "rule": "github-pat",
      "path": "src/leak.py",
      "line": 12,
      "snippet": "token = ghp_..."
    }
  ]
}
```

Findings are sorted by `(path, line, rule)`. Paths are reported relative to the scanned root.

### SARIF

Emits SARIF 2.1.0. Each unique rule id becomes a rule in `runs[0].tool.driver.rules`; each finding becomes a result in `runs[0].results` with `physicalLocation` set. All findings emit at `level: "error"`.
