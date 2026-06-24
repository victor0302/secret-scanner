# secret-scanner

[![CI](https://github.com/victor0302/secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/victor0302/secret-scanner/actions/workflows/ci.yml)

Scan a filesystem path for leaked secrets.

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
secret-scanner <path>
```

## Develop

```bash
ruff check .
pytest
```
