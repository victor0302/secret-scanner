import json

import pytest

from secret_scanner import __version__
from secret_scanner.cli import build_parser, main


def test_version():
    assert __version__ == "0.1.0"


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_parser_scan_defaults():
    args = build_parser().parse_args(["scan", "."])
    assert args.command == "scan"
    assert args.path == "."
    assert args.output == "text"


def test_scan_empty_dir(tmp_path, capsys):
    rc = main(["scan", str(tmp_path)])
    assert rc == 0
    assert "No secrets found." in capsys.readouterr().out


def test_scan_json_output(tmp_path, capsys):
    rc = main(["scan", str(tmp_path), "--output", "json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {"findings": []}


def test_scan_sarif_output(tmp_path, capsys):
    rc = main(["scan", str(tmp_path), "--output", "sarif"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "secret-scanner"


def test_scan_not_a_directory(tmp_path):
    f = tmp_path / "file"
    f.write_text("")
    rc = main(["scan", str(f)])
    assert rc == 2


def test_scan_finds_planted_secret_and_exits_1(tmp_path, capsys):
    (tmp_path / "leak.py").write_text("token = ghp_" + "a" * 36 + "\n")
    rc = main(["scan", str(tmp_path), "--output", "json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"]
    assert payload["findings"][0]["rule"] == "github-pat"
    assert payload["findings"][0]["path"] == "leak.py"


def test_scan_detectors_filter(tmp_path, capsys):
    (tmp_path / "leak.py").write_text("token = ghp_" + "a" * 36 + "\n")
    rc = main(["scan", str(tmp_path), "--detectors", "entropy", "--output", "json"])
    assert rc in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    # Regex rule should NOT appear when detectors are limited to entropy.
    assert all(f["rule"] != "github-pat" for f in payload["findings"])
