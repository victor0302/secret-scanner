import json
from pathlib import Path

from secret_scanner.detectors import Finding
from secret_scanner.output import render_json, render_sarif, render_text


def _f(path="src/leak.py", line=12, rule="github-pat", snippet="token = ghp_..."):
    return Finding(rule=rule, path=Path(path), line=line, snippet=snippet)


def test_text_empty():
    assert render_text([]) == "No secrets found."


def test_text_groups_by_file_and_sorts_by_line():
    findings = [
        _f(path="b.py", line=3, rule="github-pat"),
        _f(path="a.py", line=10, rule="aws-access-key-id"),
        _f(path="a.py", line=2, rule="github-pat"),
    ]
    out = render_text(findings, color=False)
    a_idx = out.index("a.py")
    b_idx = out.index("b.py")
    assert a_idx < b_idx
    line_2_idx = out.index("line 2")
    line_10_idx = out.index("line 10")
    assert line_2_idx < line_10_idx


def test_text_color_toggle():
    f = _f()
    colored = render_text([f], color=True)
    plain = render_text([f], color=False)
    assert "\x1b[" in colored
    assert "\x1b[" not in plain


def test_text_uses_relative_path_with_root(tmp_path):
    f = Finding(rule="x", path=tmp_path / "a" / "b.py", line=1, snippet="...")
    out = render_text([f], root=tmp_path, color=False)
    assert "a/b.py" in out
    assert str(tmp_path) not in out


def test_json_schema_and_sorting(tmp_path):
    findings = [
        Finding(rule="r1", path=tmp_path / "b.py", line=1, snippet="x"),
        Finding(rule="r2", path=tmp_path / "a.py", line=10, snippet="y"),
    ]
    payload = json.loads(render_json(findings, root=tmp_path))
    assert [f["path"] for f in payload["findings"]] == ["a.py", "b.py"]
    assert payload["findings"][0] == {
        "rule": "r2", "path": "a.py", "line": 10, "snippet": "y"
    }


def test_sarif_structure(tmp_path):
    findings = [
        Finding(rule="github-pat", path=tmp_path / "leak.py", line=5, snippet="..."),
    ]
    payload = json.loads(render_sarif(findings, root=tmp_path))
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "secret-scanner"
    assert run["tool"]["driver"]["rules"][0]["id"] == "github-pat"
    result = run["results"][0]
    assert result["ruleId"] == "github-pat"
    assert result["level"] == "error"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "leak.py"
    assert loc["region"]["startLine"] == 5
