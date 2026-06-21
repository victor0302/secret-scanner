from pathlib import Path

from secret_scanner.detectors.regex import scan_text


def _findings(text: str):
    return list(scan_text(text, Path("dummy.py")))


def test_aws_access_key_positive():
    f = _findings("aws_access_key = 'AKIAIOSFODNN7EXAMPLE'")
    assert any(x.rule == "aws-access-key-id" for x in f)


def test_aws_secret_key_positive():
    f = _findings('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"')
    assert any(x.rule == "aws-secret-access-key" for x in f)


def test_github_pat_positive():
    token = "ghp_" + "a" * 36
    assert any(x.rule == "github-pat" for x in _findings(f"token = {token}"))


def test_github_fine_grained_pat_positive():
    token = "github_pat_" + "B" * 82
    assert any(x.rule == "github-fine-grained-pat" for x in _findings(token))


def test_private_key_header_positive():
    f = _findings("-----BEGIN RSA PRIVATE KEY-----")
    assert any(x.rule == "private-key-header" for x in f)
    f2 = _findings("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert any(x.rule == "private-key-header" for x in f2)


def test_generic_api_token_positive():
    f = _findings('api_key = "abcdefghijklmnopqrst12345"')
    assert any(x.rule == "generic-api-token" for x in f)


def test_negative_random_python_code():
    code = """
def hello():
    print("hello world")
    return 42

class Foo:
    bar = "baz"
"""
    assert _findings(code) == []


def test_negative_short_token_not_flagged():
    assert _findings('api_key = "short"') == []


def test_negative_aws_lookalike_not_flagged():
    assert _findings("# AKIA but not 16 chars after") == []


def test_line_number_recorded():
    text = "harmless\n\nghp_" + "a" * 36 + "\n"
    findings = _findings(text)
    assert findings[0].line == 3


def test_snippet_truncated():
    long_value = "x" * 500
    f = _findings(f'api_key = "{long_value}"')
    assert f and f[0].snippet.endswith("…")
