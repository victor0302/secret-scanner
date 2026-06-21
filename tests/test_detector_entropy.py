from pathlib import Path

from secret_scanner.detectors.entropy import scan_text, shannon_entropy


def _findings(text: str, **kw):
    return list(scan_text(text, Path("dummy.py"), **kw))


def test_entropy_zero_for_repeated():
    assert shannon_entropy("aaaa") == 0


def test_entropy_high_for_random():
    assert shannon_entropy("aB3kL9pQ2wZx7Yc1") > 3.5


def test_high_entropy_string_detected():
    secret = "kL9pQ2wZx7Yc1aB3rT5uV8mN4oP6"
    findings = _findings(f'token = "{secret}"')
    assert findings and findings[0].rule == "high-entropy"
    assert secret not in findings[0].snippet


def test_low_entropy_string_ignored():
    assert _findings('value = "aaaaaaaaaaaaaaaaaaaaaaaa"') == []


def test_short_tokens_ignored():
    assert _findings('value = "kL9pQ2wZx7Yc"') == []


def test_base64_image_suppressed():
    blob = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAA"
    assert _findings(blob) == []


def test_hash_prefix_suppressed():
    line = "integrity: sha256:KL9pQ2wZx7Yc1aB3rT5uV8mN4oP6KL9pQ2wZx7Yc1aB3rT5uV"
    assert _findings(line) == []


def test_known_length_hex_hash_suppressed():
    sha256_hex = "a" * 32 + "b" * 32  # 64 hex chars
    assert _findings(f"checksum = {sha256_hex}") == []


def test_url_token_suppressed():
    line = "see https://example.com/Kl9pQ2wZx7Yc1aB3rT5uV8mN4oP6 for details"
    assert _findings(line) == []


def test_threshold_configurable():
    secret = "kL9pQ2wZx7Yc1aB3rT5uV8mN4oP6"
    assert _findings(secret, threshold=10.0) == []
