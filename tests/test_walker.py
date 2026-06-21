from secret_scanner.walker import WalkConfig, walk


def _names(paths):
    return sorted(p.name for p in paths)


def test_yields_text_files(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "b.py").write_text("print(1)")
    assert _names(walk(tmp_path)) == ["a.txt", "b.py"]


def test_skips_binaries(tmp_path):
    (tmp_path / "code.py").write_text("print('hi')")
    (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02\x03" * 1000)
    assert _names(walk(tmp_path)) == ["code.py"]


def test_respects_gitignore(tmp_path):
    (tmp_path / ".gitignore").write_text("secrets.txt\nbuild/\n")
    (tmp_path / "code.py").write_text("ok")
    (tmp_path / "secrets.txt").write_text("nope")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.txt").write_text("x")
    names = _names(walk(tmp_path))
    assert "code.py" in names
    assert "secrets.txt" not in names
    assert "out.txt" not in names


def test_can_disable_gitignore(tmp_path):
    (tmp_path / ".gitignore").write_text("secrets.txt\n")
    (tmp_path / "code.py").write_text("ok")
    (tmp_path / "secrets.txt").write_text("nope")
    names = _names(walk(tmp_path, WalkConfig(respect_gitignore=False)))
    assert "secrets.txt" in names


def test_skips_oversize_files(tmp_path):
    (tmp_path / "small.txt").write_text("ok")
    (tmp_path / "big.txt").write_text("A" * 2048)
    names = _names(walk(tmp_path, WalkConfig(max_bytes=1024)))
    assert names == ["small.txt"]


def test_skips_vcs_directories(tmp_path):
    (tmp_path / "code.py").write_text("ok")
    git = tmp_path / ".git"
    git.mkdir()
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    assert _names(walk(tmp_path)) == ["code.py"]


def test_handles_non_dir(tmp_path):
    f = tmp_path / "file"
    f.write_text("hi")
    assert list(walk(f)) == []
