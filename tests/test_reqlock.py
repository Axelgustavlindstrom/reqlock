from __future__ import annotations

from pathlib import Path

from reqlock import analyze, main


def test_pin_missing_in_lock(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.lock"
    inp = tmp_path / "requirements.in"
    lock.write_text("requests==2.31.0 --hash=sha256:abc123\n")
    inp.write_text("requests==2.31.0\npandas==2.2.1\n")
    report = analyze(lock, inp)
    assert any("pandas" in issue for issue in report.issues)


def test_version_drift(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.lock"
    inp = tmp_path / "requirements.in"
    lock.write_text("requests==2.30.0 --hash=sha256:abc123def456\n")
    inp.write_text("requests==2.31.0\n")
    report = analyze(lock, inp)
    assert any("2.30.0" in issue and "2.31.0" in issue for issue in report.issues)


def test_clean_lock(tmp_path: Path) -> None:
    lock = tmp_path / "requirements.lock"
    inp = tmp_path / "requirements.in"
    lock.write_text("requests==2.31.0 --hash=sha256:abc123def456\n")
    inp.write_text("requests==2.31.0\n")
    report = analyze(lock, inp)
    assert report.ok


def test_missing_lock(tmp_path: Path, capsys) -> None:  # type: ignore[name-defined]
    rc = main([str(tmp_path / "requirements.lock"), "--in", str(tmp_path / "requirements.in")])
    assert rc == 1


def test_main_clean() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        lock = Path(tmp) / "requirements.lock"
        inp = Path(tmp) / "requirements.in"
        lock.write_text("requests==2.31.0 --hash=sha256:abc123def456\n")
        inp.write_text("requests==2.31.0\n")
        rc = main([str(lock), "--in", str(inp)])
        assert rc == 0
