"""reqlock: verify requirements.lock matches requirements.in pins and PEP 508 hashes."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class LockEntry:
    name: str
    version: str | None = None
    hashes: list[str] = field(default_factory=list)
    extras: list[str] = field(default_factory=list)
    line: int = 0


REQ_FILE_LINE = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?P<spec>.*)?$")
SPEC_PIN = re.compile(r"==\s*(?P<version>[A-Za-z0-9_.+\-*!]+)")


def _extract_hashes(text: str) -> list[str]:
    hashes = []
    pos = 0
    text_lower = text.lower()
    while True:
        idx = text_lower.find("--hash=sha256:", pos)
        if idx == -1:
            break
        start = idx + len("--hash=sha256:")
        end = start
        while end < len(text) and text[end] in "0123456789abcdefABCDEF":
            end += 1
        if end > start:
            hashes.append(text[start:end].lower())
        pos = end
    return hashes


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirements(lines: Iterable[str]) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = REQ_FILE_LINE.match(line)
        if not match:
            continue
        name = _normalize(match.group("name"))
        spec = match.group("spec") or ""
        version_match = SPEC_PIN.search(spec)
        version = version_match.group("version") if version_match else None
        entries[name] = {"version": version, "extras": [], "line": idx, "hashes": []}
    return entries


def _parse_lock(lines: Iterable[str]) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    current: dict | None = None
    for idx, line in enumerate(lines, 1):
        raw = line.rstrip("\n")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("-e "):
            continue
        is_header = (not raw.startswith(" ") and not raw.startswith("\t")) or stripped.startswith("- ")
        if is_header:
            current = None
            if stripped.startswith("- "):
                stripped = stripped[2:]
            if stripped.startswith("--"):
                continue
            name_part = stripped.split()[0]
            name_part = name_part.split("==")[0] if "==" in name_part else name_part
            name = _normalize(name_part.split("[")[0])
            current = entries.setdefault(name, {"version": None, "extras": [], "line": idx, "hashes": []})
            extras = re.search(r"\[([^\]]+)\]", name_part)
            if extras:
                current["extras"] = [e.strip() for e in extras.group(1).split(",")]
            version_match = SPEC_PIN.search(stripped)
            if version_match:
                current["version"] = version_match.group("version")
            current["hashes"].extend(_extract_hashes(stripped))
            continue
        if current is None:
            continue
        current["hashes"].extend(_extract_hashes(stripped))
    return entries


class Report:
    def __init__(self) -> None:
        self.issues: list[str] = []

    def add(self, path: str, message: str) -> None:
        self.issues.append(f"{path}: {message}")

    @property
    def ok(self) -> bool:
        return not self.issues


def analyze(lock_path: Path, in_path: Path) -> Report:
    report = Report()
    if not lock_path.exists():
        report.add(str(lock_path), "missing requirements.lock file")
        return report
    if not in_path.exists():
        report.add(str(in_path), "missing requirements.in file")
        return report

    locked = _parse_lock(lock_path.read_text().splitlines())
    pins = _parse_requirements(in_path.read_text().splitlines())

    for name, pin in pins.items():
        entry = locked.get(name)
        if entry is None:
            report.add(str(lock_path), f"{name} pinned in requirements.in but missing from lock")
            continue
        if pin["version"] and pin["version"] != "*" and entry["version"] != pin["version"]:
            report.add(str(lock_path), f"{name} pinned to {pin['version']} but locked at {entry['version'] or '<missing>'}")
        if pin["extras"] and set(pin["extras"]) != set(entry["extras"]):
            report.add(str(lock_path), f"{name} extras differ: {pin['extras']} vs {entry['extras']}")

    for name, entry in locked.items():
        if not entry["hashes"]:
            report.add(str(lock_path), f"{name} missing SHA256 hash in lock")
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify requirements.lock matches requirements.in")
    parser.add_argument("lock", type=Path, default=Path("requirements.lock"), nargs="?", help="Path to requirements.lock")
    parser.add_argument("--in", dest="input", type=Path, default=Path("requirements.in"), help="Path to requirements.in")
    parser.add_argument("--strict", action="store_true", help="Treat missing hashes as errors")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    report = analyze(args.lock, args.input)
    if not args.strict:
        report.issues = [issue for issue in report.issues if "missing SHA256 hash" not in issue]
    for issue in report.issues:
        print(f"ERROR: {issue}", file=sys.stderr)
    if report.ok:
        print("OK: requirements.lock matches requirements.in")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
