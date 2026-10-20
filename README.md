# reqlock

A lightweight CLI that verifies `requirements.lock` matches `requirements.in` pins and PEP 508 SHA256 hashes.

## About

`reqlock` reads a `requirements.in` pin file and a `requirements.lock` output file, then reports mismatches such as:

- missing packages
- version drift
- extras mismatch
- missing hashes

It is designed for small Python projects using `pip-tools`-style workflows.

## Features

- Compare locked versions against pinned versions.
- Detect missing `--hash=sha256:<digest>` entries.
- Fail fast with clear `ERROR:` messages on `stderr`.

## Installation

```bash
python -m pip install -e .
```

## Usage

```bash
reqlock requirements.lock --in requirements.in
```

Add `--strict` to treat missing hashes as errors.

## Project structure

```
README.md
pyproject.toml
reqlock.py
tests/
    └── test_reqlock.py
```

## Tags

`pip-tools` `requirements.in` `requirements.lock` `sha256` `lockfile` `cli`
