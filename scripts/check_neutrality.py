#!/usr/bin/env python3
"""Fail if forbidden project-specific strings appear in tracked files."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


SKIP_DIRS = {".git", ".mypy_cache", ".pytest_cache", "__pycache__", "build", "dist"}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    paths: list[Path] = []
    for line in result.stdout.splitlines():
        path = Path(line)
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        paths.append(path)
    return paths


def configured_terms() -> list[str]:
    raw = os.environ.get("BINARY_COMP_FORBIDDEN_TERMS", "")
    return [term for term in raw.splitlines() if term]


def main() -> int:
    terms = configured_terms()
    if not terms:
        return 0

    matches: list[tuple[Path, str]] = []
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            continue

        for term in terms:
            if term in text:
                matches.append((path, term))

    if matches:
        print("Forbidden project-specific strings found:", file=sys.stderr)
        for path, term in matches:
            print(f"  {path}: {term!r}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
