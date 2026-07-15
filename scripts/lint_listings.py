#!/usr/bin/env python3
"""Validate the module listing table in README.md.

Runs on pull requests as an advisory check (not a hard merge gate): it flags a
malformed listing row so the contributor can fix it, but a maintainer still
reviews and decides. It checks the whole table, so a bad addition is caught
regardless of the diff. It only reads text - it never runs a listed module.
"""
from __future__ import annotations

import pathlib
import re
import sys

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"


def main() -> int:
    lines = README.read_text(encoding="utf-8").splitlines()

    header = next((i for i, ln in enumerate(lines)
                   if re.match(r"\s*\|\s*Module\s*\|", ln)), None)
    if header is None:
        print("Could not find the listing table (a row starting with '| Module |').")
        return 1

    problems: list[str] = []
    count = 0
    for ln in lines[header + 2:]:            # skip header + separator row
        if not ln.strip().startswith("|"):
            break                            # table ended
        if set(ln.replace("|", "").strip()) <= set("-: "):
            continue                         # a separator/divider row
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        count += 1
        if len(cells) < 5:
            problems.append(f"row {count}: expected 5 columns "
                            f"(Module | What it does | Repository | Author | License), "
                            f"got {len(cells)}: {ln.strip()}")
            continue
        module, desc, repo, author, lic = cells[:5]
        if not module:
            problems.append(f"row {count}: empty Module name")
        if not desc:
            problems.append(f"row {count} ({module}): empty description")
        if "http" not in repo:
            problems.append(f"row {count} ({module}): Repository must be a link")
        if not author:
            problems.append(f"row {count} ({module}): empty Author")
        if not lic:
            problems.append(f"row {count} ({module}): empty License")

    if problems:
        print("Listing table problems:")
        for p in problems:
            print("  -", p)
        return 1
    print(f"OK: {count} listing(s), table well-formed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
