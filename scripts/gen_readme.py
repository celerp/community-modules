#!/usr/bin/env python3
"""Regenerate the README module table from index.json.

The table between the modules:begin / modules:end markers is generated; edit
index.json, not the table. CI runs `gen_readme.py --check` to keep them in sync.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- modules:begin -->", "<!-- modules:end -->"
TIER_LABEL = {"official": "Official", "verified": "Verified", "community": "Community"}


def render(index: dict) -> str:
    lines = [
        "| Module | Tier | What it does | Source | Author | License |",
        "|---|---|---|---|---|---|",
    ]
    def cell(v) -> str:
        # Escape pipes and flatten any newline so one field cannot split the
        # markdown row (schema allows newlines in description).
        return " ".join(str(v).replace("|", "\\|").split())

    for m in index["modules"]:
        url = m.get("repo") or m.get("homepage") or ""
        link = f"[{url.split('//', 1)[-1].removeprefix('github.com/').removeprefix('www.')}]({url})" if url else ""
        cells = (m["name"], TIER_LABEL[m["tier"]], m["description"], link,
                 m["author"], m["license"])
        lines.append("| " + " | ".join(cell(c) for c in cells) + " |")
    return "\n".join(lines)


def main() -> int:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        print("README.md is missing the modules:begin / modules:end markers")
        return 1
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
    new = f"{head}{BEGIN}\n{render(index)}\n{END}{tail}"
    if "--check" in sys.argv:
        if new != text:
            print("README table is out of date: run scripts/gen_readme.py and commit")
            return 1
        print("README table in sync with index.json")
        return 0
    readme.write_text(new, encoding="utf-8")
    print("README table regenerated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
