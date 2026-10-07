#!/usr/bin/env python3
"""Regenerate the README module table from index.json.

The table between the modules:begin / modules:end markers is generated; edit
index.json, not the table. .github/workflows/readme.yml runs this after every
push to the default branch and commits the result when it changed.
"""
from __future__ import annotations

import json
import pathlib

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
        link = ""
        if m.get("repo"):
            # Link the pinned commit: that is the code the listing check ran on.
            label = m["repo"].split("//", 1)[-1].removeprefix("github.com/")
            link = f"[{label} @ {m['commit'][:7]}]({m['repo']}/tree/{m['commit']})"
        elif m.get("homepage"):
            url = m["homepage"]
            link = f"[{url.split('//', 1)[-1].removeprefix('www.')}]({url})"
        cells = (m["name"], TIER_LABEL[m["tier"]], m["description"], link,
                 m["author"], m["license"])
        lines.append("| " + " | ".join(cell(c) for c in cells) + " |")
    return "\n".join(lines)


def regenerate(text: str, index: dict) -> str:
    """README text with the generated block replaced; everything else kept."""
    if BEGIN not in text or END not in text:
        raise ValueError("README.md is missing the modules:begin / modules:end markers")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    return f"{head}{BEGIN}\n{render(index)}\n{END}{tail}"


def main() -> int:
    readme = ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
    try:
        new = regenerate(text, index)
    except ValueError as exc:
        print(exc)
        return 1
    readme.write_text(new, encoding="utf-8")
    print("README table regenerated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
