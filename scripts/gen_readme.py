#!/usr/bin/env python3
"""Regenerate the README module table from index-v2.json.

The table between the modules:begin / modules:end markers is generated; edit
index-v2.json, not the table. .github/workflows/readme.yml runs this after every
push to the default branch and commits the result when it changed.

Text from a listing is shown as plain text: every Markdown character in it is
escaped, so it cannot become a link, an image, HTML or formatting. Only the
Source column is Markdown, built from the validated repository and commit.
"""
from __future__ import annotations

import json
import pathlib
import string

from listing import CATALOG

ROOT = pathlib.Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- modules:begin -->", "<!-- modules:end -->"
TIER_LABEL = {"official": "Official", "verified": "Verified", "community": "Community"}
# CommonMark lets a backslash escape any ASCII punctuation character.
MARKDOWN_ESCAPES = str.maketrans({c: "\\" + c for c in string.punctuation})


def plain(value) -> str:
    """Listing text as one line of literal table-cell text."""
    return " ".join(str(value).split()).translate(MARKDOWN_ESCAPES)


def render(index: dict) -> str:
    lines = [
        "| Module | Tier | What it does | Source | Author | License |",
        "|---|---|---|---|---|---|",
    ]
    for m in index["modules"]:
        link = ""
        if m.get("repo"):
            # Link the pinned commit: that is the code the listing check ran on.
            label = m["repo"].split("//", 1)[-1].removeprefix("github.com/")
            link = f"[{label} @ {m['commit'][:7]}]({m['repo']}/tree/{m['commit']})"
        elif m.get("homepage"):
            url = m["homepage"]
            link = f"[{url.split('//', 1)[-1].removeprefix('www.')}]({url})"
        cells = (plain(m["name"]), TIER_LABEL[m["tier"]], plain(m["description"]), link,
                 plain(m["author"]), plain(m["license"]))
        lines.append("| " + " | ".join(cells) + " |")
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
    index = json.loads((ROOT / CATALOG).read_text(encoding="utf-8"))
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
