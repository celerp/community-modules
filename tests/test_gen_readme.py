"""The README table is generated from index-v2.json and links each pinned commit."""
from __future__ import annotations

import json
import string
import unittest

from fakes import ROOT, SHA_A, entry
from gen_readme import regenerate

README = "# Top\n\n<!-- modules:begin -->\nstale\n<!-- modules:end -->\n\nTail.\n"


class Regenerate(unittest.TestCase):
    def test_table_replaces_only_the_marked_block(self):
        out = regenerate(README, {"modules": [entry()]})
        self.assertTrue(out.startswith("# Top\n\n<!-- modules:begin -->\n| Module |"))
        self.assertTrue(out.endswith("<!-- modules:end -->\n\nTail.\n"))
        self.assertNotIn("stale", out)

    def test_source_links_the_pinned_commit(self):
        out = regenerate(README, {"modules": [entry()]})
        self.assertIn(f"[acme/widgets @ {SHA_A[:7]}](https://github.com/acme/widgets/tree/{SHA_A})",
                      out)

    def test_entry_without_repo_links_homepage(self):
        official = {"id": "celerp-x", "name": "X", "description": "X.", "tier": "official",
                    "author": "Celerp", "license": "Proprietary",
                    "homepage": "https://www.celerp.com/x"}
        self.assertIn("[celerp.com/x](https://www.celerp.com/x)",
                      regenerate(README, {"modules": [official]}))

    def test_readme_table_is_generated_from_index_v2(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        index = json.loads((ROOT / "index-v2.json").read_text(encoding="utf-8"))
        self.assertEqual(regenerate(text, index), text)


ASCII_PUNCTUATION = set(string.punctuation)


def literal(cell: str) -> str:
    """The text a cell shows, asserting every Markdown character in it is escaped."""
    out, chars = [], iter(cell)
    for ch in chars:
        if ch == "\\":
            nxt = next(chars)
            assert nxt in ASCII_PUNCTUATION, f"stray backslash before {nxt!r} in {cell!r}"
            out.append(nxt)
        else:
            assert ch not in ASCII_PUNCTUATION, f"unescaped {ch!r} in {cell!r}"
            out.append(ch)
    return "".join(out)


def cells(row: str) -> list[str]:
    """A table row split on its unescaped pipes."""
    parts, cur, chars = [], "", iter(row.strip()[1:-1])
    for ch in chars:
        if ch == "\\":
            cur += ch + next(chars)
        elif ch == "|":
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    return parts + [cur.strip()]


METADATA = {
    "link": "[install here](https://evil.example/x)",
    "image": "![logo](https://evil.example/x.png)",
    "raw html": "<img src=x onerror=alert(1)> <a href='https://evil.example'>x</a>",
    "formatting": "**bold** _em_ `code` ~~gone~~ # heading",
    "autolink": "see https://evil.example or www.evil.example or a@evil.example",
    "reference": "[x][1]\n\n[1]: https://evil.example",
    "entity": "&lt;b&gt; &#60;",
    "pipe and backslash": "a | b \\| c \\",
}


class AuthorTextStaysText(unittest.TestCase):
    """Text from a listing renders as itself: no link, image, HTML or formatting."""

    def row(self, **over) -> list[str]:
        out = regenerate(README, {"modules": [entry(**over)]})
        rows = [line for line in out.splitlines() if line.startswith("| ")]
        return cells(rows[-1])

    def test_description_cannot_make_markup(self):
        for label, text in METADATA.items():
            with self.subTest(label):
                shown = literal(self.row(description=text)[2])
                self.assertEqual(shown, " ".join(text.split()))

    def test_every_listing_text_field_is_plain(self):
        for label, text in METADATA.items():
            with self.subTest(label):
                row = self.row(name=text, author=text, license=text)
                for i in (0, 4, 5):
                    self.assertEqual(literal(row[i]), " ".join(text.split()))

    def test_row_keeps_its_six_columns(self):
        self.assertEqual(len(self.row(description="a | b\n| c |")), 6)

    def test_source_column_is_still_a_link_to_the_pinned_commit(self):
        row = self.row(description="[x](https://evil.example)")
        self.assertEqual(row[3], f"[acme/widgets @ {SHA_A[:7]}]"
                                 f"(https://github.com/acme/widgets/tree/{SHA_A})")


class Markers(unittest.TestCase):
    def test_missing_markers_raise(self):
        with self.assertRaises(ValueError):
            regenerate("# no markers\n", {"modules": []})


if __name__ == "__main__":
    unittest.main()
