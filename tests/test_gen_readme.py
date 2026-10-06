"""The README table is generated from index.json and links each pinned commit."""
from __future__ import annotations

import unittest

import fakes  # noqa: F401  (puts scripts/ on the path)
from fakes import SHA_A, entry
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

    def test_missing_markers_raise(self):
        with self.assertRaises(ValueError):
            regenerate("# no markers\n", {"modules": []})


if __name__ == "__main__":
    unittest.main()
