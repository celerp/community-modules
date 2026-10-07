"""A catalog entry's repo is exactly https://github.com/<owner>/<repository>."""
from __future__ import annotations

import copy
import unittest

import fakes  # noqa: F401  (puts scripts/ on the path)
from validate_index import check

ENTRY = {"id": "my-module", "name": "My Module", "description": "Does things.",
         "tier": "community", "repo": "https://github.com/a/b", "commit": "a" * 40,
         "author": "A", "license": "MIT",
         "data_access": "Its own records.", "network_calls": "None."}

ACCEPTED = (
    "https://github.com/acme/acme-widgets",
    "https://github.com/Acme/Acme-Widgets",          # owner and repository keep their case
    "https://github.com/a/b",
    f"https://github.com/{'a' * 39}/{'b' * 100}",
    "https://github.com/a-b/c.d_e-f",
    "https://github.com/a/.github",
    "https://github.com/a/git",
    "https://github.com/a/b.gitx",
    "https://github.com/a/b.git.c",
)

REJECTED = (
    # scheme and host case
    "HTTPS://github.com/a/b",
    "https://GitHub.com/a/b",
    "https://GITHUB.COM/a/b",
    "http://github.com/a/b",
    # trailing slash, .git in any case, further path
    "https://github.com/a/b/",
    "https://github.com/a/b.git",
    "https://github.com/a/b.GIT",
    "https://github.com/a/b.Git",
    "https://github.com/a/b.git/",
    "https://github.com/a/b/tree/main",
    "https://github.com/a",
    "https://github.com/a/",
    "https://github.com//b",
    # percent-encoding
    "https://github.com/a/b%2Fc",
    "https://github.com/a%2Fb/c",
    "https://github.com/%61/b",
    "https://github.com/a/b%00",
    # other hosts that start or end like GitHub
    "https://www.github.com/a/b",
    "https://github.com.example/a/b",
    "https://github.com.example.com/a/b",
    "https://example.com/github.com/a/b",
    "https://gist.github.com/a/b",
    "https://codeload.github.com/a/b",
    "https://raw.githubusercontent.com/a/b",
    "https://github.com:443/a/b",
    "https://user@github.com/a/b",
    "https://github.com@example.com/a/b",
    # unicode lookalikes and invisible characters
    "https://gіthub.com/a/b",                   # Cyrillic i in the host
    "https://github.com/ａ/b",                   # fullwidth a in the owner
    "https://github.com/a/bé",                  # accented letter in the repository
    "https://github.com/a/b​",                  # zero-width space
    "https://github。com/a/b",                   # ideographic full stop
    "https://github.com/a/bİ",                  # dotted capital I
    # query, fragment, whitespace, newline
    "https://github.com/a/b?x=1",
    "https://github.com/a/b#readme",
    " https://github.com/a/b",
    "https://github.com/a/b ",
    "https://github.com/a/b\n",
    "https://github.com/a/b\r\n",
    "https://github.com/a/b\t",
    # owner and repository shape
    "https://github.com/-a/b",
    "https://github.com/a-/b",
    f"https://github.com/{'a' * 40}/b",
    "https://github.com/a_b/c",
    f"https://github.com/a/{'b' * 101}",
    "https://github.com/a/.",
    "https://github.com/a/..",
    "https://github.com/a/b\\c",
)


def problems(repo: str) -> list[str]:
    # A community entry's author is its repository's owner.
    owner = repo.split("/")[3] if repo.count("/") >= 3 else "A"
    doc = {"schema_version": 2,
           "modules": [dict(copy.deepcopy(ENTRY), repo=repo, author=owner or "A")]}
    return check(doc)


class RepoUrl(unittest.TestCase):
    def test_entry_is_valid(self):
        self.assertEqual(problems(ENTRY["repo"]), [])

    def test_accepted(self):
        for repo in ACCEPTED:
            with self.subTest(repo=repo):
                self.assertEqual(problems(repo), [])

    def test_rejected(self):
        for repo in REJECTED:
            with self.subTest(repo=repo):
                found = problems(repo)
                self.assertTrue(found, f"{repo!r} passed the schema")
                self.assertIn("https://github.com/<owner>/<repository>", found[0])


if __name__ == "__main__":
    unittest.main()
