"""The listing check runs the template's lint.py at the pinned commit, and nothing else."""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from fakes import ROOT, FakeGitHub
import check_submission
from check_submission import TEMPLATE_COMMIT, TEMPLATE_LINT_SHA256, TEMPLATE_REPO, template_lint
from github_api import ApiError

TEMPLATE = os.environ.get("TEMPLATE", "")
LINT_URL = f"https://raw.githubusercontent.com/{TEMPLATE_REPO}/{TEMPLATE_COMMIT}/lint.py"
SAMPLE = "acme-maintenance"


def git(*args: str) -> bytes:
    return subprocess.run(["git", "-C", TEMPLATE, *args], check=True,
                          capture_output=True).stdout


def sample_entry() -> dict:
    index = json.loads((ROOT / "index-v2.json").read_text(encoding="utf-8"))
    return next(m for m in index["modules"] if m["id"] == SAMPLE)


@unittest.skipUnless(TEMPLATE, "set TEMPLATE to a celerp-module-template clone")
class PinnedTemplateLint(unittest.TestCase):
    def setUp(self):
        self.source = git("show", f"{TEMPLATE_COMMIT}:lint.py")

    def test_pinned_hash_is_lint_py_at_the_pinned_commit(self):
        self.assertEqual(hashlib.sha256(self.source).hexdigest(), TEMPLATE_LINT_SHA256)

    def test_listing_check_executes_exactly_that_file(self):
        lint = template_lint(FakeGitHub(downloads={LINT_URL: self.source}))
        self.assertTrue(callable(lint))
        with self.assertRaises(ApiError):
            template_lint(FakeGitHub(downloads={LINT_URL: self.source + b"\n"}))

    def test_sample_listing_passes_the_pinned_lint(self):
        commit = sample_entry()["commit"]
        lint = template_lint(FakeGitHub(downloads={LINT_URL: self.source}))
        names = git("ls-tree", "-r", "--name-only", commit, f"{SAMPLE}/").decode().split()
        with tempfile.TemporaryDirectory() as tmp:
            for name in names:
                dest = pathlib.Path(tmp) / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(git("show", f"{commit}:{name}"))
            self.assertEqual(lint(pathlib.Path(tmp) / SAMPLE), [])


if __name__ == "__main__":
    unittest.main()
