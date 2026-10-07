"""The two catalog files: index.json stays empty, index-v2.json holds every listing."""
from __future__ import annotations

import copy
import json
import unittest

from fakes import ROOT, SHA_A, entry
from validate_index import check, check_v1

V1 = {"schema_version": 1, "modules": []}


def v2(*entries: dict) -> dict:
    return {"schema_version": 2, "modules": list(entries)}


class IndexJson(unittest.TestCase):
    """index.json is the earlier format, kept for older Celerp versions."""

    def test_index_json_lists_no_modules(self):
        doc = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(doc, V1)
        self.assertEqual(check_v1(doc), [])

    def test_a_community_entry_in_index_json_is_rejected(self):
        doc = dict(V1, modules=[dict(entry(), commit=SHA_A)])
        self.assertTrue(check_v1(doc))

    def test_any_other_index_json_is_rejected(self):
        for doc in ({"schema_version": 2, "modules": []}, {"schema_version": 1},
                    {"schema_version": 1, "modules": [], "extra": 1}, []):
            with self.subTest(doc=doc):
                self.assertTrue(check_v1(doc))


class IndexV2(unittest.TestCase):
    def test_index_v2_is_valid(self):
        doc = json.loads((ROOT / "index-v2.json").read_text(encoding="utf-8"))
        self.assertEqual(check(doc), [])
        self.assertEqual(doc["schema_version"], 2)

    def test_schema_version_must_be_2(self):
        self.assertEqual(check(v2(entry())), [])
        self.assertTrue(check({"schema_version": 1, "modules": [entry()]}))

    def test_community_entry_requires_a_pinned_commit(self):
        missing = entry()
        del missing["commit"]
        for e in (missing, entry(commit="main"), entry(commit="abc1234"),
                  entry(commit="A" * 40)):
            with self.subTest(commit=e.get("commit")):
                self.assertTrue(check(v2(e)))

    def test_verified_entry_requires_a_pinned_commit(self):
        verified = entry(tier="verified", sha256="d" * 64)
        self.assertEqual(check(v2(verified)), [])
        del verified["commit"]
        self.assertTrue(any("commit" in p for p in check(v2(verified))))


class CommunityAuthor(unittest.TestCase):
    """A community entry's author is the owner of its repository."""

    def test_author_is_the_repository_owner(self):
        self.assertEqual(check(v2(entry(repo="https://github.com/acme/acme-widgets",
                                        author="Acme"))), [])

    def test_author_comparison_ignores_case(self):
        self.assertEqual(check(v2(entry(author="ACME"))), [])

    def test_another_author_is_rejected(self):
        problems = check(v2(entry(repo="https://github.com/acme/acme-widgets",
                                  author="Microsoft")))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("Microsoft", problems[0])
        self.assertIn("acme", problems[0])

    def test_author_with_extra_text_is_rejected(self):
        for author in ("Acme Inc", "acme ", "@acme", "acme/widgets"):
            with self.subTest(author=author):
                self.assertTrue(check(v2(entry(author=author))))

    def test_official_entry_names_its_own_author(self):
        official = {"id": "celerp-inventory", "name": "Inventory", "description": "Stock.",
                    "tier": "official", "author": "Celerp", "license": "Proprietary"}
        self.assertEqual(check(v2(official)), [])

    def test_fixture_is_unchanged_by_checks(self):
        doc = v2(entry())
        before = copy.deepcopy(doc)
        check(doc)
        self.assertEqual(doc, before)


if __name__ == "__main__":
    unittest.main()
