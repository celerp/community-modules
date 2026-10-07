"""Who counts as a maintainer of this directory."""
from __future__ import annotations

import unittest

import fakes  # noqa: F401  (puts scripts/ on the path)
from listing import code_owners, is_maintainer

CODEOWNERS = "# comment\n* @Lead @org/team\n/docs/ @writer\n"


class Maintainers(unittest.TestCase):
    def test_code_owners_are_the_logins_in_codeowners(self):
        self.assertEqual(code_owners(CODEOWNERS), {"lead", "writer"})

    def test_code_owner_with_contributor_association(self):
        self.assertTrue(is_maintainer("LEAD", "CONTRIBUTOR", {"lead"}))

    def test_repository_role(self):
        self.assertTrue(is_maintainer("someone", "MEMBER", set()))

    def test_creator(self):
        self.assertFalse(is_maintainer("acme", "NONE", {"lead"}))


if __name__ == "__main__":
    unittest.main()
