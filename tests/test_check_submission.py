"""Every automatic listing check: the pass case, each failure, and the flag case."""
from __future__ import annotations

import copy
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

from fakes import (SHA_A, SHA_B, SHA_C, FakeGitHub, archive_url, entry, index_text,
                   module_files, module_zip, repo_routes)
import check_submission
from check_submission import comment, review
from gen_readme import regenerate
from github_api import ApiError, TooLarge

OFFICIAL = {"id": "celerp-inventory", "name": "Inventory", "description": "Stock.",
            "tier": "official", "author": "Celerp", "license": "Proprietary"}
EXISTING = entry("beta-tools", name="Beta Tools", repo="https://github.com/beta/tools",
                 commit=SHA_B, author="Beta")
README = ("# Directory\n\nIntro.\n\n<!-- modules:begin -->\n<!-- modules:end -->\n\n"
          "## List your module\n")


def files_for(*entries: dict) -> dict[str, str]:
    """index.json in catalog order with its regenerated README."""
    rank = {"official": 0, "verified": 1, "community": 2}
    text = index_text(*sorted(entries, key=lambda e: (rank[e["tier"]], e["id"])))
    return {"index.json": text, "README.md": regenerate(README, json.loads(text))}


BASE = files_for(OFFICIAL, EXISTING)
NEW = entry()


def no_lint(folder):
    return []


class Case(unittest.TestCase):
    """A healthy submission of NEW by its owner; each test breaks one thing."""

    def setUp(self):
        self.gh = FakeGitHub(repo_routes(), {archive_url(): module_zip(module_files())})
        self.head = files_for(OFFICIAL, NEW, EXISTING)
        self.changed = ["index.json", "README.md"]
        self.author = "acme"
        self.association = "NONE"
        self.lint = no_lint

    def run_review(self):
        return review(base=BASE, head=self.head, changed=self.changed, author=self.author,
                      association=self.association, gh=self.gh, lint=self.lint)

    def assertFails(self, needle: str):
        result = self.run_review()
        self.assertEqual(result.status, "fail", result)
        self.assertTrue(any(needle in p for p in result.problems),
                        f"{needle!r} not in {result.problems}")
        return result

    def with_entry(self, *entries: dict):
        self.head = files_for(*entries)


class Passes(Case):
    def test_new_listing_passes(self):
        result = self.run_review()
        self.assertEqual((result.status, result.problems, result.flags), ("pass", [], []))
        self.assertEqual(result.entry_id, "acme-widgets")

    def test_index_only_change_without_readme_change_passes_when_table_is_unchanged(self):
        # A description-free update leaves the generated table identical.
        self.gh.routes.update(repo_routes(sha=SHA_C))
        self.gh.downloads[archive_url(sha=SHA_C)] = module_zip(module_files(), sha=SHA_C)
        base = files_for(OFFICIAL, NEW, EXISTING)
        head = files_for(OFFICIAL, dict(NEW, commit=SHA_C), EXISTING)
        result = review(base=base, head=head, changed=["index.json"], author="acme",
                        association="NONE", gh=self.gh, lint=no_lint)
        self.assertEqual(result.status, "pass", result)

    def test_update_by_same_owner_with_new_commit_passes(self):
        self.gh.routes.update(repo_routes(sha=SHA_C))
        self.gh.downloads[archive_url(sha=SHA_C)] = module_zip(module_files(), sha=SHA_C)
        base = files_for(OFFICIAL, NEW, EXISTING)
        head = files_for(OFFICIAL, dict(NEW, commit=SHA_C, description="Tracks widgets well."),
                         EXISTING)
        result = review(base=base, head=head, changed=self.changed, author="acme",
                        association="NONE", gh=self.gh, lint=no_lint)
        self.assertEqual(result.status, "pass", result)

    def test_declared_network_calls_pass(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(extra={
            "acme-widgets/acme_widgets/sync.py": "import requests\n"}))
        self.with_entry(OFFICIAL, dict(NEW, network_calls="Sends orders to api.acme.example."),
                        EXISTING)
        self.assertEqual(self.run_review().status, "pass")

    def test_owner_login_is_case_insensitive(self):
        self.author = "ACME"
        self.assertEqual(self.run_review().status, "pass")


class Maintainer(Case):
    def test_maintainer_pull_request_is_left_for_review(self):
        self.association = "OWNER"
        self.changed = ["index.json", "scripts/validate_index.py"]
        result = self.run_review()
        self.assertEqual(result.status, "maintainer")

    def test_code_owner_is_left_for_review(self):
        result = review(base=BASE, head=self.head, changed=self.changed, author="Lead",
                        association="CONTRIBUTOR", gh=self.gh, lint=no_lint,
                        maintainers={"lead"})
        self.assertEqual(result.status, "maintainer")


class Scope(Case):
    def test_other_file_changed(self):
        self.changed = ["index.json", "README.md", "scripts/validate_index.py"]
        self.assertFails("scripts/validate_index.py")

    def test_index_not_changed(self):
        self.changed = ["README.md"]
        self.assertFails("index.json")

    def test_readme_edited_by_hand(self):
        self.head["README.md"] = self.head["README.md"].replace("Intro.", "Intro! Buy now.")
        self.assertFails("README.md")

    def test_readme_not_regenerated(self):
        self.head = dict(self.head, **{"README.md": BASE["README.md"]})
        self.assertFails("gen_readme.py")

    def test_invalid_index(self):
        self.head = {"index.json": index_text(
            OFFICIAL, {k: v for k, v in NEW.items() if k != "commit"}, EXISTING),
            "README.md": BASE["README.md"]}
        self.assertFails("commit")

    def test_two_entries_added(self):
        second = entry("acme-gadgets", name="Acme Gadgets")
        self.with_entry(OFFICIAL, second, NEW, EXISTING)
        self.assertFails("exactly one")

    def test_entry_removed(self):
        self.with_entry(OFFICIAL, NEW)
        self.assertFails("beta-tools")

    def test_edit_of_another_entry(self):
        self.with_entry(OFFICIAL, NEW, dict(EXISTING, description="Changed by someone else."))
        self.assertFails("exactly one")

    def test_update_of_another_owners_entry(self):
        self.gh.routes.update(repo_routes("beta", "tools", SHA_C))
        self.gh.downloads[archive_url("beta", "tools", SHA_C)] = module_zip(
            module_files("beta-tools", display="Beta Tools"), repo="tools", sha=SHA_C)
        self.with_entry(OFFICIAL, dict(EXISTING, commit=SHA_C))
        self.assertFails("beta")

    def test_update_moving_another_owners_entry_to_own_repo(self):
        self.gh.downloads[archive_url()] = module_zip(
            module_files("beta-tools", display="Beta Tools"))
        self.with_entry(OFFICIAL, dict(EXISTING, repo="https://github.com/acme/widgets",
                                       commit=SHA_A))
        self.assertFails("beta")

    def test_update_without_new_commit(self):
        base = files_for(OFFICIAL, NEW, EXISTING)
        head = files_for(OFFICIAL, dict(NEW, description="Tracks widgets well."), EXISTING)
        result = review(base=base, head=head, changed=self.changed, author="acme",
                        association="NONE", gh=self.gh, lint=no_lint)
        self.assertEqual(result.status, "fail")
        self.assertTrue(any("new commit" in p for p in result.problems), result.problems)

    def test_official_tier_attempt(self):
        self.with_entry(dict(NEW, tier="official"), OFFICIAL, EXISTING)
        self.assertFails("community")

    def test_verified_tier_attempt(self):
        self.with_entry(OFFICIAL, dict(NEW, tier="verified", sha256="d" * 64), EXISTING)
        self.assertFails("community")

    def test_edit_of_official_entry(self):
        self.with_entry(dict(OFFICIAL, description="Edited."), EXISTING)
        self.assertFails("community")


class Ownership(Case):
    def test_submitter_does_not_own_repo(self):
        self.author = "mallory"
        self.assertFails("acme")

    def test_non_github_repo(self):
        self.with_entry(OFFICIAL, dict(NEW, repo="https://gitlab.com/acme/widgets"), EXISTING)
        self.assertFails("GitHub")

    def test_repo_url_with_extra_path(self):
        self.with_entry(OFFICIAL, dict(NEW, repo="https://github.com/acme/widgets/tree/dev"),
                        EXISTING)
        self.assertFails("https://github.com/<owner>/<repository>")

    def test_repo_moved_or_renamed(self):
        self.gh.routes["/repos/acme/widgets"] = dict(
            self.gh.routes["/repos/acme/widgets"], full_name="other/widgets",
            owner={"login": "other"})
        self.assertFails("repo")


class Naming(Case):
    def rename(self, **over):
        self.gh.downloads[archive_url()] = module_zip(module_files(
            over.get("id", "acme-widgets"), display=over.get("name", "Acme Widgets")))
        self.with_entry(OFFICIAL, dict(NEW, **over), EXISTING)

    def test_reserved_prefix(self):
        self.rename(id="celerp-widgets")
        self.assertFails("celerp-")

    def test_name_mentions_celerp(self):
        self.rename(name="Celerp Widgets")
        self.assertFails("Celerp")

    def test_name_lookalike(self):
        self.rename(name="C3l-erp Widgets")
        self.assertFails("Celerp")

    def test_name_of_official_module(self):
        self.rename(name="Inventory")
        self.assertFails("Inventory")

    def test_id_of_official_module_without_prefix(self):
        self.rename(id="inventory")
        self.assertFails("inventory")

    def test_name_already_taken(self):
        self.rename(name="Beta  tools")
        self.assertFails("Beta Tools")

    def test_manifest_display_name_mentions_celerp(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(display="Celerp Widgets"))
        self.assertFails("Celerp")


class RepoChecks(Case):
    def test_private_repo(self):
        self.gh.routes.update(repo_routes(private=True))
        self.assertFails("public")

    def test_repo_not_found(self):
        del self.gh.routes["/repos/acme/widgets"]
        self.assertFails("public")

    def test_commit_not_on_default_branch(self):
        self.gh.routes.update(repo_routes(compare="diverged"))
        self.assertFails("default branch")

    def test_commit_unknown(self):
        del self.gh.routes[f"/repos/acme/widgets/compare/main...{SHA_A}"]
        self.assertFails("default branch")

    def test_no_license(self):
        del self.gh.routes[f"/repos/acme/widgets/license?ref={SHA_A}"]
        self.assertFails("license")

    def test_license_differs_from_entry(self):
        self.gh.routes.update(repo_routes(spdx="Apache-2.0"))
        self.assertFails("Apache-2.0")

    def test_custom_license_is_accepted(self):
        self.gh.routes.update(repo_routes(spdx="NOASSERTION"))
        self.gh.downloads[archive_url()] = module_zip(module_files(license="Free to use, no resale"))
        self.with_entry(OFFICIAL, dict(NEW, license="Free to use, no resale"), EXISTING)
        self.assertEqual(self.run_review().status, "pass")

    def test_manifest_license_differs_from_entry(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(license="GPL-3.0"))
        self.assertFails("GPL-3.0")

    def test_api_error_fails_closed(self):
        self.gh.routes["/repos/acme/widgets"] = ApiError("503")
        self.assertFails("could not finish")


class ArchiveChecks(Case):
    def test_archive_too_large(self):
        self.gh.downloads[archive_url()] = TooLarge("big")
        self.assertFails("50 MB")

    def test_unpacked_too_large(self):
        with mock.patch.object(check_submission, "MAX_UNPACKED_BYTES", 100):
            self.assertFails("200 MB")

    def test_module_folder_missing(self):
        files = module_files()
        files = {k.replace("acme-widgets/", "other/", 1): v for k, v in files.items()}
        self.gh.downloads[archive_url()] = module_zip(files)
        self.assertFails("acme-widgets")

    def test_module_at_repository_root(self):
        files = {k.replace("acme-widgets/", "", 1): v for k, v in module_files().items()}
        self.gh.downloads[archive_url()] = module_zip(files)
        self.assertEqual(self.run_review().status, "pass")

    def test_manifest_name_differs_from_id(self):
        files = module_files()
        files["acme-widgets/__init__.py"] = files["acme-widgets/__init__.py"].replace(
            '"name": "acme-widgets"', '"name": "acme-other"')
        self.gh.downloads[archive_url()] = module_zip(files)
        self.assertFails("acme-other")

    def test_symlink_in_module(self):
        self.gh.downloads[archive_url()] = module_zip(
            module_files(), symlinks=("acme-widgets/link",))
        self.assertFails("link")

    def test_lint_problems(self):
        self.lint = lambda folder: ["manifest has no ui_routes"]
        self.assertFails("manifest has no ui_routes")

    def test_lint_sees_folder_named_after_id(self):
        seen = []
        self.lint = lambda folder: seen.append(folder.name) or []
        self.run_review()
        self.assertEqual(seen, ["acme-widgets"])


class Flags(Case):
    def test_undeclared_network_call_is_flagged(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(extra={
            "acme-widgets/acme_widgets/sync.py": "import requests\n"}))
        result = self.run_review()
        self.assertEqual((result.status, result.problems), ("flag", []))
        self.assertTrue(any("acme_widgets/sync.py" in f and "network_calls" in f
                            for f in result.flags), result.flags)

    def test_process_spawn_is_flagged_even_with_network_declared(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(extra={
            "acme-widgets/acme_widgets/run.py": "import subprocess\n"}))
        self.with_entry(OFFICIAL, dict(NEW, network_calls="Calls api.acme.example."), EXISTING)
        self.assertEqual(self.run_review().status, "flag")

    def test_failures_win_over_flags(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(license="GPL-3.0", extra={
            "acme-widgets/acme_widgets/run.py": "import subprocess\n"}))
        self.assertEqual(self.run_review().status, "fail")


class Comments(Case):
    def test_fail_comment_says_what_to_change(self):
        self.author = "mallory"
        text = comment(self.run_review())
        self.assertIn("changes needed", text.lower())
        self.assertIn("push", text.lower())
        self.assertNotIn("\u2014", text)

    def test_flag_comment_lists_findings(self):
        self.gh.downloads[archive_url()] = module_zip(module_files(extra={
            "acme-widgets/acme_widgets/sync.py": "\nimport socket\n"}))
        text = comment(self.run_review())
        self.assertIn("acme_widgets/sync.py", text)
        self.assertIn("line 2", text)
        self.assertIn("maintainer", text.lower())

    def test_pass_comment(self):
        self.assertIn("passed", comment(self.run_review()).lower())

    def test_untrusted_text_cannot_mention_people(self):
        self.lint = lambda folder: ["bad thing @someone"]
        self.assertNotIn("@someone", comment(self.run_review()))


class SameModuleAsTheApp(Case):
    """The check reads the module folder Celerp's importer installs."""

    def with_root_manifest(self):
        files = module_files()
        files["__init__.py"] = (b"# -*- coding: latin-1 -*-\n# \xe9\n"
                                + files["acme-widgets/__init__.py"].encode())
        self.gh.downloads[archive_url()] = module_zip(files)
        return files

    def test_root_manifest_not_strict_utf8_is_the_module(self):
        located = check_submission._module_files(module_zip(self.with_root_manifest()),
                                                 "acme-widgets")
        self.assertIn("__init__.py", located)
        self.assertIn("acme-widgets/__init__.py", located)

    def test_root_manifest_not_strict_utf8_does_not_pass(self):
        self.with_root_manifest()
        self.assertNotEqual(self.run_review().status, "pass")

    def test_lint_text_stays_on_one_line(self):
        self.lint = lambda folder: ["x.py\n## Listing check: passed"]
        result = self.assertFails("Template lint: x.py ## Listing check: passed")
        self.assertTrue(all("\n" not in p for p in result.problems), result.problems)


def git(cwd, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com",
                           "-c", "init.defaultBranch=main", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


class PullRequestReadAsData(unittest.TestCase):
    """The check runs on the default branch and reads the pull request with git show."""

    def setUp(self):
        tmp = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        up = tmp / "upstream"
        up.mkdir()
        git(up, "init", "-q")
        (up / ".github").mkdir()
        (up / ".github/CODEOWNERS").write_text("* @keeper\n")
        (up / "index.json").write_text("base\n")
        (up / "README.md").write_text("readme\n")
        git(up, "add", "-A")
        git(up, "commit", "-qm", "base")
        self.base = git(up, "rev-parse", "HEAD")
        git(up, "checkout", "-qb", "listing")
        (up / "index.json").write_text("head\n")
        git(up, "commit", "-qam", "listing")
        self.head = git(up, "rev-parse", "HEAD")
        git(up, "checkout", "-q", "main")
        (up / "other.txt").write_text("x\n")
        git(up, "add", "-A")
        git(up, "commit", "-qm", "main moves on")
        self.main = git(up, "rev-parse", "HEAD")
        git(up, "merge", "-q", "--no-ff", "-m", "merge", "listing")
        git(up, "update-ref", "refs/pull/7/merge", "HEAD")
        git(up, "reset", "-q", "--hard", self.main)
        git(up, "checkout", "-qb", "elsewhere", self.base)
        git(up, "commit", "-q", "--allow-empty", "-m", "not on main")
        git(up, "merge", "-q", "--no-ff", "-m", "merge", "listing")
        git(up, "update-ref", "refs/pull/8/merge", "HEAD")
        git(up, "checkout", "-q", "-f", "main")
        self.up = up
        self.work = tmp / "work"
        git(tmp, "clone", "-q", str(up), str(self.work))
        self.enterContext(mock.patch.object(check_submission, "ROOT", self.work))

    def merge_onto_main(self, number: int, change) -> str:
        """Commit `change(upstream)` on a branch from the base, merge it onto upstream main
        as refs/pull/N/merge, and return the head sha."""
        git(self.up, "checkout", "-qb", f"pr{number}", self.base)
        change(self.up)
        git(self.up, "add", "-A")
        git(self.up, "commit", "-qm", "listing")
        head = git(self.up, "rev-parse", "HEAD")
        git(self.up, "checkout", "-q", "--detach", "main")
        git(self.up, "merge", "-q", "--no-ff", "-m", "merge", head)
        git(self.up, "update-ref", f"refs/pull/{number}/merge", "HEAD")
        git(self.up, "checkout", "-q", "-f", "main")
        return head

    def test_reads_github_merge_without_touching_the_checkout(self):
        base_sha, changed, base, head, owners = check_submission.pull_request_data(7, self.head)
        self.assertEqual(base_sha, self.main)
        self.assertEqual(changed, ["index.json"])
        self.assertEqual(base["index.json"], "base\n")
        self.assertEqual(head["index.json"], "head\n")
        self.assertEqual(owners, {"keeper"})
        self.assertEqual(git(self.work, "rev-parse", "HEAD"), self.main)
        self.assertEqual(git(self.work, "status", "--porcelain"), "")
        self.assertEqual((self.work / "index.json").read_text(), "base\n")

    def test_merge_of_another_head_is_refused(self):
        with self.assertRaises(check_submission._Stop):
            check_submission.pull_request_data(7, "f" * 40)

    def test_merge_onto_a_branch_other_than_the_default_is_refused(self):
        with self.assertRaises(check_submission._Stop) as stop:
            check_submission.pull_request_data(8, self.head)
        self.assertIn("default branch", " ".join(stop.exception.args[0]))

    def test_a_name_with_a_space_is_one_file(self):
        def change(up):
            (up / "index.json").write_text("head\n")
            (up / "README.md index.json").write_text("anything\n")
        head = self.merge_onto_main(9, change)
        _, changed, *_ = check_submission.pull_request_data(9, head)
        self.assertEqual(sorted(changed), ["README.md index.json", "index.json"])
        self.assertTrue(check_submission._scope_problems(changed))


if __name__ == "__main__":
    unittest.main()
