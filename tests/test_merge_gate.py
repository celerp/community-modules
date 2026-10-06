"""The merge gate merges a listing only on a clean, current, unflagged check."""
from __future__ import annotations

import io
import json
import unittest
import zipfile

from fakes import FakeGitHub
from merge_gate import FLAG_LABEL, MARKER, handle

REPO = "celerp/community-modules"
R = f"/repos/{REPO}"
HEAD = "1" * 40
BASE = "2" * 40
URL = "https://api.github.com/artifact/1/zip"


def artifact(**over) -> bytes:
    result = {"pr": 12, "head_sha": HEAD, "base_sha": BASE, "status": "pass",
              "comment": "## Listing check: passed"}
    result.update(over)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("result.json", json.dumps(result))
    return buf.getvalue()


def event(**over) -> dict:
    run = {"id": 77, "event": "pull_request", "path": ".github/workflows/ci.yml",
           "head_sha": HEAD, "conclusion": "success"}
    run.update(over)
    return {"workflow_run": run}


class Gate(unittest.TestCase):
    def setUp(self):
        self.pr = {"number": 12, "state": "open", "head": {"sha": HEAD},
                   "base": {"ref": "main"}, "author_association": "NONE",
                   "labels": [], "user": {"login": "acme"}}
        self.gh = FakeGitHub({
            R: {"default_branch": "main"},
            f"{R}/pulls?state=open&per_page=100": [{"number": 12, "head": {"sha": HEAD}}],
            f"{R}/pulls/12": self.pr,
            f"{R}/pulls/12/files?per_page=100": [{"filename": "index.json"},
                                                 {"filename": "README.md"}],
            f"{R}/actions/runs/77/artifacts": {"artifacts": [
                {"name": "submission-result", "archive_download_url": URL, "expired": False}]},
            f"{R}/branches/main": {"commit": {"sha": BASE}},
            f"{R}/issues/12/comments?per_page=100": [],
        }, {URL: artifact()})
        self.event = event()

    def run_gate(self):
        handle(self.event, REPO, self.gh)
        return self.gh.writes

    def merges(self):
        return [w for w in self.run_gate() if w[0] == "PUT"]

    def comments(self):
        return [w[2]["body"] for w in self.gh.writes if w[1].endswith("/comments")
                or "/issues/comments/" in w[1]]


class Merges(Gate):
    def test_clean_pass_squash_merges_the_exact_head(self):
        [(method, path, body)] = self.merges()
        self.assertEqual(path, f"{R}/pulls/12/merge")
        self.assertEqual((body["merge_method"], body["sha"]), ("squash", HEAD))

    def test_pass_posts_the_result_comment(self):
        self.run_gate()
        self.assertTrue(any(MARKER in c and "passed" in c for c in self.comments()))


class Refuses(Gate):
    def assertNoMerge(self):
        self.assertEqual(self.merges(), [])

    def test_run_did_not_succeed(self):
        self.event = event(conclusion="failure")
        self.assertNoMerge()

    def test_flag_label_present(self):
        self.pr["labels"] = [{"name": FLAG_LABEL}]
        self.assertNoMerge()

    def test_pr_head_moved_since_the_run(self):
        self.pr["head"] = {"sha": "3" * 40}
        self.assertNoMerge()

    def test_artifact_for_another_head(self):
        self.gh.downloads[URL] = artifact(head_sha="3" * 40)
        self.assertNoMerge()

    def test_artifact_for_another_pr(self):
        self.gh.downloads[URL] = artifact(pr=13)
        self.assertNoMerge()

    def test_artifact_missing(self):
        self.gh.routes[f"{R}/actions/runs/77/artifacts"] = {"artifacts": []}
        self.assertNoMerge()
        self.assertTrue(any("did not finish" in c for c in self.comments()))

    def test_artifact_malformed(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("result.json", "{not json")
        self.gh.downloads[URL] = buf.getvalue()
        self.assertNoMerge()

    def test_unknown_status(self):
        self.gh.downloads[URL] = artifact(status="maintainer")
        self.assertNoMerge()

    def test_other_files_changed(self):
        self.gh.routes[f"{R}/pulls/12/files?per_page=100"] = [
            {"filename": "index.json"}, {"filename": ".github/workflows/ci.yml"}]
        self.assertNoMerge()
        self.assertTrue(any("index.json" in c for c in self.comments()))

    def test_renamed_file_counts_both_names(self):
        self.gh.routes[f"{R}/pulls/12/files?per_page=100"] = [
            {"filename": "README.md", "previous_filename": "scripts/gen_readme.py"},
            {"filename": "index.json"}]
        self.assertNoMerge()

    def test_index_not_changed(self):
        self.gh.routes[f"{R}/pulls/12/files?per_page=100"] = [{"filename": "README.md"}]
        self.assertNoMerge()

    def test_maintainer_pull_request(self):
        self.pr["author_association"] = "OWNER"
        self.assertEqual(self.run_gate(), [])

    def test_code_owner_pull_request(self):
        self.pr["author_association"] = "CONTRIBUTOR"
        self.pr["user"] = {"login": "Lead"}
        handle(self.event, REPO, self.gh, maintainers={"lead"})
        self.assertEqual(self.gh.writes, [])

    def test_base_branch_not_default(self):
        self.pr["base"] = {"ref": "dev"}
        self.assertEqual(self.run_gate(), [])

    def test_closed_pull_request(self):
        self.pr["state"] = "closed"
        self.assertEqual(self.run_gate(), [])

    def test_main_moved_since_the_check(self):
        self.gh.routes[f"{R}/branches/main"] = {"commit": {"sha": "4" * 40}}
        self.assertNoMerge()
        self.assertTrue(any("new commit" in c for c in self.comments()))

    def test_push_runs_are_ignored(self):
        self.event = event(event="push")
        self.assertEqual(self.run_gate(), [])

    def test_other_workflows_are_ignored(self):
        self.event = event(path=".github/workflows/other.yml")
        self.assertEqual(self.run_gate(), [])

    def test_no_open_pull_request_for_the_head(self):
        self.gh.routes[f"{R}/pulls?state=open&per_page=100"] = []
        self.assertEqual(self.run_gate(), [])


class FailAndFlag(Gate):
    def test_fail_comments_without_label_or_merge(self):
        self.gh.downloads[URL] = artifact(status="fail", comment="## Listing check: changes needed")
        self.event = event(conclusion="failure")
        writes = self.run_gate()
        self.assertFalse(any(w[0] == "PUT" or w[1].endswith("/labels") for w in writes))
        self.assertTrue(any("changes needed" in c for c in self.comments()))

    def test_flag_labels_and_comments(self):
        self.gh.downloads[URL] = artifact(status="flag", comment="## Listing check: waiting")
        writes = self.run_gate()
        self.assertIn(("POST", f"{R}/issues/12/labels", {"labels": [FLAG_LABEL]}), writes)
        self.assertFalse(any(w[0] == "PUT" for w in writes))

    def test_existing_comment_is_updated_in_place(self):
        self.gh.routes[f"{R}/issues/12/comments?per_page=100"] = [
            {"id": 5, "body": f"{MARKER}\nold", "user": {"login": "github-actions[bot]"}}]
        writes = self.run_gate()
        self.assertTrue(any(w[0] == "PATCH" and w[1] == f"{R}/issues/comments/5" for w in writes))
        self.assertFalse(any(w[0] == "POST" and w[1].endswith("/comments") for w in writes))

    def test_marker_comment_by_someone_else_is_not_reused(self):
        self.gh.routes[f"{R}/issues/12/comments?per_page=100"] = [
            {"id": 5, "body": f"{MARKER}\nold", "user": {"login": "acme"}}]
        writes = self.run_gate()
        self.assertFalse(any(w[0] == "PATCH" for w in writes))

    def test_comment_body_is_capped(self):
        self.gh.downloads[URL] = artifact(status="fail", comment="x" * 200_000)
        self.event = event(conclusion="failure")
        self.run_gate()
        self.assertTrue(all(len(c) < 70_000 for c in self.comments()))


if __name__ == "__main__":
    unittest.main()
