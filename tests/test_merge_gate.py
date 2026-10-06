"""The merge gate merges a listing only on a clean, current, unflagged check."""
from __future__ import annotations

import io
import json
import unittest
import zipfile

from fakes import ROOT, FakeGitHub
from github_api import ApiError
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


def check_run(**over) -> dict:
    run = {"id": 77, "run_attempt": 1, "event": "pull_request_target",
           "path": ".github/workflows/listing-check.yml", "head_sha": HEAD, "status": "completed",
           "conclusion": "success"}
    run.update(over)
    return run


def event(**over) -> dict:
    return {"workflow_run": check_run(**over)}


def runs_path(head: str) -> str:
    return (f"{R}/actions/workflows/listing-check.yml/runs?event=pull_request_target"
            f"&head_sha={head}&per_page=100")


def bot_comment(body: str, cid: int = 5) -> dict:
    return {"id": cid, "body": body, "user": {"login": "github-actions[bot]"}}


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
        # The triggering run is the latest check for its head unless a test says otherwise.
        run = self.event["workflow_run"]
        self.gh.routes.setdefault(runs_path(run["head_sha"]), {"workflow_runs": [run]})
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


class MergeOutcome(Gate):
    """The outcome comment records the check as answered, so it is written only once
    the merge's outcome is known."""

    def put_fails(self, error: BaseException, *, merged: bool) -> None:
        def put(path, body):
            self.gh.writes.append(("PUT", path, body))
            if merged:
                self.pr.update(state="closed", merged=True)
            raise error
        self.gh.put = put

    def test_comment_follows_the_merge(self):
        writes = [w[0] for w in self.run_gate()]
        self.assertEqual(writes, ["PUT", "POST"])

    def test_merge_whose_answer_was_lost_is_reported_as_merged(self):
        self.put_fails(ApiError("PUT merge: timed out"), merged=True)
        self.run_gate()
        [body] = self.comments()
        self.assertIn("passed", body)
        self.assertNotIn("not merged", body)

    def test_merge_that_did_not_happen_is_reported(self):
        self.put_fails(ApiError("PUT merge: HTTP 405"), merged=False)
        self.run_gate()
        [body] = self.comments()
        self.assertIn("not merged", body)
        self.assertNotIn("refused", body)

    def test_job_stopping_at_the_merge_leaves_the_check_unanswered(self):
        self.put_fails(SystemExit(1), merged=False)
        with self.assertRaises(SystemExit):
            self.run_gate()
        self.assertEqual(self.comments(), [])


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
        self.gh.routes[runs_path("3" * 40)] = {"workflow_runs": []}
        self.assertEqual(self.run_gate(), [])

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

    def test_error_reading_the_result_is_retried_not_answered(self):
        # A rate limit or outage is not the check's outcome: the run fails and the
        # next gate run reads the result again.
        for route, error in ((URL, "GET artifact: HTTP 403"),
                             (f"{R}/actions/runs/77/artifacts", "GET artifacts: HTTP 502")):
            with self.subTest(route=route):
                self.gh.writes.clear()
                table = self.gh.downloads if route == URL else self.gh.routes
                saved, table[route] = table[route], ApiError(error)
                with self.assertRaises(ApiError):
                    self.run_gate()
                self.assertEqual(self.gh.writes, [])
                table[route] = saved
        self.assertEqual(len(self.merges()), 1)

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
        self.gh.routes[f"{R}/issues/12/comments?per_page=100"] = [bot_comment(f"{MARKER}\nold")]
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


class EveryCheckIsHandled(Gate):
    """Each gate run handles every open pull request whose latest completed check
    has no outcome yet, so a run left out of the merge queue is never lost."""

    def add_pr(self, number: int, head: str, run_id: int, **run_over):
        pr = dict(self.pr, number=number, head={"sha": head})
        self.gh.routes[f"{R}/pulls?state=open&per_page=100"].append(
            {"number": number, "head": {"sha": head}})
        self.gh.routes[f"{R}/pulls/{number}"] = pr
        self.gh.routes[f"{R}/pulls/{number}/files?per_page=100"] = [{"filename": "index.json"}]
        self.gh.routes[f"{R}/issues/{number}/comments?per_page=100"] = []
        self.gh.routes[runs_path(head)] = {"workflow_runs": [
            check_run(id=run_id, head_sha=head, **run_over)]}
        url = f"https://api.github.com/artifact/{run_id}/zip"
        self.gh.routes[f"{R}/actions/runs/{run_id}/artifacts"] = {"artifacts": [
            {"name": "submission-result", "archive_download_url": url, "expired": False}]}
        self.gh.downloads[url] = artifact(pr=number, head_sha=head, status="fail",
                                          comment="## Listing check: changes needed")

    def test_other_unhandled_check_is_handled(self):
        self.add_pr(13, "5" * 40, 76, conclusion="failure")
        writes = self.run_gate()
        self.assertTrue(any(w[1] == f"{R}/issues/13/comments" for w in writes))
        self.assertEqual([w[1] for w in writes if w[0] == "PUT"], [f"{R}/pulls/12/merge"])

    def test_handled_check_is_not_repeated(self):
        self.gh.routes[f"{R}/issues/12/comments?per_page=100"] = [
            bot_comment(f"{MARKER}\n<!-- listing-run: 77.1 -->\n## Listing check: waiting")]
        self.assertEqual(self.run_gate(), [])

    def test_outcome_records_the_run(self):
        self.run_gate()
        self.assertTrue(all("<!-- listing-run: 77.1 -->" in c for c in self.comments()))
        self.assertTrue(self.comments())

    def test_new_attempt_of_a_handled_run_is_handled(self):
        self.gh.routes[f"{R}/issues/12/comments?per_page=100"] = [
            bot_comment(f"{MARKER}\n<!-- listing-run: 77.1 -->\nold")]
        self.event = event(run_attempt=2)
        self.assertEqual(len(self.merges()), 1)

    def test_check_still_running_is_left_for_its_own_gate_run(self):
        self.add_pr(13, "5" * 40, 78, status="in_progress", conclusion=None)
        self.run_gate()
        self.assertFalse(any("/13/" in w[1] for w in self.gh.writes))

    def test_only_the_latest_check_counts(self):
        self.gh.routes[runs_path(HEAD)] = {"workflow_runs": [
            check_run(id=70), check_run(id=78, status="queued", conclusion=None)]}
        self.assertEqual(self.run_gate(), [])

    def test_runs_of_other_workflows_are_not_used(self):
        self.gh.routes[runs_path(HEAD)] = {"workflow_runs": [
            check_run(id=79, path=".github/workflows/other.yml")]}
        self.assertEqual(self.run_gate(), [])

    def other_pull_requests_check(self, run_id: int, **result) -> None:
        """A newer check of the same commit, run for another pull request with that head."""
        self.gh.routes[runs_path(HEAD)] = {"workflow_runs": [check_run(),
                                                             check_run(id=run_id)]}
        url = f"https://api.github.com/artifact/{run_id}/zip"
        self.gh.routes[f"{R}/actions/runs/{run_id}/artifacts"] = {"artifacts": [
            {"name": "submission-result", "archive_download_url": url, "expired": False}
        ] if result else []}
        self.gh.downloads[url] = artifact(**result)

    def test_newer_check_of_the_same_commit_in_another_pull_request_does_not_block(self):
        self.other_pull_requests_check(99, pr=13, status="fail")
        self.assertEqual(len(self.merges()), 1)

    def test_newer_check_without_a_result_does_not_block(self):
        # A pull request into another branch leaves a skipped run with no result.
        self.other_pull_requests_check(99)
        self.assertEqual(len(self.merges()), 1)

    def test_answered_check_stays_answered_after_another_pull_requests_check(self):
        self.gh.routes[f"{R}/issues/12/comments?per_page=100"] = [
            bot_comment(f"{MARKER}\n<!-- listing-run: 77.1 -->\nmerged")]
        self.other_pull_requests_check(99, pr=13, status="fail")
        self.assertEqual(self.run_gate(), [])

    def test_error_on_one_pull_request_does_not_stop_the_others(self):
        self.add_pr(13, "5" * 40, 76, conclusion="failure")
        self.gh.routes[f"{R}/pulls/12"] = ApiError("GET pulls/12: HTTP 502")
        with self.assertRaises(ApiError):
            self.run_gate()
        self.assertTrue(any(w[1] == f"{R}/issues/13/comments" for w in self.gh.writes))


class ScheduledSweep(Gate):
    def test_scheduled_run_handles_unhandled_checks(self):
        self.gh.routes[runs_path(HEAD)] = {"workflow_runs": [check_run()]}
        handle({"schedule": "17 * * * *"}, REPO, self.gh)
        self.assertEqual([w[1] for w in self.gh.writes if w[0] == "PUT"], [f"{R}/pulls/12/merge"])


class OldTrigger(Gate):
    """Only the default-branch check counts; a run of the old in-branch check does not."""

    def test_old_trigger_run_is_not_used(self):
        old = check_run(event="pull_request", path=".github/workflows/ci.yml")
        self.gh.routes[runs_path(HEAD)] = {"workflow_runs": [old]}
        self.gh.writes.clear()
        handle({"workflow_run": old}, REPO, self.gh)
        self.assertEqual(self.gh.writes, [])
        handle({}, REPO, self.gh)
        self.assertEqual(self.gh.writes, [])


class Workflow(unittest.TestCase):
    def test_merges_are_serialized_and_the_newest_waiting_run_is_kept(self):
        text = (ROOT / ".github/workflows/listing-merge.yml").read_text()
        block = text.split("concurrency:", 1)[1].split("jobs:", 1)[0]
        self.assertIn("group: listing-merge\n", block)
        self.assertIn("cancel-in-progress: false", block)

    def test_follows_the_listing_check(self):
        text = (ROOT / ".github/workflows/listing-merge.yml").read_text()
        self.assertIn("workflows: [Listing check]", text)
        self.assertIn("github.event.workflow_run.event == 'pull_request_target'", text)

    def test_runs_on_a_schedule_as_well(self):
        text = (ROOT / ".github/workflows/listing-merge.yml").read_text()
        self.assertIn("schedule:", text.split("permissions:", 1)[0])
        self.assertIn("github.event_name == 'schedule'", text)


if __name__ == "__main__":
    unittest.main()
