"""The listing check runs from the default branch and reads the pull request as data."""
from __future__ import annotations

import re
import unittest

from fakes import ROOT

WORKFLOWS = ROOT / ".github" / "workflows"
CHECK = WORKFLOWS / "listing-check.yml"
DEFAULT_BRANCH = "${{ github.event.repository.default_branch }}"
INSTALL = "pip install --quiet --require-hashes -r scripts/requirements.txt"


def steps(text: str) -> list[str]:
    """Each step of the workflow, as its own block of text."""
    body = text.split("steps:", 1)[1]
    return [s for s in re.split(r"\n\s+- ", "\n" + body) if s.strip()]


def run_lines(text: str) -> list[str]:
    """The shell text of every run step, block scalars included."""
    found, lines = [], text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"(\s*)(?:- )?run:\s*(.*)$", line)
        if not m:
            continue
        found.append(m.group(2))
        if m.group(2).strip() in ("|", ">", "|-", ">-"):
            indent = len(m.group(1))
            for nxt in lines[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent + 2:
                    break
                found.append(nxt)
    return found


class ListingCheck(unittest.TestCase):
    def setUp(self):
        self.text = CHECK.read_text(encoding="utf-8")
        self.triggers = self.text.split("\non:", 1)[1].split("\npermissions:", 1)[0]

    def test_runs_on_pull_request_target_only(self):
        self.assertIn("pull_request_target:", self.triggers)
        self.assertIsNone(re.search(r"\bpull_request:", self.triggers))
        self.assertNotIn("workflow_dispatch", self.triggers)

    def test_reads_contents_only(self):
        block = self.text.split("\npermissions:", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(block.split(), ["contents:", "read"])
        self.assertNotIn("permissions:", self.text.split("\njobs:", 1)[1])

    def test_uses_no_secrets(self):
        self.assertNotIn("secrets.", self.text)

    def test_checks_out_only_the_default_branch(self):
        checkouts = [s for s in steps(self.text) if "actions/checkout@" in s]
        self.assertTrue(checkouts)
        for step in checkouts:
            self.assertIn(f"ref: {DEFAULT_BRANCH}", step)
            self.assertIn("persist-credentials: false", step)

    def test_never_names_pull_request_head_content(self):
        for needle in ("github.event.pull_request.head", "github.head_ref", "refs/pull/",
                       "github.event.pull_request.merge_commit_sha"):
            self.assertNotIn(needle, self.text)

    def test_run_lines_interpolate_nothing(self):
        lines = run_lines(self.text)
        self.assertTrue(lines)
        for line in lines:
            self.assertNotIn("${{", line)

    def test_runs_only_default_branch_scripts(self):
        allowed = re.compile(re.escape(INSTALL) + r'$|'
                             r'python3 scripts/[a-z_]+\.py( "\$RUNNER_TEMP/result\.json")?$')
        for line in run_lines(self.text):
            self.assertRegex(line.strip(), allowed)

    def test_only_pinned_actions(self):
        for use in re.findall(r"uses:\s*(\S+)", self.text):
            self.assertRegex(use, r"^actions/(checkout|setup-python|upload-artifact)@[0-9a-f]{40}$")

    def test_checks_run_on_the_pinned_python(self):
        # The scan folds letters newer than this Python's Unicode data from a fixed list.
        for workflow in (CHECK, WORKFLOWS / "ci.yml"):
            with self.subTest(workflow.name):
                self.assertIn('python-version: "3.12"', workflow.read_text(encoding="utf-8"))

    def test_one_check_per_pull_request_at_a_time(self):
        block = self.text.split("\nconcurrency:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("group: listing-check-${{ github.event.pull_request.number }}", block)
        self.assertIn("cancel-in-progress: true", block)

    def test_only_pull_requests_into_the_default_branch(self):
        self.assertIn("if: github.event.pull_request.base.ref == "
                      "github.event.repository.default_branch", self.text)


class PinnedDependencies(unittest.TestCase):
    """The scripts' dependencies are installed at exact versions checked by hash."""

    def test_every_workflow_installs_only_the_hashed_requirements(self):
        for workflow in ("listing-check.yml", "ci.yml"):
            with self.subTest(workflow=workflow):
                text = (WORKFLOWS / workflow).read_text(encoding="utf-8")
                installs = [line.strip() for line in run_lines(text) if "pip" in line]
                self.assertEqual(installs, [INSTALL])

    def test_every_requirement_is_an_exact_version_with_hashes(self):
        text = (ROOT / "scripts" / "requirements.txt").read_text(encoding="utf-8")
        entries = [e.strip() for e in re.split(r"\n(?=\S)", text)
                   if e.strip() and not e.startswith("#")]
        self.assertIn("jsonschema", {e.split("==")[0] for e in entries})
        for entry in entries:
            with self.subTest(entry=entry.split()[0]):
                self.assertRegex(entry, r"^[A-Za-z0-9._-]+==[A-Za-z0-9.]+ \\\n")
                self.assertRegex(entry, r"--hash=sha256:[0-9a-f]{64}")
                self.assertNotRegex(entry, r"[<>~!]=|>|<")


class ReadmeRebuild(unittest.TestCase):
    """README.md's table is rebuilt on the default branch, so a listing changes index-v2.json only."""

    def setUp(self):
        self.text = (WORKFLOWS / "readme.yml").read_text(encoding="utf-8")
        self.triggers = self.text.split("\non:", 1)[1].split("\npermissions:", 1)[0]

    def test_runs_on_push_to_main_only(self):
        self.assertEqual(self.triggers.split(), ["push:", "branches:", "[main]"])

    def test_writes_contents_only(self):
        block = self.text.split("\npermissions:", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(block.split(), ["contents:", "write"])
        self.assertNotIn("secrets.", self.text)

    def test_one_rebuild_at_a_time(self):
        block = self.text.split("\nconcurrency:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("cancel-in-progress: false", block)

    def test_rebuilds_from_the_current_default_branch(self):
        checkouts = [s for s in steps(self.text) if "actions/checkout@" in s]
        self.assertEqual(len(checkouts), 1)
        self.assertIn(f"ref: {DEFAULT_BRANCH}", checkouts[0])

    def test_only_pinned_actions(self):
        for use in re.findall(r"uses:\s*(\S+)", self.text):
            self.assertRegex(use, r"^actions/(checkout|setup-python)@[0-9a-f]{40}$")

    def test_commits_the_generated_readme_only_when_it_changed(self):
        lines = [line.strip() for line in run_lines(self.text) if line.strip() not in ("|", "")]
        self.assertEqual(lines[0], "python3 scripts/gen_readme.py")
        self.assertIn("git diff --quiet -- README.md && exit 0", lines)
        commits = [line for line in lines if line.startswith("git commit")]
        self.assertEqual(len(commits), 1)
        self.assertTrue(commits[0].endswith("-- README.md"), commits[0])
        self.assertEqual(lines[-1], "git push")
        for line in lines:
            self.assertNotIn("${{", line)


class CatalogValidation(unittest.TestCase):
    def test_validation_no_longer_requires_the_readme_in_the_same_change(self):
        self.assertNotIn("gen_readme", (WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))

    def test_validation_workflow_no_longer_runs_the_listing_check(self):
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn("check_submission", text)
        self.assertNotIn("pull_request_target", text)


if __name__ == "__main__":
    unittest.main()
