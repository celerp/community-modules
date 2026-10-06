#!/usr/bin/env python3
"""Merge a listing pull request whose check passed; comment on the rest.

Runs from the default branch when the "Validate catalog" workflow finishes for
a pull request. It never checks out or runs pull request content: it reads the
check's result artifact and the pull request through the GitHub API.

Each run, and an hourly scheduled run, handles every open pull request whose
latest completed check has no outcome yet, not only the one that triggered it.
The outcome comment records the check run it answers, so a check is handled
once even when the run that was started for it never ran.

The result artifact is used only when the pull request changes nothing but
index.json and README.md, so the check that produced it ran this repository's
own scripts. A pull request is squash-merged only when all of these hold:
  - the check run for its exact head commit succeeded and reported "pass"
  - the head has not moved and the default branch has not moved since the check
  - it targets the default branch, is open, and was not opened by a maintainer
  - it carries no flag label
A "flag" result adds the flag label, which stays until a maintainer removes it.
"""
from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import zipfile

from github_api import ApiError, GitHub
from listing import CODEOWNERS, LISTING_FILES, code_owners, is_maintainer

FLAG_LABEL = "needs-review"
MARKER = "<!-- listing-check -->"
BOT_LOGIN = "github-actions[bot]"
CHECK_WORKFLOW = ".github/workflows/ci.yml"
CHECK_RUNS = "/actions/workflows/ci.yml/runs?event=pull_request&head_sha={sha}&per_page=100"
ARTIFACT = "submission-result"
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_COMMENT_CHARS = 60_000
STATUSES = ("pass", "fail", "flag")

DID_NOT_FINISH = ("## Listing check: did not finish\n\n"
                  "The automatic check did not finish, so this pull request was not merged. "
                  "Push a new commit (an empty one is fine) to run it again.\n")
OTHER_FILES = ("## Listing check: changes needed\n\n"
               "This pull request changes files other than index.json and README.md, so it "
               "cannot be merged automatically. Take the other changes out of this pull "
               "request and push again.\n")
BRANCH_MOVED = ("## Listing check: run again\n\n"
                "The catalog changed after this check ran, so it was not merged. Push a new "
                "commit (an empty one is fine) to check it against the current catalog.\n")
NOT_MERGED = ("## Listing check: not merged\n\n"
              "The check passed but GitHub refused the merge. A maintainer will look at it.\n")


def _artifact_result(gh, base: str, run_id: int) -> dict | None:
    """The check's result.json, or None when it is missing or unusable."""
    try:
        listed = gh.get(f"{base}/actions/runs/{run_id}/artifacts").get("artifacts", [])
        found = [a for a in listed if a.get("name") == ARTIFACT and not a.get("expired")]
        if len(found) != 1:
            return None
        data = gh.download(found[0]["archive_download_url"], MAX_ARTIFACT_BYTES, auth=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info = zf.getinfo("result.json")
            if info.file_size > MAX_ARTIFACT_BYTES:
                return None
            result = json.loads(zf.read(info))
    except (ApiError, zipfile.BadZipFile, KeyError, ValueError):
        return None
    return result if isinstance(result, dict) else None


def _latest_check(gh, base: str, head: str) -> dict | None:
    """The newest check run for this head, or None while it has not completed."""
    runs = [r for r in gh.get(base + CHECK_RUNS.format(sha=head)).get("workflow_runs", [])
            if r.get("path") == CHECK_WORKFLOW and r.get("event") == "pull_request"
            and r.get("head_sha") == head]
    if not runs:
        return None
    latest = max(runs, key=lambda r: r["id"])
    return latest if latest.get("status") == "completed" else None


def _run_marker(run: dict) -> str:
    return f"<!-- listing-run: {run['id']}.{run.get('run_attempt', 1)} -->"


def _gate_comment(gh, base: str, number: int) -> dict | None:
    for c in gh.paged(f"{base}/issues/{number}/comments?per_page=100"):
        if (c.get("user") or {}).get("login") == BOT_LOGIN and MARKER in (c.get("body") or ""):
            return c
    return None


def _handle_pr(gh, base: str, default: str, number: int, maintainers: set[str]) -> None:
    pr = gh.get(f"{base}/pulls/{number}")
    if (pr.get("state") != "open" or pr["base"]["ref"] != default
            or is_maintainer(pr["user"]["login"], pr.get("author_association", ""), maintainers)):
        return
    head = pr["head"]["sha"]
    run = _latest_check(gh, base, head)
    if run is None:
        return
    existing = _gate_comment(gh, base, number)
    if existing and _run_marker(run) in (existing.get("body") or ""):
        return

    def say(text: str) -> None:
        """Write the outcome into this pull request's one gate comment."""
        nonlocal existing
        body = f"{MARKER}\n{_run_marker(run)}\n{text[:MAX_COMMENT_CHARS]}"
        if existing and existing.get("id"):
            gh.patch(f"{base}/issues/comments/{existing['id']}", {"body": body})
        else:
            existing = gh.post(f"{base}/issues/{number}/comments", {"body": body})

    names = set()
    for f in gh.paged(f"{base}/pulls/{number}/files?per_page=100"):
        names.add(f["filename"])
        if f.get("previous_filename"):
            names.add(f["previous_filename"])
    if not names <= set(LISTING_FILES) or "index.json" not in names:
        say(OTHER_FILES)
        return
    result = _artifact_result(gh, base, run["id"])
    if (result is None or result.get("pr") != number or result.get("head_sha") != head
            or result.get("status") not in STATUSES
            or not isinstance(result.get("comment"), str)
            or not isinstance(result.get("base_sha"), str)):
        say(DID_NOT_FINISH)
        return
    status = result["status"]
    if status == "fail":
        say(result["comment"])
        return
    if run.get("conclusion") != "success":
        say(DID_NOT_FINISH)
        return
    if status == "flag":
        gh.post(f"{base}/issues/{number}/labels", {"labels": [FLAG_LABEL]})
        say(result["comment"])
        return
    if any(label.get("name") == FLAG_LABEL for label in pr.get("labels", [])):
        return
    if gh.get(f"{base}/branches/{default}")["commit"]["sha"] != result["base_sha"]:
        say(BRANCH_MOVED)
        return
    say(result["comment"])
    try:
        gh.put(f"{base}/pulls/{number}/merge", {"merge_method": "squash", "sha": head})
    except ApiError:
        say(NOT_MERGED)


def handle(event: dict, repo: str, gh, maintainers: set[str] = frozenset()) -> None:
    """maintainers: the lowercased logins in the default branch's CODEOWNERS."""
    run = event.get("workflow_run")
    if run is not None and (run.get("event") != "pull_request"
                            or run.get("path") != CHECK_WORKFLOW):
        return
    base = f"/repos/{repo}"
    default = gh.get(base)["default_branch"]
    errors = []
    for pr in gh.paged(f"{base}/pulls?state=open&per_page=100"):
        try:
            _handle_pr(gh, base, default, pr["number"], maintainers)
        except ApiError as exc:
            errors.append(f"#{pr['number']}: {exc}")
    if errors:
        raise ApiError("; ".join(errors))


def main() -> int:
    event = json.loads(pathlib.Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    owners = code_owners((pathlib.Path(__file__).resolve().parents[1] / CODEOWNERS)
                         .read_text(encoding="utf-8"))
    handle(event, os.environ["GITHUB_REPOSITORY"], GitHub(), owners)
    return 0


if __name__ == "__main__":
    sys.exit(main())
