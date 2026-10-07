#!/usr/bin/env python3
"""Validate the catalog: index-v2.json against its JSON Schema plus the policy rules
a schema cannot say, and index.json as the empty earlier format.

Runs in CI on every pull request. It only reads text - it never runs a module.

index.json is the catalog format older Celerp versions read. It stays exactly
{"schema_version": 1, "modules": []}; every listing is in index-v2.json.

Policy rules on top of the index-v2.json schema:
  - ids are unique and the list is sorted by (tier rank, id)
  - the "celerp-" id prefix is reserved for the official tier
  - community and verified tiers require a public repo and its commit
  - repo is exactly https://github.com/<owner>/<repository> (the schema's pattern)
  - community and verified tiers require data_access and network_calls
  - a community entry's author is its repository's owner (any letter case)
  - community tier carries no version (the module's own manifest is the version)
  - verified tier requires sha256
  - a price requires the verified or official tier (we do not sell unverified code)

Run `validate_index.py --selftest` to exercise every rule against inline fixtures.
"""
from __future__ import annotations

import copy
import json
import pathlib
import re
import sys

import jsonschema

from listing import CATALOG

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema" / "index-v2.schema.json").read_text(encoding="utf-8"))
V1_FILE = "index.json"
V1_INDEX = {"schema_version": 1, "modules": []}
TIER_RANK = {"official": 0, "verified": 1, "community": 2}
# The repository address, with the owner and repository name as its two groups.
REPO_URL = re.compile(SCHEMA["$defs"]["module"]["properties"]["repo"]["pattern"])
REPO_FORMAT = ("must be the address of a public GitHub repository, exactly "
               "https://github.com/<owner>/<repository> with nothing after the repository name")


def _ecma(pattern: str) -> re.Pattern:
    """A schema pattern as JSON Schema reads it: $ is the end of the string. Python's $
    also matches before a final newline. The patterns here use $ only as an anchor."""
    return re.compile(re.sub(r"(?<!\\)\$", r"\\Z", pattern))


def _pattern(validator, pattern, instance, schema):
    if validator.is_type(instance, "string") and not _ecma(pattern).search(instance):
        yield jsonschema.ValidationError(f"{instance!r} does not match {pattern!r}")


Validator = jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": _pattern})


def check(index: dict) -> list[str]:
    problems: list[str] = []
    for err in Validator(SCHEMA).iter_errors(index):
        where = "/".join(str(p) for p in err.path)
        if err.validator == "pattern" and where.endswith("/repo"):
            problems.append(f"schema: {where}: repo is {err.instance!r}. It {REPO_FORMAT}.")
        else:
            problems.append(f"schema: {where}: {err.message}")
    if problems:
        return problems  # policy checks assume a schema-valid document

    modules = index["modules"]
    seen: set[str] = set()
    for m in modules:
        mid, tier = m["id"], m["tier"]
        if mid in seen:
            problems.append(f"{mid}: duplicate id (ids are unique forever)")
        seen.add(mid)
        if mid.startswith("celerp-") and tier != "official":
            problems.append(f"{mid}: the 'celerp-' prefix is reserved for official modules")
        if tier in ("community", "verified"):
            for field in ("repo", "commit", "data_access", "network_calls"):
                if not m.get(field):
                    problems.append(f"{mid}: {tier} tier requires {field}")
        if tier == "community":
            owner = REPO_URL.fullmatch(m["repo"]).group(1) if m.get("repo") else None
            if owner and m["author"].lower() != owner.lower():
                problems.append(f"{mid}: author is {m['author']!r} but the repository belongs "
                                f"to {owner!r}. A community entry's author is the GitHub "
                                "account that owns its repository.")
        if tier == "community" and "version" in m:
            problems.append(f"{mid}: leave out version; a community module's version is the one in its own manifest")
        if tier == "verified" and not m.get("sha256"):
            problems.append(f"{mid}: verified tier requires sha256")
        if (m.get("price_monthly") or m.get("price_once")) and tier == "community":
            problems.append(f"{mid}: a price requires the verified or official tier")

    ordered = sorted(modules, key=lambda m: (TIER_RANK[m["tier"]], m["id"]))
    if [m["id"] for m in modules] != [m["id"] for m in ordered]:
        problems.append("modules must be sorted by tier (official, verified, community), then id")
    return problems


def check_v1(index) -> list[str]:
    """index.json: the earlier catalog format, which lists no modules."""
    if index != V1_INDEX:
        return [f"must be exactly {json.dumps(V1_INDEX)}; every listing goes in {CATALOG}"]
    return []


def selftest() -> int:
    base = {
        "schema_version": 2,
        "modules": [
            {"id": "my-module", "name": "My Module", "description": "Does things.",
             "tier": "community", "repo": "https://github.com/a/b", "commit": "a" * 40,
             "author": "A", "license": "MIT",
             "data_access": "Its own records.", "network_calls": "None."},
        ],
    }
    assert check(base) == [], "valid fixture must pass"
    for url in ("https://github.com/a-b/c.d_e-f", "https://github.com/A1/B2",
                f"https://github.com/{'a' * 39}/{'b' * 100}", "https://github.com/a/.github",
                "https://github.com/a/b..c", "https://github.com/a/git"):
        doc = copy.deepcopy(base)
        doc["modules"][0]["repo"] = url
        doc["modules"][0]["author"] = url.split("/")[3]
        assert check(doc) == [], f"{url} must pass"

    def broken(mutate) -> dict:
        doc = copy.deepcopy(base)
        mutate(doc["modules"])
        return doc

    cases = {
        "schema version 1": {**base, "schema_version": 1},
        "author is not the repo owner": broken(lambda ms: ms[0].update(author="Someone")),
        "bad tier": broken(lambda ms: ms[0].update(tier="platinum")),
        "duplicate id": broken(lambda ms: ms.append(dict(ms[0]))),
        "reserved prefix": broken(lambda ms: ms[0].update(id="celerp-sneaky")),
        "community without repo": broken(lambda ms: ms[0].pop("repo")),
        "community without data_access": broken(lambda ms: ms[0].pop("data_access")),
        "community without network_calls": broken(lambda ms: ms[0].pop("network_calls")),
        "community without commit": broken(lambda ms: ms[0].pop("commit")),
        "short commit": broken(lambda ms: ms[0].update(commit="abc1234")),
        "branch name as commit": broken(lambda ms: ms[0].update(commit="main")),
        "upper-case commit": broken(lambda ms: ms[0].update(commit="A" * 40)),
        "commit with a newline": broken(lambda ms: ms[0].update(commit="a" * 40 + "\n")),
        **{f"repo {label}": broken(lambda ms, url=url: ms[0].update(repo=url)) for label, url in {
            "not on GitHub": "https://gitlab.com/a/b",
            "over http": "http://github.com/a/b",
            "with .git": "https://github.com/a/b.git",
            "with .GIT": "https://github.com/a/b.GIT",
            "with a trailing slash": "https://github.com/a/b/",
            "with a path": "https://github.com/a/b/tree/main",
            "with a query": "https://github.com/a/b?tab=readme",
            "with a fragment": "https://github.com/a/b#readme",
            "with userinfo": "https://user@github.com/a/b",
            "with a port": "https://github.com:443/a/b",
            "on www": "https://www.github.com/a/b",
            "in upper case": "https://GitHub.com/a/b",
            "with no repository": "https://github.com/a",
            "with an owner starting with a hyphen": "https://github.com/-a/b",
            "with an owner ending with a hyphen": "https://github.com/a-/b",
            "with an owner of 40 characters": f"https://github.com/{'a' * 40}/b",
            "with an underscore in the owner": "https://github.com/a_b/c",
            "named .": "https://github.com/a/.",
            "named ..": "https://github.com/a/..",
            "with a space": "https://github.com/a/b c",
            "with a percent escape": "https://github.com/a/b%2Fc",
            "with a repository of 101 characters": f"https://github.com/a/{'b' * 101}",
            "with a newline": "https://github.com/a/b\n",
        }.items()},
        "community with version": broken(lambda ms: ms[0].update(version="1.0.0")),
        "paid community": broken(lambda ms: ms[0].update(price_monthly=9)),
        "verified without sha256": broken(lambda ms: ms[0].update(tier="verified")),
        "bad id chars": broken(lambda ms: ms[0].update(id="My Module!")),
        "unknown field": broken(lambda ms: ms[0].update(surprise=1)),
        "unsorted": broken(lambda ms: ms.insert(0, {
            "id": "zz-later", "name": "Z", "description": "Z.",
            "tier": "community", "repo": "https://github.com/a/z", "commit": "b" * 40,
            "author": "A", "license": "MIT",
            "data_access": "Its own records.", "network_calls": "None."})),
    }
    failures = [label for label, doc in cases.items() if not check(doc)]
    assert check_v1(V1_INDEX) == [], "the empty earlier index must pass"
    if not check_v1({"schema_version": 1, "modules": base["modules"]}):
        failures.append(f"{V1_FILE} with a module")
    if failures:
        print("selftest FAILED, these fixtures passed validation:", ", ".join(failures))
        return 1
    print(f"selftest ok ({len(cases)} invalid fixtures all rejected)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    failed = False
    for name, rule in ((CATALOG, check), (V1_FILE, check_v1)):
        index = json.loads((ROOT / name).read_text(encoding="utf-8"))
        problems = rule(index)
        for p in problems:
            print(f"{name}: {p}")
        if not problems:
            print(f"{name} ok ({len(index['modules'])} modules)")
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
