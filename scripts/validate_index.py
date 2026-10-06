#!/usr/bin/env python3
"""Validate index.json: JSON Schema plus the policy rules a schema cannot say.

Runs in CI on every pull request. It only reads text - it never runs a module.

Policy rules on top of the schema:
  - ids are unique and the list is sorted by (tier rank, id)
  - the "celerp-" id prefix is reserved for the official tier
  - community and verified tiers require a public repo and its commit
  - community and verified tiers require data_access and network_calls
  - community tier carries no version (the module's own manifest is the version)
  - verified tier requires sha256
  - a price requires the verified or official tier (we do not sell unverified code)

Run `validate_index.py --selftest` to exercise every rule against inline fixtures.
"""
from __future__ import annotations

import copy
import json
import pathlib
import sys

import jsonschema

ROOT = pathlib.Path(__file__).resolve().parents[1]
TIER_RANK = {"official": 0, "verified": 1, "community": 2}


def check(index: dict, schema: dict) -> list[str]:
    problems: list[str] = []
    validator = jsonschema.Draft202012Validator(schema)
    for err in validator.iter_errors(index):
        problems.append(f"schema: {'/'.join(str(p) for p in err.path)}: {err.message}")
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


def selftest() -> int:
    schema = json.loads((ROOT / "schema" / "index.schema.json").read_text(encoding="utf-8"))
    base = {
        "schema_version": 1,
        "modules": [
            {"id": "my-module", "name": "My Module", "description": "Does things.",
             "tier": "community", "repo": "https://github.com/a/b", "commit": "a" * 40,
             "author": "A", "license": "MIT",
             "data_access": "Its own records.", "network_calls": "None."},
        ],
    }
    assert check(base, schema) == [], "valid fixture must pass"

    def broken(mutate) -> dict:
        doc = copy.deepcopy(base)
        mutate(doc["modules"])
        return doc

    cases = {
        "bad tier": broken(lambda ms: ms[0].update(tier="platinum")),
        "duplicate id": broken(lambda ms: ms.append(dict(ms[0]))),
        "reserved prefix": broken(lambda ms: ms[0].update(id="celerp-sneaky")),
        "community without repo": broken(lambda ms: ms[0].pop("repo")),
        "community without data_access": broken(lambda ms: ms[0].pop("data_access")),
        "community without network_calls": broken(lambda ms: ms[0].pop("network_calls")),
        "community without commit": broken(lambda ms: ms[0].pop("commit")),
        "short commit": broken(lambda ms: ms[0].update(commit="abc1234")),
        "branch name as commit": broken(lambda ms: ms[0].update(commit="main")),
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
    failures = [label for label, doc in cases.items() if not check(doc, schema)]
    if failures:
        print("selftest FAILED, these fixtures passed validation:", ", ".join(failures))
        return 1
    print(f"selftest ok ({len(cases)} invalid fixtures all rejected)")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()
    schema = json.loads((ROOT / "schema" / "index.schema.json").read_text(encoding="utf-8"))
    index = json.loads((ROOT / "index.json").read_text(encoding="utf-8"))
    problems = check(index, schema)
    for p in problems:
        print(f"index.json: {p}")
    if not problems:
        print(f"index.json ok ({len(index['modules'])} modules)")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
