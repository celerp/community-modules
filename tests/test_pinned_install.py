"""The workflows install only packages pinned by version and sha256, dependencies included."""
from __future__ import annotations

import re
import unittest
from importlib import metadata

from fakes import ROOT

WORKFLOWS = ROOT / ".github" / "workflows"
REQUIREMENTS = ROOT / "scripts" / "requirements.txt"
INSTALL = "pip install --quiet --require-hashes -r scripts/requirements.txt"
INSTALLERS = re.compile(r"\b(pip3?|python3? -m pip|uv|pipx|poetry|conda|easy_install)\b")
REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.+!-]+)$")


def requirements() -> dict[str, tuple[str, list[str]]]:
    """name -> (version, sha256 hashes), one entry per requirement."""
    text = REQUIREMENTS.read_text(encoding="utf-8")
    logical = re.sub(r"\\\n", " ", text)
    found: dict[str, tuple[str, list[str]]] = {}
    for line in logical.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        spec, *options = line.split()
        m = REQUIREMENT.match(spec)
        if not m:
            raise AssertionError(f"not an exact pin: {line}")
        hashes = []
        for opt in options:
            if not opt.startswith("--hash=sha256:"):
                raise AssertionError(f"option other than a sha256 hash: {opt}")
            hashes.append(opt.removeprefix("--hash=sha256:"))
        name = metadata_name(m.group(1))
        if name in found:
            raise AssertionError(f"{name} pinned twice")
        found[name] = (m.group(2), hashes)
    return found


def metadata_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class WorkflowsInstallOnlyHashedPins(unittest.TestCase):
    def test_every_install_in_every_workflow_is_the_hashed_one(self):
        installs = {}
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.lstrip().startswith("#"):
                    continue
                if INSTALLERS.search(line):
                    installs.setdefault(path.name, []).append(line.strip())
        self.assertEqual(installs, {
            "ci.yml": [f"- run: {INSTALL}"],
            "listing-check.yml": [f"- run: {INSTALL}"],
        })

    def test_no_python_setup_action_installs_packages(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            with self.subTest(path.name):
                text = path.read_text(encoding="utf-8")
                self.assertNotIn("cache: pip", text)
                self.assertNotIn("requirements", text.replace(INSTALL, ""))


class RequirementsArePinnedWithHashes(unittest.TestCase):
    def test_every_line_is_an_exact_version_with_sha256_hashes(self):
        for name, (version, hashes) in requirements().items():
            with self.subTest(name):
                self.assertTrue(hashes, f"{name} has no hash")
                for h in hashes:
                    self.assertRegex(h, r"^[0-9a-f]{64}$")

    def test_no_index_link_or_include_options(self):
        text = REQUIREMENTS.read_text(encoding="utf-8")
        for option in ("--index-url", "--extra-index-url", "-i ", "--find-links", "-f ",
                       "--trusted-host", "-e ", "--editable", "-r ", "-c ", "://", " @ "):
            with self.subTest(option):
                body = "\n".join(l.split("#", 1)[0] for l in text.splitlines())
                self.assertNotIn(option, body)

    def test_jsonschema_is_pinned(self):
        self.assertIn("jsonschema", requirements())


class DependenciesArePinned(unittest.TestCase):
    """Every package jsonschema needs on this Python is pinned, at the installed version.
    Runs where the pinned set is installed (CI after the hashed install)."""

    def setUp(self):
        self.pins = requirements()
        try:
            installed = metadata.version("jsonschema")
        except metadata.PackageNotFoundError:
            self.skipTest("jsonschema is not installed")
        if installed != self.pins["jsonschema"][0]:
            self.skipTest(f"jsonschema {installed} installed, not the pinned version")

    def test_transitive_dependencies_are_all_pinned(self):
        seen, todo = set(), ["jsonschema"]
        while todo:
            name = metadata_name(todo.pop())
            if name in seen:
                continue
            seen.add(name)
            with self.subTest(name):
                self.assertIn(name, self.pins, f"{name} is installed but not pinned")
                self.assertEqual(metadata.version(name), self.pins[name][0])
            for req in metadata.requires(name) or []:
                spec, _, marker = req.partition(";")
                if marker.strip() and not _marker_applies(marker):
                    continue
                todo.append(re.split(r"[ <>=!~\[(]", spec.strip(), maxsplit=1)[0])


def _marker_applies(marker: str) -> bool:
    """Evaluate a dependency marker for this interpreter, with no extras requested."""
    try:
        from packaging.markers import Marker
    except ImportError:  # pip vendors packaging
        from pip._vendor.packaging.markers import Marker
    return Marker(marker.strip()).evaluate({"extra": ""})


if __name__ == "__main__":
    unittest.main()
