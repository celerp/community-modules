"""In-memory stand-ins for the GitHub REST API and module archives."""
from __future__ import annotations

import io
import json
import pathlib
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from github_api import NotFound  # noqa: E402

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40


class FakeGitHub:
    """Serves canned JSON by API path and canned bytes by URL; records writes."""

    def __init__(self, routes: dict | None = None, downloads: dict | None = None):
        self.routes = dict(routes or {})
        self.downloads = dict(downloads or {})
        self.writes: list[tuple[str, str, dict | None]] = []

    def get(self, path: str):
        if path not in self.routes:
            raise NotFound(path)
        value = self.routes[path]
        if isinstance(value, Exception):
            raise value
        return value

    def paged(self, path: str) -> list:
        return list(self.get(path))

    def download(self, url: str, cap: int, *, auth: bool = False) -> bytes:
        if url not in self.downloads:
            raise NotFound(url)
        data = self.downloads[url]
        if isinstance(data, Exception):
            raise data
        if len(data) > cap:
            from github_api import TooLarge
            raise TooLarge(url)
        return data

    def _write(self, method: str, path: str, body: dict | None):
        self.writes.append((method, path, body))
        return {}

    def post(self, path: str, body: dict):
        return self._write("POST", path, body)

    def patch(self, path: str, body: dict):
        return self._write("PATCH", path, body)

    def put(self, path: str, body: dict):
        return self._write("PUT", path, body)

    def delete(self, path: str):
        return self._write("DELETE", path, None)


MANIFEST = '''PLUGIN_MANIFEST = {{
    "name": "{name}",
    "version": "1.0.0",
    "display_name": "{display}",
    "license": "{license}",
    "api_routes": "{pkg}.routes",
}}
'''


def module_zip(files: dict[str, str | bytes], *, repo: str = "widgets", sha: str = SHA_A,
               symlinks: tuple[str, ...] = ()) -> bytes:
    """A GitHub-style archive: every path sits under `<repo>-<sha>/`."""
    buf = io.BytesIO()
    top = f"{repo}-{sha}/"
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(top, "")
        for path, content in files.items():
            zf.writestr(top + path, content)
        for path in symlinks:
            info = zipfile.ZipInfo(top + path)
            info.external_attr = (0o120777 << 16)
            zf.writestr(info, "target")
    return buf.getvalue()


def module_files(mid: str = "acme-widgets", *, display: str = "Acme Widgets",
                 license: str = "MIT", extra: dict | None = None) -> dict[str, str]:
    pkg = mid.replace("-", "_")
    files = {
        "LICENSE": "MIT License\n",
        f"{mid}/__init__.py": MANIFEST.format(name=mid, display=display, license=license, pkg=pkg),
        f"{mid}/{pkg}/__init__.py": "",
        f"{mid}/{pkg}/routes.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
    }
    files.update(extra or {})
    return files


def entry(mid: str = "acme-widgets", **over) -> dict:
    e = {
        "id": mid, "name": "Acme Widgets", "description": "Tracks widgets.",
        "tier": "community", "repo": "https://github.com/acme/widgets",
        "commit": SHA_A, "author": "Acme", "license": "MIT",
        "data_access": "Its own widget records.", "network_calls": "None.",
    }
    e.update(over)
    return e


def index_text(*entries: dict) -> str:
    return json.dumps({"schema_version": 2, "modules": list(entries)}, indent=2) + "\n"


def repo_routes(owner: str = "acme", name: str = "widgets", sha: str = SHA_A, *,
                private: bool = False, spdx: str | None = "MIT", compare: str = "behind") -> dict:
    """API responses for a healthy public repo with `sha` on its default branch."""
    base = f"/repos/{owner}/{name}"
    routes = {
        base: {"full_name": f"{owner}/{name}", "private": private,
               "visibility": "private" if private else "public",
               "owner": {"login": owner}, "default_branch": "main"},
        f"{base}/compare/main...{sha}": {"status": compare},
    }
    if spdx is not None:
        routes[f"{base}/license?ref={sha}"] = {"license": {"spdx_id": spdx}}
    return routes


def archive_url(owner: str = "acme", name: str = "widgets", sha: str = SHA_A) -> str:
    return f"https://codeload.github.com/{owner}/{name}/zip/{sha}"
