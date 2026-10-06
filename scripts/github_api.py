"""A small GitHub REST client for the listing workflows (standard library only).

The token is sent only to api.github.com. Redirects are followed by hand so the
Authorization header never travels to another host (artifact and archive
downloads redirect to storage hosts).
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
MAX_JSON_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5


class ApiError(Exception):
    """GitHub answered with an error, or could not be reached."""


class NotFound(ApiError):
    """GitHub answered 404."""


class TooLarge(ApiError):
    """A download was larger than its cap."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class GitHub:
    def __init__(self, token: str | None = None):
        self.token = token if token is not None else os.environ.get("GITHUB_TOKEN", "")

    def _request(self, method: str, url: str, body: dict | None, cap: int, auth: bool):
        data = json.dumps(body).encode() if body is not None else None
        for _ in range(MAX_REDIRECTS + 1):
            headers = {"Accept": "application/vnd.github+json",
                       "X-GitHub-Api-Version": "2022-11-28",
                       "User-Agent": "celerp-community-modules"}
            if auth and self.token and urllib.parse.urlsplit(url).netloc == "api.github.com":
                headers["Authorization"] = f"Bearer {self.token}"
            if data is not None:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with _OPENER.open(req, timeout=60) as resp:
                    payload = resp.read(cap + 1)
                    if len(payload) > cap:
                        raise TooLarge(url)
                    return payload, resp.headers
            except urllib.error.HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308) and exc.headers.get("Location"):
                    url = urllib.parse.urljoin(url, exc.headers["Location"])
                    if exc.code == 303:
                        method, data = "GET", None
                    continue
                if exc.code == 404:
                    raise NotFound(url) from None
                raise ApiError(f"{method} {url}: HTTP {exc.code}") from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise ApiError(f"{method} {url}: {exc}") from None
        raise ApiError(f"{method} {url}: too many redirects")

    def _json(self, method: str, path: str, body: dict | None = None):
        payload, headers = self._request(method, API + path, body, MAX_JSON_BYTES, True)
        try:
            return (json.loads(payload) if payload else {}), headers
        except ValueError:
            raise ApiError(f"{method} {path}: response is not JSON") from None

    def get(self, path: str):
        return self._json("GET", path)[0]

    def paged(self, path: str) -> list:
        """Every item of a list endpoint, following the Link header."""
        items: list = []
        url = path
        while url:
            page, headers = self._json("GET", url)
            if not isinstance(page, list):
                raise ApiError(f"GET {url}: expected a list")
            items.extend(page)
            nxt = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link", ""))
            url = nxt.group(1).removeprefix(API) if nxt else ""
        return items

    def post(self, path: str, body: dict):
        return self._json("POST", path, body)[0]

    def patch(self, path: str, body: dict):
        return self._json("PATCH", path, body)[0]

    def put(self, path: str, body: dict):
        return self._json("PUT", path, body)[0]

    def delete(self, path: str):
        return self._json("DELETE", path)[0]

    def download(self, url: str, cap: int, *, auth: bool = False) -> bytes:
        return self._request("GET", url, None, cap, auth)[0]
