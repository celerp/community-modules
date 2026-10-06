"""The static scan reads a module's files as text and reports what it finds."""
from __future__ import annotations

import unittest

import fakes  # noqa: F401  (puts scripts/ on the path)
from scan_module import scan_folder


def kinds(files: dict[str, str | bytes]) -> set[str]:
    return {f.kind for f in scan_folder({k: v.encode() if isinstance(v, str) else v
                                         for k, v in files.items()})}


def py(src: str) -> dict[str, str]:
    return {"__init__.py": "PLUGIN_MANIFEST = {}\n", "pkg/code.py": src}


class CleanCode(unittest.TestCase):
    def test_plain_module_has_no_findings(self):
        self.assertEqual(kinds(py(
            "import re, uuid\nfrom urllib.parse import quote\n"
            "def f(x):\n    return quote(re.sub('a', 'b', x))\n")), set())

    def test_own_api_client_is_not_a_network_call(self):
        self.assertEqual(kinds(py(
            "import httpx\nfrom ui.config import API_BASE\n"
            "def c():\n    return httpx.AsyncClient(base_url=API_BASE, timeout=5)\n"
            "async def call(c, method, url):\n"
            "    try:\n        return await getattr(c, method)(url)\n"
            "    except httpx.HTTPError:\n        return None\n")), set())

    def test_file_under_celerp_data_dir_is_allowed(self):
        self.assertEqual(kinds(py(
            "from pathlib import Path\nfrom starlette.responses import FileResponse\n"
            "def serve(key):\n"
            "    from celerp.config import settings\n"
            "    dest = Path(settings.data_dir) / key.lstrip('/')\n"
            "    if not dest.is_file():\n        return None\n"
            "    return FileResponse(path=str(dest))\n")), set())

    def test_tests_folder_is_not_scanned(self):
        files = py("x = 1\n")
        files["tests/test_x.py"] = "import subprocess\nsubprocess.run(['true'])\n"
        files["tests/conftest.py"] = "import os\nos.environ['A'] = '1'\n"
        self.assertEqual(kinds(files), set())

    def test_data_files_are_fine(self):
        files = py("x = 1\n")
        files.update({"README.md": "# hi", "static/logo.png": b"\x89PNG", "LICENSE": "MIT"})
        self.assertEqual(kinds(files), set())


class Network(unittest.TestCase):
    def test_requests_import(self):
        self.assertEqual(kinds(py("import requests\nrequests.get('x')\n")), {"network"})

    def test_socket_alias(self):
        self.assertEqual(kinds(py("import socket as s\n")), {"network"})

    def test_urllib_request_from_import(self):
        self.assertEqual(kinds(py("from urllib.request import urlopen\n")), {"network"})

    def test_httpx_client_to_another_host(self):
        self.assertEqual(kinds(py(
            "import httpx\ndef c():\n    return httpx.Client(base_url='https://example.com')\n")),
            {"network"})

    def test_httpx_module_level_get(self):
        self.assertEqual(kinds(py("import httpx\nhttpx.get(u)\n")), {"network"})

    def test_absolute_url_in_code(self):
        self.assertEqual(kinds(py("U = 'https://example.com/hook'\n")), {"network"})

    def test_url_in_docstring_is_not_a_call(self):
        self.assertEqual(kinds(py('"""See https://example.com/docs."""\nx = 1\n')), set())

    def test_javascript_fetch(self):
        files = py("x = 1\n")
        files["static/app.js"] = "fetch('/x').then(r => r.json())\n"
        self.assertEqual(kinds(files), {"network"})


class Process(unittest.TestCase):
    def test_subprocess(self):
        self.assertEqual(kinds(py("import subprocess\n")), {"process"})

    def test_os_system_via_alias(self):
        self.assertEqual(kinds(py("import os as o\no.system('ls')\n")), {"process"})

    def test_from_os_import_popen(self):
        self.assertEqual(kinds(py("from os import popen\n")), {"process"})

    def test_asyncio_subprocess(self):
        self.assertEqual(kinds(py("import asyncio\nasyncio.create_subprocess_exec('ls')\n")),
                         {"process"})


class DynamicCode(unittest.TestCase):
    def test_eval(self):
        self.assertEqual(kinds(py("eval(x)\n")), {"dynamic_code"})

    def test_exec(self):
        self.assertEqual(kinds(py("exec(x)\n")), {"dynamic_code"})

    def test_dunder_import(self):
        self.assertEqual(kinds(py("m = __import__(name)\n")), {"dynamic_code"})

    def test_importlib(self):
        self.assertEqual(kinds(py("import importlib\nimportlib.import_module(n)\n")),
                         {"dynamic_code"})

    def test_getattr_on_a_module_with_computed_name(self):
        self.assertEqual(kinds(py("import os\nf = getattr(os, name)\n")), {"dynamic_code"})

    def test_getattr_with_constant_name_resolves(self):
        self.assertEqual(kinds(py("import os\nf = getattr(os, 'system')\n")), {"process"})

    def test_pickle(self):
        self.assertEqual(kinds(py("import pickle\npickle.loads(b)\n")), {"dynamic_code"})

    def test_tests_imported_by_module_code_are_scanned(self):
        files = py("from .tests import helper\n")
        files["tests/helper.py"] = "import subprocess\n"
        self.assertIn("process", kinds(files))


class Secrets(unittest.TestCase):
    def test_os_environ(self):
        self.assertEqual(kinds(py("import os\nk = os.environ['KEY']\n")), {"secrets"})

    def test_getenv(self):
        self.assertEqual(kinds(py("from os import getenv\nk = getenv('KEY')\n")), {"secrets"})

    def test_celerp_secret_setting(self):
        self.assertEqual(kinds(py(
            "from celerp.config import settings\nk = settings.jwt_secret\n")), {"secrets"})


class Files(unittest.TestCase):
    def test_open_relative_path(self):
        self.assertEqual(kinds(py("open('notes.txt').read()\n")), {"files"})

    def test_path_outside_data_dir(self):
        self.assertEqual(kinds(py("from pathlib import Path\nPath.home().read_text()\n")),
                         {"files"})

    def test_shutil(self):
        self.assertEqual(kinds(py("import shutil\nshutil.rmtree(p)\n")), {"files"})

    def test_data_dir_name_reassigned_elsewhere(self):
        self.assertEqual(kinds(py(
            "from celerp.config import settings\n"
            "def f(flag):\n"
            "    p = settings.data_dir\n"
            "    if flag:\n        p = '/srv'\n"
            "    return open(p)\n")), {"files"})

    def test_parent_segment_under_data_dir(self):
        self.assertEqual(kinds(py(
            "from pathlib import Path\nfrom celerp.config import settings\n"
            "p = Path(settings.data_dir) / '..' / 'x'\n")), {"files"})


class Unreadable(unittest.TestCase):
    def test_compiled_extension(self):
        files = py("x = 1\n")
        files["pkg/fast.so"] = b"\x7fELF"
        self.assertEqual(kinds(files), {"unreadable"})

    def test_shell_script(self):
        files = py("x = 1\n")
        files["setup.sh"] = "echo hi\n"
        self.assertEqual(kinds(files), {"unreadable"})

    def test_python_that_does_not_parse(self):
        self.assertEqual(kinds(py("def (:\n")), {"unreadable"})


class FindingDetail(unittest.TestCase):
    def test_finding_names_file_and_line(self):
        [f] = scan_folder({"__init__.py": b"x = 1\n", "pkg/a.py": b"\n\nimport socket\n"})
        self.assertEqual((f.kind, f.path, f.line), ("network", "pkg/a.py", 3))


def module(manifest: dict, files: dict[str, str]) -> dict[str, str]:
    """A module folder: the manifest at its root plus the given files."""
    return {"__init__.py": f"PLUGIN_MANIFEST = {manifest!r}\n", **files}


OWN = {"name": "acme", "api_routes": "acme_w.routes", "ui_routes": "acme_w.ui_routes",
       "migrations": "acme_w.migrations",
       "slots": {"search_provider": {"handler": "acme_w.search:find"},
                 "doc_detail_actions": [{"render": "acme_w.ui_routes:button"}]}}
OWN_FILES = {"acme_w/__init__.py": "", "acme_w/routes.py": "x = 1\n",
             "acme_w/ui_routes.py": "x = 1\n", "acme_w/search.py": "x = 1\n",
             "acme_w/migrations/__init__.py": "", "acme_w/migrations/m001.py": "x = 1\n"}


class ManifestReferences(unittest.TestCase):
    """Celerp imports the code the manifest names; it must be the module's own."""

    def test_own_references_are_fine(self):
        self.assertEqual(kinds(module(OWN, OWN_FILES)), set())

    def test_route_module_outside_the_folder(self):
        self.assertEqual(kinds(module({**OWN, "api_routes": "celerp.routers.system"},
                                      OWN_FILES)), {"dynamic_code"})

    def test_slot_handler_outside_the_folder(self):
        slots = {"search_provider": {"handler": "celerp.ai.service:run"}}
        self.assertEqual(kinds(module({**OWN, "slots": slots}, OWN_FILES)),
                         {"dynamic_code"})

    def test_slot_render_outside_the_folder(self):
        slots = {"doc_detail_actions": [{"render": "ui.routes.documents:page"}]}
        self.assertEqual(kinds(module({**OWN, "slots": slots}, OWN_FILES)),
                         {"dynamic_code"})

    def test_migrations_folder_outside_the_module(self):
        self.assertEqual(kinds(module({**OWN, "migrations": "/srv/other"}, OWN_FILES)),
                         {"dynamic_code"})

    def test_own_package_named_like_the_standard_library(self):
        manifest = {"name": "acme", "api_routes": "json.routes"}
        files = {"json/__init__.py": "", "json/routes.py": "x = 1\n"}
        self.assertEqual(kinds(module(manifest, files)), {"dynamic_code"})

    def test_top_level_module_named_like_an_installed_package(self):
        files = {**OWN_FILES, "requests.py": "x = 1\n"}
        self.assertEqual(kinds(module(OWN, files)), {"dynamic_code"})

    def test_locale_file_outside_the_folder(self):
        manifest = {**OWN, "locales": {"th": {"file": "../../other/th.json"}}}
        self.assertEqual(kinds(module(manifest, OWN_FILES)), {"files"})

    def test_locale_file_in_the_folder(self):
        manifest = {**OWN, "locales": {"th": {"file": "locales/th.json"}}}
        files = {**OWN_FILES, "locales/th.json": "{}"}
        self.assertEqual(kinds(module(manifest, files)), set())


class ImportableFiles(unittest.TestCase):
    def test_compiled_file_named_like_a_license(self):
        files = py("x = 1\n")
        files["license.pyc"] = b"\x00"
        self.assertEqual(kinds(files), {"unreadable"})

    def test_extension_named_like_a_notice(self):
        files = py("x = 1\n")
        files["notice.so"] = b"\x7fELF"
        self.assertEqual(kinds(files), {"unreadable"})


class ImportMachinery(unittest.TestCase):
    def test_sys_path(self):
        self.assertEqual(kinds(py("import sys\nsys.path.insert(0, d)\n")), {"dynamic_code"})

    def test_meta_path(self):
        self.assertEqual(kinds(py("import sys\nsys.meta_path.append(f)\n")),
                         {"dynamic_code"})

    def test_site_zipimport_pkgutil(self):
        for src in ("import site\n", "import zipimport\n", "import pkgutil\n"):
            with self.subTest(src=src):
                self.assertEqual(kinds(py(src)), {"dynamic_code"})

    def test_celerp_handler_resolver(self):
        self.assertEqual(kinds(py(
            "from celerp.modules.slots import resolve_handler\nresolve_handler(p)\n")),
            {"dynamic_code"})

    def test_celerp_slot_registration(self):
        self.assertEqual(kinds(py("from celerp.modules import slots\nslots.register(a, b)\n")),
                         {"dynamic_code"})

    def test_celerp_module_loader(self):
        self.assertEqual(kinds(py("from celerp.modules import loader\n")), {"dynamic_code"})


class SecretSettings(unittest.TestCase):
    def test_more_secret_settings(self):
        for attr in ("backup_encryption_key", "deployment_nonce", "activation_verifier",
                     "redis_url", "smtp_user"):
            with self.subTest(attr=attr):
                self.assertEqual(kinds(py(
                    f"from celerp.config import settings\nk = settings.{attr}\n")),
                    {"secrets"})

    def test_settings_object_under_another_name(self):
        self.assertEqual(kinds(py(
            "from celerp.config import settings\ns = settings\nk = s.jwt_secret\n")),
            {"secrets"})

    def test_settings_dumped_whole(self):
        self.assertEqual(kinds(py(
            "from celerp.config import settings\nd = settings.model_dump()\n")),
            {"secrets"})

    def test_ui_settings_object(self):
        self.assertEqual(kinds(py("from ui.config import _settings\nprint(_settings)\n")),
                         {"secrets"})

    def test_config_file_reader(self):
        self.assertEqual(kinds(py("from celerp.config import read_config\nc = read_config()\n")),
                         {"secrets"})

    def test_fresh_settings_instance(self):
        self.assertEqual(kinds(py("from celerp.config import Settings\ns = Settings()\n")),
                         {"secrets"})

    def test_standard_module_reached_through_a_core_module(self):
        self.assertEqual(kinds(py("from ui.config import os\nk = os.environ\n")),
                         {"secrets"})

    def test_plain_settings_are_fine(self):
        self.assertEqual(kinds(py(
            "from celerp.config import settings\n"
            "from ui.config import API_BASE, COOKIE_NAME, get_role\n"
            "n = settings.log_level\n")), set())


class CoreWrappers(unittest.TestCase):
    """Celerp code that makes the call for the module counts as the module's call."""

    def test_email_service(self):
        self.assertEqual(kinds(py("from celerp.services.email import send\n")), {"network"})

    def test_connectors_package(self):
        self.assertEqual(kinds(py("import celerp.connectors.shopify\n")), {"network"})

    def test_backup_service(self):
        self.assertEqual(kinds(py("from celerp.services import backup\n")), {"process"})

    def test_gateway_state(self):
        self.assertIn("secrets", kinds(py("from celerp.gateway.state import get\n")))

    def test_ordinary_core_services_are_fine(self):
        self.assertEqual(kinds(py(
            "from celerp.services.auth import get_current_user\n"
            "from celerp.services import attachments, permissions\n"
            "from ui.components.shell import page\nfrom ui.api_client import client\n")),
            set())


if __name__ == "__main__":
    unittest.main()
