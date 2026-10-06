"""Code the scan cannot follow is flagged, ordinary code is not, and only Celerp's
own API client is exempt from the network rule.

Every fixture is read as text and never run. The calls they hide are harmless
ones the scan reports when written plainly (os.getenv reads the environment).
"""
from __future__ import annotations

import os
import subprocess
import unittest

import fakes  # noqa: F401  (puts scripts/ on the path)
from scan_module import scan_folder


def kinds(src: str) -> set[str]:
    files = {"__init__.py": b"PLUGIN_MANIFEST = {}\n", "pkg/code.py": src.encode()}
    return {f.kind for f in scan_folder(files)}


class FlaggedCase(unittest.TestCase):
    def assertFlagged(self, cases: dict[str, str], expected: set[str]) -> None:
        """Each fixture goes to review with one of the expected kinds."""
        for name, src in cases.items():
            with self.subTest(name):
                found = kinds(src)
                self.assertTrue(found & expected, f"{name}: {found or 'no findings'}")

    def assertClean(self, cases: dict[str, str]) -> None:
        for name, src in cases.items():
            with self.subTest(name):
                self.assertEqual(kinds(src), set())


UNFOLLOWED = {"dynamic_code"}
UNFOLLOWED_OR_SECRET = {"dynamic_code", "secrets"}
UNFOLLOWED_OR_NETWORK = {"dynamic_code", "network"}


class ClassAttributes(FlaggedCase):
    def test_module_or_callable_held_by_a_class(self):
        self.assertFlagged({
            "class attribute": "import os\nclass C:\n    o = os\nC.o.getcwd()\n",
            "instance attribute": "import os\nclass C:\n    def __init__(self):\n"
                                  "        self.o = os\nC().o.getcwd()\n",
            "method returns module": "import os\nclass C:\n    def go(self):\n"
                                     "        return os\nC().go().getcwd()\n",
            "setattr on class": "import os\nclass C:\n    pass\nsetattr(C, 'o', os)\n"
                                "C.o.getcwd()\n",
            "class keyword": "import os\nclass C(m=os):\n    pass\n",
        }, UNFOLLOWED)
        self.assertFlagged({
            "callable as class attribute": "import os\nclass C:\n    g = os.getenv\n"
                                           "C.g('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)


class Closures(FlaggedCase):
    def test_module_held_by_a_closure_or_lambda(self):
        self.assertFlagged({
            "inner function returns module": "import os\ndef outer():\n    def inner():\n"
                                             "        return os\n    return inner\n"
                                             "outer()().getcwd()\n",
            "nonlocal rebinding": "import os\ndef outer():\n    m = None\n"
                                  "    def inner():\n        nonlocal m\n        m = os\n"
                                  "    inner()\n    return m\n",
            "lambda returns module": "import os\nf = lambda: os\nf().getcwd()\n",
            "lambda default": "import os\nf = lambda m=os: m.getcwd()\n",
            "generator yields module": "import os\ndef g():\n    yield os\n",
        }, UNFOLLOWED)


class Decorators(FlaggedCase):
    def test_module_or_callable_through_a_decorator(self):
        self.assertFlagged({
            "decorator returns module": "import os\ndef deco(fn):\n    return os\n"
                                        "@deco\ndef h():\n    pass\nh.getcwd()\n",
            "decorator argument": "import os\ndef reg(m):\n    def d(fn):\n"
                                  "        return fn\n    return d\n"
                                  "@reg(os)\ndef h():\n    pass\n",
        }, UNFOLLOWED)
        self.assertFlagged({
            "decorator returns callable": "import os\ndef deco(fn):\n    return os.getenv\n"
                                          "@deco\ndef h():\n    pass\nh('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)


class DunderImport(FlaggedCase):
    def test_import_by_string(self):
        self.assertFlagged({
            "__import__": "m = __import__('os')\nm.getcwd()\n",
            "builtins.__import__": "import builtins\nm = builtins.__import__('os')\n",
            "importlib by name": "import importlib\nm = importlib.import_module('os')\n",
        }, UNFOLLOWED)


class NamespaceDicts(FlaggedCase):
    def test_globals_vars_locals(self):
        self.assertFlagged({
            "globals()": "g = globals()\n",
            "globals() item": "globals()['__builtins__']\n",
            "globals alias": "g = globals\ng()\n",
            "vars()": "v = vars()\n",
            "vars(module)": "import os\nv = vars(os)\n",
            "locals()": "l = locals()\n",
        }, UNFOLLOWED)

    def test_a_module_namespace_read_by_key(self):
        # A name looked up by string in a module's own namespace is a name the scan
        # cannot follow, exactly like vars(os)['getenv'].
        self.assertFlagged({
            "module __dict__ item": "import os\nos.__dict__['getenv']('HOME')\n",
            "module __dict__.get": "import os\nos.__dict__.get('getenv')('HOME')\n",
            "module __getattribute__": "import os\nos.__getattribute__('getenv')('HOME')\n",
            "sys __dict__ modules": "import sys\nsys.__dict__['modules']['os'].getenv('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)


class SysModules(FlaggedCase):
    def test_lookups_in_sys_modules(self):
        self.assertFlagged({
            "item": "import sys\nm = sys.modules['os']\nm.getcwd()\n",
            "get": "import sys\nm = sys.modules.get('os')\n",
            "aliased sys": "import sys as s\nm = s.modules['os']\n",
            "sys as a value": "import sys\nt = sys\nt.modules['os'].getcwd()\n",
            "from sys import modules": "from sys import modules\nmodules['os'].getcwd()\n",
        }, UNFOLLOWED)


class RunpyPkgutil(FlaggedCase):
    def test_loading_by_name(self):
        self.assertFlagged({
            "runpy.run_module": "import runpy\nrunpy.run_module('os')\n",
            "from runpy import run_path": "from runpy import run_path\nrun_path('x.py')\n",
            "pkgutil.resolve_name": "import pkgutil\npkgutil.resolve_name('os.getcwd')()\n",
            "from pkgutil import": "from pkgutil import resolve_name\n"
                                  "resolve_name('os:getcwd')()\n",
        }, UNFOLLOWED)


class TypingCast(FlaggedCase):
    def test_module_or_callable_through_cast(self):
        self.assertFlagged({
            "typing.cast module": "import os, typing\nm = typing.cast(object, os)\n"
                                  "m.getcwd()\n",
            "from typing import cast": "import os\nfrom typing import cast\n"
                                       "m = cast('module', os)\nm.getcwd()\n",
        }, UNFOLLOWED)
        self.assertFlagged({
            "cast of a callable": "import os\nfrom typing import cast\n"
                                  "cast(object, os.getenv)('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)


class ModulesReachedThroughOtherModules(FlaggedCase):
    def test_a_standard_module_reexported_by_another(self):
        # logging, pathlib and shlex each import os, and typing imports sys, so
        # logging.os is os. The scan treats ui.config.os the same way (core packages).
        self.assertFlagged({
            "logging.os": "import logging\nlogging.os.getenv('HOME')\n",
            "pathlib.os": "import pathlib\npathlib.os.getenv('HOME')\n",
            "shlex.os": "import shlex\nshlex.os.getenv('HOME')\n",
            "typing.sys.modules": "import typing\ntyping.sys.modules['os'].getenv('HOME')\n",
            "stored": "import logging\nm = logging.os\nm.getenv('HOME')\n",
            "getattr literal": "import pathlib\nm = getattr(pathlib, 'os')\nm.getenv('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_a_holder_taken_with_getattr_and_a_literal_name(self):
        # p = os.path is flagged as passed on; the same object through getattr is not.
        self.assertFlagged({
            "getattr(os, 'path')": "import os\np = getattr(os, 'path')\n"
                                   "p.expanduser('~')\n",
        }, UNFOLLOWED | {"files"})


class NamesFromLiteralLoops(FlaggedCase):
    def test_each_literal_name_is_checked(self):
        self.assertFlagged({
            "hidden call": "import os\nfor k in ('system',):\n    getattr(os, k)('ls')\n",
        }, {"process"})
        self.assertFlagged({
            "holder taken": "import os\nps = [getattr(os, k) for k in ('path',)]\n",
            "loop name rebound by match": "import os\nfor k in ('getcwd',):\n    pass\n"
                                          "match s:\n    case k:\n        getattr(os, k)()\n",
            "inspect beyond its predicates": "import inspect\nm = inspect.getmodule(print)\n",
        }, UNFOLLOWED)


class BindingsTheScopeMisses(FlaggedCase):
    def test_module_bound_inside_an_annotation(self):
        # Without `from __future__ import annotations`, Python 3.10 to 3.13 evaluate
        # these annotations when the module loads, so the walrus binds m to os.
        self.assertFlagged({
            "variable annotation": "import os\nx: (m := os) = 1\nm.getenv('HOME')\n",
            "argument annotation": "import os\ndef f(a: (m := os)):\n    pass\n"
                                   "m.getenv('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_module_imported_into_a_global_from_a_function(self):
        self.assertFlagged({
            "global import": "def f():\n    global o\n    import os as o\nf()\n"
                             "o.getenv('HOME')\n",
            "nonlocal import": "def f():\n    m = None\n    def g():\n        nonlocal m\n"
                               "        import os as m\n    g()\n    return m\n",
            "import and assignment": "o = None\nimport os as o\no.getenv('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)


class OrdinaryCodeStaysClean(FlaggedCase):
    """Benign shapes a module commonly uses. None of them should go to review."""

    def test_everyday_module_code(self):
        self.assertClean({
            "logging": "import logging\nlogger = logging.getLogger(__name__)\nlogger.info('x')\n",
            "except tuple": "import httpx\ndef f():\n    try:\n        pass\n"
                            "    except (httpx.HTTPError, ValueError):\n        pass\n",
            "sort key": "import os\nnames = sorted(['a'], key=os.path.basename)\n",
            "os.sep": "import os\nx = os.sep.join(['a', 'b'])\n",
            "dataclass factory": "from dataclasses import dataclass, field\n@dataclass\n"
                                 "class A:\n    xs: list = field(default_factory=list)\n",
            "asyncio": "import asyncio\nasync def g():\n    pass\nasync def f(ts):\n"
                       "    await asyncio.sleep(0)\n    asyncio.create_task(g())\n"
                       "    return await asyncio.gather(*ts)\n",
            "asyncio.Lock factory": "import asyncio\nfrom dataclasses import dataclass, field\n"
                                    "@dataclass\nclass A:\n"
                                    "    lock: asyncio.Lock = field(default_factory=asyncio.Lock)\n",
            "functools.wraps": "import functools\ndef deco(fn):\n    @functools.wraps(fn)\n"
                               "    def w(*a):\n        return fn(*a)\n    return w\n",
            "typing.cast of data": "from typing import cast\ny = cast(int, '1')\n",
            "TYPE_CHECKING": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
                             "    from pathlib import Path\n",
            "getattr literal with default": "def f(o):\n    return getattr(o, 'name', '--')\n",
            "datetime, json, re, uuid, decimal": "import json, re, uuid\n"
                                                 "from datetime import datetime, timezone\n"
                                                 "from decimal import Decimal\n"
                                                 "x = (json.loads('{}'), re.compile('x'),"
                                                 " uuid.uuid4(), datetime.now(timezone.utc),"
                                                 " Decimal('1'))\n",
            "pydantic and sqlalchemy": "import sqlalchemy as sa\nfrom pydantic import BaseModel\n"
                                       "class M(BaseModel):\n    x: int = 1\n"
                                       "t = sa.Column(sa.String)\n",
            "fasthtml": "from fasthtml.common import Div, P\ndef page():\n"
                        "    return Div(P('x'))\n",
            "Path annotations": "from pathlib import Path\n"
                                "def f(p: Path | None = None) -> Path | None:\n    return p\n",
            "isinstance Path": "from pathlib import Path\ndef f(p):\n    return isinstance(p, Path)\n",
            "in-memory buffers": "import csv, io\nbuf = io.StringIO()\nw = csv.writer(buf)\n",
            "httpx.Timeout": "import httpx\nt = httpx.Timeout(5)\n",
            "request params": "from starlette.requests import Request\n"
                              "async def h(request: Request):\n"
                              "    return request.query_params.get('q')\n",
            "sys.version_info and stderr": "import sys\nPY = sys.version_info >= (3, 11)\n"
                                           "print('x', file=sys.stderr)\n",
            "own folder name": "import os\nHERE = os.path.dirname(__file__)\n",
        })

    def test_benign_shapes_near_flagged_ones(self):
        self.assertClean({
            "getattr over literal names": "def f(o):\n"
                                          "    return {k: getattr(o, k) for k in ('a', 'b')}\n",
            "zip in memory": "import io, zipfile\nbuf = io.BytesIO()\n"
                             "with zipfile.ZipFile(buf, 'w') as z:\n    z.writestr('a', 'b')\n",
            "inspect.iscoroutinefunction": "import inspect\nasync def g():\n    pass\n"
                                           "ok = inspect.iscoroutinefunction(g)\n",
            "setattr over literal names": "def f(rule, p):\n    for k in ('a', 'b'):\n"
                                          "        setattr(rule, k, getattr(p, k))\n",
            "sqlalchemy.inspect": "import sqlalchemy as sa\ndef f(e):\n"
                                  "    return sa.inspect(e).attrs\n",
            "Annotated dependency": "from typing import Annotated\nfrom fastapi import Depends\n"
                                    "def db():\n    pass\n"
                                    "def f(s: Annotated[int, Depends(db)]):\n    pass\n",
            "two imports for one name": "try:\n    import ujson as json\nexcept ImportError:\n"
                                        "    import json\njson.loads('1')\n",
        })

    def test_files_next_to_the_module_code_go_to_review(self):
        # The module's own folder is outside Celerp's data folder.
        self.assertFlagged({
            "own locale file": "import json\nfrom pathlib import Path\n"
                               "d = json.loads((Path(__file__).parent / 'locales' / 'en.json')"
                               ".read_text())\n",
        }, {"files"})


TEMPLATE = os.environ.get("TEMPLATE", "")
TEMPLATE_COMMIT = "f863c419441a527e291503d50c53cbd126d13454"  # the catalog's template entry


class TemplateScansClean(unittest.TestCase):
    @unittest.skipUnless(TEMPLATE, "set TEMPLATE to a celerp-module-template checkout")
    def test_template_module_has_no_findings(self):
        def git(*args):
            return subprocess.run(["git", "-C", TEMPLATE, *args], check=True,
                                  capture_output=True).stdout
        folder = "acme-maintenance/"
        names = git("ls-tree", "-r", "--name-only", TEMPLATE_COMMIT, folder).decode().split()
        files = {n[len(folder):]: git("show", f"{TEMPLATE_COMMIT}:{n}") for n in names}
        self.assertEqual(scan_folder(files), [])


H = "import httpx\nfrom ui.config import API_BASE\n"
OWN = H + "def _api():\n    return httpx.AsyncClient(base_url=API_BASE, timeout=5)\n"
ELSEWHERE = "'http:' + '//example.com'"  # a host other than Celerp's, not one literal


class OwnApiClient(FlaggedCase):
    def test_shapes_treated_as_celerp_own_api(self):
        self.assertClean({
            "template shape": OWN + "async def call(m, u):\n    async with _api() as c:\n"
                                    "        return await getattr(c, m)(u)\n",
            "client in with": H + "async def call(m, u):\n"
                                  "    async with httpx.AsyncClient(base_url=API_BASE) as c:\n"
                                  "        return await getattr(c, m)(u)\n",
            "client assigned": H + "async def call(m, u):\n"
                                   "    c = httpx.AsyncClient(base_url=API_BASE)\n"
                                   "    return await getattr(c, m)(u)\n",
            "from httpx import": "from httpx import AsyncClient\nfrom ui.config import API_BASE\n"
                                 "c = AsyncClient(base_url=API_BASE)\n",
            "ui.config module": "import httpx\nimport ui.config as cfg\n"
                                "c = httpx.AsyncClient(base_url=cfg.API_BASE)\n",
            "wrapped _api": OWN + "def wrap():\n    return _api()\nasync def call(m, u):\n"
                                  "    async with wrap() as c:\n"
                                  "        return await getattr(c, m)(u)\n",
        })

    def test_shapes_not_treated_as_own_api(self):
        self.assertFlagged({
            "client passed in": "async def call(c, m, u):\n    return await getattr(c, m)(u)\n",
            "no base_url": "import httpx\nc = httpx.AsyncClient()\n",
            "literal base_url": "import httpx\nc = httpx.AsyncClient(base_url='http://localhost:8000')\n",
            "API_BASE rebound in the file": H + f"API_BASE = {ELSEWHERE}\n"
                                                "c = httpx.AsyncClient(base_url=API_BASE)\n",
            "API_BASE as a parameter": H + "def f(API_BASE):\n"
                                           "    return httpx.AsyncClient(base_url=API_BASE)\n",
            "one of two returns elsewhere": H + "def _api(x):\n    if x:\n"
                                                "        return httpx.AsyncClient(base_url=API_BASE)\n"
                                                f"    return httpx.AsyncClient(base_url={ELSEWHERE})\n",
            "_api rebound": OWN + "def other():\n    return httpx.AsyncClient(base_url=B)\n"
                                  "_api = other\n",
        }, UNFOLLOWED_OR_NETWORK)

    def test_a_non_celerp_base_url_is_not_own_api(self):
        self.assertFlagged({
            "ui.config.API_BASE rewritten": "import httpx\nimport ui.config as cfg\n"
                                            f"cfg.API_BASE = {ELSEWHERE}\n"
                                            "c = httpx.AsyncClient(base_url=cfg.API_BASE)\n",
            "API_BASE rewritten via from ui import config": "from ui import config\n"
                                                            f"config.API_BASE = {ELSEWHERE}\n",
            "API_BASE rewritten via setattr": "import ui.config as cfg\n"
                                              f"setattr(cfg, 'API_BASE', {ELSEWHERE})\n",
            "a standard module changed": "import sys\nsys.stdout = None\n",
            "client base_url replaced": OWN + "async def f():\n    async with _api() as c:\n"
                                              f"        c.base_url = {ELSEWHERE}\n"
                                              "        return await c.get('/')\n",
        }, UNFOLLOWED_OR_NETWORK)

    def test_httpx_client_class_passed_on(self):
        # The client class stored, subclassed or wrapped is a client the scan cannot
        # follow, like a module stored in a variable.
        self.assertFlagged({
            "subclass": "import httpx\nclass C(httpx.AsyncClient):\n    pass\n"
                        f"c = C(base_url={ELSEWHERE})\n",
            "alias": "import httpx\nAC = httpx.AsyncClient\n"
                     f"c = AC(base_url={ELSEWHERE})\n",
            "request function": "import httpx\nfetch = httpx.get\n",
            "partial": "import functools, httpx\n"
                       "mk = functools.partial(httpx.AsyncClient, "
                       f"base_url={ELSEWHERE})\n",
        }, UNFOLLOWED_OR_NETWORK)


if __name__ == "__main__":
    unittest.main()
