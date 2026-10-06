"""The scan rules for introspection, re-exports, literal getattr names, annotations,
global/nonlocal, httpx values, attribute stores, literal-loop names, read-only names
and in-memory files: each covers its closely related forms, and ordinary code near
them stays clean.

Every fixture is read as text and never run. The calls they hide are harmless
ones the scan reports when written plainly (os.getenv reads the environment).
"""
from __future__ import annotations

import inspect
import unittest

import fakes  # noqa: F401  (puts scripts/ on the path)
from scan_module import READ_ONLY
from test_scan_coverage import FlaggedCase

UNFOLLOWED = {"dynamic_code"}
UNFOLLOWED_OR_SECRET = {"dynamic_code", "secrets"}
UNFOLLOWED_OR_NETWORK = {"dynamic_code", "network"}
FILES = {"files"}

OWN = "import httpx\nfrom ui.config import API_BASE\nc = httpx.AsyncClient(base_url=API_BASE)\n"


class Introspection(FlaggedCase):
    def test_namespace_reads_on_any_object(self):
        self.assertFlagged({
            "__dict__.get": "import os\nos.__dict__.get('getenv')('HOME')\n",
            "type(module).__dict__": "import os\ntype(os).__dict__\n",
            "getattr with '__getattribute__'": "import os\n"
                                               "getattr(os, '__getattribute__')('getenv')\n",
            "object.__getattribute__": "import os\n"
                                       "object.__getattribute__(os, 'getenv')('HOME')\n",
            "type.__getattribute__": "import os\ntype.__getattribute__(os, 'getenv')('HOME')\n",
            "super().__getattr__": "class C:\n    def __getattr__(self, n):\n"
                                   "        return super().__getattr__(n)\n",
        }, UNFOLLOWED)


class ProvidedModuleReexports(FlaggedCase):
    def test_reexport_under_the_module_name(self):
        self.assertFlagged({
            "logging.os": "import logging\nlogging.os.getenv('HOME')\n",
            "from logging import os": "from logging import os\nos.getenv('HOME')\n",
            "os.path.os": "import os.path\nos.path.os.getenv('HOME')\n",
        }, {"secrets"})
        self.assertFlagged({
            "stored": "import logging\nm = logging.os\n",
            "library root": "import fastapi\nfastapi.routing.inspect.getmodule(fastapi)\n",
        }, UNFOLLOWED)


class GetattrWithALiteralName(FlaggedCase):
    def test_result_is_value_checked(self):
        self.assertFlagged({
            "with a default": "import os\np = getattr(os, 'path', None)\n",
            "passed": "import os\nprint(getattr(os, 'path'))\n",
            "returned": "import os\ndef f():\n    return getattr(os, 'path')\n",
            "nested getattr": "import os\np = getattr(getattr(os, 'path'), 'os')\n",
        }, UNFOLLOWED)

    def test_ordinary_objects_stay_clean(self):
        self.assertClean({
            "own object": "class S:\n    a = 1\ns = S()\nv = getattr(s, 'a', None)\n"
                          "w = getattr(s, 'b')\n",
            "hasattr": "import os\nok = hasattr(os, 'getcwd')\n",
        })


class Annotations(FlaggedCase):
    def test_code_inside_an_annotation_is_scanned(self):
        self.assertFlagged({
            "walrus in a subscript": "import os\nx: list[(m := os)] = []\nm.getenv('HOME')\n",
            "walrus in an argument": "import os\ndef f(a: (m := os)):\n    pass\n"
                                     "m.getenv('HOME')\n",
            "lambda": "import os\nx: (lambda: os)() = 1\n",
            # Python refuses to compile this; flagging it is harmless.
            "walrus under future annotations": "from __future__ import annotations\n"
                                               "import os\nx: (m := os) = 1\n"
                                               "m.getenv('HOME')\n",
        }, UNFOLLOWED)
        self.assertFlagged({
            "call": "import os\nx: os.getenv('HOME') = 1\n",
        }, {"secrets"})

    def test_ordinary_annotations_stay_clean(self):
        self.assertClean({
            "httpx client types": "from __future__ import annotations\nimport httpx\n"
                                  "from typing import Optional\n"
                                  "def f(c: httpx.AsyncClient, d: Optional[httpx.Client] = None)"
                                  " -> httpx.AsyncClient | None:\n"
                                  "    x: httpx.AsyncClient = c\n    return x\n",
            "dataclass": "import datetime\nfrom dataclasses import dataclass, field\n"
                         "@dataclass\nclass Row:\n    code: str\n    when: datetime.date\n"
                         "    tags: list[str] = field(default_factory=list)\n",
            "pydantic": "from typing import Optional\nfrom pydantic import BaseModel, Field\n"
                        "class Item(BaseModel):\n    code: str = Field(..., max_length=20)\n"
                        "    signal: Optional[int] = None\n",
            "Annotated Depends": "from typing import Annotated\n"
                                 "from fastapi import APIRouter, Depends\n"
                                 "from sqlalchemy.ext.asyncio import AsyncSession\n"
                                 "router = APIRouter()\n"
                                 "async def get_session() -> AsyncSession: ...\n"
                                 "@router.get('/x')\n"
                                 "async def x(db: Annotated[AsyncSession, Depends(get_session)])"
                                 " -> dict:\n    return {}\n",
            "TYPE_CHECKING": "from __future__ import annotations\nimport typing\n"
                             "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
                             "    from sqlalchemy.ext.asyncio import AsyncSession\n"
                             "    from fastapi import Request\nif typing.TYPE_CHECKING:\n"
                             "    import datetime\n"
                             "def f(s: AsyncSession, r: Request) -> None: ...\n",
        })


class GlobalAndNonlocal(FlaggedCase):
    def test_bindings_go_to_the_named_scope(self):
        self.assertFlagged({
            "global from a nested function": "def f():\n    def g():\n        global o\n"
                                             "        import os as o\n    g()\nf()\n"
                                             "o.getenv('HOME')\n",
            "global from-import": "def f():\n    global g\n    from os import getenv as g\n"
                                  "f()\ng('HOME')\n",
            "nonlocal import": "def outer():\n    o = None\n    def inner():\n"
                               "        nonlocal o\n        import os as o\n    inner()\n"
                               "    o.getenv('HOME')\n",
            "import and assignment": "o = None\nimport os as o\no.getenv('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_ordinary_globals_stay_clean(self):
        self.assertClean({
            "counter": "def make():\n    n = 0\n    def inc():\n        nonlocal n\n"
                       "        n += 1\n        return n\n    return inc\n",
            "cache": "_cache = None\ndef get():\n    global _cache\n    if _cache is None:\n"
                     "        _cache = {}\n    return _cache\n",
            "match captures": "def f(cmd):\n    match cmd:\n"
                              "        case {'op': op, **rest}:\n            return op, rest\n"
                              "        case [first, *others]:\n            return first\n"
                              "        case str() as s:\n            return s\n",
        })


class HttpxAsValues(FlaggedCase):
    def test_client_class_or_request_function_as_a_value(self):
        self.assertFlagged({
            "default argument": "import httpx\ndef f(factory=httpx.AsyncClient):\n"
                                "    return factory(base_url='/x')\n",
            "dict value": "import httpx\nKINDS = {'a': httpx.get}\n",
            "from-import alias": "from httpx import AsyncClient as AC\nX = AC\n",
        }, {"network"})

    def test_type_checks_stay_clean(self):
        self.assertClean({
            "isinstance": "import httpx\ndef f(c):\n    return isinstance(c, httpx.AsyncClient)\n",
            "isinstance tuple": "import httpx\ndef f(c):\n"
                                "    return isinstance(c, (httpx.AsyncClient, httpx.Client))\n",
            "isinstance union": "import httpx\ndef f(c):\n"
                                "    return isinstance(c, httpx.AsyncClient | httpx.Client)\n",
            "issubclass tuple": "import httpx\ndef f(c):\n    return issubclass(c, (httpx.Client,))\n",
            "except tuple": "import httpx\ntry:\n    pass\n"
                            "except (httpx.HTTPError, httpx.TimeoutException):\n    pass\n",
        })


class AttributeStores(FlaggedCase):
    def test_stores_on_reserved_names(self):
        self.assertFlagged({
            "augmented": "import ui.config as cfg\ncfg.API_BASE += '.example.com'\n",
            "del": "import os\ndel os.getcwd\n",
            "for target": "import ui.config as cfg\nfor cfg.API_BASE in ['x']:\n    pass\n",
            "with target": "import contextlib\nimport ui.config as cfg\n"
                           "with contextlib.nullcontext('x') as cfg.API_BASE:\n    pass\n",
            "tuple target": "import ui.config as cfg\ncfg.API_BASE, y = 'x', 1\n",
            "setattr over literal loop": "import os\nfor n in ('getcwd',):\n"
                                         "    setattr(os, n, print)\n",
            "delattr": "import ui.config as cfg\ndelattr(cfg, 'API_BASE')\n",
        }, UNFOLLOWED)
        self.assertFlagged({
            "own client base_url": OWN + "c.base_url = '/x'\n",
        }, UNFOLLOWED_OR_NETWORK)

    def test_ordinary_stores_stay_clean(self):
        self.assertClean({
            "own package": "from acme import util\nutil.LIMIT = 3\nimport acme.util as u\nu.X = 1\n",
            "own instance": "class Svc:\n    def __init__(self):\n        self.os = None\n"
                            "        self.code = 1\ns = Svc()\ns.code = 2\n",
            "settings with base_url": "from pydantic_settings import BaseSettings\n"
                                      "class Settings(BaseSettings):\n    base_url: str = '/api'\n"
                                      "settings = Settings()\nsettings.base_url = '/v2'\n",
            "dataclass with base_url": "from dataclasses import dataclass\n@dataclass\n"
                                       "class Conf:\n    base_url: str\n"
                                       "c = Conf(base_url='/x')\nc.base_url = '/y'\n",
            "logger": "import logging\nlog = logging.getLogger(__name__)\n"
                      "log.propagate = False\n",
            "request state": "from fastapi import Request\n"
                             "async def f(request: Request):\n    request.state.user = None\n",
        })


class LiteralLoopNames(FlaggedCase):
    def test_each_name_checked_or_computed(self):
        self.assertFlagged({
            "list": "import os\nfor n in ['getenv']:\n    getattr(os, n)('HOME')\n",
            "set": "import os\nfor n in {'getenv'}:\n    getattr(os, n)('HOME')\n",
            "second name hidden": "import os\nfor n in ('getcwd', 'getenv'):\n    getattr(os, n)\n",
        }, {"secrets"})
        self.assertFlagged({
            "rebound inside the loop": "import os\nfor n in ('getcwd',):\n"
                                       "    n = 'get' + 'env'\n    getattr(os, n)('HOME')\n",
            "nested loops": "import os\nfor a in ('get',):\n    for b in ('env',):\n"
                            "        getattr(os, a + b)('HOME')\n",
            "loop over a loop variable": "import os\nfor t in (('getenv',),):\n"
                                         "    for n in t:\n        getattr(os, n)('HOME')\n",
            "rebound by a global": "import os\nfor n in ('getcwd',):\n    pass\n"
                                   "def f():\n    global n\n    n = 'getenv'\n"
                                   "f()\ngetattr(os, n)('HOME')\n",
            "attrgetter": "import os, operator\nfor n in ('getenv',):\n"
                          "    operator.attrgetter(n)(os)('HOME')\n",
            "methodcaller": "import os, operator\nfor n in ('getenv',):\n"
                            "    operator.methodcaller(n, 'HOME')(os)\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_loop_variable_seen_only_where_python_sees_it(self):
        self.assertFlagged({
            # A comprehension variable lives in the comprehension; after it, n is the
            # module's n.
            "comprehension in a function": "import os\nn = 'getenv'\ndef f():\n"
                                           "    [0 for n in ('getcwd',)]\n"
                                           "    return getattr(os, n)('HOME')\n",
            # A method does not see its class body's names.
            "class body loop": "import os\nn = 'getenv'\nclass C:\n"
                               "    for n in ('getcwd',):\n        pass\n"
                               "    def m(self):\n        return getattr(os, n)('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_ordinary_loops_stay_clean(self):
        self.assertClean({
            "dump fields": "def dump(o):\n    return {k: getattr(o, k) for k in ('code', 'name')}\n",
            "set fields": "class P:\n    def __init__(self, **kw):\n        for k in ('a', 'b'):\n"
                          "            setattr(self, k, kw.get(k))\n",
            "module functions": "import os\nprint([getattr(os, n) for n in ('getcwd', 'getpid')])\n",
        })


class ReadOnlyNames(FlaggedCase):
    def test_every_inspect_name_admitted_is_a_predicate(self):
        admitted = [n for n in dir(inspect) if READ_ONLY.match(f"inspect.{n}")]
        self.assertTrue(admitted)
        for n in admitted:
            with self.subTest(n):
                self.assertTrue(n.startswith("is"))
                self.assertIsInstance(getattr(inspect, n)(object), bool)

    def test_the_rest_of_inspect_is_flagged(self):
        self.assertFlagged({
            "getmodule": "import inspect\ninspect.getmodule(print)\n",
            "module stored": "import inspect\nm = inspect\n",
            "predicate's globals": "import inspect\ninspect.isclass.__globals__['sys']\n",
            "metadata's sys": "import importlib.metadata\n"
                              "importlib.metadata.sys.modules['os'].getenv('HOME')\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_importlib_metadata_loaders(self):
        # importlib.metadata imports import_module, and entry points load the
        # object they name.
        self.assertFlagged({
            "import_module": "import importlib.metadata\n"
                             "importlib.metadata.import_module('os').getenv('HOME')\n",
            "from-import": "from importlib.metadata import import_module\n"
                           "import_module('os').getenv('HOME')\n",
            "EntryPoint.load": "from importlib.metadata import EntryPoint\n"
                               "EntryPoint(name='x', value='os:getenv', group='g').load()('HOME')\n",
            "entry_points load": "import importlib.metadata as md\n"
                                 "for ep in md.entry_points(group='g'):\n    ep.load()\n",
        }, UNFOLLOWED_OR_SECRET)

    def test_read_only_uses_stay_clean(self):
        self.assertClean({
            "predicates as values": "import inspect\nchecks = [inspect.isclass, inspect.isfunction]\n",
            "version": "import importlib.metadata\nv = importlib.metadata.version('fastapi')\n",
        })


class InMemoryFiles(FlaggedCase):
    def test_in_memory_files_stay_clean(self):
        self.assertClean({
            "zip": "import io, zipfile\nzipfile.ZipFile(io.BytesIO(), 'w')\n",
            "csv": "import csv, io\nbuf = io.StringIO()\ncsv.writer(buf).writerow(['a'])\n",
            "workbook": "import io\nfrom openpyxl import Workbook\nbuf = io.BytesIO()\n"
                        "Workbook().save(buf)\n",
        })

    def test_an_in_memory_zip_that_touches_the_disk(self):
        self.assertFlagged({
            "extractall": "import io, zipfile\n"
                          "zipfile.ZipFile(io.BytesIO(b'')).extractall('/tmp/x')\n",
            "extract": "import io, zipfile\nz = zipfile.ZipFile(io.BytesIO(b''))\n"
                       "z.extract('a', '/tmp/x')\n",
            "write a disk file in": "import io, zipfile\nz = zipfile.ZipFile(io.BytesIO(), 'w')\n"
                                    "z.write('/etc/hostname')\n",
            "data folder zip extracted elsewhere": "import zipfile\n"
                                                   "from celerp.config import settings\n"
                                                   "zipfile.ZipFile(settings.data_dir / 'a.zip')"
                                                   ".extractall('/tmp/x')\n",
        }, FILES)


class OrdinaryIdiomsStayClean(FlaggedCase):
    def test_everyday_idioms(self):
        self.assertClean({
            "class attributes named like stdlib modules": "class Account:\n    code = ''\n"
                                                          "    signal = 0\n    inspect = None\n"
                                                          "a = Account()\n"
                                                          "print(a.code, Account.signal, a.inspect)\n",
            "enum members": "import enum\nclass Kind(enum.Enum):\n    code = 'code'\n"
                            "    os = 'os'\nprint(Kind.code.value, Kind['os'], Kind.os)\n",
            "sqlalchemy model": "from sqlalchemy import String, select, func, inspect\n"
                                "from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column\n"
                                "class Base(DeclarativeBase):\n    pass\n"
                                "class Thing(Base):\n    __tablename__ = 'thing'\n"
                                "    id: Mapped[int] = mapped_column(primary_key=True)\n"
                                "    code: Mapped[str] = mapped_column(String(20))\n"
                                "q = select(Thing).where(Thing.code == 'x')\n"
                                "n = select(func.count()).select_from(Thing)\n"
                                "cols = inspect(Thing).columns\n",
            "fastapi route": "from fastapi import APIRouter, HTTPException, Request, status\n"
                             "from fastapi.responses import JSONResponse\n"
                             "from fastapi.security.http import HTTPBearer\n"
                             "router = APIRouter(prefix='/x')\n@router.get('/')\n"
                             "async def idx(request: Request):\n"
                             "    if not request.query_params.get('q'):\n"
                             "        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)\n"
                             "    return JSONResponse({'ok': True})\n",
            "stdlib values": "import datetime, json, uuid\n"
                             "now = datetime.datetime.now(datetime.timezone.utc)\n"
                             "t = datetime.time(1, 2)\nd = json.dumps({'a': 1})\n"
                             "u = uuid.uuid4().hex\n",
        })

    def test_optional_import(self):
        # The module is the import or None; nothing is passed on.
        self.assertClean({
            "yaml or None": "try:\n    import yaml\nexcept ImportError:\n    yaml = None\n"
                            "def load(s):\n    return yaml.safe_load(s) if yaml else None\n",
        })


if __name__ == "__main__":
    unittest.main()
