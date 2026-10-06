"""Static scan of a module's files, read as text. Nothing is imported or run.

`scan_folder` takes the module folder as {relative path: bytes} and reports what
the code does in five areas a listing must declare or the maintainer must see:
network calls, starting other programs, running code built at runtime, reading
environment secrets or credentials, and file access outside Celerp's data
folder. Files it cannot read as source or plain data are reported as well.

The manifest is read the same way: the code Celerp imports from it (routes, slot
handlers, migrations) must be the module's own package, and the files it reads
(locales) must be in the folder.

Python is read with `ast`, names are resolved through the file's own imports,
so `import os as o; o.system(...)` is seen as `os.system`. Test files are left
out unless the module's own code imports them.
"""
from __future__ import annotations

import ast
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    line: int
    detail: str


# Plain-language name of each kind, as the listing comment shows it.
KINDS = {
    "network": "makes network calls",
    "process": "starts other programs",
    "dynamic_code": "runs code that is built or loaded while it runs",
    "secrets": "reads environment variables, credentials or Celerp's secret settings",
    "files": "reads or writes files outside Celerp's data folder",
    "unreadable": "contains files that cannot be checked as source code or plain data",
}

NETWORK = (
    "socket", "ssl", "http.client", "http.server", "urllib.request", "urllib3", "requests",
    "aiohttp", "websocket", "websockets", "ftplib", "smtplib", "aiosmtplib", "poplib",
    "imaplib", "telnetlib", "nntplib", "xmlrpc", "socketserver", "paramiko", "grpc",
    "pycurl", "dns", "boto3", "botocore", "webbrowser", "asyncio.open_connection",
    "asyncio.start_server", "asyncio.open_unix_connection", "asyncio.start_unix_server",
    # Celerp code that makes the call itself when a module calls it.
    "celerp.ai.llm", "celerp.ai.tools", "celerp.connectors", "celerp.gateway",
    "celerp.services.email", "celerp.services.outbound_url", "celerp.services.relay_share",
    "celerp.services.star_cta", "celerp.services.supporter_badge", "celerp.services.update",
    "celerp.services.backup_repo", "celerp.modules.license", "celerp.entitlement_preflight",
    "ui.marketplace_catalog",
)
HTTPX_CALLS = {f"httpx.{n}" for n in (
    "Client", "AsyncClient", "get", "post", "put", "patch", "delete", "head", "options",
    "request", "stream")}
# The only base_url a module may give an httpx client without it counting as a
# network call: Celerp's own API, which the UI layer calls for every page.
OWN_API = "ui.config.API_BASE"
PROCESS = (
    "subprocess", "multiprocessing", "pty", "signal", "os.system", "os.popen", "os.fork",
    "os.forkpty", "os.kill", "os.killpg", "os.startfile", "os.posix_spawn", "os.posix_spawnp",
    *(f"os.exec{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    *(f"os.spawn{s}" for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")),
    "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
    "concurrent.futures.ProcessPoolExecutor",
    # Celerp code that starts other programs itself when a module calls it.
    "celerp.cli", "celerp.embedded_pg", "celerp.services.backup", "celerp.services.backup_export",
    "celerp.services.backup_import", "celerp.services.update", "celerp.routers.system",
)
DYNAMIC = (
    "eval", "exec", "compile", "__import__", "globals", "locals", "vars", "breakpoint",
    "__builtins__", "builtins", "imp", "runpy", "ctypes", "cffi", "pickle", "cPickle",
    "marshal", "shelve", "dill", "code", "codeop", "types.FunctionType", "types.CodeType",
    "sys.modules", "sys._getframe", "yaml.load", "yaml.unsafe_load",
    "importlib.import_module", "importlib.util", "importlib.machinery", "importlib.reload",
    "importlib.__import__", "importlib.abc", "sys.path", "sys.path_hooks", "sys.meta_path",
    "sys.path_importer_cache", "site", "zipimport", "pkgutil", "__loader__", "__spec__",
    "inspect", "gc", "sys._current_frames",
    # Celerp code that imports whatever a string names, or registers it to be imported.
    "celerp.modules.slots.resolve_handler", "celerp.modules.slots.register",
    "celerp.modules.loader", "celerp.modules.importer", "celerp.modules.migrations_runner",
)
SECRETS = ("os.environ", "os.environb", "os.getenv", "os.getenvb", "os.putenv",
           "os.unsetenv", "getpass", "keyring", "netrc", "dotenv",
           "celerp.gateway.state", "celerp.connectors.relay_token")
SECRET_SETTING = re.compile(
    r"secret|password|passwd|token|key|credential|dsn|database_url|db_url|redis_url|jwt|"
    r"nonce|verifier|smtp_user|instance_id", re.I)
# Celerp's settings objects. A module may read a plain setting by name; the object
# itself, its secret settings and its dump methods count as reading secrets.
SETTINGS_OBJECTS = ("celerp.config.settings", "ui.config._settings")
SETTINGS_METHODS = re.compile(
    r"^(_|model_)|^(dict|json|copy|schema|schema_json|construct|parse_obj|parse_raw|"
    r"parse_file|from_orm|validate|fields)$")
# Everything else in celerp.config reads or writes Celerp's configuration file.
CONFIG_FILE = "celerp.config"
UI_CONFIG = "ui.config"
# Top-level packages Celerp itself provides; a module's code reached through them
# is checked as the standard module it names (ui.config.os.environ is os.environ).
CORE_PACKAGES = ("celerp", "ui")
# Top-level names of the libraries installed with Celerp, and of those its code
# imports when present. The module folder and the modules directory sit first on
# sys.path, so a module named like one of these would be what Celerp imports.
# Generated from celerp origin/main 19c83f23: packages_distributions() in a fresh
# venv of its dependencies and its prod extra, plus botocore, aiobotocore and tomli.
CELERP_LIBRARIES = frozenset({
    "PIL", "aiobotocore", "aiofiles", "aiosmtplib", "alembic", "annotated_doc",
    "annotated_types", "anyio", "asyncpg", "barcode", "bcrypt", "botocore", "bs4",
    "celerp_postgres", "certifi", "cffi", "charset_normalizer", "click", "cryptography",
    "dateutil", "default_modules", "deprecated", "dotenv", "ecdsa", "et_xmlfile",
    "fastapi", "fastcore", "fasthtml", "greenlet", "gunicorn", "h11", "httpcore",
    "httpcore2", "httptools", "httpx", "httpx2", "idna", "itsdangerous", "jose",
    "limits", "mako", "markupsafe", "multipart", "numpy", "oauthlib", "openpyxl",
    "opentelemetry", "packaging", "passlib", "psutil", "psycopg2", "pyasn1",
    "pycparser", "pydantic", "pydantic_core", "pydantic_settings", "pypdf",
    "python_multipart", "qrcode", "reportlab", "rsa", "six", "slowapi", "soupsieve",
    "sqlalchemy", "starlette", "tomli", "truststore", "typing_extensions",
    "typing_inspection", "tzdata", "uvicorn", "uvloop", "watchfiles", "websockets",
    "wrapt", "yaml"
})
FILE_CALLS = (
    "open", "io.open", "os.open", "os.remove", "os.unlink", "os.rename", "os.renames",
    "os.replace", "os.rmdir", "os.removedirs", "os.mkdir", "os.makedirs", "os.listdir",
    "os.scandir", "os.walk", "os.chmod", "os.chown", "os.link", "os.symlink", "os.truncate",
    "os.utime", "os.chdir", "os.path.expanduser", "os.path.expandvars", "shutil", "tempfile",
    "glob", "fileinput", "aiofiles", "sqlite3.connect", "zipfile.ZipFile", "tarfile.open",
    "pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath",
    "starlette.responses.FileResponse", "fastapi.responses.FileResponse",
    "fastapi.FileResponse",
)
PATH_KWARGS = ("path", "file", "filename", "src", "dst")
DATA_DIR = "celerp.config.settings.data_dir"
# Calls that keep a path inside the folder its first argument names.
PATH_KEEPERS = ("pathlib.Path", "pathlib.PurePath", "str", "os.fspath", "os.path.join")
PATH_JOINERS = ("pathlib.Path", "pathlib.PurePath", "os.path.join")
PATH_METHODS = ("resolve", "absolute", "joinpath", "with_suffix", "with_name", "as_posix")
BAD_SEGMENT = re.compile(r"(^|[/\\])\.\.([/\\]|$)|^[/\\]|^[A-Za-z]:|^~")
URL = re.compile(r"\b(?:https?|wss?|ftp)://", re.I)

DATA_SUFFIXES = {
    ".md", ".txt", ".rst", ".json", ".toml", ".yaml", ".yml", ".cfg", ".ini", ".csv",
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".po", ".pot", ".mo",
    ".woff", ".woff2", ".ttf", ".otf", ".typed",
}
DATA_NAMES = {"license", "licence", "copying", "notice", "readme", "changelog", "authors",
              ".gitignore", ".gitkeep", ".gitattributes"}
# Manifest keys whose value Celerp imports as a module, and slot keys it imports
# as "module:function".
# Attributes that reach another frame's names, a function's globals or every class,
# and through them anything a module could import.
INTROSPECTION = {"f_globals", "f_builtins", "f_locals", "f_back", "gi_frame", "cr_frame",
                 "ag_frame", "tb_frame", "__globals__", "__builtins__", "__subclasses__"}
MANIFEST = "PLUGIN_MANIFEST"
ROUTE_KEYS = ("api_routes", "ui_routes")
HANDLER_KEYS = ("handler", "render")
SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".html", ".htm", ".svg"}
JS_NETWORK = re.compile(r"\bfetch\s*\(|XMLHttpRequest|\bWebSocket\b|\bEventSource\b|"
                        r"sendBeacon|\b(?:https?|wss?)://(?!www\.w3\.org/)")
JS_DYNAMIC = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bimport\s*\(")


def _matches(name: str, prefixes) -> bool:
    return any(name == p or name.startswith(p + ".") for p in prefixes)


def _is_test(path: PurePosixPath) -> bool:
    return (path.name == "conftest.py" or path.name.startswith("test_")
            or any(part in ("tests", "test") for part in path.parts[:-1]))


def _reserved(top: str) -> bool:
    """A top-level name Python or Celerp already provides."""
    return top in sys.stdlib_module_names or _matches(top, CORE_PACKAGES) \
        or top.startswith("celerp") or top in CELERP_LIBRARIES


PROVIDED = "a name Python, Celerp or a library Celerp uses already provides"


def _secret_config(name: str) -> bool:
    for obj in SETTINGS_OBJECTS:
        if name == obj:
            return False  # judged where it is used, see _File.scan
        if name.startswith(obj + "."):
            attr = name[len(obj) + 1:].split(".")[0]
            return bool(SECRET_SETTING.search(attr) or SETTINGS_METHODS.search(attr))
    if name.startswith(CONFIG_FILE + "."):
        return True
    return name.startswith(UI_CONFIG + ".") and bool(SECRET_SETTING.search(name.split(".")[-1]))


def _names_tests(module: str) -> bool:
    return any(p in ("tests", "test", "conftest") or p.startswith("test_")
               for p in module.split("."))


# ── scopes: which names are imports, which are local values ──────────────────

class _Scope:
    def __init__(self, parent: "_Scope | None"):
        self.parent = parent
        # name -> list of ("import", dotted) or ("value", expr or None)
        self.binds: dict[str, list[tuple[str, object]]] = {}

    def bind(self, name: str, kind: str, value) -> None:
        self.binds.setdefault(name, []).append((kind, value))

    def lookup(self, name: str):
        scope = self
        while scope is not None:
            if name in scope.binds:
                return scope, scope.binds[name]
            scope = scope.parent
        return None, None


_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)


def _bind_targets(target: ast.AST, scope: _Scope, value) -> None:
    if isinstance(target, ast.Name):
        scope.bind(target.id, "value", value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for t in target.elts:
            _bind_targets(t, scope, None)
    elif isinstance(target, ast.Starred):
        _bind_targets(target.value, scope, None)


def _collect(node: ast.AST, scope: _Scope, scopes: dict[int, _Scope]) -> None:
    """First pass: record every binding in the scope that owns it."""
    scopes[id(node)] = scope
    for child in ast.iter_child_nodes(node):
        inner = scope
        if isinstance(child, _SCOPE_NODES):
            if not isinstance(child, ast.Lambda):
                scope.bind(child.name, "value", None)
            inner = _Scope(scope)
            if not isinstance(child, ast.ClassDef):
                a = child.args
                for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs, a.vararg, a.kwarg):
                    if arg is not None:
                        inner.bind(arg.arg, "value", None)
        elif isinstance(child, (ast.Import, ast.ImportFrom)):
            for alias in child.names:
                if isinstance(child, ast.Import):
                    local = alias.asname or alias.name.split(".")[0]
                    dotted = alias.name if alias.asname else alias.name.split(".")[0]
                    scope.bind(local, "import", dotted)
                elif alias.name != "*":
                    base = ("." * child.level) + (child.module or "")
                    scope.bind(alias.asname or alias.name, "import",
                               f"{base}.{alias.name}" if child.level == 0 else None)
        elif isinstance(child, ast.Assign):
            for t in child.targets:
                _bind_targets(t, scope, child.value if isinstance(t, ast.Name) else None)
        elif isinstance(child, ast.AnnAssign) and child.value is not None:
            _bind_targets(child.target, scope, child.value)
        elif isinstance(child, ast.AugAssign):
            _bind_targets(child.target, scope, None)
        elif isinstance(child, ast.NamedExpr):
            _bind_targets(child.target, scope, child.value)
        elif isinstance(child, (ast.For, ast.AsyncFor, ast.comprehension)):
            _bind_targets(child.target, scope, None)
        elif isinstance(child, ast.withitem) and child.optional_vars is not None:
            _bind_targets(child.optional_vars, scope, None)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            scope.bind(child.name, "value", None)
        elif isinstance(child, (ast.Global, ast.Nonlocal)):
            for name in child.names:
                scope.bind(name, "value", None)
        _collect(child, inner, scopes)


class _File:
    def __init__(self, path: str, tree: ast.Module):
        self.path = path
        self.scopes: dict[int, _Scope] = {}
        _collect(tree, _Scope(None), self.scopes)
        self.tree = tree
        self.findings: list[Finding] = []
        # Celerp uses the manifest object __init__.py ends up with; only its literal is read.
        node = manifest_node(tree) if path == "__init__.py" else None
        self.manifest_literal = {id(t) for t in node.targets} if node is not None else set()

    def resolve(self, node: ast.AST, scope: _Scope) -> str | None:
        """Dotted name an expression refers to through imports, or None."""
        if isinstance(node, ast.Name):
            _, binds = scope.lookup(node.id)
            if binds is None:
                return node.id  # a builtin
            if all(k == "import" for k, _ in binds) and len({v for _, v in binds}) == 1:
                return binds[0][1]
            return None
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value, scope)
            return f"{base}.{node.attr}" if base else None
        if (isinstance(node, ast.Call) and self.resolve(node.func, scope) == "getattr"
                and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            base = self.resolve(node.args[0], scope)
            return f"{base}.{node.args[1].value}" if base else None
        return None

    def rooted(self, node: ast.AST, scope: _Scope, seen: frozenset = frozenset()) -> bool:
        """True when a path expression stays inside Celerp's data folder."""
        if isinstance(node, ast.Name):
            owner, binds = scope.lookup(node.id)
            if binds is None or (node.id, id(owner)) in seen:
                return False
            seen = seen | {(node.id, id(owner))}
            return all(k == "value" and v is not None and self.rooted(v, owner, seen)
                       for k, v in binds)
        if self.resolve(node, scope) == DATA_DIR:
            return True
        if isinstance(node, ast.Call):
            if self.resolve(node.func, scope) in PATH_KEEPERS:
                return bool(node.args) and self.rooted(node.args[0], scope, seen) and \
                    self._safe_parts(node.args[1:])
            if (isinstance(node.func, ast.Attribute) and node.func.attr in PATH_METHODS):
                return self.rooted(node.func.value, scope, seen) and self._safe_parts(node.args)
            return False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self.rooted(node.left, scope, seen) and self._safe_parts([node.right])
        if isinstance(node, ast.JoinedStr) and node.values:
            first = node.values[0]
            return (isinstance(first, ast.FormattedValue)
                    and self.rooted(first.value, scope, seen)
                    and self._safe_parts(node.values[1:]))
        return False

    @staticmethod
    def _safe_parts(parts) -> bool:
        """No literal path part that leaves the folder or starts a new root."""
        def literals(node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                yield node.value
            elif isinstance(node, ast.JoinedStr):
                for v in node.values:
                    yield from literals(v)
            elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
                yield from literals(node.left)
                yield from literals(node.right)
        for part in parts:
            if isinstance(part, ast.Starred):
                return False
            if any(BAD_SEGMENT.search(text) for text in literals(part)):
                return False
        return True

    def add(self, kind: str, node: ast.AST, detail: str) -> None:
        self.findings.append(Finding(kind, self.path, getattr(node, "lineno", 1), detail))

    def check_name(self, name: str, node: ast.AST) -> None:
        if _secret_config(name):
            self.add("secrets", node, name)
        parts = name.split(".")
        names = [name]
        if _matches(name, CORE_PACKAGES):
            names += [".".join(parts[i:]) for i in range(1, len(parts))
                      if parts[i] in sys.stdlib_module_names]
        for n in names:
            if _matches(n, NETWORK):
                self.add("network", node, name)
            if _matches(n, PROCESS):
                self.add("process", node, name)
            if _matches(n, DYNAMIC) and not n.startswith("importlib.metadata"):
                self.add("dynamic_code", node, name)
            if _matches(n, SECRETS):
                self.add("secrets", node, name)

    def scan(self) -> list[Finding]:
        bare_strings = {id(n.value) for n in ast.walk(self.tree)
                        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        read_by_attribute = {id(n.value) for n in ast.walk(self.tree)
                             if isinstance(n, ast.Attribute)}
        for node in ast.walk(self.tree):
            if ((isinstance(node, ast.Name) and node.id == MANIFEST
                 and id(node) not in self.manifest_literal)
                    or (isinstance(node, ast.Attribute) and node.attr == MANIFEST)
                    or (isinstance(node, ast.Constant) and node.value == MANIFEST)):
                self.add("dynamic_code", node, f"{MANIFEST} used outside its literal")
            if ((isinstance(node, ast.Attribute) and node.attr in INTROSPECTION)
                    or (isinstance(node, ast.Constant) and node.value in INTROSPECTION)):
                self.add("dynamic_code", node, "reaches other code's names")
            scope = self.scopes.get(id(node))
            if scope is None:
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.check_name(alias.name, node)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                for alias in node.names:
                    self.check_name(node.module if alias.name == "*"
                                    else f"{node.module}.{alias.name}", node)
            elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                name = self.resolve(node, scope)
                if name in SETTINGS_OBJECTS and id(node) not in read_by_attribute:
                    self.add("secrets", node, f"{name} used as a whole")
                if name and (isinstance(node, ast.Attribute) or not _local_import(scope, node)):
                    self.check_name(name, node)
            elif isinstance(node, ast.Call):
                self.check_call(node, scope)
            elif (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                  and not self._safe_parts([node.right])):
                self.add("files", node, "a path that leaves its folder")
            elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
                  and id(node) not in bare_strings and URL.search(node.value)):
                self.add("network", node, "a web address in the code")
        return self.findings

    def check_call(self, node: ast.Call, scope: _Scope) -> None:
        name = self.resolve(node.func, scope)
        if name is None:
            return
        if name != "getattr":
            self.check_name(name, node)
        elif (target := self.resolve(node, scope)) is not None:
            self.check_name(target, node)
        if name in PATH_JOINERS and not self._safe_parts(node.args[1:]):
            self.add("files", node, "a path that leaves its folder")
        if (isinstance(node.func, ast.Attribute) and node.func.attr in PATH_METHODS
                and not self._safe_parts(node.args)):
            self.add("files", node, "a path that leaves its folder")
        if name == "getattr" and len(node.args) >= 2 and not (
                isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
            if self.resolve(node.args[0], scope) is not None:
                self.add("dynamic_code", node, "getattr with a computed name")
        if name in HTTPX_CALLS:
            base = next((k.value for k in node.keywords if k.arg == "base_url"), None)
            own = (name in ("httpx.Client", "httpx.AsyncClient") and base is not None
                   and self.resolve(base, scope) == OWN_API)
            if not own:
                self.add("network", node, name)
        if _matches(name, FILE_CALLS):
            args = [*node.args, *(k.value for k in node.keywords if k.arg in PATH_KWARGS)]
            if not args or not all(self.rooted(a, scope) for a in args[:1]) \
                    or not self._safe_parts(args[1:]):
                self.add("files", node, name)


def _local_import(scope: _Scope, node: ast.AST) -> bool:
    """A bare Name bound by an import is reported at the import, not per use."""
    _, binds = scope.lookup(node.id)
    return binds is not None


def manifest_node(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "PLUGIN_MANIFEST" for t in node.targets):
            return node
    return None


def read_manifest(data: bytes) -> dict | None:
    """PLUGIN_MANIFEST as plain values, decoded the way Celerp's importer decodes it."""
    try:
        node = manifest_node(ast.parse(data.decode("utf-8", errors="replace")))
        value = ast.literal_eval(node.value) if node is not None else None
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _handlers(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in HANDLER_KEYS and isinstance(item, str):
                yield key, item
            else:
                yield from _handlers(item)
    elif isinstance(value, list):
        for item in value:
            yield from _handlers(item)


def _own_code(dotted: str, files: dict[str, bytes], name: object, package: bool) -> bool:
    """True when a dotted name Celerp imports is a file of the module's own package."""
    parts = dotted.split(".")
    if not all(p.isidentifier() for p in parts) or _reserved(parts[0]):
        return False
    if package:  # the migrations runner joins every part onto the module folder
        return any(p.startswith("/".join(parts) + "/") for p in files)
    stems = []
    if f"{parts[0]}/__init__.py" in files:
        stems.append("/".join(parts))
    if parts[0] == name:  # the module folder is itself the package
        stems.append("/".join(parts[1:]))
    return any(f"{s}.py" in files or posixpath.join(s, "__init__.py") in files
               for s in stems)


def _manifest_findings(files: dict[str, bytes]) -> list[Finding]:
    """What the manifest makes Celerp import or read must be inside the folder."""
    manifest = read_manifest(files.get("__init__.py", b""))
    if manifest is None:
        return []
    tree = ast.parse(files["__init__.py"].decode("utf-8", errors="replace"))
    lines = {n.value: n.lineno for n in ast.walk(manifest_node(tree))
             if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    name = manifest.get("name")
    found, own = [], set()

    def check(key: str, dotted, package: bool = False) -> None:
        if isinstance(dotted, str) and _own_code(dotted, files, name, package):
            own.add(dotted.split(".")[0])
        elif isinstance(dotted, str) and _reserved(dotted.split(".")[0]):
            found.append(Finding("dynamic_code", "__init__.py", lines.get(dotted, 1),
                                 f"manifest {key} {dotted!r} is named like "
                                 f"{dotted.split('.')[0]!r}, {PROVIDED}"))
        elif dotted:
            found.append(Finding("dynamic_code", "__init__.py", lines.get(dotted, 1),
                                 f"manifest {key} {dotted!r} is not the module's own code"))

    if isinstance(name, str) and _reserved(name):
        found.append(Finding("dynamic_code", "__init__.py", lines.get(name, 1),
                             f"the module folder is importable as {name!r}, {PROVIDED}"))

    for key in ROUTE_KEYS:
        check(key, manifest.get(key))
    check("migrations", manifest.get("migrations"), package=True)
    for key, ref in _handlers(manifest.get("slots")):
        check(key, ref.split(":", 1)[0])
    locales = manifest.get("locales")
    for entry in (locales.values() if isinstance(locales, dict) else ()):
        path = entry.get("file") if isinstance(entry, dict) else None
        if isinstance(path, str) and posixpath.normpath(path) not in files:
            found.append(Finding("files", "__init__.py", lines.get(path, 1),
                                 f"locale file {path!r} is not in the module folder"))
    for p in files:
        pp = PurePosixPath(p)
        if _is_test(pp):
            continue
        if len(pp.parts) == 1 and pp.suffix == ".py" and pp.name != "__init__.py":
            top = pp.stem
        elif len(pp.parts) == 2 and pp.name == "__init__.py":
            top = pp.parts[0]
        else:
            continue
        if top not in own:
            found.append(Finding("dynamic_code", p, 1, f"importable as {top!r}, which the "
                                 "manifest does not name as the module's own package"))
    return found


def _scan_python(path: str, data: bytes) -> list[Finding]:
    try:
        tree = ast.parse(data.decode("utf-8"), filename=path)
    except (UnicodeDecodeError, SyntaxError, ValueError):
        return [Finding("unreadable", path, 1, "Python that does not parse")]
    return _File(path, tree).scan()


def _scan_script(path: str, data: bytes) -> list[Finding]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding("unreadable", path, 1, "not UTF-8 text")]
    found = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if JS_NETWORK.search(line):
            found.append(Finding("network", path, lineno, "browser network call"))
        if JS_DYNAMIC.search(line):
            found.append(Finding("dynamic_code", path, lineno, "code built at runtime"))
    return found


def _imports_tests(path: str, data: bytes) -> bool:
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError, ValueError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(_names_tests(a.name) for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (
                _names_tests(node.module or "") or any(_names_tests(a.name) for a in node.names)):
            return True
    return False


def scan_folder(files: dict[str, bytes]) -> list[Finding]:
    """Findings for a module folder, one per kind per file line."""
    paths = {p: PurePosixPath(p) for p in files}
    skip_tests = not any(
        _imports_tests(p, files[p]) for p, pp in paths.items()
        if pp.suffix == ".py" and not _is_test(pp))
    findings = _manifest_findings(files)
    for p, pp in sorted(paths.items()):
        if skip_tests and _is_test(pp):
            continue
        suffix = pp.suffix.lower()
        if suffix == ".py":
            findings += _scan_python(p, files[p])
        elif suffix in SCRIPT_SUFFIXES:
            findings += _scan_script(p, files[p])
        elif suffix not in DATA_SUFFIXES and pp.name.lower() not in DATA_NAMES:
            findings.append(Finding("unreadable", p, 1, "not source code or plain data"))
    unique: dict[tuple, Finding] = {}
    for f in findings:
        unique.setdefault((f.kind, f.path, f.line), f)
    return list(unique.values())
