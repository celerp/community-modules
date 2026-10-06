"""Static scan of a module's files, read as text. Nothing is imported or run.

`scan_folder` takes the module folder as {relative path: bytes} and reports what
the code does in five areas a listing must declare or the maintainer must see:
network calls, starting other programs, running code built at runtime, reading
environment secrets or credentials, and file access outside Celerp's data
folder. Files it cannot read as source or plain data are reported as well.

The manifest is read the same way: the code Celerp imports from it (routes, slot
handlers, migrations) must be the module's own package, and the files it reads
(locales) must be in the folder.

Python is read with `ast`, names are resolved through the file's own imports, so
`import os as o; o.system(...)` is seen as `os.system`. Browser code is read in
script, page and style sheet files and in the module's Python strings and bytes,
docstrings left out unless the file reads them back through `__doc__`. A web
address counts with a scheme (`https://host/...`). One without a scheme
(`//host/...`) counts when its host is an IPv6 address in brackets, or has a dot
or colon with more of the host after it; a single word such as `//name/` does
not. Text is read the way a browser reads an address. Escapes are decoded in the
language the text is written in (character references such as `&#46;` in markup,
`\\x2e` in script strings, `\\2e` in style sheet strings and `url()`, all three
in strings built in Python), then tab and newline characters are dropped (and,
separately, read as a space between two addresses), backslashes read as slashes,
look-alike characters folded, characters IDNA ignores dropped and
percent-encoding decoded as far as a browser decodes it, before the text is
matched. Letters a browser folds that are newer than the Unicode data of Python
3.12, which the checks run on, are listed by hand, so letters added in a later
Unicode version are not folded. An address or call built while the code runs is
not followed. Where the scan cannot follow a name (a module such as `os` stored
or passed as a value, an attribute name built at runtime) it reports that
instead, as it does code that changes names in modules Python, Celerp or its
libraries provide. It is a review aid, not a security boundary: it reports the
ordinary ways of doing these things, not every way Python can reach a name, and
a clean scan is not proof of what the code does. Test files are left out unless
the module's own code imports them.
"""
from __future__ import annotations

import ast
import html
import posixpath
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote


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
    "importlib.metadata", "inspect", "gc", "sys._current_frames",
    # Celerp code that imports whatever a string names, or registers it to be imported.
    "celerp.modules.slots.resolve_handler", "celerp.modules.slots.register",
    "celerp.modules.loader", "celerp.modules.importer", "celerp.modules.migrations_runner",
)
# Parts of those that only read package metadata or test what an object is. Entry
# points and the rest of inspect reach or load other code.
READ_ONLY = re.compile(r"^importlib\.metadata(\.(version|metadata|requires|packages_distributions|"
                       r"PackageNotFoundError))?$|^inspect(\.is[a-z]+)?$")
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
# Top-level packages Celerp itself provides.
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
# Files held in memory, never on disk.
IN_MEMORY = ("io.BytesIO", "io.StringIO")
# Archives, and their methods that read or write a path on disk: the position and
# keyword of that path. Without one they extract into the working folder.
ARCHIVES = ("zipfile.ZipFile", "tarfile.open", "tarfile.TarFile")
ARCHIVE_PATHS = {"extract": (1, "path"), "extractall": (0, "path"), "write": (0, "filename"),
                 "add": (0, "name")}
# Calls that keep a path inside the folder its first argument names.
PATH_KEEPERS = ("pathlib.Path", "pathlib.PurePath", "str", "os.fspath", "os.path.join")
PATH_JOINERS = ("pathlib.Path", "pathlib.PurePath", "os.path.join")
PATH_METHODS = ("resolve", "absolute", "joinpath", "with_suffix", "with_name", "as_posix")
BAD_SEGMENT = re.compile(r"(^|[/\\])\.\.([/\\]|$)|^[/\\]|^[A-Za-z]:|^~")
# An address without a scheme (//host/...) uses the page's own scheme to reach that
# host. Browsers skip extra slashes and a user name up to the last @. The host runs to
# the first space or / \ ? # ' " ` < > ( ), or the end. It is an address when it holds a
# letter or digit, and is an IPv6 address in [ ] (the only bracketed host a browser
# accepts) or has a . or : followed by something other than . , ; : ! ("//done." and
# "//TODO: x" are text). A host followed by ( is a call, as in "//console.log(x)", and
# "a // b" or a single word ("//intranet/") is not an address.
# The pattern reads plain ASCII; _readings turns other spellings into it.
USER_CHAR = r"[^\s/\\?#]"
HOST_CHAR = r"[^\s/\\?#'\"`<>()]"
NETWORK_PATH = (rf"(?<![\w:/.\\])//+"
                rf"(?:(?=(?P<user>{USER_CHAR}*@))(?P=user)|(?!{USER_CHAR}*@))"
                rf"(?=\[[0-9a-f:.]*:[0-9a-f:.]*\]|[^\s/\\?#'\"`<>().:]*[.:]{HOST_CHAR}*?"
                rf"[^\s/\\?#'\"`<>().,;:!])"
                rf"(?={HOST_CHAR}*?[^\W_])(?={HOST_CHAR}*(?!{HOST_CHAR}|\())")
URL = re.compile(rf"\b(?:https?|wss?|ftp)://|{NETWORK_PATH}", re.I)
# Characters a browser's URL parser drops or reads as another: tab and newline, the
# characters IDNA ignores in a host (soft hyphen, zero-width characters, variation
# selectors, Hangul fillers; from a Chromium scan of every code point), the ideographic
# full stop NFKC leaves as it is, a backslash, and letters and digits a browser folds that
# are newer than the Unicode data of the Python running the scan (outlined A-Z and 0-9).
LINE_BREAK = re.compile(r"[\t\n\r]")
IGNORED = re.compile("[\u00ad\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b\u2060-\u2064"
                     "\u206a-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\U0001bca0-\U0001bca3"
                     "\U0001d173-\U0001d17a\U000e0100-\U000e01ef]")
BROWSER_READS = str.maketrans({"\u3002": ".", "\\": "/", "\ua7f1": "s", **{
    chr(0x1ccd6 + i): c for i, c in enumerate("abcdefghijklmnopqrstuvwxyz0123456789")}})
# Escapes a language decodes before a browser reads an address written in it, read only
# inside the literals that can hold an address. Script strings and template literals:
# \xHH, \uHHHH, \u{H...}, \n and the other control letters, a backslash before a line
# break (dropped) and before any other character but a digit, x or u (that character).
# Style sheet strings and url(), whose name may itself be escaped: \ and 1 to 6 hex
# digits with one optional space after them, or \ before any other character (that
# character). Markup reads character references (&#46;, &period;) with the standard
# library.
QUOTED = r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\""
SCRIPT_LITERAL = re.compile(rf"{QUOTED}|`(?:[^`\\]|\\.)*`", re.S)
STYLE_LITERAL = re.compile(
    rf"{QUOTED}|((?:[\w-]|\\[0-9a-fA-F]{{1,6}}[ \t\n\r\f]?|\\.)+)\((?:[^)\\]|\\.)*\)", re.S)
SCRIPT_ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]+)\}"
                           r"|(\r\n|[^xu1-9]))")
SCRIPT_CONTROLS = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0",
                   "\n": "", "\r": "", "\r\n": "", "\u2028": "", "\u2029": ""}
STYLE_ESCAPE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})(?:\r\n|[ \t\n\r\f])?|([^\n\r\f0-9a-fA-F]))")

DATA_SUFFIXES = {
    ".md", ".txt", ".rst", ".json", ".toml", ".yaml", ".yml", ".cfg", ".ini", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".po", ".pot", ".mo",
    ".woff", ".woff2", ".ttf", ".otf", ".typed",
}
DATA_NAMES = {"license", "licence", "copying", "notice", "readme", "changelog", "authors",
              ".gitignore", ".gitkeep", ".gitattributes"}
# Manifest keys whose value Celerp imports as a module, and slot keys it imports
# as "module:function".
# Attributes that reach another frame's names, a function's globals or every class,
# and through them anything a module could import.
INTROSPECTION = {"f_globals", "f_builtins", "f_locals", "f_back", "gi_frame", "cr_frame",
                 "ag_frame", "tb_frame", "__globals__", "__builtins__", "__subclasses__",
                 "__dict__", "__getattribute__", "__getattr__"}
# Calls that take an attribute name; one built at runtime can reach any name.
NAMED_ATTRIBUTE = {"getattr": slice(1, 2), "operator.attrgetter": slice(None),
                   "operator.methodcaller": slice(0, 1)}
MANIFEST = "PLUGIN_MANIFEST"
ROUTE_KEYS = ("api_routes", "ui_routes")
HANDLER_KEYS = ("handler", "render")
SCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".html", ".htm", ".svg", ".css"}
JS_NETWORK = re.compile(r"\bfetch\s*\(|XMLHttpRequest|\bWebSocket\b|\bEventSource\b|"
                        rf"sendBeacon|(?i:\b(?:https?|wss?)://(?!www\.w3\.org/)|{NETWORK_PATH})")
JS_DYNAMIC = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bimport\s*\(")


def _matches(name: str, prefixes) -> bool:
    return any(name == p or name.startswith(p + ".") for p in prefixes)


def _is_test(path: PurePosixPath) -> bool:
    return (path.name == "conftest.py" or path.name.startswith("test_")
            or any(part in ("tests", "test") for part in path.parts[:-1]))


def _provided(top: str) -> bool:
    """A top-level module Python, Celerp or a library Celerp uses provides."""
    return top in sys.stdlib_module_names or _matches(top, CORE_PACKAGES) \
        or top in CELERP_LIBRARIES


def _reserved(top: str) -> bool:
    """A top-level name Python or Celerp already provides, or one Celerp reserves."""
    return _provided(top) or top.startswith("celerp")


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


def _variants(name: str) -> list[str]:
    """The name, and the standard modules it reaches through the imports of a
    module Python, Celerp or a library provides: logging.os.environ and
    ui.config.os.environ are os.environ."""
    parts = name.split(".")
    if not _provided(parts[0]):
        return [name]
    return [name, *(".".join(parts[i:]) for i in range(1, len(parts))
                    if parts[i] in sys.stdlib_module_names)]


# Modules and objects that hold a name the scan reports, such as os (os.system),
# and modules only part of which is read-only (inspect). Passed on as a value,
# what is later called through them cannot be followed.
REPORTED = (*NETWORK, *PROCESS, *DYNAMIC, *SECRETS, *FILE_CALLS, *HTTPX_CALLS)
HOLDERS = frozenset({*(".".join(n.split(".")[:i])
                       for n in REPORTED for i in range(1, n.count(".") + 1)),
                     *(n for n in DYNAMIC if READ_ONLY.match(n))})
UNFOLLOWED = "passed on as a value, so the scan cannot follow what is called through it"


def _names_tests(module: str) -> bool:
    return any(p in ("tests", "test", "conftest") or p.startswith("test_")
               for p in module.split("."))


# ── scopes: which names are imports, which are local values ──────────────────

class _Scope:
    def __init__(self, parent: "_Scope | None", kind: str = "function"):
        self.parent = parent
        # "function", "class" or "comprehension"
        self.kind = kind
        # a comprehension's first iterable, which runs in the scope around it
        self.first_iterable: ast.AST | None = None
        # name -> list of ("import", dotted), ("value", expr or None) or
        # ("item", the iterable a loop takes it from)
        self.binds: dict[str, list[tuple[str, object]]] = {}
        # names a global or nonlocal statement binds in another scope
        self.elsewhere: dict[str, _Scope] = {}

    def bind(self, name: str, kind: str, value) -> None:
        if name in self.elsewhere:
            self.elsewhere[name].bind(name, kind, value)
        else:
            self.binds.setdefault(name, []).append((kind, value))

    def declare(self, name: str, is_global: bool) -> None:
        """global/nonlocal: later bindings of the name belong to that scope."""
        target = self.parent
        if is_global:
            while target.parent is not None:
                target = target.parent
        else:
            while target.parent is not None and name not in target.binds:
                target = target.parent
        self.elsewhere[name] = target

    def lookup(self, name: str):
        """Python's lookup: a class body's names are not seen from the scopes in it."""
        scope = self
        while scope is not None:
            if name in scope.binds and (scope is self or scope.kind != "class"):
                return scope, scope.binds[name]
            scope = scope.parent
        return None, None


_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


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
        if child is scope.first_iterable or _outside(node, child):
            inner = scope.parent
        elif isinstance(child, _SCOPE_NODES):
            if not isinstance(child, ast.Lambda):
                scope.bind(child.name, "value", child)
            inner = _Scope(scope, "class" if isinstance(child, ast.ClassDef) else "function")
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
        elif isinstance(child, _COMPREHENSIONS):
            inner = _Scope(scope, "comprehension")
            inner.first_iterable = child.generators[0].iter
        elif isinstance(child, ast.NamedExpr):
            owner = scope
            while owner.kind == "comprehension":
                owner = owner.parent
            _bind_targets(child.target, owner, child.value)
        elif isinstance(child, (ast.For, ast.AsyncFor, ast.comprehension)):
            if isinstance(child.target, ast.Name):
                scope.bind(child.target.id, "item", child.iter)
            else:
                _bind_targets(child.target, scope, None)
        elif isinstance(child, ast.withitem) and child.optional_vars is not None:
            _bind_targets(child.optional_vars, scope, child.context_expr)
        elif isinstance(child, ast.ExceptHandler) and child.name:
            scope.bind(child.name, "value", None)
        elif isinstance(child, (ast.MatchAs, ast.MatchStar)) and child.name:
            scope.bind(child.name, "value", None)
        elif isinstance(child, ast.MatchMapping) and child.rest:
            scope.bind(child.rest, "value", None)
        elif isinstance(child, (ast.Global, ast.Nonlocal)) and scope.parent is not None:
            for name in child.names:
                scope.declare(name, isinstance(child, ast.Global))
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

    def candidates(self, node: ast.AST, scope: _Scope) -> list[str]:
        """Dotted names an expression can refer to: the one it resolves to, or one per
        import when its name is bound to imports and to other values."""
        name = self.resolve(node, scope)
        if name is not None:
            return [name]
        suffix = ""
        while isinstance(node, ast.Attribute):
            suffix = f".{node.attr}{suffix}"
            node = node.value
        if not isinstance(node, ast.Name):
            return []
        _, binds = scope.lookup(node.id)
        return sorted({f"{v}{suffix}" for k, v in binds or () if k == "import" and v})

    def attr_names(self, node: ast.AST, scope: _Scope) -> list[str] | None:
        """The attribute names an argument can hold: a literal, or a loop variable
        over literals. None when the name is built while the code runs."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            _, binds = scope.lookup(node.id)
            names = [_str_literals(v) if k == "item" else None for k, v in binds or ()]
            if names and None not in names:
                return [n for group in names for n in group]
        return None

    def got_names(self, node: ast.Call, scope: _Scope) -> list[str]:
        """Dotted names a getattr call can return, when its object resolves."""
        bases = self.candidates(node.args[0], scope) if node.args else []
        names = self.attr_names(node.args[1], scope) if len(node.args) >= 2 else None
        return [f"{b}.{n}" for b in bases for n in names or ()]

    def rooted(self, node: ast.AST, scope: _Scope, seen: frozenset = frozenset()) -> bool:
        """True when a path expression stays inside Celerp's data folder or in memory."""
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
            if self.resolve(node.func, scope) in IN_MEMORY:
                return True
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

    def archive(self, node: ast.AST, scope: _Scope, seen: frozenset = frozenset()) -> bool:
        """True when an expression can be a zip or tar archive object."""
        if isinstance(node, ast.Name):
            owner, binds = scope.lookup(node.id)
            if binds is None or (node.id, id(owner)) in seen:
                return False
            seen = seen | {(node.id, id(owner))}
            return any(k == "value" and v is not None and self.archive(v, owner, seen)
                       for k, v in binds)
        return isinstance(node, ast.Call) and _matches(self.resolve(node.func, scope) or "",
                                                       ARCHIVES)

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
        for n in _variants(name):
            if _matches(n, NETWORK):
                self.add("network", node, name)
            if _matches(n, PROCESS):
                self.add("process", node, name)
            if _matches(n, DYNAMIC) and not READ_ONLY.match(n):
                self.add("dynamic_code", node, name)
            if _matches(n, SECRETS):
                self.add("secrets", node, name)

    def check_value(self, name: str, node: ast.AST) -> None:
        """A name used as a value: stored, packed, passed, returned or a default."""
        for n in _variants(name):
            if n in HOLDERS:
                self.add("dynamic_code", node, f"{name} {UNFOLLOWED}")
            elif _matches(n, FILE_CALLS):
                self.add("files", node, f"{name} {UNFOLLOWED}")
            elif n in HTTPX_CALLS:
                self.add("network", node, f"{name} {UNFOLLOWED}")

    def _followed(self) -> set[int]:
        """Uses the scan follows: attribute reads, calls, type annotations, type checks
        and truth or identity tests."""
        ids: set[int] = set()
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Attribute):
                ids.add(id(n.value))
            elif isinstance(n, ast.Call):
                ids.add(id(n.func))
                scope = self.scopes.get(id(n), _Scope(None))
                name = self.resolve(n.func, scope)
                if name in ("isinstance", "issubclass"):
                    ids.update(id(x) for a in n.args[1:] for x in _type_nodes(a))
                elif name in ("getattr", "hasattr") and len(n.args) >= 2 and self.attr_names(
                        n.args[1], scope) is not None:
                    ids.add(id(n.args[0]))
            if isinstance(n, (ast.If, ast.IfExp, ast.While, ast.Assert)):
                ids.update(id(x) for x in _tested(n.test))
            elif isinstance(n, (ast.UnaryOp, ast.Compare)):
                ids.update(id(x) for x in _tested(n))
            annotations = []
            if isinstance(n, ast.arg):
                annotations.append(n.annotation)
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                annotations.append(n.returns)
            elif isinstance(n, ast.AnnAssign):
                annotations.append(n.annotation)
            for a in annotations:
                ids.update(id(x) for x in _type_nodes(a))
        return ids

    def scan(self) -> list[Finding]:
        # Docstrings are not code, unless the file reads them back through __doc__.
        reads_doc = any((isinstance(n, ast.Name) and n.id == "__doc__")
                        or (isinstance(n, ast.Attribute) and n.attr == "__doc__")
                        or (isinstance(n, ast.Constant) and n.value == "__doc__")
                        for n in ast.walk(self.tree))
        bare_strings = set() if reads_doc else {
            id(n.value) for n in ast.walk(self.tree)
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)}
        read_by_attribute = {id(n.value) for n in ast.walk(self.tree)
                             if isinstance(n, ast.Attribute)}
        followed = self._followed()
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
                    if alias.name == "*":
                        self.check_value(node.module, node)
            elif isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load):
                for name in self.candidates(node, scope):
                    if name in SETTINGS_OBJECTS and id(node) not in read_by_attribute:
                        self.add("secrets", node, f"{name} used as a whole")
                    if isinstance(node, ast.Attribute) or not _local_import(scope, node):
                        self.check_name(name, node)
                    if id(node) not in followed:
                        self.check_value(name, node)
            elif isinstance(node, ast.Attribute):
                self.check_store(node.value, node, scope)
            elif isinstance(node, ast.Call):
                self.check_call(node, scope)
                if id(node) not in followed:
                    for name in self.got_names(node, scope):
                        self.check_value(name, node)
            elif (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
                  and not self._safe_parts([node.right])):
                self.add("files", node, "a path that leaves its folder")
            elif (isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes))
                  and id(node) not in bare_strings):
                # Markup, script and style built in Python reach the browser like a page.
                text = node.value if isinstance(node.value, str) else _bytes_text(node.value)
                readings = _readings(text, PAGE_LANGUAGES)
                if any(map(URL.search, readings)):
                    self.add("network", node, "a web address in the code")
                elif any(map(JS_NETWORK.search, readings)):
                    self.add("network", node, "browser network call")
                if any(map(JS_DYNAMIC.search, readings)):
                    self.add("dynamic_code", node, "code built at runtime")
        return self.findings

    def check_store(self, obj: ast.AST, node: ast.AST, scope: _Scope) -> None:
        """An attribute set or deleted on obj."""
        names = self.candidates(obj, scope)
        for name in names:
            if _reserved(name.split(".")[0]):
                self.add("dynamic_code", node, f"changes a name in {name}, which other code uses")

    def check_call(self, node: ast.Call, scope: _Scope) -> None:
        if (isinstance(node.func, ast.Attribute) and node.func.attr in ARCHIVE_PATHS
                and self.archive(node.func.value, scope)):
            position, keyword = ARCHIVE_PATHS[node.func.attr]
            path = next((k.value for k in node.keywords if k.arg == keyword),
                        node.args[position] if len(node.args) > position else None)
            if path is None or not self.rooted(path, scope):
                self.add("files", node, f"an archive's {node.func.attr}")
        for name in self.candidates(node.func, scope):
            self._check_call(name, node, scope)

    def _check_call(self, name: str, node: ast.Call, scope: _Scope) -> None:
        if name != "getattr":
            self.check_name(name, node)
        for target in self.got_names(node, scope) if name == "getattr" else ():
            self.check_name(target, node)
        if name in ("setattr", "delattr") and node.args:
            self.check_store(node.args[0], node, scope)
        if name in PATH_JOINERS and not self._safe_parts(node.args[1:]):
            self.add("files", node, "a path that leaves its folder")
        if (isinstance(node.func, ast.Attribute) and node.func.attr in PATH_METHODS
                and not self._safe_parts(node.args)):
            self.add("files", node, "a path that leaves its folder")
        if name in NAMED_ATTRIBUTE:
            names = node.args[NAMED_ATTRIBUTE[name]]
            computed = not names or any(self.attr_names(a, scope) is None for a in names)
            if computed:
                self.add("dynamic_code", node, f"{name} with a computed name")
        if name in HTTPX_CALLS:
            self.add("network", node, name)
        if _matches(name, FILE_CALLS):
            args = [*node.args, *(k.value for k in node.keywords if k.arg in PATH_KWARGS)]
            if not args or not all(self.rooted(a, scope) for a in args[:1]) \
                    or not self._safe_parts(args[1:]):
                self.add("files", node, name)


def _str_literals(node) -> list[str] | None:
    """The strings of a literal tuple, list or set of strings."""
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)) and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
        return [e.value for e in node.elts]
    return None


def _tested(node):
    """A test's nodes whose value is only checked for truth or identity."""
    yield node
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            yield from _tested(value)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        yield from _tested(node.operand)
    elif isinstance(node, ast.Compare) and all(isinstance(o, (ast.Is, ast.IsNot))
                                               for o in node.ops):
        yield from (node.left, *node.comparators)


def _type_nodes(node):
    """An annotation's nodes that only name a type. A call, walrus or lambda in it
    runs when the annotation is evaluated, so it is scanned like other code."""
    if node is None:
        return
    yield node
    children = {ast.Subscript: ("value", "slice"), ast.BinOp: ("left", "right"),
                ast.Tuple: ("elts",), ast.List: ("elts",)}.get(type(node), ())
    for field in children:
        value = getattr(node, field)
        for child in value if isinstance(value, list) else [value]:
            yield from _type_nodes(child)


def _outside(node: ast.AST, child: ast.AST) -> bool:
    """A part of a function or class that runs in the scope around it: decorators,
    defaults, annotations and bases."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return not any(child is c for c in node.body)
    return isinstance(node, ast.Lambda) and child is not node.body


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


def _bytes_text(data: bytes) -> str:
    """Bytes as a page reads them: UTF-8, or one character per byte when not UTF-8."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _readings(text: str, languages: tuple) -> tuple[str, ...]:
    """Text as written, and each literal it holds (the text as one of its languages
    decodes it) as a browser reads the address in it.

    The text as written is matched too, as dropping a line break joins the last word of a
    line to the next one ("x\\nfetch(u)" reads "xfetch(u)").
    """
    literals = dict.fromkeys((text, *(decode(text) for decode in languages)))
    return (text, *(reading for literal in literals for reading in _as_browser_reads(literal)))


def _script_text(text: str) -> str:
    return SCRIPT_LITERAL.sub(lambda literal: SCRIPT_ESCAPE.sub(_script_char, literal[0]), text)


def _script_char(escape: re.Match[str]) -> str:
    if digits := escape[1] or escape[2] or escape[3]:
        return chr(int(digits, 16)) if int(digits, 16) < 0x110000 else escape[0]
    return SCRIPT_CONTROLS.get(escape[4], escape[4])


def _style_text(text: str) -> str:
    return STYLE_LITERAL.sub(_style_literal, text)


def _style_literal(literal: re.Match[str]) -> str:
    """A style string, or a function whose name reads "url", with its escapes read."""
    if literal[1] is not None and STYLE_ESCAPE.sub(_style_char, literal[1]).lower() != "url":
        return literal[0]
    return STYLE_ESCAPE.sub(_style_char, literal[0])


def _style_char(escape: re.Match[str]) -> str:
    if not escape[1]:
        return escape[2]
    code = int(escape[1], 16)
    return chr(code) if 0 < code < 0x110000 and not 0xd800 <= code < 0xe000 else "\ufffd"


# The languages each page file is written in; markup holds script and style too.
PAGE_LANGUAGES = (html.unescape, _script_text, _style_text)
FILE_LANGUAGES = {".js": (_script_text,), ".mjs": (_script_text,), ".cjs": (_script_text,),
                  ".css": (_style_text,)}


def _as_browser_reads(literal: str) -> tuple[str, str]:
    """A literal as a browser's URL parser reads it, with a line break dropped (inside one
    address: "ht\\ttps://") and read as a space (between two, as in a list of addresses).

    Chromium decodes %XX once and then maps the host as IDNA does (_fold). A % that mapping
    makes from a fullwidth or small percent sign is decoded once more ("%EF%BC%852e" reads
    "\uff052e", then "%2e", then "."). A % the first decode leaves ("%252e") and a third
    level are not decoded, as the browser rejects those hosts.
    """
    return tuple("%".join(_fold(unquote(_fold(part))) for part in unquote(text).split("%"))
                 for text in (LINE_BREAK.sub(gap, literal) for gap in ("", " ")))


def _fold(text: str) -> str:
    return IGNORED.sub("", unicodedata.normalize("NFKC", text)).translate(BROWSER_READS)


def _scan_script(path: str, data: bytes) -> list[Finding]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [Finding("unreadable", path, 1, "not UTF-8 text")]
    languages = FILE_LANGUAGES.get(PurePosixPath(path).suffix.lower(), PAGE_LANGUAGES)
    found = []
    for lineno, line in enumerate(text.splitlines(), 1):
        readings = _readings(line, languages)
        if any(map(JS_NETWORK.search, readings)):
            found.append(Finding("network", path, lineno, "browser network call"))
        if any(map(JS_DYNAMIC.search, readings)):
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
