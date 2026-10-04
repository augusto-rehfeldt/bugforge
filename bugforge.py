"""bugforge: find real bugs in Python libraries by falsifying documented properties.

mathforge's premise moved to software: a model's claim that code is wrong is worth
nothing; a script that reproduces the failure is worth something. One model reads a
module's API and source and proposes properties its documentation promises; a
second, rewarded for breaking them, writes a randomized search; a different model
writes a minimal standalone reproducer from the witness and runs it; a judge reads
the reproducer's output, the documentation and the project's existing issues and
decides BUG, DOC_BUG, DUPLICATE or NOT_A_BUG.

    python bugforge.py fractions               # one module
    python bugforge.py --auto 5 --workers 3    # the five least-hunted stdlib modules
    python bugforge.py --forever --workers 3

Nothing is filed unless asked. A confirmed bug gets a drafted issue in report.md for a
person to check and file: maintainers are already flooded with AI reports, and
every one sent should be one a person stands behind. `--file` files a published
result upstream unread, says so in the issue, and files no other in that project
while it is open.

Generated scripts run unsandboxed in the run directory (as in mathforge), so
modules that touch files, processes, the network or deserialization are refused.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import functools
import importlib
import importlib.metadata
import importlib.util
import inspect
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATHFORGE = Path(os.getenv("MATHFORGE_DIR") or HERE.parent / "mathforge")
sys.path.insert(0, str(MATHFORGE))
import mathforge as mf  # noqa: E402

OUTPUT_ROOT = Path(os.getenv("BUGFORGE_OUTPUT") or HERE / "bug_output")


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ImportError:  # the parent package is missing
        return False


# pure-computation stdlib modules with precise documentation: a promise to test, no side effects
AUTO_TARGETS = tuple(m for m in (
    "fractions", "decimal", "statistics", "difflib", "textwrap", "ipaddress", "json", "colorsys", "calendar",
    "datetime", "urllib.parse", "shlex", "base64", "html", "html.parser", "string", "email.utils",
    "email.headerregistry", "configparser", "csv", "heapq", "bisect", "itertools", "math", "cmath", "random",
    "unicodedata", "zlib", "graphlib", "tomllib", "fnmatch", "reprlib", "pprint", "plistlib", "quopri", "wave",
    "struct", "operator",
    # popular PyPI packages of the same kind: parsing and arithmetic, no files, processes or network
    "packaging.version", "packaging.specifiers", "packaging.utils", "idna", "dateutil.parser",
    "dateutil.relativedelta", "dateutil.rrule", "markupsafe", "more_itertools", "sortedcontainers", "isodate",
    "wcwidth", "tabulate", "yarl") if _installed(m))  # a module not in this Python is no target
# fuzzing these could delete files, start processes, talk to the network or run code
DENIED = ("os", "shutil", "subprocess", "socket", "tempfile", "signal", "multiprocessing", "ctypes",
          "urllib.request", "http", "ftplib", "smtplib", "poplib", "imaplib", "asyncio", "webbrowser", "ssl",
          "sqlite3", "pathlib", "glob", "zipfile", "tarfile", "dbm", "shelve", "pty", "winreg", "msvcrt", "sys",
          "builtins", "importlib", "pickle", "marshal", "code", "runpy", "threading", "concurrent", "io",
          "logging", "mmap", "select", "selectors", "venv", "ensurepip", "site", "sysconfig", "gc", "atexit")
GITHUB_SEARCH = "https://api.github.com/search/issues?"
RESULTS_REPO = os.getenv("BUGFORGE_RESULTS_REPO", "bugforge-results")  # `name` or `owner/name`
RESULTS_CHECKOUT = Path(os.getenv("BUGFORGE_RESULTS_DIR") or Path.home() / "bugforge-results")
PUBLISH_STATUSES = ("bug", "doc-bug")
BUGFORGE_URL = "https://github.com/augusto-rehfeldt/bugforge"
_REPO_LOCK = threading.Lock()


def check_target(module: str, unsafe: bool = False) -> None:
    """AUTO_TARGETS only: importing a module runs it (`antigravity` opens a browser), and a
    denylist cannot name every private or platform module that starts processes."""
    if any(module == d or module.startswith(d + ".") for d in DENIED):
        raise ValueError(f"{module}: refused, its functions have side effects outside the run directory")
    if not unsafe and module not in AUTO_TARGETS:
        raise ValueError(f"{module}: not a vetted target; pass --unsafe-target once you know importing and "
                         "calling it touches no files, processes or network")


def one_per_target(props: list) -> list:
    """Independent proposers converge on the same function; one hunt per target is enough."""
    seen, kept = set(), []
    for c in props:
        if c.get("target") not in seen:
            seen.add(c.get("target"))
            kept.append(c)
    return kept


def earlier_properties(module: str, current: Path) -> list:
    """Properties hunted in this module's earlier runs, so a new run does not repeat them."""
    found = []
    for state in sorted(OUTPUT_ROOT.glob(f"{module}-*/state.json")):
        if state.parent.resolve() != current.resolve():
            try:
                data = json.loads(state.read_text(encoding="utf-8"))
            except (OSError, ValueError):  # a damaged old run must not stop new ones
                continue
            if not isinstance(data, dict):
                continue
            found += [f"{r.get('target', '')}: {r.get('statement', '')}"[:200] for r in data.get("results") or []]
    return found[-30:]


_GITHUB_LOCK = threading.Lock()
_GITHUB_LAST = [0.0]


@functools.lru_cache(maxsize=1)
def _gh_token() -> str:
    """The gh CLI's own login, for when GITHUB_TOKEN is unset; empty when gh is missing or logged out."""
    if not shutil.which("gh"):
        return ""
    try:
        return mf._gh("gh", "auth", "token", timeout=15).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def github(url: str) -> dict:
    """GitHub search, spaced under its per-minute limit across threads, one retry on a limit reply.

    ponytail: spacing is per process; two bugforge processes at once can still hit the limit.
    """
    headers = {"User-Agent": mf.USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.getenv("GITHUB_TOKEN") or _gh_token()
    if token:  # 30 searches a minute instead of 10; sent only to api.github.com
        headers["Authorization"] = f"Bearer {token}"
    gap = 2.0 if token else 6.0
    for attempt in range(2):
        with _GITHUB_LOCK:
            time.sleep(max(0.0, _GITHUB_LAST[0] + gap - time.time()))
            _GITHUB_LAST[0] = time.time()
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
                    return json.loads(response.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as exc:
                reply = exc.headers or {}
                limited = exc.code == 429 or reply.get("Retry-After") or reply.get("X-RateLimit-Remaining") == "0"
                if not limited or attempt:  # a 403 for a bad token is not waited out
                    raise
                wait = reply.get("Retry-After", "")
                time.sleep(min(int(wait), 120) if str(wait).isdigit() else 60)


def _names(module: str) -> list:
    mod = importlib.import_module(module)
    names = getattr(mod, "__all__", None) or [n for n in dir(mod) if not n.startswith("_")]
    out = []
    for n in names:
        obj = getattr(mod, n, None)
        if not callable(obj) or inspect.ismodule(obj):
            continue
        out.append(n)
        if inspect.isclass(obj):  # `fractions` is one class: its methods are what to divide up
            out += [f"{n}.{a}" for a in vars(obj) if not a.startswith("_") and callable(getattr(obj, a, None))]
    return out


def api(module: str, limit: int = 12000) -> str:
    """Public callables and their signatures: what a proposer needs to pick a target."""
    mod = importlib.import_module(module)
    names = getattr(mod, "__all__", None) or [n for n in dir(mod) if not n.startswith("_")]
    lines = []
    for name in names:
        obj = getattr(mod, name, None)
        if inspect.ismodule(obj) or not callable(obj):
            continue
        lines.append(f"{name}{_sig(obj)}  -- {_doc(obj)}")
        if inspect.isclass(obj):
            for attr, member in vars(obj).items():
                if not attr.startswith("_") and callable(member):
                    lines.append(f"    .{attr}{_sig(member)}  -- {_doc(member)}")
    return "\n".join(lines)[:limit]


def _sig(obj) -> str:
    try:
        return str(inspect.signature(obj))
    except (TypeError, ValueError):
        return "(...)"


def _doc(obj) -> str:
    return (inspect.getdoc(obj) or "").split("\n", 1)[0][:120]


def source(module: str, limit: int = 30000) -> str:
    try:
        return inspect.getsource(importlib.import_module(module))[:limit]
    except (OSError, TypeError):
        return "(no Python source: a compiled module)"


CPYTHON_MAIN = "https://raw.githubusercontent.com/python/cpython/main/Lib/"
SHIM_CHARS = 3000  # module source shorter than this holds no implementation


def main_diff(module: str, limit: int = 40000) -> str:
    """How CPython's main branch differs from the installed stdlib module: a bug already
    fixed upstream is not worth a search, a reproducer or a report."""
    if module.split(".")[0] not in sys.stdlib_module_names:
        return ""
    try:
        mod = importlib.import_module(module)
        local = inspect.getsource(mod)
    except (OSError, TypeError):
        return "(compiled module: no Python source to compare with main)"
    if len(local) < SHIM_CHARS:
        # `datetime`, `struct`, `tomllib`: a few lines re-exporting the real code, and "identical" there
        # told both judges the implementation matched main
        return "(a shim over another module: the implementation was not compared with main)"
    note = "\n(a package: only its __init__.py was compared)" if hasattr(mod, "__path__") else ""
    path = module.replace(".", "/")
    upstream, errors = None, []
    for name in (f"{path}.py", f"{path}/__init__.py"):
        try:
            upstream = mf._http_get(CPYTHON_MAIN + name)
            break
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}")
    if upstream is None:
        return f"(could not fetch main: {'; '.join(errors)})"
    diff = "".join(difflib.unified_diff(local.splitlines(True), upstream.splitlines(True),
                                        "installed", "main", n=2))
    if len(diff) > limit:
        return diff[:limit] + "\n(diff truncated)"
    return (diff or "(identical to main)") + note


def _dist(module: str) -> str:
    """The PyPI distribution that ships `module`: `dateutil` comes from python-dateutil."""
    top = module.split(".")[0]
    return (importlib.metadata.packages_distributions().get(top) or [top])[0]


def environment(module: str) -> str:
    top = module.split(".")[0]
    if top in sys.stdlib_module_names:
        return f"Python {platform.python_version()} ({platform.platform()}), standard library `{module}`"
    try:
        version = importlib.metadata.version(_dist(module))
    except importlib.metadata.PackageNotFoundError:
        version = "unknown version"
    return f"Python {platform.python_version()} ({platform.platform()}), `{top}` {version}"


UNLISTED_TRACKERS = {"sortedcontainers": "grantjenks/python-sortedcontainers"}  # its metadata links only its website
TRACKER_LABELS = ("source", "source code", "code", "repository", "homepage", "github", "tracker", "bug tracker",
                  "issue tracker", "issues")


@functools.lru_cache(maxsize=None)
def tracker(module: str) -> str:
    """`owner/name` of the GitHub repository whose issues take reports about `module`, or '' when
    its package names none: python/cpython for the standard library, else the package's own links."""
    top = module.split(".")[0]
    if top in sys.stdlib_module_names:
        return "python/cpython"
    try:
        meta = importlib.metadata.metadata(_dist(module))
    except (importlib.metadata.PackageNotFoundError, ValueError):
        return ""
    urls = (meta.get_all("Project-URL") or []) + [f"homepage, {meta.get('Home-page') or ''}"]
    # the source link first: aio-libs also links its code of conduct, which lives in another repository
    for url in sorted(urls, key=lambda u: u.split(",")[0].strip().lower() not in TRACKER_LABELS):
        found = re.search(r"github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)", url)
        if found and found.group(1) != "sponsors":
            return f"{found.group(1)}/{found.group(2)}"
    return UNLISTED_TRACKERS.get(top, "")


TOP_PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
POPULAR_RANK = 1000


@functools.lru_cache(maxsize=1)
def _top_pypi() -> tuple:
    """The most downloaded PyPI projects by normalized name; the list is kept a month in bug_output."""
    cache = OUTPUT_ROOT / "top-pypi.json"
    if not cache.exists() or time.time() - cache.stat().st_mtime > 30 * 86400:
        OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
        cache.write_text(mf._http_get(TOP_PYPI), encoding="utf-8")
    rows = json.loads(cache.read_text(encoding="utf-8"))["rows"][:POPULAR_RANK]
    return tuple(re.sub(r"[-_.]+", "-", row["project"]).lower() for row in rows)


def unfileable(module: str) -> str:
    """Why a result in `module` must not go upstream, or ''. A package has to be popular, since a
    small project's maintainer has no time for a tool's reports, and installed at its latest
    release, since an older one's bug may be fixed already."""
    if module.split(".")[0] in sys.stdlib_module_names:
        return ""
    dist = _dist(module)
    try:
        if re.sub(r"[-_.]+", "-", dist).lower() not in _top_pypi():
            return f"{dist} is not among the {POPULAR_RANK} most downloaded PyPI projects"
        latest = json.loads(mf._http_get(f"https://pypi.org/pypi/{dist}/json"))["info"]["version"]
        installed = importlib.metadata.version(dist)
        if latest != installed:
            return f"{dist} {installed} is installed and {latest} is out: upgrade it and hunt again"
    except Exception as exc:  # unchecked is not filed
        return f"{dist} could not be checked: {type(exc).__name__}: {exc}"
    return ""


class BugForge(mf.Forge):
    def propose_one(self, module: str, nth: int, count: int):
        """One property per call, on the review model, cached like mathforge's proposals."""
        # the same prompt sent to every proposer brought back the same property four times
        names = _names(module)
        mine = names[nth - 1::count] or names
        earlier = earlier_properties(module, self.run.path)
        try:
            got = self.run.stage(f"conjecture{nth}", lambda: self.ask_json(
                f"You are a senior engineer hunting real bugs in the Python module `{module}`.\n"
                f"Environment: {environment(module)}\n\nPUBLIC API:\n{api(module)}\n\n"
                f"SOURCE (may be truncated):\n```python\n{source(module)}\n```\n\n"
                f"YOUR ASSIGNED NAMES (pick your target among these or their methods): {', '.join(mine)}\n\n"
                + ("ALREADY HUNTED IN EARLIER RUNS (do not propose these or variants of them):\n"
                   + "\n".join(f"- {p}" for p in earlier) + "\n\n" if earlier else "")
                + "Propose exactly ONE property that the module's DOCUMENTATION "
                "promises (a round trip, an invariant, agreement with a mathematical definition, a "
                "documented exception and nothing else, idempotence, consistency between two functions) "
                "and that you suspect the code breaks on some input: edge cases in the source, unusual "
                "but valid inputs, boundary values, unicode, huge or tiny numbers, empty inputs. A "
                "property the documentation does not promise is not a bug, however surprising. The "
                "property must be checkable in pure computation: no files, network or processes.\n\n"
                'Return ONLY JSON: {"title": "...", "target": "module.function", "statement": "the '
                'property, precisely, with its input domain", "spec_basis": "the documentation sentence '
                'that promises it, quoted, and where it is", "input_space": "how to generate valid '
                'inputs, including the edge cases to stress", "why_suspect": "what in the source makes '
                'you think it fails"}',
                "statement", model_type="review"))
            return dict(got) if got.get("statement") else None  # propose() adds an id; keep the cache clean
        except Exception as exc:
            mf.vlog(f"proposer {nth}/{count} produced nothing: {type(exc).__name__}: {exc}")
            with self.run.lock:
                self.run.data.pop(f"conjecture{nth}", None)
            return None

    def falsify(self, c: dict) -> dict:
        return self.write_and_run(
            "You are an adversarial tester. Your ONLY goal is to break this documented property of "
            "an installed Python library with an explicit failing input.\n\n"
            f"TARGET: {c.get('target', '')}\nPROPERTY: {c['statement']}\n"
            f"INPUT SPACE: {c.get('input_space', '')}\nDOCUMENTATION: {c.get('spec_basis', '')}\n\n"
            "Write ONE self-contained Python 3 script (stdlib only) that imports the installed module "
            "and checks the property on hand-picked edge cases first, then on random inputs from a "
            "fixed seed, for at most 3 minutes. Requirements:\n"
            "- Never touch files, the network, environment variables or processes.\n"
            "- Compute the expected side independently (a from-scratch reference, exact arithmetic, "
            "the documented definition), never by calling the function under test.\n"
            "- Only use inputs the documentation calls valid. An exception on invalid input is not a bug.\n"
            "- Print two sanity checks showing your reference agrees with the module on ordinary "
            "inputs; if they disagree, print SANITY FAILED and exit.\n"
            "- On a failure, re-run that one input to rule out flakiness, then print exactly "
            "`COUNTEREXAMPLE:` followed by the input as a Python literal (repr), the actual result "
            "and the expected one, and exit.\n"
            "- If nothing fails, print exactly `NO COUNTEREXAMPLE` and the number of cases tested.\n"
            "- Exit code 0 in both cases; never print both markers.\n"
            "Return only the script in one ```python fence.",
            f"{c['id']}_falsify",
            markers=("COUNTEREXAMPLE", "SANITY FAILED"),
        )

    def confirm_refutation(self, c: dict, search_output: str) -> dict:
        """The reproducer a maintainer would run, written by the other model from the witness alone."""
        return self.write_and_run(
            "You are a maintainer triaging a bug report. You do not trust the reporter's script: it "
            "may have used an invalid input, a wrong reference or a misread of the documentation.\n\n"
            f"TARGET: {c.get('target', '')}\nCLAIMED PROPERTY: {c['statement']}\n"
            f"DOCUMENTATION: {c.get('spec_basis', '')}\n\n"
            f"REPORTER'S OUTPUT (the failing input is in here):\n{search_output[-2000:]}\n\n"
            "Write the shortest standalone Python 3 script (stdlib only, no files or network) that a "
            "maintainer could paste into an issue: it imports the module, builds the reported input, "
            "checks that the input is valid by the documentation, calls the function, and computes "
            "the documented expectation independently. Print exactly `REFUTATION CONFIRMED:` with "
            "the input, actual and expected values if the documented promise is broken; otherwise "
            "print `REFUTATION REJECTED:` and why. Exit code 0 either way; no bare `assert`. Return "
            "only the script in one ```python fence.",
            f"{c['id']}_repro",
            markers=("REFUTATION CONFIRMED", "REFUTATION REJECTED"),
            model_type="review",
        )

    def duplicates(self, c: dict) -> dict:
        """Existing issues that may already report it: the project's tracker for the stdlib."""
        # the module, not the model-written target: "Fraction.limit_denominator" is no module name
        module = self.run.data.get("module") or c.get("target", "")
        repo = f" repo:{tracker(module)}" if tracker(module) else ""
        try:
            queries = self.ask_json(
                f"Write 3 short GitHub issue-search queries (3-6 words each) that would find an existing "
                f"report of this bug.\nTARGET: {c.get('target', '')}\nPROPERTY: {c['statement']}\n\n"
                'Return ONLY JSON: {"queries": ["...", "...", "..."]}', "queries", model_type="review")["queries"]
        except ValueError:
            queries = []
        queries = [queries] if isinstance(queries, str) else [str(q) for q in queries or []][:3]
        # long model phrasings missed cpython#155052; the bare name plus the documented words found it
        name = c.get("target", "").rsplit(".", 1)[-1]
        # a quote mark not inside a word: "Python's docs" is no quotation
        quoted = re.search(r"(?<!\w)['\"“‘`]([^'\"”’`]{8,80})", c.get("spec_basis", ""))
        fixed = f'{name} "{" ".join(quoted.group(1).split()[:6])}"' if quoted else name
        hits, errors, seen = [], [], set()
        for q in [fixed] + queries:
            # pull requests too: a merged fix is the strongest sign it is already handled
            url = GITHUB_SEARCH + urllib.parse.urlencode({"q": q + repo, "per_page": 8})
            try:
                items = github(url).get("items") or []
            except Exception as exc:  # rate limited (10/min unauthenticated) or offline
                errors.append(f"{q}: {type(exc).__name__}: {exc}")
                continue
            for i in items:
                if i.get("html_url") in seen:  # the four queries overlap
                    continue
                seen.add(i.get("html_url"))
                pr = i.get("pull_request")
                body = i.get("body") or ""
                body = body.split("</details>", 1)[-1]  # cpython's bpo-migration header says nothing
                hits.append({"title": i.get("title", ""), "url": i.get("html_url", ""),
                             "kind": "pull request" if pr else "issue",
                             "state": "merged" if pr and pr.get("merged_at") else i.get("state", ""),
                             "body": body.strip()[:600]})
        return {"queries": [fixed] + queries, "hits": hits, "errors": errors}

    def prior(self, c: dict, dupes: dict) -> dict:
        """Before any search is written: is this already reported, or already changed on main?
        On the work model, like the final judge; the review model proposed the property."""
        hits = "\n\n".join(f"[{h.get('kind', 'issue')}, {h['state']}] {h['title']}\n{h['url']}\n{h['body']}"
                            for h in dupes["hits"]) or "(none)"
        failed = "\n".join(dupes.get("errors") or [])
        return self.ask_json(
            "A property of a Python library is about to be tested for a bug. Decide whether that work "
            "would be wasted because the behaviour is already known.\n\n"
            f"TARGET: {c.get('target', '')}\nPROPERTY: {c['statement']}\n"
            f"WHY SUSPECTED: {c.get('why_suspect', '')}\n\n"
            f"ISSUES AND PULL REQUESTS FOUND ({len(dupes['hits'])}):\n{hits}\n\n"
            + (f"SEARCHES THAT FAILED:\n{failed}\n\n" if failed else "")
            + f"HOW THE UPSTREAM DEVELOPMENT BRANCH DIFFERS FROM THE INSTALLED MODULE:\n"
            f"{self.run.data.get('main_diff') or '(not compared)'}\n\n"
            "KNOWN only if an issue or pull request above reports or fixes this same failure (open, "
            "closed or merged): the same function misbehaving in the same way. An issue about the same "
            "function with another symptom, or the change that introduced the behaviour, is not it. The "
            "upstream diff alone never makes it KNOWN: a changed line is not a fix until a test says so. "
            "When unsure, say NEW.\n\n"
            'Return ONLY JSON: {"verdict": "KNOWN"|"NEW", "known_as": "the url of that issue or pull request", '
            '"reasoning": "..."}',
            "verdict",
            model_type="writing",
        )

    def judge(self, c: dict, repro: dict, dupes: dict) -> dict:
        """On the work model: the reproducer came from the review model, so the verdict is a
        model reading evidence it did not produce."""
        hits = "\n\n".join(f"[{h.get('kind', 'issue')}, {h['state']}] {h['title']}\n{h['url']}\n{h['body']}"
                           for h in dupes["hits"]) or "(none)"
        failed = "\n".join(dupes.get("errors") or [])
        return self.ask_json(
            "Decide whether a reproduced behaviour is a bug worth reporting. You did not write the "
            "reproducer; read its code and output yourself.\n\n"
            f"TARGET: {c.get('target', '')}\nENVIRONMENT: {environment(c.get('target', ''))}\n"
            f"CLAIMED PROPERTY: {c['statement']}\nDOCUMENTATION CITED: {c.get('spec_basis', '')}\n\n"
            f"REPRODUCER:\n```python\n{repro['code']}\n```\nOUTPUT:\n{repro['output'][-2000:]}\n\n"
            f"EXISTING ISSUES AND PULL REQUESTS FOUND ({len(dupes['hits'])}):\n{hits}\n\n"
            f"UPSTREAM DEVELOPMENT BRANCH VS INSTALLED MODULE:\n{self.run.data.get('main_diff') or '(not compared)'}\n\n"
            + (f"SEARCHES THAT FAILED (the tracker was not fully checked; say so in reasoning):\n{failed}\n\n"
               if failed else "")
            + "Be harsh. NOT_A_BUG if the documentation does not really promise the property, the input "
            "is invalid, the expectation is computed wrongly, or the behaviour is a documented "
            "limitation (floating point rounding the docs warn about, implementation-defined order). "
            "DUPLICATE if an issue or pull request above reports or fixes the same behaviour, open, "
            "closed or merged: a merged fix means it is already handled. DOC_BUG if the code is reasonable "
            "and the documentation is what is wrong. BUG only if the code breaks a clear documented "
            "promise on a valid input.\n\n"
            'Return ONLY JSON: {"verdict": "BUG"|"DOC_BUG"|"DUPLICATE"|"NOT_A_BUG", "reasoning": "...", '
            '"duplicate_of": "url or empty", "expected": "...", "actual": "...", "issue_title": "a '
            'maintainer-style title", "severity": "low"|"medium"|"high"}',
            "verdict",
            model_type="writing",
        )


    def _thread(self, r: dict) -> str:
        talk = self.run.data.get(f"{r['id']}.conversation") or {}
        return "\n\n".join(
            f"{c['author']} ({c['role']}), {c['date']}" + (f", on pull request {c['where']}" if c.get("where") else "")
            + f":\n{c['body']}" for c in talk.get("comments") or [])

    def fix(self, r: dict) -> dict:
        """A patch to the module's own source, kept only when the reproducer stops confirming the bug
        and the module's test suite still passes: executed gates, not a model's opinion of its patch."""
        module = self.run.data.get("module", "")
        origin = str(getattr(importlib.util.find_spec(module), "origin", ""))
        if not origin.endswith(".py"):
            return {"status": "unfixable", "why": "no Python source (a compiled module)"}
        original = Path(origin).read_text(encoding="utf-8")
        if len(original) > FIX_SOURCE_LIMIT:
            return {"status": "unfixable", "why": f"{len(original)} characters of source is more than a prompt carries"}
        thread, j = self._thread(r), r.get("judge") or {}
        prompt = (
            f"You are fixing a confirmed bug in the Python module `{module}`.\n\n"
            f"TARGET: {r.get('target', '')}\nPROPERTY BROKEN: {r['statement']}\n"
            f"EXPECTED: {j.get('expected', '')}\nACTUAL: {j.get('actual', '')}\n\n"
            f"REPRODUCER (it must print REFUTATION REJECTED once the module is fixed):\n```python\n"
            f"{r['repro']['code']}\n```\nITS OUTPUT NOW:\n{r['repro']['output'][-1500:]}\n\n"
            + (f"WHAT THE MAINTAINERS SAID ON THE UPSTREAM ISSUE (their constraints outrank your taste; "
               f"follow a design they ask for):\n{thread}\n\n" if thread else "")
            + f"MODULE SOURCE:\n```python\n{original}\n```\n\n"
            "Write the smallest change a maintainer would merge: keep the fast path and the public "
            "behaviour on every input that works today, match the surrounding style, add no "
            "dependency. Reply with one or more blocks of exactly this form and nothing else:\n"
            "<<<<<<< SEARCH\nlines copied verbatim from the source, enough to match exactly once\n"
            "=======\nthe replacement lines\n>>>>>>> REPLACE"
        )
        try:
            path = "Lib/" + Path(origin).relative_to(Path(os.__file__).parent).as_posix()
        except ValueError:  # not the standard library
            path = Path(origin).name
        complaint = failure = ""
        for attempt in range(mf.MAX_CODE_REPAIRS + 1):
            reply = self.ask(prompt + complaint)
            try:
                patched = apply_edits(original, reply)
                failure = check_fix(self.run, r, module, patched)
            except ValueError as exc:
                failure = f"{type(exc).__name__}: {exc}"
            if not failure:
                diff = "".join(difflib.unified_diff(original.splitlines(True), patched.splitlines(True),
                                                    f"a/{path}", f"b/{path}"))
                return {"status": "fixed", "diff": diff, "repairs": attempt, "tests": _test_suite(module),
                        "model": self.models.get("writing", "")}
            mf.vlog(f"  fix: attempt {attempt + 1} rejected: {failure[:200]}", r["id"])
            complaint = (f"\n\nYOUR PREVIOUS REPLY:\n{reply[-6000:]}\n\nIT WAS REJECTED:\n{failure[-3000:]}\n\n"
                         "Reply with corrected SEARCH/REPLACE blocks against the ORIGINAL source above.")
        return {"status": "failed", "why": failure[-2000:], "repairs": mf.MAX_CODE_REPAIRS}

    def go_ahead(self, r: dict) -> dict:
        """Where the upstream thread stands after its latest comment: read from the thread, never assumed."""
        talk = self.run.data.get(f"{r['id']}.conversation") or {}
        prs = "\n".join(f"{p['url']} by {p['author']}: {p['state']}" for p in talk.get("prs") or []) or "(none)"
        return self.ask_json(
            "A bug was reported upstream and the reporter proposed a fix. Decide from the thread what "
            "the reporter should do after its latest comment.\n\n"
            f"REPORTER: {talk.get('reporter', '')}\nISSUE STATE: {talk.get('state', '')}\n"
            f"LINKED PULL REQUESTS:\n{prs}\n\nTHREAD (author, their role in the project, date):\n{self._thread(r)}\n\n"
            "APPROVED only if someone whose role is MEMBER, OWNER or COLLABORATOR said, after the "
            "reporter's latest proposal, that the approach is fine or asked for the pull request, and "
            "none of their questions (a benchmark, precision, a design choice, waiting for another "
            "maintainer) is still unanswered or unacknowledged.\n"
            "REJECTED only if such a person dismissed the fix as a whole (not a bug, will not be "
            "changed, not applicable, closed as not planned) and asked nothing and proposed no "
            "alternative: there is nothing left to answer. Also REJECTED, whatever else the comment "
            "says, if such a person told the reporter to stop: to stop replying, to stop sending "
            "these, or not to answer with generated text.\n"
            "CHANGES if the latest comments ask the reporter a question, request a measurement or a "
            "test, or propose a different design, even inside a refusal of the current patch: "
            "something the reporter can answer with a revised patch or a reply.\n"
            "WAIT for anything else: told to wait for another maintainer, a bot's message, approval or "
            "remarks from someone who is not a maintainer, or nothing addressed to the reporter. When "
            "unsure between APPROVED and anything else, do not say APPROVED.\n\n"
            'Return ONLY JSON: {"verdict": "APPROVED"|"REJECTED"|"CHANGES"|"WAIT", "reasoning": "..."}',
            "verdict")

    def reply(self, r: dict, fixed: dict) -> str:
        """A draft answer to the upstream thread, for a person to check and post."""
        return self.ask(
            "Write a reply to the maintainers on this issue, in the reporter's voice. It may be posted "
            "without a person reading it first, so it must hold up on its own.\n\n"
            f"ISSUE: {(r.get('judge') or {}).get('issue_title') or r.get('title', '')}\n\n"
            f"THE THREAD SO FAR:\n{self._thread(r)}\n\n"
            f"THE PATCH NOW PROPOSED:\n```diff\n{fixed['diff']}\n```\n"
            f"WHAT WAS RUN ON IT: the issue's reproducer no longer fails"
            + (f"; `python -m unittest {fixed['tests']}` passes" if fixed.get("tests") else "") + ".\n\n"
            "Answer each open question in the thread, shortly and plainly. State only what the patch "
            "and the runs above show. Where a maintainer asks for a measurement or a build that was "
            "not run (a benchmark, a PGO build, another platform), say it has not been run yet "
            "instead of guessing a number. Where a comment can be read two ways, ask which is meant "
            "instead of picking one. Write the way a courteous contributor writes in a tracker: first "
            "person, plain words, a few short paragraphs, thanks at most once. No flattery, no "
            "headings, no bullet-point summary of what you did.")


def hunt(forge, c: dict) -> dict:
    """One property: prior art -> falsify -> reproduce -> judge. The tracker search runs first,
    so a known bug costs a search, not a search script, a reproducer and two judgements."""
    run, cid = forge.run, c["id"]
    # a search that failed (GitHub's limit) left the verdicts blind: redo them on resume
    if (run.data.get(f"{cid}.duplicates") or {}).get("errors"):
        with run.lock:
            for key in ("duplicates", "prior", "judge"):
                run.data.pop(f"{cid}.{key}", None)
    dupes = run.stage(f"{cid}.duplicates", lambda: forge.duplicates(c))
    try:
        known = run.stage(f"{cid}.prior", lambda: forge.prior(c, dupes))
    except Exception as exc:  # an advisory gate fails open: the executable stages still decide
        known = {"verdict": "NEW", "reasoning": f"prior-art judge failed: {type(exc).__name__}: {exc}"}
    # the hunt stops only on a tracker entry the search actually returned; "the diff looks like a fix"
    # is an opinion, and it ended five untested hunts
    cited = str(known.get("known_as", ""))
    if known.get("verdict") == "KNOWN" and any(h.get("url") and h["url"] in cited for h in dupes["hits"]):
        return {**c, "status": "known", "duplicates": dupes, "prior": known}
    found = run.stage(f"{cid}.falsify", lambda: forge.falsify(c))
    found = {**found, "output": mf.canon_negatives(found["output"])}
    search = mf.classify_search(found["exit_code"], found["output"])
    if search == "clean":
        return {**c, "status": "holds", "falsification": found}
    if search != "refuted":
        return {**c, "status": "inconclusive", "falsification": found}
    repro = run.stage(f"{cid}.repro", lambda: forge.confirm_refutation(c, found["output"]))
    if not mf.refutation_confirmed(repro):
        return {**c, "status": "inconclusive", "falsification": found, "repro": repro}
    verdict = run.stage(f"{cid}.judge", lambda: forge.judge(c, repro, dupes))
    status = {"BUG": "bug", "DOC_BUG": "doc-bug", "DUPLICATE": "duplicate"}.get(verdict.get("verdict"), "not-a-bug")
    return {**c, "status": status, "falsification": found, "repro": repro, "duplicates": dupes, "judge": verdict}


def _hunt_safely(forge, c: dict) -> dict:
    try:
        return hunt(forge, c)
    except Exception as exc:  # one property must not cost the run; nothing cached, a rerun retries
        mf.log(f"  error — {type(exc).__name__}: {exc}", c["id"])
        return {**c, "status": "error", "error": f"{type(exc).__name__}: {exc}"}


def report(module: str, results: list, environment_line: str | None = None) -> str:
    """`environment_line` is the run's own, recorded when it ran; the live one is for a fresh run."""
    env = environment_line or environment(module)
    out = [f"# bugforge: `{module}`", "", env, "",
           "Drafted issues are not filed. Read the reproducer, run it yourself, and check the tracker before "
           "filing anything.", ""]
    for r in results:
        out += [f"## {r['id']} `{r['status']}`: {r.get('title', '')}", "", f"Target: `{r.get('target', '')}`", "",
                f"Property: {r.get('statement', '')}", ""]
        j = r.get("judge") or {}
        if r["status"] == "duplicate":
            out += [f"Duplicate of: {j.get('duplicate_of') or '(see judge)'}", "",
                    f"Judge: {j.get('reasoning', '')}", ""]
        elif r["status"] in ("bug", "doc-bug"):
            out += [f"### Draft issue: {j.get('issue_title') or r.get('title', '')}", "",
                    f"**Environment:** {env}", "",
                    f"**Documented behaviour:** {r.get('spec_basis', '')}", "",
                    f"**Expected:** {j.get('expected', '')}", "", f"**Actual:** {j.get('actual', '')}", "",
                    "**Reproducer:**", "", "```python", r["repro"]["code"].strip(), "```", "",
                    *([f"WARNING: the tracker search was incomplete ({'; '.join(r['duplicates']['errors'])}); "
                       "search it by hand before filing.", ""] if (r.get("duplicates") or {}).get("errors") else []),
                    "**Output:**", "", "```", r["repro"]["output"].strip()[-1500:], "```", "",
                    f"Judge: {j.get('verdict')} ({j.get('severity', '')}) -- {j.get('reasoning', '')}", ""]
        elif r["status"] == "known":
            p = r.get("prior") or {}
            out += [f"Already known: {p.get('known_as', '')} -- {p.get('reasoning', '')}", ""]
        elif r["status"] == "not-a-bug":
            out += [f"Judge: {j.get('reasoning', '')}", ""]
        elif r["status"] == "inconclusive":
            why = (r.get("repro") or r["falsification"])["output"]
            out += [f"Inconclusive: {mf._verdict_line(why, 300)}", ""]
        elif r["status"] == "holds":
            out += [f"Held: {mf._verdict_line(r['falsification']['output'], 200)}", ""]
        elif r.get("error"):
            out += [f"Error: {r['error']}", ""]
    return "\n".join(out) + "\n"


def _checkout() -> tuple[str, Path]:
    """(owner/name, local checkout) of the public results repository, created on first use."""
    repo = RESULTS_REPO
    if "/" not in repo:
        login = mf._gh("gh", "api", "user", "-q", ".login").stdout.strip()
        if not login:
            raise RuntimeError("gh is not logged in (gh auth login)")
        repo = f"{login}/{repo}"
    if not (RESULTS_CHECKOUT / ".git").exists():
        if mf._gh("gh", "repo", "view", repo).returncode != 0:
            made = mf._gh("gh", "repo", "create", repo, "--public", "--description",
                          "Reproduced bugs in Python libraries, found by bugforge; not yet reviewed by a person")
            if made.returncode != 0:
                raise RuntimeError(f"gh repo create {repo}: {(made.stdout + made.stderr).strip()[-300:]}")
        cloned = mf._gh("gh", "repo", "clone", repo, str(RESULTS_CHECKOUT))
        if cloned.returncode != 0:
            raise RuntimeError(f"gh repo clone {repo}: {(cloned.stdout + cloned.stderr).strip()[-300:]}")
        mf._gh("git", "checkout", "-B", "main", cwd=RESULTS_CHECKOUT)
    mf._gh("git", "pull", "--ff-only", "origin", "main", cwd=RESULTS_CHECKOUT)  # fails harmlessly when empty
    return repo, RESULTS_CHECKOUT


def results_index(checkout: Path) -> str:
    rows = sorted((json.loads(p.read_text(encoding="utf-8")) for p in checkout.glob("*/result.json")),
                  key=lambda m: (m.get("date", ""), m.get("folder", "")), reverse=True)
    lines = ["# bugforge results", "",
             f"Behaviour of Python libraries that breaks their documentation, found by [bugforge]({BUGFORGE_URL}): "
             "one language model proposes a documented property, another searches for a failing input, a "
             "third writes a minimal standalone reproducer, which is run, and a judge reads the reproducer, "
             "the documentation and the project's issue tracker. Every folder holds the reproducer and its "
             "output on the Python version named. No person reviewed these before publication. A result "
             "is linked to its upstream issue once one is filed, at most one open issue per project.", "",
             f"{len(rows)} result(s).", "",
             "| Date | Target | Verdict | Title | Python | Upstream |", "| --- | --- | --- | --- | --- | --- |"]
    for m in rows:
        title = re.sub(r"([\\\[\]|])", r"\\\1", m.get("title", ""))  # a lone `[` ends the link text early
        talk = m.get("conversation") or {}
        upstream = (m.get("upstream") or "not filed") + (
            f" ({talk.get('state', '')}, {talk.get('comments', 0)} comment(s))" if talk else "")
        lines.append(f"| {m.get('date', '')} | `{m.get('target', '')}` | {m.get('status', '')} | "
                     f"[{title}]({m['folder']}/) | {m.get('python', '')} | {upstream} |")
    return "\n".join(lines) + "\n"


def publish_one(run, r: dict) -> dict:
    """One confirmed bug as a folder of the results repository. Never raises."""
    if not shutil.which("gh") or not shutil.which("git"):
        return {"error": "gh and git must be on PATH to publish"}
    module = run.data.get("module", "")
    try:
        with _REPO_LOCK:
            repo, checkout = _checkout()
            # cached URLs keep the folders published as `<module>-cN` before runs got their own
            folder = checkout / f"{run.path.name}-{r['id']}"
            folder.mkdir(exist_ok=True)
            for name in (f"{r['id']}_repro.py", f"{r['id']}_falsify.py"):
                if (run.path / name).exists():
                    shutil.copy2(run.path / name, folder / name)
            env = run.data.get("environment") or environment(module)
            (folder / "README.md").write_text(
                "*Found and written by language models (bugforge); not reviewed by a person.*\n\n"
                + report(module, [r], env), encoding="utf-8")
            title = (r.get("judge") or {}).get("issue_title") or r.get("title", r["id"])
            meta = folder / "result.json"
            upstream = json.loads(meta.read_text(encoding="utf-8")).get("upstream") if meta.exists() else None
            meta.write_text(json.dumps({
                "folder": folder.name, "status": r["status"], "target": r.get("target", ""), "title": title,
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "python": (re.match(r"Python (\S+)", env) or [None, platform.python_version()])[1],
                "run": run.path.name, "id": r["id"], "upstream": upstream}, indent=2) + "\n", encoding="utf-8")
            (checkout / "README.md").write_text(results_index(checkout), encoding="utf-8")
            mf._gh("git", "add", "-A", cwd=checkout)
            mf._gh("git", "commit", "-m", f"{r['status']}: {title}", cwd=checkout)
            pushed = mf._gh("git", "push", "-u", "origin", "main", cwd=checkout)
            if pushed.returncode != 0:
                return {"error": f"git push: {(pushed.stdout + pushed.stderr).strip()[-300:]}"}
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return {"url": f"https://github.com/{repo}/tree/main/{folder.name}", "status": r["status"], "title": title}


def publish(run, results: list) -> list:
    """Publish every bug and doc-bug once; the URL is cached in state.json, a failure is retried next time."""
    published = []
    for r in results:
        key = f"{r['id']}.published"
        if r["status"] not in PUBLISH_STATUSES:
            stale = (run.data.get(key) or {}).get("url")
            if stale:
                mf.log(f"PUBLIC {stale} no longer qualifies (now `{r['status']}`); retract it", r["id"])
            continue
        if (r.get("duplicates") or {}).get("errors"):
            # the judge ruled without the tracker; --resume redoes the search, then it can go out
            mf.log("not published: the duplicate search was incomplete", r["id"])
            continue
        info = run.data.get(key) or {}
        if not info.get("url") and (r.get("judge") or {}).get("severity") == "low":
            # two thirds of confirmed results are low: contrived inputs no maintainer would act on
            mf.log("not published: low severity (the draft stays in report.md)", r["id"])
            continue
        if not info.get("url"):
            info = publish_one(run, r)
            if info.get("url"):
                with run.lock:
                    run.data[key] = info
                run.save()
        mf.log(f"published: {info['url']}" if info.get("url") else f"publish failed: {info.get('error')}", r["id"])
        if info.get("url"):
            published.append(info)
    return published


def link_upstream(folder: str, url: str) -> str:
    """Record the upstream issue filed by hand for a published result; returns an error or ''."""
    try:
        with _REPO_LOCK:
            _repo, checkout = _checkout()
            meta = checkout / Path(folder).name / "result.json"
            if not meta.exists():
                return f"{folder}: no such published result in {checkout}"
            data = json.loads(meta.read_text(encoding="utf-8"))
            number = re.search(r"github\.com/([^/]+)/([^/]+)/(?:issues|pull)/(\d+)", url)
            data["upstream"] = f"[{number.group(2)}#{number.group(3)}]({url})" if number else url
            meta.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            (checkout / "README.md").write_text(results_index(checkout), encoding="utf-8")
            mf._gh("git", "add", "-A", cwd=checkout)
            mf._gh("git", "commit", "-m", f"Link {meta.parent.name} to {url}", cwd=checkout)
            pushed = mf._gh("git", "push", "-u", "origin", "main", cwd=checkout)
            if pushed.returncode != 0:
                return f"git push: {(pushed.stdout + pushed.stderr).strip()[-300:]}"
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as exc:
        return f"{type(exc).__name__}: {exc}"
    return ""


UPSTREAM_ISSUE = re.compile(r"github\.com/([^/\s)]+)/([^/\s)]+)/(?:issues|pull)/(\d+)")


@functools.lru_cache(maxsize=1)
def _login() -> str:
    """The GitHub account gh is logged in as, or ''."""
    if not shutil.which("gh"):
        return ""
    try:
        return mf._gh("gh", "api", "user", "-q", ".login", timeout=30).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _said(c: dict, where: str = "") -> dict:
    """One comment, review or review remark as the thread keeps it. A bot's role is BOT: it is
    logged, and it never makes it our turn."""
    user = c.get("user") or {}
    bot = user.get("type") == "Bot" or user.get("login", "").endswith("[bot]")
    body = (f"[review: {c['state'].lower()}] " if c.get("state") else "") + (
        f"[on {c['path']}] " if c.get("path") else "") + (c.get("body") or "")
    return {"author": user.get("login", ""), "role": "BOT" if bot else c.get("author_association", ""),
            "date": c.get("created_at") or c.get("submitted_at") or "", "body": body[:4000],
            **({"where": where} if where else {})}


def conversation(url: str, me: str = "") -> dict:
    """An upstream issue as its maintainers left it: state, labels, linked pull requests and one
    thread in date order. A pull request `me` opened for it is part of the discussion, so its
    comments, reviews and review remarks join the thread, each marked with where it was said.

    ponytail: the first 100 comments of each; page when a thread outgrows that.
    """
    owner, name, number = UPSTREAM_ISSUE.search(url).groups()
    repo = f"https://api.github.com/repos/{owner}/{name}"
    issue = github(f"{repo}/issues/{number}")
    thread = [_said(c) for c in (github(f"{repo}/issues/{number}/comments?per_page=100") if issue.get("comments") else [])]
    prs = []
    # CPython's bot lists `gh-N` under "Linked PRs" in the issue body
    for n in dict.fromkeys(re.findall(r"gh-(\d+)", (issue.get("body") or "").partition("Linked PRs")[2])):
        try:
            pr = github(f"{repo}/pulls/{n}")
            author, where = (pr.get("user") or {}).get("login", ""), pr.get("html_url", "")
            if me and author == me:  # someone else's pull request is their conversation, not ours
                for part in (f"issues/{n}/comments", f"pulls/{n}/reviews", f"pulls/{n}/comments"):
                    thread += [_said(c, where) for c in github(f"{repo}/{part}?per_page=100")
                               if c.get("body") or c.get("state") in ("APPROVED", "CHANGES_REQUESTED")]
        except Exception:  # a deleted pull request must not hide the thread
            continue
        prs.append({"url": where, "author": author, "state": "merged" if pr.get("merged") else pr.get("state", "")})
    return {"url": f"https://github.com/{owner}/{name}/issues/{number}", "state": issue.get("state", ""),
            "reporter": (issue.get("user") or {}).get("login", ""), "prs": prs,
            "labels": [label.get("name", "") for label in issue.get("labels") or []],
            "updated": issue.get("updated_at", ""), "comments": sorted(thread, key=lambda c: c["date"])}


def discover(checkout: Path, me: str) -> int:
    """Link published results to the upstream issues (or pull requests) `me` filed for them, so a
    report filed by hand is followed without --link; returns how many were linked.

    An issue counts when it is yours, names bugforge, and either names the result's folder or
    names the target of exactly one unlinked result. Each project is searched in the tracker
    `tracker()` names for it.
    """
    metas = {m: json.loads(m.read_text(encoding="utf-8")) for m in sorted(checkout.glob("*/result.json"))}
    taken = {UPSTREAM_ISSUE.search(d["upstream"]).group(0) for d in metas.values()
             if UPSTREAM_ISSUE.search(d.get("upstream") or "")}
    unlinked = {m: d for m, d in metas.items() if not d.get("upstream") and tracker(d.get("target", ""))}
    if not me or not unlinked:
        return 0
    found = []
    for repo in sorted({tracker(d["target"]) for d in unlinked.values()}):
        found += github(GITHUB_SEARCH + urllib.parse.urlencode(
            {"q": f"repo:{repo} author:{me} bugforge in:body", "per_page": 50})).get("items") or []
    linked = 0
    for item in sorted(found, key=lambda i: "pull_request" in i):  # the issue before its pull request
        link = UPSTREAM_ISSUE.search(item.get("html_url") or "")
        if not link or link.group(0) in taken:
            continue
        text = f"{item.get('title', '')}\n{item.get('body') or ''}"
        hits = [m for m, d in unlinked.items() if d["folder"] in text] or [
            m for m, d in unlinked.items() if d.get("target") and re.search(rf"(?<![\w.]){re.escape(d['target'])}(?![\w.])", text)
            and tracker(d["target"]).lower() == f"{link.group(1)}/{link.group(2)}".lower()]
        if len(hits) != 1:
            if hits:
                mf.log(f"{item['html_url']} fits {len(hits)} results; --link the right one")
            continue
        data = unlinked.pop(hits[0])
        data["upstream"] = f"[{link.group(2)}#{link.group(3)}]({item['html_url']})"
        hits[0].write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        taken.add(link.group(0))
        mf.log(f"{data['folder']}: found your upstream report {item['html_url']}")
        linked += 1
    return linked


def track() -> int:
    """Refresh the upstream conversation of every published result that links one; returns how many
    changed. The index gets the state and comment count; the thread itself stays in the run's
    state.json, where --fix reads it. Nothing is posted."""
    with _REPO_LOCK:
        _repo, checkout = _checkout()
        me = _login()
        try:
            changed = discover(checkout, me)
        except Exception as exc:  # the search being down must not stop the threads already linked
            mf.log(f"upstream reports not searched: {type(exc).__name__}: {exc}")
            changed = 0
        for meta in sorted(checkout.glob("*/result.json")):
            data = json.loads(meta.read_text(encoding="utf-8"))
            if not UPSTREAM_ISSUE.search(data.get("upstream") or ""):
                continue
            if (data.get("conversation") or {}).get("state") == "closed":
                continue  # solved or turned down: a closed thread is not read again
            try:
                talk = conversation(data["upstream"], me)
            except Exception as exc:  # one unreachable issue must not hide the others
                mf.log(f"{meta.parent.name}: not tracked: {type(exc).__name__}: {exc}")
                continue
            seen = (data.get("conversation") or {}).get("comments", 0)
            for c in talk["comments"][seen:]:
                mf.log(f"{meta.parent.name}: new comment by {c['author']} ({c['role']}): "
                       f"{' '.join(c['body'].split())[:300]}")
                # the console scrolls away under --forever: every response is also kept in one local file
                OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
                with open(OUTPUT_ROOT / "responses.md", "a", encoding="utf-8") as responses:
                    responses.write(f"## {meta.parent.name}: {c.get('where') or talk['url']}\n\n**{c['author']}** ({c['role']}), "
                                    f"{c['date']}:\n\n{c['body']}\n\n")
            if (OUTPUT_ROOT / str(data.get("run")) / "state.json").exists():
                run = mf.Run(OUTPUT_ROOT / data["run"])
                run.data[f"{data['id']}.conversation"] = talk
                run.save()
            summary = {"state": talk["state"], "comments": len(talk["comments"]), "updated": talk["updated"]}
            if summary != data.get("conversation"):
                data["conversation"] = summary
                meta.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                changed += 1
        if changed:
            (checkout / "README.md").write_text(results_index(checkout), encoding="utf-8")
            mf._gh("git", "add", "-A", cwd=checkout)
            mf._gh("git", "commit", "-m", f"Track {changed} upstream conversation(s)", cwd=checkout)
            pushed = mf._gh("git", "push", "-u", "origin", "main", cwd=checkout)
            if pushed.returncode != 0:
                mf.log(f"track: git push: {(pushed.stdout + pushed.stderr).strip()[-300:]}")
    return changed


SEVERITIES = ("high", "medium", "low")


def issue_body(r: dict, env: str, folder_url: str, cpython: bool = True) -> str:
    """The upstream issue for one confirmed result; CPython's tracker gets its bug-report layout.
    It says what it is: written by a tool and not read by a person, with the reproducer's own output."""
    j = r.get("judge") or {}
    body = [f"**Documented behaviour:** {r.get('spec_basis', '')}", "",
            f"**Expected:** {j.get('expected', '')}", "", f"**Actual:** {j.get('actual', '')}", "",
            "```python", r["repro"]["code"].strip(), "```", "", f"Output on {env}:", "",
            "```", r["repro"]["output"].strip()[-1500:], "```", "",
            f"This report was found and written by an automated property-testing tool I run ([bugforge]({BUGFORGE_URL})). "
            "The reproducer above was executed and its output is pasted unedited; no person reviewed the report "
            f"before it was filed. The search script is in {folder_url}", ""]
    if cpython:
        body = ["# Bug report", "", "### Bug description:", "", *body,
                "### CPython versions tested on:", "", (re.match(r"Python (\d+\.\d+)", env) or [None, ""])[1], "",
                "### Operating systems tested on:", "", platform.system(), ""]
    return "\n".join(body)


def _busy(checkout: Path, metas: list) -> set:
    """Projects that already have an open report of ours, each `owner/name` in lower case: a linked
    result whose issue is not closed (a thread never read counts as open), or an open tracking
    issue named in the results repository's `tracking.json` ({"owner/name": issue URL})."""
    busy = set()
    for d in metas:
        link = UPSTREAM_ISSUE.search(d.get("upstream") or "")
        if link and (d.get("conversation") or {}).get("state") != "closed":
            busy.add(f"{link.group(1)}/{link.group(2)}".lower())
    path = checkout / "tracking.json"
    for repo, url in (json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}).items():
        link = UPSTREAM_ISSUE.search(url)
        try:
            state = github(f"https://api.github.com/repos/{link.group(1)}/{link.group(2)}/issues/{link.group(3)}").get("state")
        except Exception:  # unread counts as open
            state = ""
        if state != "closed":
            busy.add(repo.lower())
    return busy


def file_upstream(post: bool = True) -> list:
    """File published results that have no upstream report as issues in their project's tracker,
    the most severe first; returns the issue URLs. One at a time per project: nothing is filed
    where a report of ours is still open, so the next one waits until that is solved or turned
    down. A flood of reports gets them all closed unread, as python/cpython did with ninety.

    Each is checked again first: the package must be popular and at its latest release, the
    reproducer must still confirm the bug when run now, and one issue per target is enough, so a
    second finding in a function already reported is held back. `post=False` writes the
    `cN_issue.md` drafts and files nothing.
    """
    track()  # a report filed by hand is linked first, never filed twice
    with _REPO_LOCK:
        repo, checkout = _checkout()
        metas = [json.loads(m.read_text(encoding="utf-8")) for m in sorted(checkout.glob("*/result.json"))]
        busy = _busy(checkout, metas)
    reported = {d.get("target") for d in metas if d.get("upstream")}
    rows = []
    for data in metas:
        if data.get("upstream") or not (OUTPUT_ROOT / str(data.get("run")) / "state.json").exists():
            continue
        run = mf.Run(OUTPUT_ROOT / data["run"])
        r = next((x for x in run.data.get("results") or []
                  if x.get("id") == data.get("id") and x.get("status") in PUBLISH_STATUSES), None)
        if r:
            severity = (r.get("judge") or {}).get("severity")
            rows.append((SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES), data, run, r))
    filed = []
    for _rank, data, run, r in sorted(rows, key=lambda row: row[0]):
        module, where = run.data.get("module") or data.get("target", ""), f"{run.path.name}/{r['id']}"
        project = tracker(module)
        if not project or project.lower() in busy:
            continue  # no tracker known, or it is that project's turn to answer
        if data.get("target") in reported:
            mf.log(f"not filed: {data.get('target')} already has a report", where)
            continue
        why = unfileable(module)
        if why:
            mf.log(f"not filed: {why}", where)
            continue
        _rc, out = _run_shadowed([f"{r['id']}_repro.py"], None, run.path, mf.CODE_TIMEOUT)
        if "REFUTATION CONFIRMED" not in out:
            mf.log("not filed: the reproducer no longer confirms the bug", where)
            continue
        reported.add(data.get("target"))
        busy.add(project.lower())
        draft = run.path / f"{r['id']}_issue.md"
        draft.write_text(issue_body(r, environment(module), f"https://github.com/{repo}/tree/main/{data['folder']}",
                                    project == "python/cpython"), encoding="utf-8")
        if not post:
            mf.log(f"would file on {project}: {data['title']}  ({draft})", r["id"])
            filed.append(str(draft))
            continue
        sent = mf._gh("gh", "issue", "create", "-R", project, "--title", data["title"], "--body-file", str(draft))
        url = UPSTREAM_ISSUE.search(sent.stdout)
        if sent.returncode != 0 or not url:
            raise RuntimeError(f"gh issue create: {(sent.stdout + sent.stderr).strip()[-300:]}")
        url = "https://" + url.group(0)
        mf.log(f"filed: {url}", r["id"])
        filed.append(url)
        error = link_upstream(data["folder"], url)
        if error:  # the body names the folder, so the next track() finds and links it
            mf.log(f"filed but not linked: {error}", r["id"])
    return filed


EDIT = re.compile(r"<<<<<<< SEARCH\n(.*?)\n=======\n(.*?)\n?>>>>>>> REPLACE", re.S)
FIX_SOURCE_LIMIT = 200_000  # characters of module source a fix prompt may carry


def apply_edits(text: str, reply: str) -> str:
    """The module source with the reply's SEARCH/REPLACE blocks applied; ValueError says what is wrong."""
    edits = EDIT.findall(reply)
    if not edits:
        raise ValueError("no SEARCH/REPLACE block in the reply")
    for old, new in edits:
        if text.count(old) != 1:
            raise ValueError(f"a SEARCH text must match the source exactly once; this one matches "
                             f"{text.count(old)} times:\n{old[:300]}")
        text = text.replace(old, new)
    ast.parse(text)  # a SyntaxError is a ValueError
    return text


def _shadow(module: str, patched: str, folder: Path) -> Path:
    """A directory that, first on PYTHONPATH, makes `module` import the patched source."""
    origin = Path(importlib.util.find_spec(module).origin)
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    if "." in module or origin.name == "__init__.py":  # a submodule needs its whole package beside it
        top = module.split(".")[0]
        package = Path(importlib.util.find_spec(top).origin).parent
        shutil.copytree(package, folder / top, ignore=shutil.ignore_patterns("__pycache__"))
        target = folder / top / origin.relative_to(package)
    else:
        target = folder / origin.name
    target.write_text(patched, encoding="utf-8")
    return folder


def _run_shadowed(args: list, shadow: Path | None, cwd: Path, timeout: int) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            [sys.executable, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONPATH": str(shadow or "")}, timeout=timeout,
            cwd=str(cwd), creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return -1, f"TIMEOUT: exceeded {timeout}s wall clock."


def _test_suite(module: str) -> str:
    """The stdlib test module for `module`, or ''.

    ponytail: guessed from the name; `urllib.parse` (test_urlparse) lands on test_urllib. A table when it matters.
    """
    for name in dict.fromkeys((module.replace(".", "_"), module.rsplit(".", 1)[-1], module.split(".")[0])):
        try:
            if importlib.util.find_spec(f"test.test_{name}"):
                return f"test.test_{name}"
        except (ImportError, ValueError):
            continue
    return ""


def _failed_tests(output: str) -> set:
    return set(re.findall(r"^(?:FAIL|ERROR): (.+)$", output, re.M))


def check_fix(run, r: dict, module: str, patched: str) -> str:
    """'' when the patched module passes the executable gates, else what failed: the reproducer must
    stop confirming the bug, and the module's own test suite must fail nothing it passed before."""
    shadow = _shadow(module, patched, run.path / f"{r['id']}_fix")
    _rc, out = _run_shadowed([f"{r['id']}_repro.py"], shadow, run.path, mf.CODE_TIMEOUT)
    if "REFUTATION CONFIRMED" in out or "REFUTATION REJECTED" not in out:
        return f"the reproducer still reports the bug with your patch applied:\n{out[-2000:]}"
    suite = _test_suite(module)
    if suite:
        rc, out = _run_shadowed(["-m", "unittest", suite], shadow, run.path, 900)
        if rc != 0:
            # a suite that already fails here (a missing resource, a Windows quirk) is not the patch's fault
            broken = _failed_tests(out) - _failed_tests(_run_shadowed(["-m", "unittest", suite], None, run.path, 900)[1])
            if broken or not _failed_tests(out):
                return f"{suite} fails with your patch applied:\n{out[-3000:]}"
    return ""


def pull_request_advice(talk: dict, me: str) -> list:
    """What to do about a pull request once the maintainers agreed: reopen your own closed one,
    never count on someone else's."""
    lines = []
    for pr in talk.get("prs") or []:
        if pr["state"] == "merged":
            lines.append(f"{pr['url']} is merged: nothing to open")
        elif pr["author"] != me:
            lines.append(f"{pr['url']} ({pr['state']}) was opened by {pr['author'] or 'someone else'}, not you: only "
                         "its author or a maintainer can reopen it, so open your own from the fix")
        elif pr["state"] == "closed":
            lines.append(f"reopen your pull request: gh pr reopen {pr['url']}")
        else:
            lines.append(f"your pull request {pr['url']} is open: push the fix to it")
    return lines or ["no pull request is linked yet: open one from the fix"]


def fix_result(forge, cid: str) -> dict:
    """Patch one confirmed bug and, when its upstream thread is tracked, draft the reply. Writes
    `cN_fix.diff` and `cN_reply.md` into the run directory; opens no pull request and posts nothing."""
    run = forge.run
    r = next((x for x in run.data.get("results") or [] if x.get("id") == cid), None)
    if not r or r.get("status") != "bug":
        raise ValueError(f"{cid}: no confirmed `bug` with that id in {run.path.name}")
    with run.lock:  # a new maintainer comment changes what the fix should be: never reuse the last one
        for key in ("fix", "reply"):
            run.data.pop(f"{cid}.{key}", None)
    fixed = run.stage(f"{cid}.fix", lambda: forge.fix(r))
    if fixed.get("status") != "fixed":
        mf.log(f"no fix: {fixed.get('why', '')[:300]}", cid)
        return fixed
    (run.path / f"{cid}_fix.diff").write_text(fixed["diff"], encoding="utf-8")
    mf.log(f"fix passes the reproducer and the test suite: {run.path / f'{cid}_fix.diff'}", cid)
    if (run.data.get(f"{cid}.conversation") or {}).get("comments"):
        (run.path / f"{cid}_reply.md").write_text(
            run.stage(f"{cid}.reply", lambda: forge.reply(r, fixed)), encoding="utf-8")
        mf.log(f"draft reply: {run.path / f'{cid}_reply.md'}", cid)
    return fixed


MAX_REPLIES = 5  # our comments on one issue before a person has to take over
REPLY_FOOTER = ("\n\n*Drafted and posted by [bugforge]({url}), an LLM tool I run. The patch behind it was "
                "checked by running the reproducer and the module's test suite, not by me reading this reply.*\n")


def take_turn(forge, cid: str, me: str, post: bool = False) -> str:
    """One turn of one upstream thread; returns where it stands.

    The thread is a loop with two exits. `approved`: a maintainer agreed, so the pull request can be
    opened or reopened. `rejected`: a maintainer dismissed the idea as a whole and left nothing to
    answer. Until one of them, every new comment that asks or proposes something (`changes`) gets a
    fresh fix and a reply, and then it is their move (`waiting`). Whose move it is is read from the
    thread, not judged: our own comment last means wait. Each comment is answered at most once.
    """
    run = forge.run
    talk = run.data.get(f"{cid}.conversation") or {}
    comments = [c for c in talk.get("comments") or [] if c.get("role") != "BOT"]  # a bot's note is no one's move
    if not comments or comments[-1]["author"] == me:
        return "waiting"
    if run.data.get(f"{cid}.answered") == comments[-1]["date"]:  # this comment was already acted on
        return run.data.get(f"{cid}.thread", "waiting")
    r = next((x for x in run.data.get("results") or [] if x.get("id") == cid), None)
    if not r:
        return "waiting"
    if talk.get("state") == "closed":  # solved or turned down: a closed issue is never answered
        mf.log(f"upstream closed {talk.get('url', '')}; no reply", cid)
        with run.lock:
            run.data[f"{cid}.answered"], run.data[f"{cid}.thread"] = comments[-1]["date"], "rejected"
        run.save()
        return "rejected"
    verdict = forge.go_ahead(r)  # a failure here raises: the comment stays unanswered and is retried
    status = {"APPROVED": "approved", "REJECTED": "rejected", "CHANGES": "changes"}.get(verdict.get("verdict"), "waiting")
    why = verdict.get("reasoning", "")[:300]
    if status == "approved":
        for line in pull_request_advice(talk, me):
            mf.log(f"maintainers agreed; {line}", cid)
    elif status == "rejected":
        mf.log(f"upstream turned it down; no more replies: {why}", cid)
    elif status == "waiting":
        mf.log(f"nothing to answer yet: {why}", cid)
    else:
        fixed = fix_result(forge, cid) if r.get("status") == "bug" else {"why": "not a code bug"}
        if fixed.get("status") != "fixed":
            mf.log(f"a person has to answer {talk.get('url', '')}: no patch passed ({fixed.get('why', '')[:200]})", cid)
        elif not post:
            mf.log("reply drafted, not posted (--no-post)", cid)
        elif sum(c["author"] == me for c in comments) >= MAX_REPLIES:
            mf.log(f"a person has to answer {talk.get('url', '')}: {MAX_REPLIES} replies already sent", cid)
        else:
            draft = run.path / f"{cid}_reply.md"
            draft.write_text(draft.read_text(encoding="utf-8").rstrip() + REPLY_FOOTER.format(url=BUGFORGE_URL),
                             encoding="utf-8")
            # answered where it was said: on the issue, or on our own pull request
            sent = mf._gh("gh", "issue", "comment", comments[-1].get("where") or talk["url"], "--body-file", str(draft))
            if sent.returncode != 0:
                raise RuntimeError(f"gh issue comment: {(sent.stdout + sent.stderr).strip()[-300:]}")
            mf.log(f"replied: {sent.stdout.strip()}", cid)
            status = "replied"
    with run.lock:
        run.data[f"{cid}.answered"], run.data[f"{cid}.thread"] = comments[-1]["date"], status
    run.save()
    return status


def converse(forge_for, post: bool = False) -> dict:
    """One turn of every upstream thread; {run/cN: status}. Run again (after every module of a hunt)
    it continues each thread until it is approved or rejected. Does nothing before the first
    --publish: there is no results repository to read the links from, and none is created here."""
    me = _login()
    if not me or not (RESULTS_CHECKOUT / ".git").exists():
        return {}
    track()
    turns = {}
    for state in sorted(OUTPUT_ROOT.glob("*/state.json")):
        run = mf.Run(state.parent)
        for cid in [k.split(".")[0] for k in run.data if k.endswith(".conversation")]:
            try:
                turns[f"{run.path.name}/{cid}"] = take_turn(forge_for(run), cid, me, post)
            except Exception as exc:  # one thread must not cost the others their turn
                mf.log(f"turn failed, retried next time: {type(exc).__name__}: {exc}", cid)
    return turns


def _index() -> list:
    path = OUTPUT_ROOT / "index.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError:  # kept for a person to look at, never silently reset
        path.rename(path.with_name(f"index.damaged-{int(time.time())}.json"))
        return []


def _save_index(rows: list) -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT_ROOT / "index.json.tmp"
    tmp.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    os.replace(tmp, OUTPUT_ROOT / "index.json")


def next_targets(n: int) -> list:
    """The least-hunted modules first, in AUTO_TARGETS order among ties."""
    hunted = {}
    for row in _index():
        hunted[row["module"]] = hunted.get(row["module"], 0) + 1
    order = list(dict.fromkeys(AUTO_TARGETS))
    return sorted(order, key=lambda m: (hunted.get(m, 0), order.index(m)))[:n]


def research(forge_for, module: str, properties: int = 4, workers: int = 1, run_dir: Path | None = None,
             unsafe: bool = False, publish_results: bool = False) -> dict:
    check_target(module, unsafe)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run = mf.Run(run_dir or OUTPUT_ROOT / f"{module}-{stamp}")
    run.data.setdefault("module", module)
    run.data.setdefault("environment", environment(module))
    forge = forge_for(run)
    started = time.time()
    mf.rule(module)
    run.stage("main_diff", lambda: main_diff(module))
    props = one_per_target(run.stage("conjectures", lambda: forge.propose(module, properties, workers)))
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(props)))) as pool:
        results = list(pool.map(lambda c: _hunt_safely(forge, c), props))
    run.data["results"] = results
    run.save()
    tally = {}
    for r in results:
        tally[r["status"]] = tally.get(r["status"], 0) + 1
    (run.path / "report.md").write_text(report(module, results), encoding="utf-8")
    mf.log(f"{module} done in {mf._dur(time.time() - started)}: {tally}  ({run.path / 'report.md'})")
    published = publish(run, results) if publish_results else []
    summary = {"module": module, "path": run.path.name, "tally": tally, "environment": environment(module),
               "published": [p["url"] for p in published],
               "finished": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    _save_index([row for row in _index() if row.get("path") != run.path.name] + [summary])
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("modules", nargs="*", help="importable module names to hunt in")
    ap.add_argument("--auto", type=int, metavar="N", help="hunt in the N least-hunted modules of AUTO_TARGETS")
    ap.add_argument("--forever", action="store_true")
    ap.add_argument("--resume", nargs="?", const="latest",
                    help="existing run directory; bare --resume selects the latest saved run, "
                         "finished first with --forever")
    ap.add_argument("--properties", type=int, default=4, help="properties proposed per module")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--provider")
    ap.add_argument("--model")
    ap.add_argument("--review-model")
    ap.add_argument("--effort", choices=mf.EFFORTS, help="work-model reasoning effort; overrides the menu pick")
    ap.add_argument("--review-effort", choices=mf.EFFORTS, help="review-model reasoning effort; overrides the menu pick")
    ap.add_argument("--publish", action="store_true",
                    help=f"push every bug / doc-bug to the PUBLIC GitHub repository {RESULTS_REPO} (needs gh); "
                         "files nothing upstream")
    ap.add_argument("--publish-existing", action="store_true", help="publish qualifying results already on disk and exit")
    ap.add_argument("--unsafe-target", action="store_true",
                    help="allow a module outside AUTO_TARGETS; generated scripts run unsandboxed")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--link", nargs=2, metavar=("FOLDER", "URL"),
                    help="record the upstream issue URL you filed for a published result folder and exit")
    ap.add_argument("--file", action="store_true",
                    help="file published, unfiled results as issues in their project's tracker, as you through gh: "
                         "python/cpython or a popular package's GitHub repository, one open report per project "
                         "at a time. Alone it files and exits, with a hunt it tries after each module. Nobody "
                         "read these")
    ap.add_argument("--track", action="store_true",
                    help="refresh the upstream conversation of every linked result and exit; posts nothing")
    ap.add_argument("--fix", nargs=2, metavar=("RUN", "ID"),
                    help="patch the bug ID (c1, c2, ...) of run directory RUN, keep the patch only if the "
                         "reproducer and the test suite pass, draft the upstream reply, and exit")
    ap.add_argument("--converse", action="store_true",
                    help="take one turn in every upstream thread now and exit. Every hunt does this by itself "
                         "after each module: it finds the issues you filed for published results, and a comment "
                         "there (or on your pull request) that asks or proposes something gets a fresh fix and "
                         f"a reply posted as you through gh, at most {MAX_REPLIES} per issue, until a maintainer "
                         "approves or turns the idea down")
    ap.add_argument("--no-post", action="store_true",
                    help="draft those replies, and the issues of --file, into the run directory; post nothing upstream")
    args = ap.parse_args(argv)
    if args.track:
        mf.log(f"track: {track()} conversation(s) changed")
        return 0
    if args.fix:
        fix_dir = Path(args.fix[0]) if (Path(args.fix[0]) / "state.json").exists() else OUTPUT_ROOT / args.fix[0]
        if not (fix_dir / "state.json").exists():
            ap.error(f"{args.fix[0]}: no such run")
    if args.link:
        error = link_upstream(*args.link)
        if error:
            ap.error(error)
        mf.log(f"linked {args.link[0]} to {args.link[1]}")
        return 0
    if args.publish_existing:  # no model calls: the reports and reproducers are on disk
        count = 0
        for state in sorted(OUTPUT_ROOT.glob("*/state.json")):
            run = mf.Run(state.parent)
            count += len(publish(run, run.data.get("results") or []))
        mf.log(f"publish: {count} result(s) published")
        return 0
    hunting = args.modules or args.auto or args.forever or args.resume
    if args.file and not hunting:
        mf.log(f"file: {len(file_upstream(not args.no_post))} issue(s) {'drafted' if args.no_post else 'filed'}")
        return 0
    if not (hunting or args.fix or args.converse):
        ap.error("give module names, --auto N, --forever, --resume DIR or --publish-existing")
    for m in args.modules:
        try:
            check_target(m, args.unsafe_target)
        except ValueError as exc:
            ap.error(str(exc))
    if args.resume == "latest":
        path = mf.latest_run_dir(OUTPUT_ROOT)
        if path is None:
            ap.error(f"no previous run to resume under {OUTPUT_ROOT}")
        args.resume = str(path)
    if args.resume:
        state = Path(args.resume) / "state.json"
        if not state.exists():
            ap.error(f"{args.resume}: no state.json there")
        try:
            saved = json.loads(state.read_text(encoding="utf-8"))
            module = saved.get("module") if isinstance(saved, dict) else None
            if not isinstance(module, str) or not module:
                raise ValueError("state.json has no valid module recorded")
            check_target(module, args.unsafe_target)
        except (OSError, ValueError) as exc:
            ap.error(f"{args.resume}: cannot resume: {exc}")
    mf.VERBOSE = mf.VERBOSE or args.verbose
    sys.stdout.reconfigure(line_buffering=True)
    mf.exit_on_ctrl_c(message="stopped; finished stages are cached, --resume picks them up")

    sys.path.insert(0, str(MATHFORGE.parent / "seqforge"))
    from seqforge import setup_ai  # the same provider menu and model wiring
    ai = setup_ai(args, OUTPUT_ROOT / "provider_state.json")
    forge_for = lambda run: BugForge(ai, run, None, search=False)  # noqa: E731

    if args.fix:
        try:
            track()  # the fix and the go-ahead read the thread as it is now
        except Exception as exc:
            mf.log(f"track failed: {type(exc).__name__}: {exc}")
        try:
            return 0 if fix_result(forge_for(mf.Run(fix_dir)), args.fix[1]).get("status") == "fixed" else 1
        except ValueError as exc:
            ap.error(str(exc))

    def talk_upstream() -> None:
        # ponytail: every linked issue is read after every module; space it out when there are dozens
        try:
            if args.file:
                file_upstream(not args.no_post)
        except Exception as exc:  # the tracker being down must not stop the hunt
            mf.log(f"file failed: {type(exc).__name__}: {exc}")
        try:
            for name, status in converse(forge_for, not args.no_post).items():
                mf.log(f"upstream {name}: {status}")
        except Exception as exc:  # the tracker being down must not stop the hunt
            mf.log(f"converse failed: {type(exc).__name__}: {exc}")

    talk_upstream()
    if args.resume:
        path = Path(args.resume)
        research(forge_for, module, args.properties, args.workers, path, args.unsafe_target,
                 args.publish)
    for m in args.modules:
        research(forge_for, m, args.properties, args.workers, unsafe=args.unsafe_target, publish_results=args.publish)
        talk_upstream()
    while args.auto or args.forever:
        for m in next_targets(args.auto or 5):
            try:
                research(forge_for, m, args.properties, args.workers, publish_results=args.publish)
            except Exception as exc:
                mf.log(f"{m} failed: {type(exc).__name__}: {exc}")
            talk_upstream()
        if not args.forever:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
