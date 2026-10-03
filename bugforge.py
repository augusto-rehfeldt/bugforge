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

Nothing is filed anywhere. A confirmed bug gets a drafted issue in report.md for a
person to check and file: maintainers are already flooded with AI reports, and
every one sent should be one a person stands behind.

Generated scripts run unsandboxed in the run directory (as in mathforge), so
modules that touch files, processes, the network or deserialization are refused.
"""
from __future__ import annotations

import argparse
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
# pure-computation stdlib modules with precise documentation: a promise to test, no side effects
AUTO_TARGETS = tuple(m for m in (
    "fractions", "decimal", "statistics", "difflib", "textwrap", "ipaddress", "json", "colorsys", "calendar",
    "datetime", "urllib.parse", "shlex", "base64", "html", "html.parser", "string", "email.utils",
    "email.headerregistry", "configparser", "csv", "heapq", "bisect", "itertools", "math", "cmath", "random",
    "unicodedata", "zlib", "graphlib", "tomllib", "fnmatch", "reprlib", "pprint", "plistlib", "quopri", "wave",
    "struct", "operator") if importlib.util.find_spec(m))  # a module removed from this Python is no target
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


def github(url: str) -> dict:
    """GitHub search, spaced under its per-minute limit across threads, one retry on a limit reply.

    ponytail: spacing is per process; two bugforge processes at once can still hit the limit.
    """
    headers = {"User-Agent": mf.USER_AGENT, "Accept": "application/vnd.github+json"}
    if os.getenv("GITHUB_TOKEN"):  # 30 searches a minute instead of 10; sent only to api.github.com
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    gap = 2.0 if os.getenv("GITHUB_TOKEN") else 6.0
    for attempt in range(2):
        with _GITHUB_LOCK:
            time.sleep(max(0.0, _GITHUB_LAST[0] + gap - time.time()))
            _GITHUB_LAST[0] = time.time()
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
                    return json.loads(response.read().decode("utf-8", "replace"))
            except urllib.error.HTTPError as exc:
                headers = exc.headers or {}
                limited = exc.code == 429 or headers.get("Retry-After") or headers.get("X-RateLimit-Remaining") == "0"
                if not limited or attempt:  # a 403 for a bad token is not waited out
                    raise
                wait = headers.get("Retry-After", "")
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


def environment(module: str) -> str:
    top = module.split(".")[0]
    if top in sys.stdlib_module_names:
        return f"Python {platform.python_version()} ({platform.platform()}), standard library `{module}`"
    try:
        version = importlib.metadata.version(top)
    except importlib.metadata.PackageNotFoundError:
        version = "unknown version"
    return f"Python {platform.python_version()} ({platform.platform()}), `{top}` {version}"


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
        repo = " repo:python/cpython" if module.split(".")[0] in sys.stdlib_module_names else ""
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
        hits, errors = [], []
        for q in [fixed] + queries:
            # pull requests too: a merged fix is the strongest sign it is already handled
            url = GITHUB_SEARCH + urllib.parse.urlencode({"q": q + repo, "per_page": 8})
            try:
                items = github(url).get("items") or []
            except Exception as exc:  # rate limited (10/min unauthenticated) or offline
                errors.append(f"{q}: {type(exc).__name__}: {exc}")
                continue
            for i in items:
                pr = i.get("pull_request")
                body = i.get("body") or ""
                body = body.split("</details>", 1)[-1]  # cpython's bpo-migration header says nothing
                hits.append({"title": i.get("title", ""), "url": i.get("html_url", ""),
                             "kind": "pull request" if pr else "issue",
                             "state": "merged" if pr and pr.get("merged_at") else i.get("state", ""),
                             "body": body.strip()[:600]})
        return {"queries": [fixed] + queries, "hits": hits, "errors": errors}

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


def hunt(forge, c: dict) -> dict:
    """One property: falsify -> reproduce -> duplicate search -> judge."""
    run, cid = forge.run, c["id"]
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
    # a search that failed (GitHub's 10/min limit) left the verdict blind: redo both on resume
    if (run.data.get(f"{cid}.duplicates") or {}).get("errors"):
        with run.lock:
            run.data.pop(f"{cid}.duplicates", None)
            run.data.pop(f"{cid}.judge", None)
    dupes = run.stage(f"{cid}.duplicates", lambda: forge.duplicates(c))
    verdict = run.stage(f"{cid}.judge", lambda: forge.judge(c, repro, dupes))
    status = {"BUG": "bug", "DOC_BUG": "doc-bug", "DUPLICATE": "duplicate"}.get(verdict.get("verdict"), "not-a-bug")
    return {**c, "status": status, "falsification": found, "repro": repro, "duplicates": dupes, "judge": verdict}


def _hunt_safely(forge, c: dict) -> dict:
    try:
        return hunt(forge, c)
    except Exception as exc:  # one property must not cost the run; nothing cached, a rerun retries
        mf.log(f"  error — {type(exc).__name__}: {exc}", c["id"])
        return {**c, "status": "error", "error": f"{type(exc).__name__}: {exc}"}


def report(module: str, results: list) -> str:
    out = [f"# bugforge: `{module}`", "", environment(module), "",
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
                    f"**Environment:** {environment(module)}", "",
                    f"**Documented behaviour:** {r.get('spec_basis', '')}", "",
                    f"**Expected:** {j.get('expected', '')}", "", f"**Actual:** {j.get('actual', '')}", "",
                    "**Reproducer:**", "", "```python", r["repro"]["code"].strip(), "```", "",
                    *([f"WARNING: the tracker search was incomplete ({'; '.join(r['duplicates']['errors'])}); "
                       "search it by hand before filing.", ""] if (r.get("duplicates") or {}).get("errors") else []),
                    "**Output:**", "", "```", r["repro"]["output"].strip()[-1500:], "```", "",
                    f"Judge: {j.get('verdict')} ({j.get('severity', '')}) -- {j.get('reasoning', '')}", ""]
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
             "output on the Python version named. No person reviewed these before publication; upstream "
             "reports are filed by hand, and a result is linked to its issue once filed.", "",
             f"{len(rows)} result(s).", "",
             "| Date | Target | Verdict | Title | Python | Upstream |", "| --- | --- | --- | --- | --- | --- |"]
    for m in rows:
        title = m.get("title", "").replace("|", "\\|")
        lines.append(f"| {m.get('date', '')} | `{m.get('target', '')}` | {m.get('status', '')} | "
                     f"[{title}]({m['folder']}/) | {m.get('python', '')} | {m.get('upstream') or 'not filed'} |")
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
            (folder / "README.md").write_text(report(module, [r]), encoding="utf-8")
            title = (r.get("judge") or {}).get("issue_title") or r.get("title", r["id"])
            meta = folder / "result.json"
            upstream = json.loads(meta.read_text(encoding="utf-8")).get("upstream") if meta.exists() else None
            meta.write_text(json.dumps({
                "folder": folder.name, "status": r["status"], "target": r.get("target", ""), "title": title,
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "python": platform.python_version(),
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
        if r["status"] not in PUBLISH_STATUSES:
            continue
        key = f"{r['id']}.published"
        info = run.data.get(key) or {}
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
    ap.add_argument("--resume", help="an existing run directory under bug_output")
    ap.add_argument("--properties", type=int, default=4, help="properties proposed per module")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--provider")
    ap.add_argument("--model")
    ap.add_argument("--review-model")
    ap.add_argument("--publish", action="store_true",
                    help=f"push every bug / doc-bug to the PUBLIC GitHub repository {RESULTS_REPO} (needs gh); "
                         "files nothing upstream")
    ap.add_argument("--publish-existing", action="store_true", help="publish qualifying results already on disk and exit")
    ap.add_argument("--unsafe-target", action="store_true",
                    help="allow a module outside AUTO_TARGETS; generated scripts run unsandboxed")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    if args.publish_existing:  # no model calls: the reports and reproducers are on disk
        count = 0
        for state in sorted(OUTPUT_ROOT.glob("*/state.json")):
            run = mf.Run(state.parent)
            count += len(publish(run, run.data.get("results") or []))
        mf.log(f"publish: {count} result(s) published")
        return 0
    if not (args.modules or args.auto or args.forever or args.resume):
        ap.error("give module names, --auto N, --forever, --resume DIR or --publish-existing")
    for m in args.modules:
        try:
            check_target(m, args.unsafe_target)
        except ValueError as exc:
            ap.error(str(exc))
    if args.resume and not (Path(args.resume) / "state.json").exists():
        ap.error(f"{args.resume}: no state.json there")
    mf.VERBOSE = mf.VERBOSE or args.verbose
    sys.stdout.reconfigure(line_buffering=True)
    mf.exit_on_ctrl_c(message="stopped; finished stages are cached, --resume picks them up")

    sys.path.insert(0, str(MATHFORGE.parent / "seqforge"))
    from seqforge import setup_ai  # the same provider menu and model wiring
    ai = setup_ai(args, OUTPUT_ROOT / "provider_state.json")
    forge_for = lambda run: BugForge(ai, run, None, search=False)  # noqa: E731

    if args.resume:
        path = Path(args.resume)
        research(forge_for, mf.Run(path).data["module"], args.properties, args.workers, path, args.unsafe_target,
                 args.publish)
    for m in args.modules:
        research(forge_for, m, args.properties, args.workers, unsafe=args.unsafe_target, publish_results=args.publish)
    while args.auto or args.forever:
        for m in next_targets(args.auto or 5):
            try:
                research(forge_for, m, args.properties, args.workers, publish_results=args.publish)
            except Exception as exc:
                mf.log(f"{m} failed: {type(exc).__name__}: {exc}")
        if not args.forever:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
