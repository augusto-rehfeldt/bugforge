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
import inspect
import json
import os
import platform
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
MATHFORGE = Path(os.getenv("MATHFORGE_DIR") or HERE.parent / "mathforge")
sys.path.insert(0, str(MATHFORGE))
import mathforge as mf  # noqa: E402

OUTPUT_ROOT = Path(os.getenv("BUGFORGE_OUTPUT") or HERE / "bug_output")
# pure-computation stdlib modules with precise documentation: a promise to test, no side effects
AUTO_TARGETS = ("fractions", "decimal", "statistics", "difflib", "textwrap", "ipaddress", "json", "colorsys",
                "calendar", "datetime", "urllib.parse", "shlex", "base64", "html", "html.parser", "string",
                "email.utils", "email.headerregistry", "configparser", "csv", "heapq", "bisect", "itertools",
                "math", "cmath", "random", "unicodedata", "zlib", "graphlib", "tomllib", "fnmatch",
                "textwrap", "reprlib", "pprint", "plistlib", "quopri", "uu", "wave", "struct", "operator")
# fuzzing these could delete files, start processes, talk to the network or run code
DENIED = ("os", "shutil", "subprocess", "socket", "tempfile", "signal", "multiprocessing", "ctypes",
          "urllib.request", "http", "ftplib", "smtplib", "poplib", "imaplib", "asyncio", "webbrowser", "ssl",
          "sqlite3", "pathlib", "glob", "zipfile", "tarfile", "dbm", "shelve", "pty", "winreg", "msvcrt", "sys",
          "builtins", "importlib", "pickle", "marshal", "code", "runpy", "threading", "concurrent", "io",
          "logging", "mmap", "select", "selectors", "venv", "ensurepip", "site", "sysconfig", "gc", "atexit")
STATUSES = ("bug", "doc-bug", "duplicate", "not-a-bug", "holds", "inconclusive", "error")
GITHUB_SEARCH = "https://api.github.com/search/issues?"


def check_target(module: str) -> None:
    if any(module == d or module.startswith(d + ".") for d in DENIED):
        raise ValueError(f"{module}: refused, its functions have side effects outside the run directory")


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
        try:
            got = self.run.stage(f"conjecture{nth}", lambda: self.ask_json(
                f"You are a senior engineer hunting real bugs in the Python module `{module}`.\n"
                f"Environment: {environment(module)}\n\nPUBLIC API:\n{api(module)}\n\n"
                f"SOURCE (may be truncated):\n```python\n{source(module)}\n```\n\n"
                f"You are proposer {nth} of {count}, working independently; pick a function or area the "
                "others are unlikely to pick. Propose exactly ONE property that the module's DOCUMENTATION "
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
            return got if got.get("statement") else None
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
        top = c.get("target", "").split(".")[0]
        repo = " repo:python/cpython" if top in sys.stdlib_module_names else ""
        try:
            queries = self.ask_json(
                f"Write 3 short GitHub issue-search queries (3-6 words each) that would find an existing "
                f"report of this bug.\nTARGET: {c.get('target', '')}\nPROPERTY: {c['statement']}\n\n"
                'Return ONLY JSON: {"queries": ["...", "...", "..."]}', "queries", model_type="review")["queries"]
        except ValueError:
            queries = [c.get("target", "")]
        hits, errors = [], []
        for q in [str(q) for q in queries][:3]:
            url = GITHUB_SEARCH + urllib.parse.urlencode({"q": f"{q} is:issue{repo}", "per_page": 5})
            try:
                items = json.loads(mf._http_get(url)).get("items") or []
            except Exception as exc:  # rate limited (10/min unauthenticated) or offline
                errors.append(f"{q}: {type(exc).__name__}")
                continue
            hits += [{"title": i.get("title", ""), "url": i.get("html_url", ""), "state": i.get("state", ""),
                      "body": (i.get("body") or "")[:600]} for i in items]
        return {"queries": queries, "hits": hits, "errors": errors}

    def judge(self, c: dict, repro: dict, dupes: dict) -> dict:
        hits = "\n\n".join(f"[{h['state']}] {h['title']}\n{h['url']}\n{h['body']}" for h in dupes["hits"]) or "(none)"
        return self.ask_json(
            "Decide whether a reproduced behaviour is a bug worth reporting. You did not write the "
            "reproducer; read its code and output yourself.\n\n"
            f"TARGET: {c.get('target', '')}\nENVIRONMENT: {environment(c.get('target', ''))}\n"
            f"CLAIMED PROPERTY: {c['statement']}\nDOCUMENTATION CITED: {c.get('spec_basis', '')}\n\n"
            f"REPRODUCER:\n```python\n{repro['code']}\n```\nOUTPUT:\n{repro['output'][-2000:]}\n\n"
            f"EXISTING ISSUES FOUND ({len(dupes['hits'])}):\n{hits}\n\n"
            "Be harsh. NOT_A_BUG if the documentation does not really promise the property, the input "
            "is invalid, the expectation is computed wrongly, or the behaviour is a documented "
            "limitation (floating point rounding the docs warn about, implementation-defined order). "
            "DUPLICATE if an issue above reports the same behaviour. DOC_BUG if the code is reasonable "
            "and the documentation is what is wrong. BUG only if the code breaks a clear documented "
            "promise on a valid input.\n\n"
            'Return ONLY JSON: {"verdict": "BUG"|"DOC_BUG"|"DUPLICATE"|"NOT_A_BUG", "reasoning": "...", '
            '"duplicate_of": "url or empty", "expected": "...", "actual": "...", "issue_title": "a '
            'maintainer-style title", "severity": "low"|"medium"|"high"}',
            "verdict",
            model_type="review",
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
        if r["status"] in ("bug", "doc-bug", "duplicate"):
            j = r.get("judge") or {}
            if j.get("duplicate_of"):
                out += [f"Duplicate of: {j['duplicate_of']}", ""]
            out += [f"### Draft issue: {j.get('issue_title') or r.get('title', '')}", "",
                    f"**Environment:** {environment(module)}", "",
                    f"**Documented behaviour:** {r.get('spec_basis', '')}", "",
                    f"**Expected:** {j.get('expected', '')}", "", f"**Actual:** {j.get('actual', '')}", "",
                    "**Reproducer:**", "", "```python", r["repro"]["code"].strip(), "```", "",
                    "**Output:**", "", "```", r["repro"]["output"].strip()[-1500:], "```", "",
                    f"Judge: {j.get('verdict')} ({j.get('severity', '')}) -- {j.get('reasoning', '')}", ""]
        elif r["status"] == "holds":
            out += [f"Held: {mf._verdict_line(r['falsification']['output'], 200)}", ""]
        elif r.get("error"):
            out += [f"Error: {r['error']}", ""]
    return "\n".join(out) + "\n"


def _index() -> list:
    path = OUTPUT_ROOT / "index.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


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


def research(forge_for, module: str, properties: int = 4, workers: int = 1, run_dir: Path | None = None) -> dict:
    check_target(module)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run = mf.Run(run_dir or OUTPUT_ROOT / f"{module}-{stamp}")
    run.data.setdefault("module", module)
    run.data.setdefault("environment", environment(module))
    forge = forge_for(run)
    started = time.time()
    mf.rule(module)
    props = run.stage("conjectures", lambda: forge.propose(module, properties, workers))
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(props)))) as pool:
        results = list(pool.map(lambda c: _hunt_safely(forge, c), props))
    run.data["results"] = results
    run.save()
    tally = {}
    for r in results:
        tally[r["status"]] = tally.get(r["status"], 0) + 1
    (run.path / "report.md").write_text(report(module, results), encoding="utf-8")
    mf.log(f"{module} done in {mf._dur(time.time() - started)}: {tally}  ({run.path / 'report.md'})")
    summary = {"module": module, "path": run.path.name, "tally": tally, "environment": environment(module),
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
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)
    if not (args.modules or args.auto or args.forever or args.resume):
        ap.error("give module names, --auto N, --forever or --resume DIR")
    for m in args.modules:
        try:
            check_target(m)
        except ValueError as exc:
            ap.error(str(exc))
    mf.VERBOSE = mf.VERBOSE or args.verbose
    sys.stdout.reconfigure(line_buffering=True)
    mf.exit_on_ctrl_c(message="stopped; finished stages are cached, --resume picks them up")

    sys.path.insert(0, str(MATHFORGE.parent / "seqforge"))
    from seqforge import setup_ai  # the same provider menu and model wiring
    ai = setup_ai(args, OUTPUT_ROOT / "provider_state.json")
    forge_for = lambda run: BugForge(ai, run, None, search=False)  # noqa: E731

    if args.resume:
        path = Path(args.resume)
        research(forge_for, mf.Run(path).data["module"], args.properties, args.workers, run_dir=path)
    for m in args.modules:
        research(forge_for, m, args.properties, args.workers)
    while args.auto or args.forever:
        for m in next_targets(args.auto or 5):
            try:
                research(forge_for, m, args.properties, args.workers)
            except Exception as exc:
                mf.log(f"{m} failed: {type(exc).__name__}: {exc}")
        if not args.forever:
            break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
