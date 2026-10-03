"""Offline checks for bugforge: no network, no model calls, temporary output."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bugforge as bf
import sys
sys.path.insert(0, str(bf.MATHFORGE.parent / "seqforge"))
import seqforge

_real_gh_token = bf._gh_token
bf._gh_token = lambda: ""  # offline: the search tests must not ask the gh CLI for a login


class StubAI:
    def __init__(self, replies):
        self.replies, self.prompts = list(replies), []

    def generate_content(self, prompt, **kwargs):
        self.prompts.append(prompt)
        return self.replies.pop(0)


def _ran(output, code="print()"):
    return {"code": code, "exit_code": 0, "output": output, "repairs": 0, "model": "m"}


class BugforgeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        for name, value in (("OUTPUT_ROOT", self.tmp), ("main_diff", lambda module: "")):  # offline
            patcher = mock.patch.object(bf, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_bare_resume_selects_latest_saved_run_before_forever(self):
        import os
        old = bf.mf.Run(self.tmp / "old")
        old.data.update(module="json")
        old.save()
        latest = bf.mf.Run(self.tmp / "completed")
        latest.data.update(module="fractions", results=[])
        latest.save()
        scratch = bf.mf.Run(self.tmp / "_scratch")
        scratch.save()
        for run, stamp in ((old, 10), (latest, 20), (scratch, 30)):
            os.utime(run.path / "state.json", (stamp, stamp))
        with mock.patch.object(seqforge, "setup_ai"), mock.patch.object(bf.sys, "stdout"), \
                mock.patch.object(bf.mf, "exit_on_ctrl_c"), mock.patch.object(bf, "research") as research, \
                mock.patch.object(bf, "next_targets", side_effect=[["json"], KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt):
                bf.main(["--resume", "--forever"])
        self.assertEqual(research.call_args_list[0].args[1], "fractions")
        self.assertEqual(research.call_args_list[0].args[4], latest.path)
        self.assertEqual(research.call_args_list[1].args[1], "json")

    def test_bare_resume_without_runs_fails_before_ai_setup(self):
        with mock.patch.object(seqforge, "setup_ai") as setup, mock.patch.object(bf.sys, "stderr"):
            with self.assertRaises(SystemExit) as stopped:
                bf.main(["--resume"])
        self.assertEqual(stopped.exception.code, 2)
        setup.assert_not_called()

    def test_explicit_resume_path_is_preserved_and_efforts_are_parsed(self):
        path = self.tmp / "older"
        run = bf.mf.Run(path)
        run.data.update(module="json")
        run.save()
        with mock.patch.object(seqforge, "setup_ai") as setup, mock.patch.object(bf.sys, "stdout"), \
                mock.patch.object(bf.mf, "exit_on_ctrl_c"), mock.patch.object(bf, "research") as research:
            self.assertEqual(bf.main(["--resume", str(path), "--effort", "low", "--review-effort", "high"]), 0)
        self.assertEqual(research.call_args.args[4], path)
        self.assertEqual((setup.call_args.args[0].effort, setup.call_args.args[0].review_effort), ("low", "high"))

    def test_unusable_resume_state_fails_before_ai_setup_without_mutation(self):
        path = self.tmp / "broken"
        path.mkdir()
        state = path / "state.json"
        for content in ('{', '{}', '[]', '{"module": null}', '{"module": 7}',
                        '{"module": ""}', '{"module": "os"}', '{"module": "antigravity"}'):
            for resume in (["--resume"], ["--resume", str(path)]):
                with self.subTest(content=content, resume=resume):
                    state.write_text(content, encoding="utf-8")
                    with mock.patch.object(seqforge, "setup_ai") as setup, \
                            mock.patch.object(bf.sys, "stdout"), mock.patch.object(bf.sys, "stderr"), \
                            mock.patch.object(bf.mf, "exit_on_ctrl_c"):
                        with self.assertRaises(SystemExit) as stopped:
                            bf.main(resume)
                    self.assertEqual(stopped.exception.code, 2)
                    setup.assert_not_called()
                    self.assertEqual(state.read_text(encoding="utf-8"), content)

    def test_resume_preserves_unsafe_target_opt_in(self):
        run = bf.mf.Run(self.tmp / "unsafe")
        run.data["module"] = "antigravity"
        run.save()
        with mock.patch.object(seqforge, "setup_ai"), mock.patch.object(bf.sys, "stdout"), \
                mock.patch.object(bf.mf, "exit_on_ctrl_c"), mock.patch.object(bf, "research") as research:
            self.assertEqual(bf.main(["--resume", str(run.path), "--unsafe-target"]), 0)
        self.assertEqual(research.call_args.args[1], "antigravity")
        self.assertTrue(research.call_args.args[5])

    def test_invalid_efforts_fail_before_ai_setup(self):
        for flag in ("--effort", "--review-effort"):
            with self.subTest(flag=flag), mock.patch.object(seqforge, "setup_ai") as setup, \
                    mock.patch.object(bf.sys, "stderr"):
                with self.assertRaises(SystemExit) as stopped:
                    bf.main(["json", flag, "invalid"])
                self.assertEqual(stopped.exception.code, 2)
                setup.assert_not_called()

    def test_modules_with_side_effects_are_refused(self):
        for name in ("os", "os.path", "shutil", "pickle", "urllib.request", "subprocess", "sys"):
            with self.assertRaises(ValueError, msg=name):
                bf.check_target(name)
        for name in ("fractions", "urllib.parse", "json", "difflib"):
            bf.check_target(name)

    def test_only_vetted_modules_unless_unsafe_is_asked_for(self):
        for name in ("antigravity", "nt", "_winapi", "gzip", "pydoc"):
            with self.assertRaises(ValueError, msg=name):
                bf.check_target(name)
        bf.check_target("gzip", unsafe=True)
        with self.assertRaises(ValueError):
            bf.check_target("os", unsafe=True)  # denied even then

    def test_auto_targets_exist_on_this_python(self):
        self.assertNotIn("uu", bf.AUTO_TARGETS)  # removed in 3.13
        self.assertEqual(len(bf.AUTO_TARGETS), len(set(bf.AUTO_TARGETS)))

    def test_proposers_get_disjoint_api_slices_and_earlier_properties(self):
        ai = StubAI(['{"title": "t", "target": "fractions.Fraction", "statement": "p"}'])
        run = bf.mf.Run(self.tmp / "fractions-old")
        run.data.update(module="fractions", results=[{"statement": "Fraction.__format__ honours the int-str limit"}])
        run.save()
        forge = bf.BugForge(ai, bf.mf.Run(self.tmp / "p"), None, search=False)
        forge.propose_one("fractions", 2, 3)
        self.assertIn("YOUR ASSIGNED NAMES", ai.prompts[0])
        self.assertIn("int-str limit", ai.prompts[0])

    def test_one_property_per_target(self):
        props = [{"id": "c1", "target": "a.f"}, {"id": "c2", "target": "a.f"}, {"id": "c3", "target": "a.g"}]
        self.assertEqual([c["id"] for c in bf.one_per_target(props)], ["c1", "c3"])

    def test_api_lists_public_callables_with_signatures(self):
        listing = bf.api("fractions")
        self.assertIn("Fraction", listing)
        self.assertNotIn("_gcd", listing)
        self.assertIn("limit_denominator(", listing)

    def test_hunt_outcomes(self):
        c = {"id": "c1", "target": "fractions.Fraction", "statement": "p", "spec_basis": "doc"}
        forge = mock.Mock()
        forge.run = bf.mf.Run(self.tmp / "h")
        forge.duplicates.return_value = {"queries": ["q"], "hits": [], "errors": []}
        forge.prior.return_value = {"verdict": "NEW"}
        forge.falsify.return_value = _ran("NO COUNTEREXAMPLE after 5000 cases")
        self.assertEqual(bf.hunt(forge, c)["status"], "holds")

        forge.run = bf.mf.Run(self.tmp / "h2")
        forge.falsify.return_value = _ran("COUNTEREXAMPLE: x=1")
        forge.confirm_refutation.return_value = _ran("REFUTATION REJECTED: outside the input space")
        self.assertEqual(bf.hunt(forge, c)["status"], "inconclusive")

        forge.run = bf.mf.Run(self.tmp / "h3")
        forge.confirm_refutation.return_value = _ran("REFUTATION CONFIRMED: x=1", code="import fractions")
        forge.judge.return_value = {"verdict": "BUG", "expected": "e", "actual": "a"}
        r = bf.hunt(forge, c)
        self.assertEqual(r["status"], "bug")
        self.assertEqual(r["repro"]["code"], "import fractions")

        forge.run = bf.mf.Run(self.tmp / "h4")
        forge.judge.return_value = {"verdict": "NOT_A_BUG"}
        self.assertEqual(bf.hunt(forge, c)["status"], "not-a-bug")

    def test_duplicates_search_cpython_issues_and_prs_for_stdlib(self):
        ai = StubAI(['{"queries": "Fraction limit_denominator negative"}'])  # a string, not a list
        run = bf.mf.Run(self.tmp / "d")
        run.data["module"] = "fractions"
        forge = bf.BugForge(ai, run, None, search=True)
        body = "BPO | 1\nNosy | x\n</details>\n\nreal text"
        page = {"items": [{"title": "limit_denominator wrong", "html_url": "https://github.com/python/cpython/pull/1",
                           "state": "closed", "pull_request": {"merged_at": "2026"}, "body": body + "x" * 2000}]}
        with mock.patch.object(bf, "github", return_value=page) as get:
            found = forge.duplicates({"target": "Fraction.limit_denominator", "statement": "p",
                                      "spec_basis": "'limit_denominator() finds the closest Fraction' in the docs"})
        urls = [call[0][0] for call in get.call_args_list]
        self.assertTrue(all("repo%3Apython%2Fcpython" in u and "is%3Aissue" not in u for u in urls))
        self.assertTrue(any("limit_denominator" in u and "closest+Fraction" in u for u in urls))  # the fixed query
        self.assertIn("Fraction+limit_denominator+negative", urls[-1])
        hit = found["hits"][0]
        self.assertEqual((hit["kind"], hit["state"]), ("pull request", "merged"))
        self.assertTrue(hit["body"].startswith("real text"))
        self.assertLessEqual(len(hit["body"]), 600)

    def test_failed_duplicate_search_is_redone_on_resume_and_shown_to_the_judge(self):
        c = {"id": "c1", "target": "fractions.Fraction", "statement": "p"}
        forge = mock.Mock()
        forge.run = bf.mf.Run(self.tmp / "r")
        forge.falsify.return_value = _ran("COUNTEREXAMPLE: x=1")
        forge.confirm_refutation.return_value = _ran("REFUTATION CONFIRMED: x=1")
        forge.duplicates.return_value = {"queries": ["q"], "hits": [], "errors": ["q: HTTPError"]}
        forge.prior.return_value = {"verdict": "NEW"}
        forge.judge.return_value = {"verdict": "BUG"}
        bf.hunt(forge, c)
        bf.hunt(forge, c)
        self.assertEqual(forge.duplicates.call_count, 2)
        self.assertEqual(forge.prior.call_count, 2)  # a blind prior-art verdict is redone too

    def test_judge_runs_on_the_work_model_with_search_errors(self):
        ai = StubAI(['{"verdict": "NOT_A_BUG"}'])
        forge = bf.BugForge(ai, bf.mf.Run(self.tmp / "j"), None, search=False)
        seen = {}
        ai.generate_content = lambda prompt, **kw: seen.update(kw, prompt=prompt) or '{"verdict": "NOT_A_BUG"}'
        forge.judge({"target": "fractions.Fraction", "statement": "p"}, _ran("REFUTATION CONFIRMED"),
                    {"hits": [], "errors": ["q: HTTPError 403"]})
        self.assertEqual(seen["model_type"], "writing")
        self.assertIn("HTTPError 403", seen["prompt"])

    def test_research_writes_a_draft_issue_and_never_files_it(self):
        bug = {"id": "c1", "title": "Fraction rounds wrong", "target": "fractions.Fraction", "statement": "p",
               "spec_basis": "the docs say so", "status": "bug",
               "repro": _ran("REFUTATION CONFIRMED: got 1, expected 2", code="from fractions import Fraction"),
               "judge": {"verdict": "BUG", "expected": "2", "actual": "1"}}
        forge = mock.Mock()
        forge.propose.return_value = [{"id": "c1", "statement": "p", "target": "fractions.Fraction"},
                                      {"id": "c2", "statement": "q", "target": "fractions.gcd"}]
        outcomes = iter([bug, {"id": "c2", "statement": "q", "status": "holds",
                                    "falsification": _ran("NO COUNTEREXAMPLE in 900 cases")}])
        with mock.patch.object(bf, "hunt", side_effect=lambda f, c: next(outcomes)):
            summary = bf.research(lambda run: forge, "fractions", properties=2, workers=2)
        self.assertEqual(summary["tally"], {"bug": 1, "holds": 1})
        report = next(self.tmp.glob("fractions-*/report.md")).read_text(encoding="utf-8")
        self.assertIn("from fractions import Fraction", report)
        self.assertIn("Python " + bf.platform.python_version(), report)
        self.assertIn("not filed", report)
        self.assertIn("NO COUNTEREXAMPLE in 900 cases", report)
        self.assertEqual(bf.next_targets(1), [m for m in bf.AUTO_TARGETS if m != "fractions"][:1])



class BugforgeRobustnessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        patcher = mock.patch.object(bf, "OUTPUT_ROOT", self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_single_class_modules_still_get_disjoint_slices(self):
        names = bf._names("fractions")
        self.assertIn("Fraction.limit_denominator", names)
        self.assertGreater(len(names), 4)

    def test_a_damaged_old_state_does_not_stop_new_runs(self):
        (self.tmp / "fractions-old").mkdir()
        (self.tmp / "fractions-old" / "state.json").write_text("{broken", encoding="utf-8")
        (self.tmp / "fractions-list").mkdir()
        (self.tmp / "fractions-list" / "state.json").write_text("[]", encoding="utf-8")
        self.assertEqual(bf.earlier_properties("fractions", self.tmp / "new"), [])

    def test_github_rate_limit_is_waited_out_once(self):
        import io
        import urllib.error
        limited = urllib.error.HTTPError("u", 403, "rate limit exceeded", {"Retry-After": "7"}, io.BytesIO(b""))
        ok = mock.MagicMock()
        ok.__enter__.return_value.read.return_value = b'{"items": []}'
        sleeps = []
        with mock.patch.object(bf.urllib.request, "urlopen", side_effect=[limited, ok]), \
                mock.patch.object(bf.time, "sleep", sleeps.append):
            self.assertEqual(bf.github("https://api.github.com/search/issues?q=x"), {"items": []})
        self.assertIn(7, sleeps)
        denied = urllib.error.HTTPError("u", 403, "bad credentials", {}, io.BytesIO(b""))
        with mock.patch.object(bf.urllib.request, "urlopen", side_effect=[denied]), \
                mock.patch.object(bf.time, "sleep", sleeps.append), self.assertRaises(urllib.error.HTTPError):
            bf.github("https://api.github.com/search/issues?q=x")

    def test_an_incomplete_tracker_check_is_said_in_the_draft(self):
        bug = {"id": "c1", "title": "t", "target": "statistics.kde", "statement": "p", "status": "bug",
               "repro": _ran("REFUTATION CONFIRMED"), "judge": {"verdict": "BUG"},
               "duplicates": {"hits": [], "errors": ["kde overflow: HTTPError 403"]}}
        self.assertIn("tracker search was incomplete", bf.report("statistics", [bug]))

    def test_fixed_query_ignores_apostrophes(self):
        ai = StubAI(['{"queries": []}'])
        run = bf.mf.Run(self.tmp / "q")
        run.data["module"] = "statistics"
        forge = bf.BugForge(ai, run, None, search=True)
        with mock.patch.object(bf, "github", return_value={"items": []}) as get:
            forge.duplicates({"target": "statistics.kde", "statement": "p",
                              "spec_basis": "Python's docs say: \"Create a continuous probability density function\""})
        self.assertIn("Create+a+continuous", get.call_args_list[0][0][0])


class BugforgePublishTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.checkout = self.tmp / "results"
        self.checkout.mkdir()
        self.calls = []

        def gh(*args, cwd=None, timeout=180):
            self.calls.append(args)
            return bf.subprocess.CompletedProcess(args, 0, "", "")
        for obj, name, value in ((bf, "OUTPUT_ROOT", self.tmp), (bf.mf, "_gh", gh),
                                 (bf, "_checkout", lambda: ("u/bugforge-results", self.checkout))):
            patcher = mock.patch.object(obj, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_only_confirmed_bugs_are_published_once_with_their_reproducer(self):
        run = bf.mf.Run(self.tmp / "statistics-20261003-010644")
        run.data["module"] = "statistics"
        (run.path / "c1_repro.py").write_text("import statistics", encoding="utf-8")
        bug = {"id": "c1", "title": "kde overflows", "target": "statistics.kde", "statement": "p", "status": "bug",
               "repro": _ran("REFUTATION CONFIRMED", code="import statistics"),
               "judge": {"verdict": "BUG", "issue_title": "statistics.kde logistic kernel overflows"}}
        held = {"id": "c2", "target": "statistics.mean", "statement": "q", "status": "holds",
                "falsification": _ran("NO COUNTEREXAMPLE")}
        with mock.patch.object(bf.shutil, "which", return_value="x"):
            got = bf.publish(run, [bug, held])
            again = bf.publish(run, [bug, held])
        self.assertEqual([g["url"] for g in got], ["https://github.com/u/bugforge-results/tree/main/statistics-20261003-010644-c1"])
        self.assertEqual(again, got)
        self.assertEqual(sum(1 for c in self.calls if c[:2] == ("git", "push")), 1)
        folder = self.checkout / "statistics-20261003-010644-c1"
        self.assertIn("import statistics", (folder / "README.md").read_text(encoding="utf-8"))
        self.assertTrue((folder / "c1_repro.py").exists())
        index = (self.checkout / "README.md").read_text(encoding="utf-8")
        self.assertIn("statistics.kde logistic kernel overflows", index)
        self.assertIn("not filed", index)
        readme = (folder / "README.md").read_text(encoding="utf-8")
        self.assertIn("not reviewed by a person", readme.splitlines()[0])

    def test_unchecked_duplicates_are_held_back_and_stale_urls_flagged(self):
        run = bf.mf.Run(self.tmp / "difflib-20261003-011733")
        run.data.update(module="difflib", environment="Python 3.13.1 (old), standard library `difflib`")
        blind = {"id": "c2", "target": "difflib.ndiff", "statement": "p", "status": "bug",
                 "repro": _ran("REFUTATION CONFIRMED"), "judge": {"verdict": "BUG"},
                 "duplicates": {"hits": [], "errors": ["q: HTTPError 403"]}}
        with mock.patch.object(bf.shutil, "which", return_value="x"):
            self.assertEqual(bf.publish(run, [blind]), [])
        run.data["c3.published"] = {"url": "https://github.com/u/r/tree/main/difflib-c3"}
        stale = {"id": "c3", "target": "difflib.HtmlDiff", "statement": "q", "status": "duplicate"}
        with mock.patch.object(bf.mf, "log") as log:
            bf.publish(run, [stale])
        self.assertIn("no longer qualifies", log.call_args[0][0])

    def test_low_severity_is_held_back_and_a_filed_issue_is_linked(self):
        run = bf.mf.Run(self.tmp / "heapq-20261003-022813")
        run.data["module"] = "heapq"
        low = {"id": "c1", "target": "heapq.merge", "statement": "p", "status": "bug",
               "repro": _ran("REFUTATION CONFIRMED"), "judge": {"verdict": "BUG", "severity": "low"}}
        medium = {**low, "id": "c2", "judge": {"verdict": "BUG", "severity": "medium", "issue_title": "merge breaks"}}
        with mock.patch.object(bf.shutil, "which", return_value="x"):
            got = bf.publish(run, [low, medium])
        self.assertEqual([g["url"].rsplit("/", 1)[-1] for g in got], ["heapq-20261003-022813-c2"])
        url = "https://github.com/python/cpython/issues/158631"
        self.assertEqual(bf.link_upstream("heapq-20261003-022813-c2", url), "")
        self.assertIn(f"[cpython#158631]({url})", (self.checkout / "README.md").read_text(encoding="utf-8"))
        self.assertIn("no such published result", bf.link_upstream("heapq-nope", url))

    def test_track_records_the_upstream_thread_and_shows_its_state(self):
        run = bf.mf.Run(self.tmp / "statistics-20261003-010644")
        run.data["module"] = "statistics"
        run.save()
        folder = self.checkout / "statistics-c1"
        folder.mkdir()
        (folder / "result.json").write_text(json.dumps({
            "folder": "statistics-c1", "run": run.path.name, "id": "c1", "title": "kde overflows",
            "upstream": "[cpython#158631](https://github.com/python/cpython/issues/158631)"}), encoding="utf-8")
        (self.checkout / "unfiled").mkdir()
        (self.checkout / "unfiled" / "result.json").write_text(json.dumps({"folder": "unfiled", "upstream": None}),
                                                               encoding="utf-8")
        comments = [{"user": {"login": "picnixz"}, "author_association": "MEMBER", "created_at": "d",
                     "body": "how are performances affected?"}]
        def replies(url):
            if "/pulls/" in url:
                return {"state": "closed", "user": {"login": "someone"}, "html_url": "https://github.com/python/cpython/pull/158632"}
            return comments if url.endswith("per_page=100") else {
                "state": "open", "comments": 1, "user": {"login": "me"}, "body": "bug\n### Linked PRs\n* gh-158632\n"}
        with mock.patch.object(bf, "github", side_effect=replies) as get, mock.patch.object(bf.mf, "log") as log:
            self.assertEqual(bf.track(), 1)
            self.assertEqual(bf.track(), 0)  # nothing new: no commit
        self.assertIn("api.github.com/repos/python/cpython/issues/158631", get.call_args_list[0][0][0])
        self.assertIn("new comment by picnixz (MEMBER)", log.call_args_list[0][0][0])
        self.assertIn("(open, 1 comment(s))", (self.checkout / "README.md").read_text(encoding="utf-8"))
        responses = (self.tmp / "responses.md").read_text(encoding="utf-8")
        self.assertEqual(responses.count("how are performances affected?"), 1)  # logged once, not per call
        talk = bf.mf.Run(run.path).data["c1.conversation"]
        self.assertEqual(talk["comments"][0]["body"], "how are performances affected?")
        self.assertEqual((talk["reporter"], talk["prs"][0]["state"]), ("me", "closed"))
        self.assertIn("not you", bf.pull_request_advice(talk, "me")[0])  # another person's PR is not ours to reopen
        self.assertIn("gh pr reopen", bf.pull_request_advice(talk, "someone")[0])
        self.assertIn("open one from the fix", bf.pull_request_advice({}, "me")[0])
        self.assertEqual(sum(1 for c in self.calls if c[:2] == ("git", "push")), 1)

    def test_a_fix_is_kept_only_when_the_reproducer_passes_and_the_thread_steers_it(self):
        (self.tmp / "bfbuggy.py").write_text("def double(x):\n    return x + x + 1\n", encoding="utf-8")
        sys.path.insert(0, str(self.tmp))
        self.addCleanup(sys.path.remove, str(self.tmp))
        run = bf.mf.Run(self.tmp / "bfbuggy-20261003-010644")
        repro = ("import bfbuggy\n"
                 "print('REFUTATION REJECTED: ok' if bfbuggy.double(2) == 4 else 'REFUTATION CONFIRMED: 5')\n")
        (run.path / "c1_repro.py").write_text(repro, encoding="utf-8")
        bug = {"id": "c1", "target": "bfbuggy.double", "statement": "double(x) == 2*x", "status": "bug",
               "repro": _ran("REFUTATION CONFIRMED: 5", code=repro), "judge": {"verdict": "BUG"}}
        run.data.update(module="bfbuggy", results=[bug])
        run.data["c1.conversation"] = {"comments": [{"author": "m", "role": "MEMBER", "date": "d",
                                                     "body": "keep the fast path"}]}
        block = "<<<<<<< SEARCH\n    return x + x + 1\n=======\n    return {}\n>>>>>>> REPLACE"
        ai = StubAI(["I would change the return.", block.format("x * 3"), block.format("x + x"), "Done as asked.",
                     '{"verdict": "WAIT", "reasoning": "the benchmark is unanswered"}'])
        with mock.patch.object(bf.mf, "log") as log:
            fixed = bf.fix_result(bf.BugForge(ai, run, None, search=False), "c1")
        self.assertIn("hold the pull request: the benchmark is unanswered", log.call_args_list[-1][0][0])
        self.assertIn("m (MEMBER)", ai.prompts[4])
        run.data["c1.conversation"]["prs"] = [{"url": "u", "author": "", "state": "closed"}]
        ai.replies += [block.format("x + x"), "Done as asked.", '{"verdict": "APPROVED", "reasoning": "asked for the PR"}']
        with mock.patch.object(bf.mf, "log") as log:
            bf.fix_result(bf.BugForge(ai, run, None, search=False), "c1")
        self.assertIn("maintainers agreed; reopen your pull request: gh pr reopen u", log.call_args_list[-1][0][0])
        self.assertEqual((fixed["status"], fixed["repairs"]), ("fixed", 2))
        self.assertIn("+    return x + x\n", (run.path / "c1_fix.diff").read_text(encoding="utf-8"))
        self.assertIn("keep the fast path", ai.prompts[0])
        self.assertIn("no SEARCH/REPLACE block", ai.prompts[1])
        self.assertIn("still reports the bug", ai.prompts[2])
        self.assertEqual((run.path / "c1_reply.md").read_text(encoding="utf-8"), "Done as asked.")
        with self.assertRaises(ValueError):
            bf.fix_result(bf.BugForge(StubAI([]), run, None, search=False), "c9")
        with self.assertRaises(ValueError):
            bf.apply_edits("a = 1\na = 1\n", "<<<<<<< SEARCH\na = 1\n=======\na = 2\n>>>>>>> REPLACE")

    def test_gh_login_is_the_fallback_search_token(self):
        self.calls.clear()
        _real_gh_token.cache_clear()
        with mock.patch.object(bf.shutil, "which", return_value=None):
            self.assertEqual(_real_gh_token(), "")
        _real_gh_token.cache_clear()
        with mock.patch.object(bf.shutil, "which", return_value="x"):
            self.assertEqual(_real_gh_token(), "")  # the stub gh prints nothing
        self.assertEqual(self.calls, [("gh", "auth", "token")])
        _real_gh_token.cache_clear()

    def test_published_report_names_the_environment_of_the_run(self):
        r = {"id": "c1", "target": "statistics.kde", "statement": "p", "status": "bug",
             "repro": _ran("REFUTATION CONFIRMED"), "judge": {"verdict": "BUG"}}
        text = bf.report("statistics", [r], environment_line="Python 3.13.1 (old), standard library `statistics`")
        self.assertIn("Python 3.13.1 (old)", text)
        self.assertNotIn(bf.platform.platform(), text)


class BugforgePriorArtTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        patcher = mock.patch.object(bf, "OUTPUT_ROOT", self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_known_report_stops_the_hunt_before_any_search_is_written(self):
        forge = mock.Mock()
        forge.run = bf.mf.Run(self.tmp / "k")
        forge.duplicates.return_value = {"queries": ["q"], "hits": [{"url": "https://github.com/python/cpython/issues/9"}],
                                         "errors": []}
        forge.prior.return_value = {"verdict": "KNOWN", "known_as": "https://github.com/python/cpython/issues/9"}
        r = bf.hunt(forge, {"id": "c1", "target": "statistics.kde", "statement": "p"})
        self.assertEqual(r["status"], "known")
        forge.falsify.assert_not_called()
        self.assertIn("issues/9", bf.report("statistics", [r]))

    def test_the_tracker_search_is_shared_by_both_judges(self):
        forge = mock.Mock()
        forge.run = bf.mf.Run(self.tmp / "s")
        forge.duplicates.return_value = {"queries": ["q"], "hits": [], "errors": []}
        forge.prior.return_value = {"verdict": "NEW"}
        forge.falsify.return_value = _ran("COUNTEREXAMPLE: x=1")
        forge.confirm_refutation.return_value = _ran("REFUTATION CONFIRMED: x=1")
        forge.judge.return_value = {"verdict": "BUG"}
        self.assertEqual(bf.hunt(forge, {"id": "c1", "target": "statistics.kde", "statement": "p"})["status"], "bug")
        self.assertEqual(forge.duplicates.call_count, 1)

    def test_main_branch_diff_for_stdlib_modules(self):
        local = bf.inspect.getsource(bf.importlib.import_module("colorsys"))
        upstream = local.replace("def rgb_to_yiq(r, g, b):", "def rgb_to_yiq(r, g, b):  # fixed upstream")
        with mock.patch.object(bf.mf, "_http_get", return_value=upstream) as get:
            diff = bf.main_diff("colorsys")
        self.assertIn("Lib/colorsys.py", get.call_args[0][0])
        self.assertIn("+def rgb_to_yiq(r, g, b):  # fixed upstream", diff)
        with mock.patch.object(bf.mf, "_http_get", return_value=local):
            self.assertIn("identical", bf.main_diff("colorsys"))
        self.assertEqual(bf.main_diff("not_a_stdlib_module_xyz"), "")

    def test_prior_judge_sees_hits_and_the_main_diff(self):
        seen = {}
        ai = StubAI([])
        ai.generate_content = lambda prompt, **kw: seen.update(kw, prompt=prompt) or '{"verdict": "NEW"}'
        run = bf.mf.Run(self.tmp / "p")
        run.data["main_diff"] = "+    return 1.0  # overflow fixed"
        forge = bf.BugForge(ai, run, None, search=False)
        forge.prior({"target": "statistics.kde", "statement": "p"},
                    {"hits": [{"title": "kde overflow", "url": "u", "state": "open", "kind": "issue", "body": ""}],
                     "errors": []})
        self.assertIn("kde overflow", seen["prompt"])
        self.assertIn("overflow fixed", seen["prompt"])
        self.assertEqual(seen["model_type"], "writing")


class BugforgeGateReviewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        patcher = mock.patch.object(bf, "OUTPUT_ROOT", self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _forge(self, name, prior):
        forge = mock.Mock()
        forge.run = bf.mf.Run(self.tmp / name)
        forge.duplicates.return_value = {"queries": ["q"], "errors": [],
                                         "hits": [{"url": "https://github.com/python/cpython/issues/9"}]}
        forge.prior.return_value = prior
        forge.falsify.return_value = _ran("NO COUNTEREXAMPLE in 10 cases")
        return forge

    def test_known_needs_a_cited_tracker_hit_not_an_opinion_about_the_diff(self):
        c = {"id": "c1", "target": "base64.b64decode", "statement": "p"}
        forge = self._forge("a", {"verdict": "KNOWN", "known_as": "the upstream change"})
        self.assertEqual(bf.hunt(forge, c)["status"], "holds")  # went on to the executable search
        forge = self._forge("b", {"verdict": "KNOWN", "known_as": "https://github.com/python/cpython/issues/9"})
        self.assertEqual(bf.hunt(forge, c)["status"], "known")

    def test_a_failed_prior_judge_does_not_cost_the_property(self):
        forge = self._forge("c", None)
        forge.prior.side_effect = ValueError("no JSON")
        self.assertEqual(bf.hunt(forge, {"id": "c1", "target": "t", "statement": "p"})["status"], "holds")

    def test_rate_limit_retry_resends_the_request_headers(self):
        import io
        import urllib.error
        limited = urllib.error.HTTPError("u", 403, "rate limit exceeded", {"Retry-After": "1"}, io.BytesIO(b""))
        ok = mock.MagicMock()
        ok.__enter__.return_value.read.return_value = b'{"items": []}'
        with mock.patch.object(bf.urllib.request, "urlopen", side_effect=[limited, ok]) as urlopen, \
                mock.patch.object(bf.time, "sleep"):
            bf.github("https://api.github.com/search/issues?q=x")
        retry = urlopen.call_args_list[1][0][0]
        self.assertEqual(retry.get_header("User-agent"), bf.mf.USER_AGENT)
        self.assertIsNone(retry.get_header("Retry-after"))

    def test_main_diff_does_not_call_a_shim_identical_and_marks_truncation(self):
        with mock.patch.object(bf.mf, "_http_get", side_effect=lambda url: bf.inspect.getsource(
                bf.importlib.import_module("struct"))):
            self.assertIn("not compared", bf.main_diff("struct"))  # a few lines re-exporting _struct
        local = bf.inspect.getsource(bf.importlib.import_module("colorsys"))
        with mock.patch.object(bf.mf, "_http_get", return_value=local.replace("def ", "def  ")):
            self.assertTrue(bf.main_diff("colorsys", limit=200).endswith("(diff truncated)"))

    def test_duplicate_hits_are_listed_once(self):
        ai = StubAI(['{"queries": ["a b c", "d e f"]}'])
        run = bf.mf.Run(self.tmp / "u")
        run.data["module"] = "statistics"
        item = {"title": "t", "html_url": "https://github.com/python/cpython/issues/1", "state": "open", "body": ""}
        with mock.patch.object(bf, "github", return_value={"items": [item]}):
            found = bf.BugForge(ai, run, None, search=True).duplicates({"target": "statistics.kde", "statement": "p"})
        self.assertEqual(len(found["hits"]), 1)


if __name__ == "__main__":
    unittest.main()
