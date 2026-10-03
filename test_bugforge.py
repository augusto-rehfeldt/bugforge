"""Offline checks for bugforge: no network, no model calls, temporary output."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bugforge as bf


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
        patcher = mock.patch.object(bf, "OUTPUT_ROOT", self.tmp)
        patcher.start()
        self.addCleanup(patcher.stop)

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
        forge.falsify.return_value = _ran("NO COUNTEREXAMPLE after 5000 cases")
        self.assertEqual(bf.hunt(forge, c)["status"], "holds")

        forge.run = bf.mf.Run(self.tmp / "h2")
        forge.falsify.return_value = _ran("COUNTEREXAMPLE: x=1")
        forge.confirm_refutation.return_value = _ran("REFUTATION REJECTED: outside the input space")
        self.assertEqual(bf.hunt(forge, c)["status"], "inconclusive")

        forge.run = bf.mf.Run(self.tmp / "h3")
        forge.confirm_refutation.return_value = _ran("REFUTATION CONFIRMED: x=1", code="import fractions")
        forge.duplicates.return_value = {"queries": ["q"], "hits": []}
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
        forge.judge.return_value = {"verdict": "BUG"}
        bf.hunt(forge, c)
        bf.hunt(forge, c)
        self.assertEqual(forge.duplicates.call_count, 2)

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


if __name__ == "__main__":
    unittest.main()
