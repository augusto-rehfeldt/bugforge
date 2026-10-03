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

    def test_duplicates_search_cpython_issues_for_stdlib(self):
        ai = StubAI(['{"queries": ["Fraction limit_denominator negative"]}'])
        forge = bf.BugForge(ai, bf.mf.Run(self.tmp / "d"), None, search=True)
        page = {"items": [{"title": "limit_denominator wrong", "html_url": "https://github.com/python/cpython/issues/1",
                           "state": "open", "body": "x" * 2000}]}
        with mock.patch.object(bf.mf, "_http_get", return_value=json.dumps(page)) as get:
            found = forge.duplicates({"target": "fractions.Fraction.limit_denominator", "statement": "p"})
        self.assertIn("repo%3Apython%2Fcpython", get.call_args[0][0])
        self.assertEqual(found["hits"][0]["url"], "https://github.com/python/cpython/issues/1")
        self.assertLessEqual(len(found["hits"][0]["body"]), 600)

    def test_research_writes_a_draft_issue_and_never_files_it(self):
        bug = {"id": "c1", "title": "Fraction rounds wrong", "target": "fractions.Fraction", "statement": "p",
               "spec_basis": "the docs say so", "status": "bug",
               "repro": _ran("REFUTATION CONFIRMED: got 1, expected 2", code="from fractions import Fraction"),
               "judge": {"verdict": "BUG", "expected": "2", "actual": "1"}}
        forge = mock.Mock()
        forge.propose.return_value = [{"id": "c1", "statement": "p"}, {"id": "c2", "statement": "q"}]
        outcomes = iter([bug, {"id": "c2", "statement": "q", "status": "holds",
                                    "falsification": _ran("NO COUNTEREXAMPLE in 900 cases")}])
        with mock.patch.object(bf, "hunt", side_effect=lambda f, c: next(outcomes)):
            summary = bf.research(lambda run: forge, "fractions", properties=2, workers=2)
        self.assertEqual(summary["tally"], {"bug": 1, "holds": 1})
        report = next(self.tmp.glob("fractions-*/report.md")).read_text(encoding="utf-8")
        self.assertIn("from fractions import Fraction", report)
        self.assertIn("Python " + bf.platform.python_version(), report)
        self.assertIn("not filed", report)
        self.assertEqual(bf.next_targets(1), [m for m in bf.AUTO_TARGETS if m != "fractions"][:1])


if __name__ == "__main__":
    unittest.main()
