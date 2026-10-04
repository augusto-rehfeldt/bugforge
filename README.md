# bugforge

Finds real bugs in Python libraries by falsifying properties their documentation
promises.

This is mathforge's premise applied to software. A model's claim that code is
wrong is worth nothing. A script that reproduces the failure is worth something.
Each property goes through these steps:

| Stage | Model | Evidence |
|---|---|---|
| Propose | review | module API, source, docs; must quote the promise (`spec_basis`) |
| Prior art | work | GitHub issues and PRs plus the diff of CPython `main` against the installed module; `KNOWN` stops here as `known` |
| Falsify | work | randomized and edge-case search with an independent reference; `COUNTEREXAMPLE` / `NO COUNTEREXAMPLE` |
| Reproduce | review | a minimal standalone script written from the witness alone; `REFUTATION CONFIRMED` / `REJECTED` |
| Judge | work | reads the reproducer, its output, the docs, the same issues and the `main` diff; returns `BUG` / `DOC_BUG` / `DUPLICATE` / `NOT_A_BUG` |

The run statuses are `bug`, `doc-bug`, `known` (stopped by prior art), `duplicate`, `not-a-bug`, `holds` (no
counterexample: a negative result, kept), `inconclusive` and `error`.

## Usage

```bash
python bugforge.py fractions                 # one module
python bugforge.py --auto 5 --workers 3      # the five least-hunted modules in AUTO_TARGETS
python bugforge.py --forever --workers 3
python bugforge.py --resume                  # latest saved run
python bugforge.py --forever --resume        # resume first, then keep hunting
python bugforge.py --resume bug_output/<run> # explicit older run
python bugforge.py json --effort low --review-effort high
python -B -m unittest -q test_bugforge       # offline checks
```

Output goes to `bug_output/<module>-<UTC stamp>/`, which holds `state.json`, the
scripts and `report.md`. `bug_output/index.json` records every run. Bare
`--resume` selects the most recently saved `state.json`, including completed runs
but excluding underscore-prefixed scratch directories. `BUGFORGE_OUTPUT` overrides
the output root. No saved run means an error before provider setup.

`--provider`, `--model` and `--review-model` use the shared ai-suite menu.
`--effort` and `--review-effort` override its per-role reasoning picks; use
`provider-default` to send no effort override. Without flags, menu/environment
picks and mathforge's unattended defaults are unchanged.

## Rules

- **Publishing.** `--publish` pushes every `bug` and `doc-bug` result the judge did
  not rate `low` severity to the public GitHub repository `<you>/bugforge-results` (`BUGFORGE_RESULTS_REPO`, checkout
  `~/bugforge-results` or `BUGFORGE_RESULTS_DIR`). Each one gets a folder holding
  the report, the reproducer and the search script, and the repository's index
  lists them. `--publish-existing` publishes results already on disk without any
  model calls. After a report is filed upstream, `--link FOLDER URL` records it
  in the folder's `result.json` and the index links it. The tracker search uses
  `GITHUB_TOKEN`, else the `gh` CLI's login (30 searches a minute instead of 10).
- **Targets.** `AUTO_TARGETS` holds standard library modules and popular PyPI
  packages (packaging, idna, python-dateutil, markupsafe, more-itertools,
  sortedcontainers, isodate, wcwidth, tabulate, yarl), all parsing or
  arithmetic with no files, processes or network. Python only: a property is
  tested by importing the module.
- **Filing.** `--file` files published results that have no upstream report as
  issues in their project's tracker, as you through `gh`: python/cpython for the
  standard library, else the GitHub repository the package's metadata names. One
  open report per project: while one of yours is open there nothing more is filed,
  and the next goes out once it is closed. Ninety filed at once on python/cpython
  were all closed unread within minutes. `tracking.json` in the results repository
  (`{"owner/name": issue URL}`) names a tracking issue that holds a project back
  the same way. Each result is checked again first: a package must be among the
  1000 most downloaded on PyPI and installed at its latest release, the reproducer
  is rerun and must still confirm the bug, and a target that already has a report
  is skipped. The issue says it was written by a tool and not read by a person.
  With `--no-post` the issue is drafted as `cN_issue.md` and nothing is filed.
- **After filing.** A report you filed by hand is found without being told: an issue
  (or pull request) of yours in the project's tracker that mentions bugforge and names the
  result's folder, or the target of exactly one unlinked result, is linked to that
  result. `--link FOLDER URL` does it by hand when two results fit. From then on the
  thread is read after every module of a hunt (`--track` reads it on demand): new
  comments are printed and appended to `bug_output/responses.md`, the index shows
  the issue's state and comment count, and the thread is kept in the run's
  `state.json`. A pull request you opened for the issue is part of the thread: its
  comments, reviews and review remarks are read too. Someone else's pull request
  is listed but not followed.
- **The conversation loop.** Every hunt takes one turn in every thread after each
  module, with no flag; `--converse` takes the turns now and exits. Whose turn it is
  comes from the thread itself: when the last comment by a person is yours, it
  waits, and a bot's note never makes it your turn. A new comment from someone else
  is read once by the work model, which answers one of four things. `CHANGES` (a
  question, a requested measurement, another design, even inside a refusal): a
  fresh fix with that comment as a constraint, and a reply posted as you through
  `gh`, where the comment was made. `APPROVED` (a maintainer agreed and none of
  their questions is open): the loop ends and it says what to do about the linked
  pull requests, `gh pr reopen` for your own closed one, a new one when the linked
  one is someone else's. `REJECTED` (a maintainer dismissed the idea as a whole and
  asked or proposed nothing): the loop ends, no reply. `WAIT`: nothing to answer. A
  later comment reopens the loop from any of these. Each posted reply ends with a
  line saying bugforge wrote and posted it, there are at most 5 per issue, and
  none goes out when no patch passed its gates: then it asks for a person.
  `--no-post` drafts the replies into the run directory instead. Before the first
  `--publish` there is nothing to follow and nothing happens.
- **Fixes.** `--fix RUN ID` (say `--fix statistics-20261003-010644 c1`) is the fix
  step on its own: the work model patches the module's own source, with the
  maintainers' comments as constraints, and the patch is kept only if the
  reproducer stops confirming the bug and the module's stdlib test suite fails
  nothing it passed before. It writes `cN_fix.diff` and, for a followed thread, a
  draft `cN_reply.md`, and posts nothing. A fix needs a pure-Python module, and
  the reply is told to say which measurements were not run.
- **No issue or pull request is opened automatically.** A `bug` gets a drafted issue
  in `report.md`: environment, documented behavior, expected and actual results,
  reproducer and its output. Maintainers already get too many AI reports, so a
  person runs the reproducer and checks the tracker before filing, and a person
  opens or reopens the pull request. Only replies in a thread you started are
  automatic.
- **No unsafe targets.** Generated scripts run unsandboxed in the run directory,
  as in mathforge. `check_target` refuses modules that touch files, processes,
  the network or deserialization (`DENIED`). `AUTO_TARGETS` lists only
  pure-computation stdlib modules.
- **Results depend on the interpreter.** They are tied to the Python that runs
  bugforge, which `report.md` records. Check a bug on the newest CPython before
  filing it.
