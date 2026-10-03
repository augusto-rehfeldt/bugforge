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
- **Nothing is filed upstream automatically.** A `bug` gets a drafted issue in `report.md`: environment,
  documented behavior, expected and actual results, reproducer and its output.
  Maintainers already get too many AI reports, so a person runs the reproducer
  and checks the tracker before filing.
- **No unsafe targets.** Generated scripts run unsandboxed in the run directory,
  as in mathforge. `check_target` refuses modules that touch files, processes,
  the network or deserialization (`DENIED`). `AUTO_TARGETS` lists only
  pure-computation stdlib modules.
- **Results depend on the interpreter.** They are tied to the Python that runs
  bugforge, which `report.md` records. Check a bug on the newest CPython before
  filing it.
