# bugforge

Finds real bugs in Python libraries by falsifying properties their documentation
promises.

This is mathforge's premise applied to software. A model's claim that code is
wrong is worth nothing. A script that reproduces the failure is worth something.
Each property goes through these steps:

| Stage | Model | Evidence |
|---|---|---|
| Propose | review | module API, source, docs; must quote the promise (`spec_basis`) |
| Falsify | work | randomized and edge-case search with an independent reference; `COUNTEREXAMPLE` / `NO COUNTEREXAMPLE` |
| Reproduce | review | a minimal standalone script written from the witness alone; `REFUTATION CONFIRMED` / `REJECTED` |
| Duplicates | review | GitHub issue search (`repo:python/cpython` for the stdlib) |
| Judge | review | reads the reproducer, its output, the docs and the issues; returns `BUG` / `DOC_BUG` / `DUPLICATE` / `NOT_A_BUG` |

The run statuses are `bug`, `doc-bug`, `duplicate`, `not-a-bug`, `holds` (no
counterexample: a negative result, kept), `inconclusive` and `error`.

## Usage

```bash
python bugforge.py fractions                 # one module
python bugforge.py --auto 5 --workers 3      # the five least-hunted modules in AUTO_TARGETS
python bugforge.py --forever --workers 3
python bugforge.py --resume bug_output/<run>
python -B -m unittest -q test_bugforge       # offline checks
```

Output goes to `bug_output/<module>-<UTC stamp>/`, which holds `state.json`, the
scripts and `report.md`. `bug_output/index.json` records every run.

## Rules

- **Nothing is filed.** A `bug` gets a drafted issue in `report.md`: environment,
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
