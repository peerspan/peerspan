# A budget for the conformance suites

Status: **Proposal, 2026-11-03.** Nothing is decided. The decisions the owner is asked for are at the end. Measurements are from `main` at `6b4b5df` and the Conformance run of `002f1a0`.

## The problem

[DEC-OWN6](decision-log.md#dec-own6-slim-the-conformance-tests-2026-10-28) and [DEC-OWN9](decision-log.md#dec-own9-shape-of-the-slim-conformance-suites-2026-10-28) chose about 10 small black-box suites, one per spec area, each under 2 minutes. Detailed edge cases were to move to Rust integration tests, and frozen evidence files were to be deleted. [DEC-OWN10](decision-log.md#dec-own10-delete-the-old-conformance-suites-2026-10-28) deleted the old suites on 2026-10-28. Six days later the suites are larger than before that cleanup:

| | 2026-10-28, after DEC-OWN10 | `main` now |
| --- | ---: | ---: |
| Python files under `conformance/` | 20 | 89 |
| Lines | 7,250 | 52,127 |
| Conformance CI jobs per push | 11 | 48 |
| Job-minutes per push | 9 | 36 to 42 |
| Files under `docs/results/` added since | – | 77 |

Each job still fits the 2-minute rule. That is only because the suites were split into more parallel jobs: the work per push has grown about fourfold. Each pull request also runs the installed onboarding bundle, which takes 15 minutes on its own. Locally, a suite can no longer be read in one sitting, and several cases are timing-sensitive. On `main`'s own build, `join_onboarding` fails two read-only cases on a slower machine because a background frame acknowledgement lands inside the case's "nothing changes" window.

## Where the growth is

| Family | Files | Lines | CI jobs | Job time per push |
| --- | ---: | ---: | ---: | ---: |
| Guided onboarding and machine linking | 56 | 35,596 | 29 | 22 min |
| Core areas and the harness | 27 | 11,925 | 18 | 11 min (conversations included) |
| Conversations | 6 | 4,606 | (above) | (above) |
| Build | – | – | 1 | 3 min |

Four patterns account for most of it.

1. **Copied helpers.** 28% of conformance code lines (12,901 of 45,563) sit in a 6-line run that is identical in another file. 185 helper functions are defined in three or more files. For example, `db_path` is defined in 27 files, `records`, `context` and `compact` in 26, `public` in 25, `settled` in 24, `traffic` in 20, and `advance_to` in 19. `slim/guided_machine.py` and `installed_participant_support.py` are 97.5% the same file.
2. **Very large scenario cases.** The guided suites have 6 cases each in 1,000 to 1,700 lines, and take 10 to 16 seconds per case. The core and conversations suites take 2 to 6 seconds per case. A guided case drives a whole ceremony and checks every intermediate state, which is the "detailed edge cases" that DEC-OWN6 moved out of conformance.
3. **Wrappers around frozen suites.** 19 `*_prerequisite.py` and `*_diagnostic.py` files, about 2,800 lines, run an unchanged suite with an added precondition or failure metadata. The suites were frozen during guided final acceptance, so fixes went into wrappers instead of the suites. The CI workflow names each wrapper per suite.
4. **Evidence files again.** 77 files under `docs/results/` were added since 2026-10-28. Most of them record a guided verification run.

## The proposal

Four changes, each of which can be taken on its own.

### 1. A budget

Write the budget into AGENTS.md beside the existing 2-minute rule:
- **Per push**, the Conformance workflow stays within **15 job-minutes**, about 1.5 times its size at DEC-OWN10.
- **Per suite**, one job under 2 minutes (unchanged), and at most about 1,000 lines. A suite that needs more is split by area, not by phase.
- **A new suite** states its cost (lines and seconds) in its PR. A PR that takes the workflow over budget moves something to the second tier (below), or asks the owner.

### 2. Two tiers

- **Per push:** one suite per spec area, as in DEC-OWN9. That means the core areas and conversations, plus one guided onboarding suite covering the accepted experience end to end: connect a project, invite someone, connect another machine, readiness.
- **Manual or nightly:** the installed onboarding bundle, the installed upgrade acceptance, the clock-heavy cases, and the per-section guided verification suites. They run on `workflow_dispatch`, on a nightly schedule, and on demand before a release. That follows the owner's guidance to keep CI light: cheap checks on every push, and heavy jobs run by hand, as the KVM jobs of the runtime already are.

At today's numbers this takes the per-push workflow from 36 to about 14 job-minutes, and pull requests lose the 15-minute bundle job.

### 3. Shared fixtures

The suite author moves the copied helpers into `conformance/slim/common.py`, and the copied guided scaffolding into one fixture module. This is a refactor with no case changes. It is checked by running both versions and comparing the case names, the outcomes, and the number of `check` calls each case makes. Expected saving: about 8,000 to 10,000 lines, mostly in the guided family.

### 4. Retire the wrappers and most evidence files

Once guided final acceptance is done and its suites are no longer frozen, each wrapper's precondition or diagnostic goes into the suite it wraps, or into the harness as an option. The wrapper is then deleted, and the CI workflow returns to one line per suite. `docs/results/` keeps one acceptance receipt per feature. Intermediate verification files are deleted; their content stays in git history and in the PRs.

## What this costs

- **Coverage.** Change 2 runs the per-section guided cases less often. A regression there is found on the next nightly or manual run, not on the pull request. Change 3 changes no case.
- **Author time.** Changes 3 and 4 are work for the spec-only author: probably two or three PRs. They don't touch the Rust host.
- **Timing.** Guided onboarding is in final acceptance, and its suites are frozen until then. Changes 1 and 2 can be made now. Changes 3 and 4 should wait until acceptance is done, so the accepted evidence was produced by the suites as they were.

## Other options

- **Do nothing.** Each suite still fits 2 minutes, so the rule holds as written. The cost per push keeps growing with every feature, and so does the time to read a suite.
- **A hard line limit for the whole tree.** Simple to check, but it pushes against adding real coverage and doesn't distinguish cheap cases from expensive ones.
- **Move the guided edge cases to Rust integration tests,** as DEC-OWN6 says. A spec-only author may write them against the built binaries. This is the most faithful option to DEC-OWN6, and the most work, so it is better taken suite by suite after change 3.

## Owner decisions needed

1. **Budget.** Adopt the per-push budget of 15 job-minutes, and about 1,000 lines per suite? Options: (a) as proposed; (b) different numbers; (c) no budget, only the 2-minute rule. *Recommended: (a).*
2. **Tiers.** Move the installed bundle, the installed upgrade, the clock-heavy cases and the per-section guided suites to a manual and nightly tier? Options: (a) all of them; (b) only the installed checks; (c) none. *Recommended: (a).*
3. **Shared fixtures.** Ask the suite author for the helper refactor of change 3 once guided acceptance is done? Options: (a) yes; (b) no. *Recommended: (a).*
4. **Wrappers and evidence files.** After acceptance, fold the wrappers into their suites, and keep one acceptance receipt per feature in `docs/results/`? Options: (a) yes; (b) keep the wrappers; (c) keep every evidence file. *Recommended: (a).*

## Measurements

- **Lines and files:** every `.py` file under `conformance/`, counted with `wc -l` at `0fa2d13` (DEC-OWN10) and `6b4b5df`.
- **Duplication:** whitespace-stripped, non-comment lines, in 6-line windows. A line counts as shared if any window containing it appears in a second file.
- **CI time:** job start to completion, from the GitHub Actions API, for the Conformance run of `002f1a0` (48 jobs, 2,183 seconds) and the Pull request checks of the same commit (installed onboarding bundle, 898 seconds).
- **Seconds per case:** a suite's job time divided by its `@suite.case` count. This is an upper bound, since it includes start-up.
