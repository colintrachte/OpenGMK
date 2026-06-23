# Project In-Processing Workflow

## Governing Rule

Never modify code before understanding the project. Produce the assessment and execution plan first, complete the plan internally, then begin work. This single discipline prevents the most common failure mode in agentic coding: editing files before grasping the project's structure and intent.

## Phase 0 — Setup

Establish a "do not touch" boundary up front: directories, files, or subsystems that should be left alone to avoid unintended refactors.

## Phase 1 — Assessment

Read the README, docs, issue tracker, and pull requests. Identify the project's purpose, primary language(s), build system, dependency manager, license, test coverage, and CI/CD configuration. Build from source and run the existing test suite to establish a baseline. Document build failures, test failures, dependency issues, missing documentation, and security concerns.

## Phase 2 — Repository Intelligence

Analyze the parent repository's open and closed issues and PRs, recent commit history, and any roadmap or discussion threads. Apply critical thinking to sort: which requests are still relevant, which issues are duplicates or already fixed, which features fit the project's trajectory, which PRs are worth merging.

Synthesize findings into a prioritized TODO.md:

- **Critical** — security vulnerabilities, crashes, data loss
- **High** — major bugs, broken functionality
- **Medium** — quality-of-life improvements
- **Low** — cosmetic and minor enhancements

Keep each item small, specific, and testable.

## Phase 3 — Safe Baseline (non-blocking, low risk)

These require no architectural decisions and can run immediately:

- Correct spelling, grammar, broken markdown, and broken links across source, comments, docs, and markdown files.
- Remove obvious dead code, obsolete comments, unused assets, and duplicate implementations. Refactor readability problems that do not alter behavior.

## Phase 4 — Dependency Modernization

Audit and upgrade runtime, build, and development dependencies to current safe versions. Resolve deprecated APIs, compiler warnings, and build warnings. Rebuild and retest after each dependency group, not all at once, so breakages are easy to isolate. Document breaking changes. Include a security audit of dependencies here.

## Phase 5 — Observability

Audit the codebase for critical paths missing log coverage: startup, shutdown, configuration load, external resource load, network and file operations, plugin initialization, and caught exceptions. Prefer logs that explain what failed, where, and why.

Guard against log spam in high-frequency loops, event listeners, and error-catch blocks. Use a counter, timestamp-delta throttle, or boolean flag to suppress floods, replacing them with a single summary, e.g.:

```
Failed to load texture. Additional occurrences suppressed (10,000 repeats).
```

Ensure debug logging can be toggled globally.

## Phase 6 — Platform Scripts

Create or update setup and run scripts per platform:

- Windows: setup.bat / setup.ps1, run.bat / run.ps1
- Linux: setup.sh, run.sh
- macOS: setup.command, run.command

Each should install dependencies, build, launch, and produce meaningful error messages. Document the equivalent manual steps in the README.

## Phase 7 — Implementation Pass

Work the prioritized TODO list. For each item: implement, verify functionality, run tests, update docs, mark complete. Commit related changes together.

When a task hits a logical ambiguity, architecture choice, or a decision requiring your approval, do not halt the pipeline. Checkpoint the exact state, context, and a clear statement of the dilemma to an APPROVALS.md queue, then pivot to the next independent task. Shelve, queue, and continue rather than idle.

## Phase 8 — Validation & Sign-Off

Verify a fresh checkout builds and all tests pass. Confirm documentation, scripts, and code agree. Run a final pass for formatting and broken links. Refresh the README to reflect the project's actual current state: status, features, installation, building from source, running, configuration, troubleshooting. Confirm all examples work.

Generate a CHANGELOG.md (bug fixes, features, dependency upgrades, breaking changes) and a final report listing remaining issues, deferred work, known risks, and suggested roadmap. Present completed tasks alongside the APPROVALS.md queue for review.
