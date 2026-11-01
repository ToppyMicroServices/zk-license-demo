# CodeQL execution scope

CodeQL is managed by `.github/workflows/codeql.yml`. It runs on changes pushed
to `main`, pull requests targeting `main`, manual dispatch, and a weekly schedule
(Sunday 18:23 UTC). Pushes and pull requests containing only `docs/`, `.beads/`
or Markdown files do not start this workflow. Mixed changes still start it.
Dependency files and workflow changes are not excluded.

The workflow preserves the former default setup's Actions and
JavaScript/TypeScript analysis, default query suite and remote threat model.
`javascript` and `typescript` are aliases of `javascript-typescript`, so only
one JavaScript/TypeScript matrix entry is needed. These interpreted languages
use `build-mode: none`. There is no CodeQL analysis-path exclusion: when a scan
runs, it scans the supported source throughout the repository.

Weekly and manual scans remain available independently of changed paths, so
new CodeQL queries can check otherwise unchanged code. Superseded PR scans
can be cancelled; separate main commits keep their own scans.

GitHub default setup must be disabled when this advanced workflow is enabled;
leaving default setup active rejects advanced CodeQL result uploads. The
previous setting was `configured`, query suite `default`, threat model `remote`,
schedule `weekly`. For rollback, restore default setup and disable this workflow
to avoid competing configurations.

Application validation is selected separately by `scripts/ci_scope.py`.
CodeQL-only edits do not run demo proofs, browsers or performance measurements.
Changes to the selector run its routing tests; unknown runtime/dependency
changes still select full application validation.

References: [CodeQL workflow options](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options),
[switching to advanced setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).
