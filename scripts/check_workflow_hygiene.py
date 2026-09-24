"""Gate: every workflow is pinned, least-privileged, bounded, and serialised.

Five properties, each of which was violated somewhere in this repository
when this check was written, and none of which any existing gate held.

**Pinned.** An action referenced by tag (``actions/checkout@v4``) runs
whatever that tag points at today. A tag is mutable, so a compromised or
retagged action executes with the workflow's token. Thirty-one steps here
already pin by commit SHA; the since-removed
``copilot-suppressed-findings.yml`` did not, and that workflow ran on
``pull_request_review`` with ``pull-requests: write``, which was the worst
place in the repository to have it.

**Least-privileged.** A workflow with no top-level ``permissions`` inherits
the repository default, which can be read/write on every scope. Declaring
the block at the top means a job that forgets its own cannot quietly get
more than it needs.

**Bounded.** A job with no ``timeout-minutes`` runs to GitHub's six-hour
ceiling. On a required check that is six hours of the merge queue blocked
behind a hang.

**Serialised.** Without a ``concurrency`` group, a second push starts a
duplicate run while the first is still going. Both finish, the older one
tells you about a commit nobody is looking at, and the minutes are spent
either way.

**Reachable.** Every cron declared by a scheduled workflow reaches at least
one job. A job condition that excludes a scheduled event otherwise makes
that cron a silent no-op.

Deliberately not checked here: which permissions a workflow asks for, and
what its timeout should be. Those are judgement calls that belong to
whoever writes the workflow. This gate asks only that the decision was
made somewhere visible rather than left to a default.

    uv run --no-project python scripts/check_workflow_hygiene.py
    uv run --no-project python scripts/check_workflow_hygiene.py --self-test

Run from the workspace root. Stdlib only, no network calls.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

#: A pinned reference: 40 hex characters. A shorter SHA is not accepted,
#: because a short SHA can collide and GitHub resolves it loosely.
_PINNED = re.compile(r"^[0-9a-f]{40}$")

#: ``uses:`` values that are not third-party actions and cannot be pinned.
#: A local action lives in this repository and moves with it; a Docker
#: reference is pinned by its own digest if at all.
_LOCAL_PREFIXES = ("./", "../")

#: A ``uses:`` key anywhere it can start a mapping entry: at the start of
#: a block line, or after ``[``, ``{`` or ``,`` in flow style / inline JSON
#: (``steps: [{ uses: owner/action@v1 }]``), optionally quoted. The value
#: ends at whitespace, a quote, or a flow-style delimiter.
_USES = re.compile(
    r"""(?:^|[\[{,])\s*(?:-\s*)?["']?uses["']?\s*:\s*["']?([^\s"',}\]]+)""",
    re.MULTILINE,
)
_TOP_LEVEL_PERMISSIONS = re.compile(r"^permissions:", re.MULTILINE)
_CONCURRENCY = re.compile(r"^concurrency:", re.MULTILINE)
_RUNS_ON = re.compile(r"^(\s+)runs-on:", re.MULTILINE)
_TIMEOUT = re.compile(r"^\s+timeout-minutes:", re.MULTILINE)
_CRON = re.compile(r"""^\s*-\s*cron:\s*["'](?P<cron>[^"']+)["']\s*$""", re.MULTILINE)
_JOB_IF = re.compile(r"^    if:\s*(?P<condition>.*)$", re.MULTILINE)
_SCHEDULE_EQUALS = re.compile(
    r"""github\.event\.schedule\s*==\s*["'](?P<cron>[^"']+)["']"""
)
_SCHEDULE_NOT_EQUALS = re.compile(
    r"""github\.event\.schedule\s*!=\s*["'](?P<cron>[^"']+)["']"""
)


def _strip_comments(text: str) -> str:
    """Drop whole-line comments, so an example in prose is not a finding."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _unpinned(body: str) -> list[str]:
    found = []
    for ref in _USES.findall(body):
        if ref.startswith(_LOCAL_PREFIXES) or ref.startswith("docker://"):
            continue
        _, _, version = ref.partition("@")
        if not _PINNED.match(version):
            found.append(ref)
    return found


def _scheduled_crons(body: str) -> list[str]:
    return [match.group("cron") for match in _CRON.finditer(body)]


def _job_conditions(body: str) -> list[str | None]:
    conditions: list[str | None] = []
    in_jobs = False
    job_lines: list[str] | None = None
    for line in body.splitlines():
        if line == "jobs:":
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith((" ", "\t")):
            break
        if not in_jobs:
            continue
        if re.match(r"^  [A-Za-z0-9_.-]+:\s*$", line):
            if job_lines is not None:
                job_body = "\n".join(job_lines)
                condition_match = _JOB_IF.search(job_body)
                conditions.append(
                    condition_match.group("condition") if condition_match else None
                )
            job_lines = []
        elif job_lines is not None:
            job_lines.append(line)
    if job_lines is not None:
        job_body = "\n".join(job_lines)
        condition_match = _JOB_IF.search(job_body)
        conditions.append(
            condition_match.group("condition") if condition_match else None
        )
    return conditions


def _job_reaches_cron(condition: str | None, cron: str) -> bool:
    if condition is None:
        return True
    if re.fullmatch(r"\s*\$\{\{\s*false\s*\}\}\s*", condition):
        return False
    equal_crons = {
        match.group("cron") for match in _SCHEDULE_EQUALS.finditer(condition)
    }
    not_equal_crons = {
        match.group("cron") for match in _SCHEDULE_NOT_EQUALS.finditer(condition)
    }
    if equal_crons and not_equal_crons:
        return cron in equal_crons and cron not in not_equal_crons
    if equal_crons:
        return cron in equal_crons
    if not_equal_crons:
        return cron not in not_equal_crons
    return True


def check(workflow_dir: Path) -> list[str]:
    """Return one failure line per violation, empty when all five hold."""
    failures: list[str] = []
    for path in sorted(workflow_dir.glob("*.yml")) + sorted(
        workflow_dir.glob("*.yaml")
    ):
        name = path.name
        body = _strip_comments(path.read_text(encoding="utf-8"))

        for ref in _unpinned(body):
            failures.append(
                f"{name}: `uses: {ref}` is not pinned to a 40-character commit "
                f"SHA. A tag is mutable, so whatever it points at later runs "
                f"with this workflow's token. Pin it and keep the version in a "
                f"trailing comment."
            )

        if not _TOP_LEVEL_PERMISSIONS.search(body):
            failures.append(
                f"{name}: no top-level `permissions:` block, so it inherits the "
                f"repository default rather than declaring what it needs."
            )

        if not _CONCURRENCY.search(body):
            failures.append(
                f"{name}: no `concurrency:` group, so a second push runs a "
                f"duplicate of a run that is still going. Set "
                f"`cancel-in-progress: false` where a run must not be "
                f"interrupted (a release), true where only the head matters."
            )

        scheduled_crons = _scheduled_crons(body)
        if scheduled_crons:
            conditions = _job_conditions(body)
            for cron in scheduled_crons:
                if not any(
                    _job_reaches_cron(condition, cron) for condition in conditions
                ):
                    failures.append(
                        f"{name}: scheduled cron {cron!r} cannot reach any job because "
                        "every job's `if:` excludes it."
                    )

        # One timeout per job. Counting `runs-on` is the cheap way to count
        # jobs without a YAML parser, and this file is stdlib-only so that
        # it runs in ci.yml's operating-rules job with no workspace sync.
        jobs = len(_RUNS_ON.findall(body))
        timeouts = len(_TIMEOUT.findall(body))
        if jobs > timeouts:
            failures.append(
                f"{name}: {jobs} job(s) but {timeouts} `timeout-minutes`. An "
                f"unbounded job runs to GitHub's 6-hour ceiling, and on a "
                f"required check that is 6 hours of merge queue blocked behind "
                f"a hang."
            )
    return failures


_GOOD = (
    "name: x\n"
    "on: [push]\n"
    "permissions:\n  contents: read\n"
    "concurrency:\n  group: x-${{ github.ref }}\n  cancel-in-progress: true\n"
    "jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n"
    "    steps:\n"
    "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n"
)

_SCHEDULED = _GOOD.replace(
    "on: [push]\n",
    'on:\n  schedule:\n    - cron: "0 10 * * 0"\n    - cron: "0 10 * * 3"\n',
).replace(
    "  a:\n",
    "  a:\n"
    "    if: ${{ github.event_name != 'schedule' || "
    "github.event.schedule == '0 10 * * 0' }}\n",
)
_SCHEDULED_COVERED = _SCHEDULED.replace(
    "github.event.schedule == '0 10 * * 0'",
    "(github.event.schedule == '0 10 * * 0' || github.event.schedule == '0 10 * * 3')",
)

_SELF_TEST_CASES: tuple[tuple[str, str, bool], ...] = (
    ("a compliant workflow passes", _GOOD, False),
    (
        "a tag-pinned action is caught",
        _GOOD.replace("de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2", "v4"),
        True,
    ),
    (
        "a short SHA is caught",
        _GOOD.replace("de0fac2e4500dabe0009e67214ff5f5447ce83dd", "de0fac2e"),
        True,
    ),
    (
        "a tag-pinned action in a flow-style step is caught",
        _GOOD.replace(
            "    steps:\n"
            "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n",
            "    steps: [{ uses: actions/checkout@v4 }]\n",
        ),
        True,
    ),
    (
        "a tag-pinned action in an inline-JSON step is caught",
        _GOOD.replace(
            "    steps:\n"
            "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n",
            '    steps: [{"name": "co", "uses": "actions/checkout@v4"}]\n',
        ),
        True,
    ),
    (
        "a SHA-pinned action in a flow-style step passes",
        _GOOD.replace(
            "    steps:\n"
            "      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2\n",
            "    steps: [{ name: co, uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd }]\n",
        ),
        False,
    ),
    (
        "a quoted tag-pinned action is caught",
        _GOOD.replace(
            "uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2",
            'uses: "actions/checkout@v4"',
        ),
        True,
    ),
    (
        "a local action is not required to be pinned",
        _GOOD.replace(
            "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2",
            "./.github/actions/setup",
        ),
        False,
    ),
    (
        "a missing top-level permissions block is caught",
        _GOOD.replace("permissions:\n  contents: read\n", ""),
        True,
    ),
    (
        "a missing concurrency group is caught",
        _GOOD.replace(
            "concurrency:\n  group: x-${{ github.ref }}\n  cancel-in-progress: true\n",
            "",
        ),
        True,
    ),
    (
        "an unbounded job is caught",
        _GOOD.replace("    timeout-minutes: 10\n", ""),
        True,
    ),
    (
        "a second job without its own timeout is caught",
        _GOOD + "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n",
        True,
    ),
    (
        "an example in a comment is not a finding",
        _GOOD + "# Example: uses: actions/checkout@v4\n",
        False,
    ),
    (
        "a scheduled cron excluded by every job is caught",
        _SCHEDULED,
        True,
    ),
    (
        "scheduled crons covered by a job condition pass",
        _SCHEDULED_COVERED,
        False,
    ),
)


def self_test() -> int:
    import tempfile

    failures: list[str] = []
    for case_name, body, should_fail in _SELF_TEST_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "w.yml").write_text(body, encoding="utf-8")
            found = check(d)
        if bool(found) is not should_fail:
            failures.append(
                f'"{case_name}": expected '
                f"{'a failure' if should_fail else 'no failure'}, got {found!r}"
            )

    if failures:
        print(f"FAIL (self-test): {len(failures)} case(s) did not behave as expected:")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(
        f"OK (self-test): all {len(_SELF_TEST_CASES)} known cases behaved as expected."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if "--self-test" in args:
        return self_test()

    failures = check(WORKFLOWS)
    if failures:
        print(f"FAIL: {len(failures)} workflow hygiene issue(s):\n")
        for line in failures:
            print(f"  {line}")
        return 1

    count = len(list(WORKFLOWS.glob("*.yml"))) + len(list(WORKFLOWS.glob("*.yaml")))
    print(
        f"OK: all {count} workflow(s) pin their actions by commit SHA, declare "
        "top-level permissions, bound every job, set a concurrency group, and "
        "route every scheduled cron to a job."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
