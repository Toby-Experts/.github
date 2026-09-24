"""Gate pull requests against the owner-approved implementation surface.

The owner decided on 2026-09-22 that implementation in Toby-Experts
repositories goes through Devin and the owner. Claude Code pull requests are
closed rather than reviewed. This standard-library-only gate reads the event,
checks the pull request head and commits through the GitHub API, comments once,
and closes a blocked pull request.

The workflow checks out ``main`` before running this file. No file from the
pull request is imported or executed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

# Owner decision dated 2026-09-22.
BLOCKED_HEAD_PREFIXES = ("claude/", "copilot/")
BLOCKED_PR_AUTHORS = frozenset(
    {"copilot", "copilot-swe-agent[bot]", "claude[bot]", "claude-code[bot]"}
)
BLOCKED_EMAIL_SUFFIXES = ("@anthropic.com",)
BLOCKED_COMMIT_LOGIN = "claude"
BLOCKED_COMMIT_PATTERNS = (
    re.compile(r"co-authored-by:\s*claude\b", re.IGNORECASE),
    re.compile(r"generated with \[claude code\]", re.IGNORECASE),
)
COMMENT_MARKER = "<!-- pull-request-origin-gate -->"
_SHA = re.compile(r"[0-9a-f]{7,12}")
_PAGE_SIZE = 100
JSON = Any
Fetcher = Callable[[str], Sequence[Mapping[str, JSON]]]


def _text(value: JSON) -> str:
    return str(value or "").strip()


def blocked_reasons(
    event: Mapping[str, JSON],
    fetch_commits: Fetcher,
) -> list[str]:
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, Mapping):
        return []
    head = pull_request.get("head")
    head = head if isinstance(head, Mapping) else {}
    ref = _text(head.get("ref"))
    reasons = [
        f"head ref prefix `{prefix}`"
        for prefix in BLOCKED_HEAD_PREFIXES
        if ref.lower().startswith(prefix)
    ]
    user = pull_request.get("user")
    user = user if isinstance(user, Mapping) else {}
    login = _text(user.get("login"))
    if login.lower() in BLOCKED_PR_AUTHORS:
        reasons.append(f"pull request author `{login}`")
    for commit in fetch_commits(_text(pull_request.get("number"))):
        sha = _text(commit.get("sha"))[:12]
        sha = sha if _SHA.fullmatch(sha) else "unknown commit"
        data = commit.get("commit")
        data = data if isinstance(data, Mapping) else {}
        message = _text(data.get("message"))
        for name in ("author", "committer"):
            identity = data.get(name)
            identity = identity if isinstance(identity, Mapping) else {}
            email = _text(identity.get("email")).lower()
            api_identity = commit.get(name)
            api_identity = api_identity if isinstance(api_identity, Mapping) else {}
            commit_login = _text(api_identity.get("login")).lower()
            for suffix in BLOCKED_EMAIL_SUFFIXES:
                if email.endswith(suffix):
                    reasons.append(f"{sha} {name} email domain `{suffix}`")
            if commit_login == BLOCKED_COMMIT_LOGIN:
                reasons.append(f"{sha} {name} login {BLOCKED_COMMIT_LOGIN}")
        for pattern in BLOCKED_COMMIT_PATTERNS:
            if pattern.search(message):
                reasons.append(f"{sha} commit message matches {pattern.pattern}")
    return list(dict.fromkeys(reasons))


def _url(path: str) -> str:
    return f"{os.environ.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')}/{path.lstrip('/')}"


def _request(
    url: str,
    token: str,
    *,
    method: str = "GET",
    payload: Mapping[str, JSON] | None = None,
) -> JSON:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "tobyai-pull-request-origin-gate",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"
    with urlopen(
        Request(url, data=data, headers=headers, method=method), timeout=30
    ) as response:
        body = response.read()
    return json.loads(body) if body else {}


def _commits(token: str, repository: str) -> Fetcher:
    def fetch(number: str) -> Sequence[Mapping[str, JSON]]:
        result: list[Mapping[str, JSON]] = []
        page = 1
        while True:
            payload = _request(
                _url(
                    f"repos/{repository}/pulls/{number}/commits?per_page={_PAGE_SIZE}&page={page}"
                ),
                token,
            )
            if not isinstance(payload, list):
                raise TypeError("GitHub returned a non-list commit response")
            result.extend(item for item in payload if isinstance(item, Mapping))
            if len(payload) < _PAGE_SIZE:
                return result
            page += 1

    return fetch


def _close(token: str, repository: str, number: str, reasons: Sequence[str]) -> None:
    page = 1
    has_marker = False
    while True:
        comments = _request(
            _url(
                f"repos/{repository}/issues/{number}/comments"
                f"?per_page={_PAGE_SIZE}&page={page}"
            ),
            token,
        )
        if not isinstance(comments, list):
            raise TypeError("GitHub returned a non-list comment response")
        has_marker = any(
            isinstance(comment, Mapping)
            and COMMENT_MARKER in _text(comment.get("body"))
            for comment in comments
        )
        if has_marker or len(comments) < _PAGE_SIZE:
            break
        page += 1
    if not has_marker:
        body = (
            f"{COMMENT_MARKER}\n\nThis repository takes changes from the owner, "
            "Devin and the registered GitHub Actions routines only "
            "(docs/fleet/registry.yaml). This pull request arrived from Claude "
            f"Code ({'; '.join(reasons)}), so the origin gate has closed it. "
            "Open the change through Devin instead."
        )
        _request(
            _url(f"repos/{repository}/issues/{number}/comments"),
            token,
            method="POST",
            payload={"body": body},
        )
    _request(
        _url(f"repos/{repository}/pulls/{number}"),
        token,
        method="PATCH",
        payload={"state": "closed"},
    )


def _self_test() -> int:
    fixtures: list[Mapping[str, JSON]] = []

    def fetch(_number: str) -> Sequence[Mapping[str, JSON]]:
        return fixtures

    def check(
        ref: str, login: str, commits: Sequence[Mapping[str, JSON]] = ()
    ) -> list[str]:
        nonlocal fixtures
        fixtures = list(commits)
        return blocked_reasons(
            {
                "pull_request": {
                    "head": {"ref": ref},
                    "user": {"login": login},
                    "number": 1,
                }
            },
            fetch,
        )

    assert check("claude/example", "owner")
    assert check("copilot/example", "owner")
    assert check("devin/example", "claude[bot]")
    assert check(
        "devin/example",
        "owner",
        [{"sha": "a" * 40, "commit": {"author": {"email": "x@anthropic.com"}}}],
    )
    assert check(
        "devin/example",
        "owner",
        [{"sha": "b" * 40, "commit": {"message": "Generated with [Claude Code]"}}],
    )
    assert check(
        "devin/example",
        "owner",
        [
            {
                "sha": "c" * 40,
                "commit": {
                    "committer": {"email": "owner@example.com"},
                    "message": "change\n\nCo-Authored-By: Claude",
                },
                "committer": {"login": "claude"},
            }
        ],
    )
    for login in ("devin-ai-integration[bot]", "github-actions[bot]", "owner"):
        assert check("devin/example", login) == []
    # Raw pull request data never reaches the posted comment.
    payload_email = "[click](https://evil.example)@anthropic.com"
    reasons = check(
        "claude/`@octocat",
        "owner",
        [
            {
                "sha": "`@octocat",
                "commit": {
                    "author": {"email": payload_email},
                    "committer": {"email": "CI@Anthropic.com"},
                },
            }
        ],
    )
    assert reasons == [
        "head ref prefix `claude/`",
        "unknown commit author email domain `@anthropic.com`",
        "unknown commit committer email domain `@anthropic.com`",
    ], reasons
    joined = "; ".join(reasons)
    assert "@octocat" not in joined and "evil.example" not in joined and "[" not in joined
    print("check_pull_request_origin self-test: all origin cases passed")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return _self_test()
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name in {"merge_group", "workflow_dispatch"}:
        print(f"Origin gate skipped: {event_name} has no pull request event.")
        return 0
    path = os.environ.get("GITHUB_EVENT_PATH")
    if event_name != "pull_request" or not path:
        print("Origin gate skipped: this event does not carry a pull request.")
        return 0
    event = json.loads(Path(path).read_text(encoding="utf-8"))
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, Mapping):
        print("Origin gate skipped: pull request event has no pull request.")
        return 0
    token = os.environ.get("GITHUB_TOKEN")
    repository = os.environ.get("GITHUB_REPOSITORY")
    number = _text(pull_request.get("number"))
    if not token or not repository or not number:
        print(
            "Origin gate failed: GitHub API environment is incomplete.", file=sys.stderr
        )
        return 2
    reasons = blocked_reasons(event, _commits(token, repository))
    if not reasons:
        print("Origin gate passed: pull request origin is allowed.")
        return 0
    _close(token, repository, number, reasons)
    print("Origin gate blocked this pull request:")
    print("\n".join(f"- {reason}" for reason in reasons))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
