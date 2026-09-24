#!/usr/bin/env python3
"""Wait for one exact tag/SHA release workflow run via the GitHub REST API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any, Protocol


TERMINAL_FAILURES = {
    "action_required",
    "cancelled",
    "failure",
    "neutral",
    "skipped",
    "stale",
    "startup_failure",
    "timed_out",
}
ACTIVE_STATUSES = {"in_progress", "pending", "queued", "requested", "waiting"}


class ReleaseRunError(RuntimeError):
    """The exact release run cannot be trusted or did not succeed."""


class JsonApi(Protocol):
    def get(self, path: str) -> dict[str, Any]:
        """Return one decoded JSON object for an API path."""


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Keep API credentials on the explicitly configured HTTPS origin."""

    def redirect_request(
        self,
        request: urllib.request.Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> urllib.request.Request | None:
        del request, file_pointer, code, message, headers, new_url
        raise ReleaseRunError("GitHub API redirect refused")


class GitHubApi:
    """Small authenticated GitHub REST client with no third-party dependency."""

    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise ReleaseRunError("GH_TOKEN or GITHUB_TOKEN is required")
        parsed = urllib.parse.urlsplit(api_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ReleaseRunError(
                "GitHub API URL must be HTTPS and contain no credentials, query, or fragment"
            )
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.opener = urllib.request.build_opener(RejectRedirects())

    def get(self, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "rust-gvm-release-poller",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            # The constructor restricts the base to HTTPS and the opener rejects redirects.
            with self.opener.open(request, timeout=30) as response:
                payload = json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            raise ReleaseRunError(f"GitHub API request failed for {path}: {error}") from error
        if not isinstance(payload, dict):
            raise ReleaseRunError(f"GitHub API returned a non-object for {path}")
        return payload


def resolve_tag(api: JsonApi, repository: str, tag: str) -> str:
    encoded_tag = urllib.parse.quote(tag, safe="")
    payload = api.get(f"/repos/{repository}/git/ref/tags/{encoded_tag}")
    target = payload.get("object")
    for _ in range(8):
        if not isinstance(target, dict):
            raise ReleaseRunError(f"tag {tag} has no Git object")
        kind = target.get("type")
        sha = target.get("sha")
        if not isinstance(sha, str) or not sha:
            raise ReleaseRunError(f"tag {tag} has no Git object SHA")
        if kind == "commit":
            return sha
        if kind != "tag":
            raise ReleaseRunError(f"tag {tag} points to unsupported Git object {kind!r}")
        payload = api.get(f"/repos/{repository}/git/tags/{sha}")
        target = payload.get("object")
    raise ReleaseRunError(f"tag {tag} has excessive annotated-tag indirection")


def assert_tag_sha(api: JsonApi, repository: str, tag: str, expected_sha: str) -> None:
    observed = resolve_tag(api, repository, tag)
    if observed != expected_sha:
        raise ReleaseRunError(
            f"tag {tag} resolves to {observed}, expected qualified commit {expected_sha}"
        )


def workflow_runs_path(repository: str, workflow: str, tag: str) -> str:
    query = urllib.parse.urlencode(
        {"branch": tag, "event": "push", "per_page": "100"}
    )
    encoded_workflow = urllib.parse.quote(workflow, safe="")
    return f"/repos/{repository}/actions/workflows/{encoded_workflow}/runs?{query}"


def matching_run(
    payload: dict[str, Any], tag: str, expected_sha: str
) -> dict[str, Any] | None:
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        raise ReleaseRunError("workflow-runs response has no workflow_runs list")

    tag_runs = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("event") == "push"
        and run.get("head_branch") == tag
    ]
    wrong_shas = sorted(
        {
            str(run.get("head_sha"))
            for run in tag_runs
            if run.get("head_sha") != expected_sha
        }
    )
    if wrong_shas:
        raise ReleaseRunError(
            f"release workflow for {tag} ran at unexpected SHA(s): {', '.join(wrong_shas)}"
        )
    exact = [run for run in tag_runs if run.get("head_sha") == expected_sha]
    if len(exact) > 1:
        ids = ", ".join(str(run.get("id")) for run in exact)
        raise ReleaseRunError(f"multiple exact release runs found for {tag}: {ids}")
    return exact[0] if exact else None


def validate_run_identity(
    run: dict[str, Any], run_id: int, tag: str, expected_sha: str
) -> None:
    expected = {
        "id": run_id,
        "event": "push",
        "head_branch": tag,
        "head_sha": expected_sha,
    }
    mismatches = [
        f"{field}={run.get(field)!r} (expected {value!r})"
        for field, value in expected.items()
        if run.get(field) != value
    ]
    if mismatches:
        raise ReleaseRunError("release run identity changed: " + "; ".join(mismatches))


def wait_for_release_run(
    api: JsonApi,
    repository: str,
    workflow: str,
    tag: str,
    expected_sha: str,
    *,
    timeout: float,
    interval: float,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    if timeout <= 0 or interval <= 0:
        raise ReleaseRunError("timeout and interval must be positive")
    deadline = clock() + timeout
    assert_tag_sha(api, repository, tag, expected_sha)
    run_id: int | None = None

    while clock() < deadline:
        if run_id is None:
            payload = api.get(workflow_runs_path(repository, workflow, tag))
            run = matching_run(payload, tag, expected_sha)
            if run is not None:
                candidate = run.get("id")
                if not isinstance(candidate, int):
                    raise ReleaseRunError("matching release run has no integer id")
                run_id = candidate
                print(f"found release workflow run {run_id} for {tag} at {expected_sha}")
        else:
            run = api.get(f"/repos/{repository}/actions/runs/{run_id}")
            validate_run_identity(run, run_id, tag, expected_sha)
            status = run.get("status")
            conclusion = run.get("conclusion")
            print(f"release workflow run {run_id}: status={status} conclusion={conclusion}")
            if status == "completed":
                assert_tag_sha(api, repository, tag, expected_sha)
                if conclusion == "success":
                    return run_id
                if conclusion in TERMINAL_FAILURES:
                    raise ReleaseRunError(
                        f"release workflow run {run_id} concluded {conclusion}"
                    )
                raise ReleaseRunError(
                    f"release workflow run {run_id} completed with invalid "
                    f"conclusion {conclusion!r}"
                )
            if status not in ACTIVE_STATUSES:
                raise ReleaseRunError(
                    f"release workflow run {run_id} has unknown status {status!r}"
                )
        remaining = deadline - clock()
        if remaining <= 0:
            break
        sleeper(min(interval, remaining))

    target = f"run {run_id}" if run_id is not None else "a matching run"
    raise ReleaseRunError(
        f"timed out after {timeout:g}s waiting for {target} for {tag} at {expected_sha}"
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="owner/repository")
    parser.add_argument("--workflow", default="release.yml")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--timeout", type=float, default=7200)
    parser.add_argument("--interval", type=float, default=20)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN", "")
    try:
        api = GitHubApi(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        wait_for_release_run(
            api,
            args.repository,
            args.workflow,
            args.tag,
            args.sha,
            timeout=args.timeout,
            interval=args.interval,
        )
    except ReleaseRunError as error:
        print(f"release workflow wait failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
