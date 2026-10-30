#!/usr/bin/env python3
"""Require a release tag to identify a commit from protected main."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class ReleaseCommitError(ValueError):
    """The release commit is not qualified for publication."""


def git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise ReleaseCommitError(f"cannot run git: {error}") from error


def resolve_commit(root: Path, revision: str) -> str:
    result = git(root, "rev-parse", "--verify", f"{revision}^{{commit}}")
    if result.returncode != 0:
        detail = result.stderr.strip() or "unknown revision"
        raise ReleaseCommitError(f"cannot resolve {revision}: {detail}")
    return result.stdout.strip()


def validate_release_commit(
    root: Path,
    release_sha: str,
    release_tag: str,
    protected_ref: str = "refs/remotes/origin/main",
) -> None:
    if FULL_SHA.fullmatch(release_sha) is None:
        raise ReleaseCommitError(f"release SHA is not a full commit ID: {release_sha!r}")

    ref_check = git(root, "check-ref-format", f"refs/tags/{release_tag}")
    if ref_check.returncode != 0 or not release_tag.startswith("v"):
        raise ReleaseCommitError(f"release tag is not a valid v-prefixed ref: {release_tag!r}")

    head_sha = resolve_commit(root, "HEAD")
    if head_sha != release_sha:
        raise ReleaseCommitError(
            f"checkout {head_sha} does not match release event SHA {release_sha}"
        )

    tag_sha = resolve_commit(root, f"refs/tags/{release_tag}")
    if tag_sha != release_sha:
        raise ReleaseCommitError(
            f"tag {release_tag} resolves to {tag_sha}, expected {release_sha}"
        )

    protected_sha = resolve_commit(root, protected_ref)
    ancestry = git(root, "merge-base", "--is-ancestor", release_sha, protected_sha)
    if ancestry.returncode == 1:
        raise ReleaseCommitError(
            f"release SHA {release_sha} is not contained in protected main "
            f"at {protected_sha}"
        )
    if ancestry.returncode != 0:
        detail = ancestry.stderr.strip() or "git merge-base failed"
        raise ReleaseCommitError(f"cannot verify protected-main ancestry: {detail}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True, help="exact release event commit SHA")
    parser.add_argument("--tag", required=True, help="exact v-prefixed release tag")
    parser.add_argument(
        "--protected-ref",
        default="refs/remotes/origin/main",
        help="fetched protected-main ref",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (default: repository containing this script)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        validate_release_commit(
            args.root.resolve(), args.sha, args.tag, args.protected_ref
        )
    except ReleaseCommitError as error:
        print(f"release commit check failed: {error}", file=sys.stderr)
        return 1
    print(f"release tag {args.tag} is qualified from protected main at {args.sha}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
