#!/usr/bin/env python3
"""Validate one exact workspace release version and its publish requirements."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


WORKSPACE_CRATES = (
    "gvm-client",
    "gvm-connection",
    "gvm-gmp",
    "gvm-mock-server",
    "gvm-protocol",
)
SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class ReleaseVersionError(ValueError):
    """The workspace is not internally consistent for a release."""


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ReleaseVersionError(f"cannot read {path}: {error}") from error


def package_uses_workspace_version(package: dict[str, Any]) -> bool:
    version = package.get("version")
    return isinstance(version, dict) and version.get("workspace") is True


def validate_workspace(root: Path, expected: str) -> None:
    if not SEMVER.fullmatch(expected):
        raise ReleaseVersionError(f"expected version is not SemVer: {expected!r}")

    manifest = load_toml(root / "Cargo.toml")
    workspace = manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise ReleaseVersionError("Cargo.toml has no [workspace] table")

    package = workspace.get("package")
    if not isinstance(package, dict) or package.get("version") != expected:
        observed = package.get("version") if isinstance(package, dict) else None
        raise ReleaseVersionError(
            f"workspace package version must be {expected}, found {observed!r}"
        )

    members = workspace.get("members")
    if not isinstance(members, list):
        raise ReleaseVersionError("workspace members must be a list")
    member_names = tuple(sorted(Path(str(member)).name for member in members))
    if member_names != WORKSPACE_CRATES:
        raise ReleaseVersionError(
            f"workspace crates must be {WORKSPACE_CRATES}, found {member_names}"
        )

    dependencies = workspace.get("dependencies")
    if not isinstance(dependencies, dict):
        raise ReleaseVersionError("Cargo.toml has no [workspace.dependencies] table")

    for crate in WORKSPACE_CRATES:
        member_path = root / "crates" / crate / "Cargo.toml"
        member = load_toml(member_path)
        member_package = member.get("package")
        if not isinstance(member_package, dict):
            raise ReleaseVersionError(f"{member_path} has no [package] table")
        if member_package.get("name") != crate:
            raise ReleaseVersionError(
                f"{member_path} package name must be {crate!r}"
            )
        if not package_uses_workspace_version(member_package):
            raise ReleaseVersionError(
                f"{member_path} must set package.version.workspace = true"
            )

        requirement = dependencies.get(crate)
        if not isinstance(requirement, dict):
            raise ReleaseVersionError(
                f"workspace dependency {crate} must be an inline table"
            )
        if requirement.get("version") != expected:
            raise ReleaseVersionError(
                f"workspace dependency {crate} must require {expected}, "
                f"found {requirement.get('version')!r}"
            )
        expected_path = f"crates/{crate}"
        if requirement.get("path") != expected_path:
            raise ReleaseVersionError(
                f"workspace dependency {crate} must use path {expected_path!r}"
            )

    lock = load_toml(root / "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise ReleaseVersionError("Cargo.lock contains no package entries")
    for crate in WORKSPACE_CRATES:
        entries = [
            entry
            for entry in packages
            if isinstance(entry, dict) and entry.get("name") == crate
        ]
        if len(entries) != 1:
            raise ReleaseVersionError(
                f"Cargo.lock must contain exactly one {crate} package, found {len(entries)}"
            )
        entry = entries[0]
        if entry.get("version") != expected:
            raise ReleaseVersionError(
                f"Cargo.lock {crate} version must be {expected}, "
                f"found {entry.get('version')!r}"
            )
        if "source" in entry:
            raise ReleaseVersionError(
                f"Cargo.lock {crate} unexpectedly resolves from {entry['source']!r}"
            )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", help="exact SemVer release version")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="workspace root (default: repository containing this script)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        validate_workspace(args.root.resolve(), args.expected)
    except ReleaseVersionError as error:
        print(f"release version check failed: {error}", file=sys.stderr)
        return 1
    print(
        f"release version {args.expected} is consistent across "
        f"{len(WORKSPACE_CRATES)} workspace crates, requirements, and Cargo.lock"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
