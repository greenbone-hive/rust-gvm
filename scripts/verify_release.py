#!/usr/bin/env python3
"""Fail-closed verification for staged or published rust-gvm release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

try:
    from scripts.check_sbom_quality import check_report, entry_path
except ModuleNotFoundError:  # Direct execution places scripts/ on sys.path.
    from check_sbom_quality import check_report, entry_path


CRATES = (
    "gvm-client",
    "gvm-connection",
    "gvm-gmp",
    "gvm-mock-server",
    "gvm-protocol",
)
BINARY_ARCHIVES = (
    "gvm-mock-server-linux-amd64.tar.gz",
    "gvm-mock-server-linux-arm64.tar.gz",
    "gvm-mock-server-linux-amd64-musl.tar.gz",
    "gvm-mock-server-macos-amd64.tar.gz",
    "gvm-mock-server-macos-arm64.tar.gz",
)
SBOM_ARCHIVE = "rust-gvm-sbom.tar.gz"
SBOM_QUALITY = "sbomqs-results.json"
SBOM_THRESHOLD = 8.3
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    """A release invariant did not hold."""


def expected_assets() -> tuple[str, ...]:
    archives = (*BINARY_ARCHIVES, SBOM_ARCHIVE)
    return tuple(sorted((*archives, *(f"{name}.sha256" for name in archives), SBOM_QUALITY)))


def run(command: list[str], *, cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as error:
        raise VerificationError(f"required command is unavailable: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = error.stderr.strip() or error.stdout.strip()
        raise VerificationError(
            f"command failed ({' '.join(command)}): {detail}"
        ) from error
    return result.stdout.strip()


def run_json(command: list[str], *, cwd: Path | None = None) -> Any:
    output = run(command, cwd=cwd)
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise VerificationError(
            f"command returned invalid JSON ({' '.join(command)}): {error}"
        ) from error


def verify_asset_names(directory: Path) -> None:
    observed = tuple(sorted(path.name for path in directory.iterdir() if path.is_file()))
    expected = expected_assets()
    if observed != expected:
        missing = sorted(set(expected) - set(observed))
        unexpected = sorted(set(observed) - set(expected))
        raise VerificationError(
            f"release asset set mismatch; missing={missing}, unexpected={unexpected}"
        )


def verify_checksum(directory: Path, archive_name: str) -> None:
    checksum_path = directory / f"{archive_name}.sha256"
    lines = checksum_path.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1:
        raise VerificationError(f"{checksum_path.name} must contain exactly one checksum")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1].lstrip("*") != archive_name:
        raise VerificationError(
            f"{checksum_path.name} must identify only {archive_name}"
        )
    expected_hash = fields[0].lower()
    if not SHA256.fullmatch(expected_hash):
        raise VerificationError(f"{checksum_path.name} has an invalid SHA-256 digest")
    digest = hashlib.sha256((directory / archive_name).read_bytes()).hexdigest()
    if digest != expected_hash:
        raise VerificationError(
            f"checksum mismatch for {archive_name}: expected {expected_hash}, found {digest}"
        )


def normalized_tar_files(archive: tarfile.TarFile) -> list[str]:
    files: list[str] = []
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts:
            raise VerificationError(f"unsafe archive path: {member.name}")
        if member.isfile():
            files.append(str(path).removeprefix("./"))
        elif not member.isdir():
            raise VerificationError(f"unsupported archive member: {member.name}")
    return sorted(files)


def verify_binary_archives(directory: Path, version: str) -> None:
    for archive_name in BINARY_ARCHIVES:
        with tarfile.open(directory / archive_name, "r:gz") as archive:
            files = normalized_tar_files(archive)
        if files != ["gvm-mock-server"]:
            raise VerificationError(f"{archive_name} has unexpected contents: {files}")

    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        print("native archive execution skipped: verifier is not Linux amd64")
        return
    with tempfile.TemporaryDirectory(prefix="rust-gvm-binary-") as temp:
        temp_path = Path(temp)
        with tarfile.open(directory / BINARY_ARCHIVES[0], "r:gz") as archive:
            archive.extractall(temp_path, filter="data")
        observed = run([str(temp_path / "gvm-mock-server"), "--build-version"])
    expected = f"gvm-mock-server {version}"
    if observed != expected:
        raise VerificationError(
            f"native binary version mismatch: expected {expected!r}, found {observed!r}"
        )


def verify_json_sbom(path: Path, version: str, supplier: str) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid JSON SBOM {path.name}: {error}") from error
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise VerificationError(f"{path.name} has no metadata object")
    if metadata.get("supplier") != {"name": supplier}:
        raise VerificationError(f"{path.name} does not identify supplier {supplier}")
    component = metadata.get("component")
    if not isinstance(component, dict) or component.get("version") != version:
        raise VerificationError(f"{path.name} primary component is not version {version}")
    if document.get("specVersion") != "1.5":
        raise VerificationError(f"{path.name} is not CycloneDX 1.5")


def verify_xml_sbom(path: Path, version: str) -> None:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError, DefusedXmlException) as error:
        raise VerificationError(f"invalid XML SBOM {path.name}: {error}") from error
    if root.attrib.get("specVersion") != "1.5":
        raise VerificationError(f"{path.name} is not CycloneDX 1.5")
    component_version = root.findtext("{*}metadata/{*}component/{*}version")
    if component_version != version:
        raise VerificationError(f"{path.name} primary component is not version {version}")


def verify_sbom(directory: Path, version: str, supplier: str) -> None:
    expected_files = sorted(
        [
            *(f"{crate}.cdx.json" for crate in CRATES),
            *(f"{crate}.cdx.xml" for crate in CRATES),
        ]
    )
    with tempfile.TemporaryDirectory(prefix="rust-gvm-sbom-") as temp:
        temp_path = Path(temp)
        with tarfile.open(directory / SBOM_ARCHIVE, "r:gz") as archive:
            files = normalized_tar_files(archive)
            if files != expected_files:
                raise VerificationError(
                    f"SBOM archive contents mismatch; expected={expected_files}, found={files}"
                )
            archive.extractall(temp_path, filter="data")
        for crate in CRATES:
            verify_json_sbom(temp_path / f"{crate}.cdx.json", version, supplier)
            verify_xml_sbom(temp_path / f"{crate}.cdx.xml", version)

    try:
        report = json.loads((directory / SBOM_QUALITY).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"invalid {SBOM_QUALITY}: {error}") from error
    if not isinstance(report, dict) or not isinstance(report.get("files"), list):
        raise VerificationError(f"invalid {SBOM_QUALITY} structure")
    scored = sorted(Path(entry_path(entry)).name for entry in report["files"] if isinstance(entry, dict))
    expected_scored = sorted(f"{crate}.cdx.json" for crate in CRATES)
    if scored != expected_scored:
        raise VerificationError(
            f"SBOM quality report file set mismatch; expected={expected_scored}, found={scored}"
        )
    try:
        failures = check_report(report, SBOM_THRESHOLD)
    except ValueError as error:
        raise VerificationError(f"invalid {SBOM_QUALITY}: {error}") from error
    if failures:
        raise VerificationError(f"SBOM quality scores below {SBOM_THRESHOLD}: {failures}")


def verify_local_assets(directory: Path, version: str, supplier: str) -> None:
    verify_asset_names(directory)
    for archive_name in (*BINARY_ARCHIVES, SBOM_ARCHIVE):
        verify_checksum(directory, archive_name)
    verify_binary_archives(directory, version)
    verify_sbom(directory, version, supplier)
    print(f"verified complete local release asset set for v{version}")


def release_asset_names(release: dict[str, Any]) -> tuple[str, ...]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise VerificationError("release response has no assets list")
    return tuple(
        sorted(
            str(asset.get("name"))
            for asset in assets
            if isinstance(asset, dict) and asset.get("name")
        )
    )


def platform_digests(index: dict[str, Any]) -> dict[str, str]:
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise VerificationError("GHCR tag is not a multi-platform image index")
    result: dict[str, str] = {}
    unexpected: list[str] = []
    for manifest in manifests:
        if not isinstance(manifest, dict):
            raise VerificationError("GHCR image index contains a non-object manifest")
        target = manifest.get("platform")
        if not isinstance(target, dict):
            raise VerificationError("GHCR image manifest has no platform")
        os_name = str(target.get("os", ""))
        architecture = str(target.get("architecture", ""))
        if (os_name, architecture) == ("unknown", "unknown"):
            continue
        key = f"{os_name}/{architecture}"
        digest = manifest.get("digest")
        if key not in {"linux/amd64", "linux/arm64"}:
            unexpected.append(key)
        elif key in result or not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise VerificationError(f"invalid or duplicate GHCR manifest for {key}")
        else:
            result[key] = digest
    if unexpected or set(result) != {"linux/amd64", "linux/arm64"}:
        raise VerificationError(
            f"GHCR platforms mismatch; found={sorted(result)}, unexpected={sorted(unexpected)}"
        )
    return result


def verify_container(repository: str, tag: str, version: str, sha: str) -> None:
    owner = repository.split("/", maxsplit=1)[0]
    image_name = f"ghcr.io/{owner}/gvm-mock-server"
    image = f"{image_name}:{tag}"
    index = run_json(["docker", "buildx", "imagetools", "inspect", "--raw", image])
    if not isinstance(index, dict):
        raise VerificationError("GHCR image index is not a JSON object")
    digests = platform_digests(index)
    expected_labels = {
        "org.opencontainers.image.source": f"https://github.com/{repository}",
        "org.opencontainers.image.revision": sha,
        "org.opencontainers.image.version": tag,
    }
    for target, digest in sorted(digests.items()):
        reference = f"{image_name}@{digest}"
        run(["docker", "pull", "--platform", target, reference])
        labels = run_json(
            ["docker", "image", "inspect", "--format", "{{json .Config.Labels}}", reference]
        )
        if not isinstance(labels, dict):
            raise VerificationError(f"{target} image has no labels")
        for label, expected in expected_labels.items():
            if labels.get(label) != expected:
                raise VerificationError(
                    f"{target} label {label} must be {expected!r}, found {labels.get(label)!r}"
                )
        observed = run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                target,
                reference,
                "--build-version",
            ]
        )
        if observed != f"gvm-mock-server {version}":
            raise VerificationError(f"{target} container reported {observed!r}")
    run(["gh", "attestation", "verify", f"oci://{image}", "--repo", repository])


def verify_published(repository: str, version: str, sha: str) -> None:
    tag = f"v{version}"
    commit = run_json(["gh", "api", f"repos/{repository}/commits/{tag}"])
    if not isinstance(commit, dict) or commit.get("sha") != sha:
        observed = commit.get("sha") if isinstance(commit, dict) else None
        raise VerificationError(
            f"tag {tag} resolves to {observed!r}, expected qualified commit {sha}"
        )
    release = run_json(
        [
            "gh",
            "release",
            "view",
            tag,
            "--repo",
            repository,
            "--json",
            "assets,body,isDraft,isPrerelease,tagName",
        ]
    )
    if not isinstance(release, dict):
        raise VerificationError("release response is not a JSON object")
    if release.get("tagName") != tag or release.get("isDraft") is not False:
        raise VerificationError(f"release {tag} is missing, draft, or identifies another tag")
    if release.get("isPrerelease") is not ("-" in version):
        raise VerificationError(f"release {tag} has incorrect prerelease state")
    if release_asset_names(release) != expected_assets():
        raise VerificationError("published release asset set is incomplete or unexpected")
    migration_version = version.split("-", maxsplit=1)[0]
    migration_url = (
        f"https://github.com/{repository}/blob/{tag}/docs/"
        f"v{migration_version}-migration.md"
    )
    if migration_url not in str(release.get("body", "")):
        raise VerificationError(f"release notes do not link {migration_url}")

    with tempfile.TemporaryDirectory(prefix="rust-gvm-release-") as temp:
        directory = Path(temp)
        run(["gh", "release", "download", tag, "--repo", repository, "--dir", str(directory)])
        verify_local_assets(directory, version, repository.split("/", maxsplit=1)[0])
        for archive_name in (*BINARY_ARCHIVES, SBOM_ARCHIVE):
            run(
                [
                    "gh",
                    "attestation",
                    "verify",
                    str(directory / archive_name),
                    "--repo",
                    repository,
                ]
            )
    verify_container(repository, tag, version, sha)
    print(f"verified published release {tag} at {sha}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    assets = subparsers.add_parser("assets", help="verify a staged asset directory")
    assets.add_argument("--directory", required=True, type=Path)
    assets.add_argument("--version", required=True)
    assets.add_argument("--supplier", default="greenbone-hive")
    published = subparsers.add_parser("published", help="verify a published release")
    published.add_argument("--repository", default="greenbone-hive/rust-gvm")
    published.add_argument("--version", required=True)
    published.add_argument("--sha", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.command == "assets":
            verify_local_assets(args.directory.resolve(), args.version, args.supplier)
        else:
            verify_published(args.repository, args.version, args.sha)
    except (OSError, tarfile.TarError, VerificationError) as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
