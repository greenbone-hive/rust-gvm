"""Regression checks for required workflow trigger and aggregate policy."""

import os
import re
import subprocess
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SETUP_RUST_ACTION = (
    "greenbone/actions/setup-rust@d6d4c9500cb4e83f8a516ec1d40b04bcc720bd22"
)
SEMGREP_IMAGE = (
    "semgrep/semgrep:1.176.1@"
    "sha256:34ab619bf1391a24bfda3f05debd0d8a6ce3093c2d5f9d39cfc00f83c1397823"
)
BLOCKED_ACTIONS = (
    "dtolnay/rust-toolchain@",
    "returntocorp/semgrep-action@",
    "swatinem/rust-cache@",
    "taiki-e/install-action@",
)
CARGO_TOOL_CONTRACTS = (
    ("ci.yml", "deny", "cargo-deny", "CARGO_DENY_VERSION", "0.20.2"),
    (
        "ci.yml",
        "coverage",
        "cargo-llvm-cov",
        "CARGO_LLVM_COV_VERSION",
        "0.9.1",
    ),
    (
        "security.yml",
        "cargo-audit",
        "cargo-audit",
        "CARGO_AUDIT_VERSION",
        "0.22.1",
    ),
    (
        "security.yml",
        "cargo-machete",
        "cargo-machete",
        "CARGO_MACHETE_VERSION",
        "0.9.1",
    ),
    (
        "security.yml",
        "cargo-vet",
        "cargo-vet",
        "CARGO_VET_VERSION",
        "0.10.3",
    ),
    (
        "security.yml",
        "sbom-quality",
        "cargo-cyclonedx",
        "CARGO_CYCLONEDX_VERSION",
        "0.5.9",
    ),
    (
        "security.yml",
        "cargo-geiger-report",
        "cargo-geiger",
        "CARGO_GEIGER_VERSION",
        "0.14.0",
    ),
    (
        "security.yml",
        "cargo-geiger-workspace-gate",
        "cargo-geiger",
        "CARGO_GEIGER_VERSION",
        "0.14.0",
    ),
    (
        "release.yml",
        "sbom",
        "cargo-cyclonedx",
        "CARGO_CYCLONEDX_VERSION",
        "0.5.9",
    ),
)

CI_GATES = (
    "fmt",
    "clippy",
    "test",
    "test-features",
    "doc",
    "deny",
    "coverage",
    "integration",
    "msrv",
)
SECURITY_GATES = (
    "cargo-audit",
    "cargo-machete",
    "cargo-vet",
    "sbom-quality",
    "cargo-geiger-report",
    "cargo-geiger-workspace-gate",
    "semgrep",
)


def workflow(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def workflow_sources() -> dict[str, str]:
    paths = sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))
    if not paths:
        raise AssertionError("repository has no workflow files")
    return {path.name: path.read_text(encoding="utf-8") for path in paths}


def trigger_block(source: str) -> str:
    match = re.search(
        r"^on:\n(?P<triggers>.*?)(?=^permissions:)", source, re.MULTILINE | re.DOTALL
    )
    if match is None:
        raise AssertionError("workflow has no top-level trigger block")
    return match.group("triggers")


def event_config(source: str, event: str) -> str:
    lines = trigger_block(source).splitlines()
    header = f"  {event}:"
    try:
        start = lines.index(header) + 1
    except ValueError as error:
        raise AssertionError(f"workflow has no {event} trigger") from error

    config = []
    for line in lines[start:]:
        if line.startswith("  ") and not line.startswith("    "):
            break
        config.append(line)
    return "\n".join(config)


def job_block(source: str, job: str) -> str:
    match = re.search(
        rf"^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [a-z0-9-]+:\n|\Z)",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"workflow has no {job} job")
    return match.group("body")


def setup_rust_cache_key(source: str, job: str) -> str:
    block = job_block(source, job)
    self_uses = f"uses: {SETUP_RUST_ACTION}"
    if block.count(self_uses) != 1:
        raise AssertionError(f"workflow job {job} must use setup-rust exactly once")
    setup_step = block.split(self_uses, 1)[1].split("\n      - ", 1)[0]
    match = re.search(r"(?m)^          cache-key: (?P<key>.+)$", setup_step)
    if match is None:
        raise AssertionError(f"workflow job {job} setup-rust has no cache key")
    return match.group("key")


def workflow_env_version(source: str, variable: str) -> str:
    declarations = re.findall(rf"(?m)^ +{re.escape(variable)}:", source)
    if len(declarations) != 1:
        raise AssertionError(
            f"workflow must declare {variable} exactly once, found {len(declarations)}"
        )
    match = re.search(
        rf'(?m)^  {re.escape(variable)}: "(?P<version>\d+\.\d+\.\d+)"$', source
    )
    if match is None:
        raise AssertionError(f"workflow has no exact top-level {variable} version")
    return match.group("version")


def job_needs(source: str, job: str) -> tuple[str, ...]:
    block = job_block(source, job)
    inline = re.search(r"(?m)^    needs: (?P<needs>.+)$", block)
    if inline is not None:
        value = inline.group("needs").strip()
        if value.startswith("[") and value.endswith("]"):
            return tuple(item.strip() for item in value[1:-1].split(","))
        return (value,)

    multiline = re.search(
        r"(?m)^    needs:\n(?P<needs>(?:      - [a-z0-9-]+\n)+)", block
    )
    if multiline is None:
        return ()
    return tuple(re.findall(r"(?m)^      - ([a-z0-9-]+)$", multiline.group("needs")))


def job_names(source: str) -> tuple[str, ...]:
    jobs = source.split("\njobs:\n", 1)[1]
    return tuple(re.findall(r"(?m)^  ([a-z0-9-]+):$", jobs))


def depends_on(source: str, job: str, required: str) -> bool:
    direct = job_needs(source, job)
    return required in direct or any(
        depends_on(source, dependency, required) for dependency in direct
    )


def aggregate_needs(source: str, aggregate: str) -> tuple[str, ...]:
    match = re.search(
        r"^    needs:\n(?P<needs>(?:      - .+\n)+).*?^    steps:",
        job_block(source, aggregate),
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"workflow has no {aggregate} aggregate needs block")
    return tuple(re.findall(r"(?m)^      - ([a-z0-9-]+)$", match.group("needs")))


def aggregate_script(source: str, aggregate: str) -> str:
    marker = "        run: |\n"
    block = job_block(source, aggregate)
    if marker not in block:
        raise AssertionError(f"workflow has no {aggregate} aggregate script")
    return textwrap.dedent(block.split(marker, 1)[1])


class WorkflowPolicyTests(unittest.TestCase):
    def test_every_external_action_is_full_sha_pinned_and_approved(self) -> None:
        sources = workflow_sources()
        all_workflows = "\n".join(sources.values())
        uses = re.findall(
            r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", all_workflows
        )
        self.assertTrue(uses)
        for action in uses:
            with self.subTest(action=action):
                if action.startswith("./"):
                    continue
                self.assertRegex(
                    action,
                    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$",
                )

        normalized = all_workflows.lower()
        for blocked in BLOCKED_ACTIONS:
            with self.subTest(blocked=blocked):
                self.assertNotIn(blocked, normalized)

    def test_setup_rust_inputs_and_cache_keys_are_fail_closed(self) -> None:
        all_workflows = "\n".join(workflow_sources().values())
        setup_count = all_workflows.count(f"uses: {SETUP_RUST_ACTION}")
        rust_versions = re.findall(r"(?m)^\s+rust-version: (.+)$", all_workflows)
        components = re.findall(r"(?m)^\s+components: (.+)$", all_workflows)
        cache_keys = re.findall(r"(?m)^\s+cache-key: (.+)$", all_workflows)

        self.assertGreater(setup_count, 0)
        self.assertEqual(len(rust_versions), setup_count)
        self.assertEqual(len(components), setup_count)
        self.assertEqual(len(cache_keys), setup_count)
        self.assertEqual(len(cache_keys), len(set(cache_keys)))
        self.assertEqual(
            set(rust_versions), {"stable", '"1.89.0"', "${{ matrix.rust }}"}
        )
        self.assertEqual(
            set(components), {"rustfmt", "clippy", "llvm-tools-preview"}
        )
        self.assertEqual(components.count("clippy"), 1)
        self.assertEqual(components.count("llvm-tools-preview"), 1)
        for cache_key in cache_keys:
            with self.subTest(cache_key=cache_key):
                self.assertIn("${{ runner.os }}", cache_key)
                self.assertIn("${{ runner.arch }}", cache_key)
                self.assertIn("${{ hashFiles('**/Cargo.lock') }}", cache_key)

        ci = workflow("ci.yml")
        self.assertIn("RUSTUP_TOOLCHAIN: ${{ matrix.rust }}", job_block(ci, "test"))
        self.assertIn('RUSTUP_TOOLCHAIN: "1.89.0"', job_block(ci, "msrv"))
        self.assertIn("components: rustfmt", job_block(ci, "fmt"))
        self.assertIn("components: clippy", job_block(ci, "clippy"))
        self.assertIn(
            "components: llvm-tools-preview", job_block(ci, "coverage")
        )

        sources = workflow_sources()
        for workflow_name, job, _tool, tool_variable, _version in CARGO_TOOL_CONTRACTS:
            with self.subTest(workflow=workflow_name, job=job):
                self.assertIn(
                    f"${{{{ env.{tool_variable} }}}}",
                    setup_rust_cache_key(sources[workflow_name], job),
                )

    def test_release_matrix_installs_every_configured_rust_target(self) -> None:
        source = workflow("release.yml")
        build = job_block(source, "build")
        targets = set(re.findall(r"(?m)^          - target: (.+)$", build))
        self.assertEqual(
            targets,
            {
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "x86_64-unknown-linux-musl",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
            },
        )
        self.assertIn('rustup target add "${{ matrix.target }}"', build)
        self.assertIn("${{ matrix.target }}", build.split("cache-key:", 1)[1])
        self.assertIn("${{ env.CROSS_REV }}", build.split("cache-key:", 1)[1])

    def test_semgrep_uses_reviewed_immutable_image_and_sarif(self) -> None:
        sources = workflow_sources()
        all_workflows = "\n".join(sources.values())
        images = re.findall(r"semgrep/semgrep:[^\s\\]+", all_workflows)
        self.assertEqual(images, [SEMGREP_IMAGE])

        semgrep = job_block(sources["security.yml"], "semgrep")
        self.assertIn(
            "uses: step-security/harden-runner@"
            "1d88384fd173af6ecb012dfd0264a306b711241a",
            semgrep,
        )
        self.assertIn('egress-policy: audit', semgrep)
        self.assertIn('--volume "$PWD:/src:ro"', semgrep)
        self.assertIn("--workdir /src", semgrep)
        self.assertIn(SEMGREP_IMAGE, semgrep)
        self.assertIn("semgrep scan --error", semgrep)
        for config in ("p/rust", "p/security-audit", "p/secrets"):
            with self.subTest(config=config):
                self.assertIn(f"--config {config}", semgrep)
        self.assertIn("--sarif > semgrep.raw.sarif", semgrep)
        self.assertIn("jq '.runs[].tool.driver.name = \"Semgrep\"'", semgrep)
        self.assertIn("semgrep.raw.sarif > semgrep.normalized.sarif", semgrep)
        self.assertIn("mv semgrep.normalized.sarif semgrep.sarif", semgrep)
        self.assertIn("sarif_file: semgrep.sarif", semgrep)

    def test_workflow_installed_tools_are_immutable_and_locked(self) -> None:
        sources = workflow_sources()
        all_workflows = "\n".join(sources.values())
        expected_installs = []
        for workflow_name, job, tool, variable, version in CARGO_TOOL_CONTRACTS:
            with self.subTest(workflow=workflow_name, job=job, tool=tool):
                source = sources[workflow_name]
                self.assertEqual(workflow_env_version(source, variable), version)
                install = f"cargo install {tool}@${{{{ env.{variable} }}}} --locked"
                self.assertEqual(job_block(source, job).count(install), 1)
                expected_installs.append(install)

        selected_installs = re.findall(
            r"(?m)^\s+run: (cargo install cargo-[a-z0-9-]+[^\n]*)$",
            all_workflows,
        )
        self.assertEqual(
            all_workflows.count("cargo install "),
            len(CARGO_TOOL_CONTRACTS) + 1,
        )
        self.assertCountEqual(selected_installs, expected_installs)
        for install in selected_installs:
            with self.subTest(install=install):
                self.assertRegex(
                    install,
                    r"^cargo install cargo-[a-z0-9-]+@\$\{\{ env\.CARGO_[A-Z0-9_]+_VERSION \}\} --locked$",
                )

        release = workflow("release.yml")
        cross_install = re.search(
            r"(?ms)^      - name: Install cross\n(?P<step>.*?)(?=^      - name:)",
            release,
        )
        self.assertIsNotNone(cross_install)
        cross_step = cross_install.group("step")
        self.assertRegex(release, r'(?m)^  CROSS_REV: "[0-9a-f]{40}"$')
        self.assertIn("--rev ${{ env.CROSS_REV }}", cross_step)
        self.assertIn("--locked", cross_step)
        self.assertNotIn("--tag", cross_step)

        security = workflow("security.yml")
        security_cyclonedx = workflow_env_version(
            security, "CARGO_CYCLONEDX_VERSION"
        )
        release_cyclonedx = workflow_env_version(
            release, "CARGO_CYCLONEDX_VERSION"
        )
        self.assertEqual(security_cyclonedx, "0.5.9")
        self.assertEqual(release_cyclonedx, security_cyclonedx)
        self.assertEqual(
            security.count(
                "cargo install cargo-cyclonedx@${{ env.CARGO_CYCLONEDX_VERSION }} --locked"
            ),
            1,
        )
        self.assertEqual(
            release.count(
                "cargo install cargo-cyclonedx@${{ env.CARGO_CYCLONEDX_VERSION }} --locked"
            ),
            1,
        )

    def test_release_write_jobs_require_protected_main_qualification(self) -> None:
        source = workflow("release.yml")
        qualification = job_block(source, "qualify")
        self.assertIn(
            '"+refs/heads/main:refs/remotes/origin/main"', qualification
        )
        self.assertIn("python3 scripts/check_release_commit.py", qualification)

        write_jobs = tuple(
            job
            for job in job_names(source)
            if re.search(r"(?m)^      [a-z-]+: write$", job_block(source, job))
        )
        self.assertTrue(write_jobs)
        for job in write_jobs:
            with self.subTest(job=job):
                self.assertTrue(depends_on(source, job, "qualify"))

    def test_release_orchestrator_restores_supported_python_after_pontos(self) -> None:
        source = workflow("release-orchestrated.yml")
        pontos = source.index("greenbone/actions/setup-pontos@")
        setup_python = source.index("actions/setup-python@", pontos)
        qualification = source.index(
            "Qualify exact protected-main commit and release version", setup_python
        )

        self.assertLess(pontos, setup_python)
        self.assertLess(setup_python, qualification)
        self.assertIn('python-version: "3.12"', source[setup_python:qualification])

    def test_release_orchestrator_attaches_qualified_sha_to_main_before_pontos(self) -> None:
        source = workflow("release-orchestrated.yml")
        qualification = source.index(
            "Qualify exact protected-main commit and release version"
        )
        create_release = source.index("Create release with pontos", qualification)
        qualification_block = source[qualification:create_release]

        self.assertIn('git switch -C main "$RELEASE_SHA"', qualification_block)
        self.assertIn(
            "git branch --set-upstream-to=origin/main main", qualification_block
        )

    def test_complete_ci_and_security_workflows_support_manual_dispatch(self) -> None:
        for name in ("ci.yml", "security.yml"):
            with self.subTest(workflow=name):
                self.assertRegex(trigger_block(workflow(name)), r"(?m)^  workflow_dispatch:$")

    def test_required_workflows_support_merge_queue_checks(self) -> None:
        for name in ("ci.yml", "security.yml"):
            with self.subTest(workflow=name):
                self.assertEqual(
                    event_config(workflow(name), "merge_group").strip(),
                    "types: [checks_requested]",
                )

    def test_required_workflows_cover_documentation_only_changes(self) -> None:
        for name in ("ci.yml", "security.yml"):
            source = workflow(name)
            for event in ("pull_request", "merge_group"):
                with self.subTest(workflow=name, event=event):
                    config = event_config(source, event)
                    self.assertNotRegex(config, r"(?m)^\s+paths(?:-ignore)?:")

    def test_scorecard_retains_manual_dispatch_for_release_qualification(self) -> None:
        self.assertRegex(
            trigger_block(workflow("scorecard.yml")), r"(?m)^  workflow_dispatch:$"
        )

    def test_ci_e2e_handoff_is_successful_main_push_only(self) -> None:
        source = workflow("ci.yml")
        e2e = job_block(source, "trigger-e2e")
        self.assertIn(
            "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
            e2e,
        )
        self.assertRegex(e2e, r"(?m)^    needs: \[test\]$")
        self.assertEqual(source.count("greenbone/actions/trigger-workflow@"), 1)

    def test_ci_aggregate_still_requires_every_gate(self) -> None:
        source = workflow("ci.yml")
        aggregate = job_block(source, "ci")
        self.assertRegex(aggregate, r"(?m)^    name: CI$")
        self.assertRegex(aggregate, r"(?m)^    if: \$\{\{ always\(\) \}\}$")
        self.assertEqual(aggregate_needs(source, "ci"), CI_GATES)
        for job in CI_GATES:
            with self.subTest(job=job):
                variable = job.upper().replace("-", "_")
                self.assertIn(
                    f"{variable}_RESULT: ${{{{ needs.{job}.result }}}}", aggregate
                )
                self.assertIn(f'test "${variable}_RESULT" = success', aggregate)

    def test_security_aggregate_still_requires_every_gate(self) -> None:
        source = workflow("security.yml")
        aggregate = job_block(source, "security")
        self.assertRegex(aggregate, r"(?m)^    name: Security$")
        self.assertRegex(aggregate, r"(?m)^    if: \$\{\{ always\(\) \}\}$")
        self.assertEqual(aggregate_needs(source, "security"), SECURITY_GATES)
        for job in SECURITY_GATES:
            with self.subTest(job=job):
                variable = job.upper().replace("-", "_")
                self.assertIn(
                    f"{variable}_RESULT: ${{{{ needs.{job}.result }}}}", aggregate
                )
                self.assertIn(f'test "${variable}_RESULT" = success', aggregate)

    def test_aggregates_fail_closed_for_every_non_success_child_result(self) -> None:
        for name, aggregate_name, gates in (
            ("ci.yml", "ci", CI_GATES),
            ("security.yml", "security", SECURITY_GATES),
        ):
            script = aggregate_script(workflow(name), aggregate_name)
            success_env = os.environ.copy()
            for job in gates:
                success_env[f"{job.upper().replace('-', '_')}_RESULT"] = "success"

            with self.subTest(workflow=name, result="all-success"):
                completed = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    check=False,
                    env=success_env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            for job in gates:
                variable = f"{job.upper().replace('-', '_')}_RESULT"
                for result in ("failure", "cancelled", "skipped"):
                    with self.subTest(workflow=name, job=job, result=result):
                        completed = subprocess.run(
                            ["bash", "-euo", "pipefail", "-c", script],
                            check=False,
                            env=success_env | {variable: result},
                            capture_output=True,
                            text=True,
                        )
                        self.assertNotEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
