"""Regression checks for required workflow trigger and aggregate policy."""

import os
import re
import subprocess
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"

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
