"""Regression checks for release-qualification workflow trigger policy."""

import re
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


def aggregate_needs(source: str, aggregate: str) -> tuple[str, ...]:
    match = re.search(
        rf"^  {re.escape(aggregate)}:\n.*?^    needs:\n(?P<needs>(?:      - .+\n)+).*?^    steps:",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"workflow has no {aggregate} aggregate needs block")
    return tuple(re.findall(r"(?m)^      - ([a-z0-9-]+)$", match.group("needs")))


class ReleaseQualificationWorkflowPolicyTests(unittest.TestCase):
    def test_complete_ci_and_security_workflows_support_manual_dispatch(self) -> None:
        for name in ("ci.yml", "security.yml"):
            with self.subTest(workflow=name):
                self.assertRegex(trigger_block(workflow(name)), r"(?m)^  workflow_dispatch:$")

    def test_scorecard_retains_manual_dispatch_for_release_qualification(self) -> None:
        self.assertRegex(
            trigger_block(workflow("scorecard.yml")), r"(?m)^  workflow_dispatch:$"
        )

    def test_ci_manual_dispatch_keeps_e2e_handoff_push_only(self) -> None:
        source = workflow("ci.yml")
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", source)

    def test_ci_aggregate_still_requires_every_gate(self) -> None:
        source = workflow("ci.yml")
        self.assertEqual(aggregate_needs(source, "ci"), CI_GATES)
        for job in CI_GATES:
            with self.subTest(job=job):
                variable = job.upper().replace("-", "_")
                self.assertIn(f'test "${variable}_RESULT" = success', source)

    def test_security_aggregate_still_requires_every_gate(self) -> None:
        source = workflow("security.yml")
        self.assertEqual(aggregate_needs(source, "security"), SECURITY_GATES)
        for job in SECURITY_GATES:
            with self.subTest(job=job):
                variable = job.upper().replace("-", "_")
                self.assertIn(f'test "${variable}_RESULT" = success', source)


if __name__ == "__main__":
    unittest.main()
