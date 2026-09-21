import unittest
from collections import defaultdict
from typing import Any

from scripts.wait_for_release_run import (
    GitHubApi,
    ReleaseRunError,
    wait_for_release_run,
    workflow_runs_path,
)


REPOSITORY = "greenbone-hive/rust-gvm"
WORKFLOW = "release.yml"
TAG = "v0.7.0"
SHA = "a" * 40
RUN_ID = 680


class FakeApi:
    def __init__(self) -> None:
        self.responses: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def add(self, path: str, *responses: dict[str, Any]) -> None:
        self.responses[path].extend(responses)

    def get(self, path: str) -> dict[str, Any]:
        queued = self.responses[path]
        if not queued:
            raise AssertionError(f"unexpected API request: {path}")
        if len(queued) == 1:
            return queued[0]
        return queued.pop(0)


class FakeTime:
    def __init__(self) -> None:
        self.value = 0.0

    def clock(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.value += duration


def tag_payload(sha: str = SHA) -> dict[str, Any]:
    return {"object": {"type": "commit", "sha": sha}}


def run_payload(
    *,
    sha: str = SHA,
    status: str = "queued",
    conclusion: str | None = None,
) -> dict[str, Any]:
    return {
        "id": RUN_ID,
        "event": "push",
        "head_branch": TAG,
        "head_sha": sha,
        "status": status,
        "conclusion": conclusion,
    }


class ReleaseRunPollingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = FakeApi()
        self.time = FakeTime()
        self.tag_path = f"/repos/{REPOSITORY}/git/ref/tags/{TAG}"
        self.runs_path = workflow_runs_path(REPOSITORY, WORKFLOW, TAG)
        self.run_path = f"/repos/{REPOSITORY}/actions/runs/{RUN_ID}"

    def wait(self, timeout: float = 10) -> int:
        return wait_for_release_run(
            self.api,
            REPOSITORY,
            WORKFLOW,
            TAG,
            SHA,
            timeout=timeout,
            interval=1,
            clock=self.time.clock,
            sleeper=self.time.sleep,
        )

    def test_success_uses_final_api_conclusion(self) -> None:
        self.api.add(self.tag_path, tag_payload(), tag_payload())
        self.api.add(self.runs_path, {"workflow_runs": [run_payload()]})
        self.api.add(
            self.run_path,
            run_payload(status="in_progress"),
            run_payload(status="completed", conclusion="success"),
        )

        self.assertEqual(self.wait(), RUN_ID)

    def test_failure_conclusion_is_blocking(self) -> None:
        self.api.add(self.tag_path, tag_payload())
        self.api.add(self.runs_path, {"workflow_runs": [run_payload()]})
        self.api.add(
            self.run_path,
            run_payload(status="completed", conclusion="failure"),
        )

        with self.assertRaisesRegex(ReleaseRunError, "concluded failure"):
            self.wait()

    def test_wrong_sha_for_exact_tag_fails_immediately(self) -> None:
        self.api.add(self.tag_path, tag_payload())
        self.api.add(
            self.runs_path,
            {"workflow_runs": [run_payload(sha="b" * 40)]},
        )

        with self.assertRaisesRegex(ReleaseRunError, "unexpected SHA"):
            self.wait()

    def test_timeout_without_an_exact_run_is_blocking(self) -> None:
        self.api.add(self.tag_path, tag_payload())
        self.api.add(self.runs_path, {"workflow_runs": []})

        with self.assertRaisesRegex(ReleaseRunError, "timed out after 3s"):
            self.wait(timeout=3)

    def test_tag_move_during_run_is_blocking(self) -> None:
        self.api.add(self.tag_path, tag_payload(), tag_payload("c" * 40))
        self.api.add(self.runs_path, {"workflow_runs": [run_payload()]})
        self.api.add(
            self.run_path,
            run_payload(status="completed", conclusion="success"),
        )

        with self.assertRaisesRegex(ReleaseRunError, "qualified commit"):
            self.wait()

    def test_api_rejects_unsafe_base_urls(self) -> None:
        unsafe_urls = (
            "file:///etc/passwd",
            "http://api.github.com",
            "https://token@api.github.com",
            "https://api.github.com?redirect=file:///etc/passwd",
            "https://api.github.com#fragment",
        )
        for url in unsafe_urls:
            with self.subTest(url=url), self.assertRaisesRegex(
                ReleaseRunError, "must be HTTPS"
            ):
                GitHubApi("token", url)

    def test_api_accepts_https_enterprise_base_path(self) -> None:
        api = GitHubApi("token", "https://github.example/api/v3/")
        self.assertEqual(api.api_url, "https://github.example/api/v3")


if __name__ == "__main__":
    unittest.main()
