import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.check_release_commit import ReleaseCommitError, validate_release_commit


class ReleaseCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="release-commit-"))
        self.addCleanup(shutil.rmtree, self.root)
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.commit("protected main")
        self.main_sha = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", self.main_sha)
        self.git("update-ref", "refs/tags/v1.0.0", self.main_sha)

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def commit(self, message: str) -> None:
        marker = self.root / "history"
        previous = marker.read_text(encoding="utf-8") if marker.exists() else ""
        marker.write_text(f"{previous}{message}\n", encoding="utf-8")
        self.git("add", "history")
        self.git("commit", "-m", message)

    def test_protected_main_tag_passes(self) -> None:
        validate_release_commit(self.root, self.main_sha, "v1.0.0")

    def test_protected_main_ancestor_still_passes_after_main_advances(self) -> None:
        self.commit("later protected main")
        self.git("update-ref", "refs/remotes/origin/main", self.git("rev-parse", "HEAD"))
        self.git("checkout", "--detach", self.main_sha)

        validate_release_commit(self.root, self.main_sha, "v1.0.0")

    def test_off_main_tag_is_rejected(self) -> None:
        self.git("checkout", "--detach", self.main_sha)
        self.commit("unreviewed topic commit")
        topic_sha = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/tags/v1.1.0", topic_sha)

        with self.assertRaisesRegex(ReleaseCommitError, "not contained in protected main"):
            validate_release_commit(self.root, topic_sha, "v1.1.0")

    def test_tag_must_resolve_to_release_sha(self) -> None:
        self.commit("later protected main")
        later_sha = self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/remotes/origin/main", later_sha)

        with self.assertRaisesRegex(ReleaseCommitError, "tag v1.0.0 resolves to"):
            validate_release_commit(self.root, later_sha, "v1.0.0")


if __name__ == "__main__":
    unittest.main()
