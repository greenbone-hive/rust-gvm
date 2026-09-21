import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.check_release_version import ReleaseVersionError, validate_workspace


CRATES = (
    "gvm-client",
    "gvm-connection",
    "gvm-gmp",
    "gvm-mock-server",
    "gvm-protocol",
)


class ReleaseVersionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="release-version-"))
        self.addCleanup(shutil.rmtree, self.root)
        members = ",\n".join(f'  "crates/{crate}"' for crate in CRATES)
        requirements = "\n".join(
            f'{crate} = {{ version = "0.7.0", path = "crates/{crate}" }}'
            for crate in CRATES
        )
        (self.root / "Cargo.toml").write_text(
            f"""[workspace]
members = [
{members},
]

[workspace.package]
version = "0.7.0"

[workspace.dependencies]
{requirements}
""",
            encoding="utf-8",
        )
        for crate in CRATES:
            path = self.root / "crates" / crate
            path.mkdir(parents=True)
            (path / "Cargo.toml").write_text(
                f"""[package]
name = "{crate}"
version.workspace = true
""",
                encoding="utf-8",
            )
        lock_packages = "\n".join(
            f'[[package]]\nname = "{crate}"\nversion = "0.7.0"\n'
            for crate in CRATES
        )
        (self.root / "Cargo.lock").write_text(
            f"version = 4\n\n{lock_packages}", encoding="utf-8"
        )

    def test_consistent_workspace_passes(self) -> None:
        validate_workspace(self.root, "0.7.0")

    def test_path_only_internal_requirement_fails_closed(self) -> None:
        manifest = (self.root / "Cargo.toml").read_text(encoding="utf-8")
        manifest = manifest.replace(
            'gvm-client = { version = "0.7.0", path = "crates/gvm-client" }',
            'gvm-client = { path = "crates/gvm-client" }',
        )
        (self.root / "Cargo.toml").write_text(manifest, encoding="utf-8")

        with self.assertRaisesRegex(ReleaseVersionError, "must require 0.7.0"):
            validate_workspace(self.root, "0.7.0")

    def test_member_and_lock_versions_must_match(self) -> None:
        lock = (self.root / "Cargo.lock").read_text(encoding="utf-8")
        lock = lock.replace(
            'name = "gvm-gmp"\nversion = "0.7.0"',
            'name = "gvm-gmp"\nversion = "0.6.0"',
        )
        (self.root / "Cargo.lock").write_text(lock, encoding="utf-8")

        with self.assertRaisesRegex(ReleaseVersionError, "gvm-gmp version"):
            validate_workspace(self.root, "0.7.0")

    def test_invalid_expected_version_is_rejected(self) -> None:
        with self.assertRaisesRegex(ReleaseVersionError, "not SemVer"):
            validate_workspace(self.root, "release")


if __name__ == "__main__":
    unittest.main()
