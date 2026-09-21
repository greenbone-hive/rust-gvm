import tempfile
import unittest
from pathlib import Path

from scripts.verify_release import (
    VerificationError,
    expected_assets,
    platform_digests,
    release_asset_names,
    verify_xml_sbom,
)


class ReleaseVerificationTests(unittest.TestCase):
    def test_xml_sbom_rejects_entity_declarations(self) -> None:
        malicious = """\
<!DOCTYPE bom [<!ENTITY payload "untrusted">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" specVersion="1.5">
  <metadata><component><version>&payload;</version></component></metadata>
</bom>
"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "malicious.cdx.xml"
            path.write_text(malicious, encoding="utf-8")
            with self.assertRaisesRegex(VerificationError, "invalid XML SBOM"):
                verify_xml_sbom(path, "0.7.0")

    def test_xml_sbom_accepts_expected_cyclonedx_metadata(self) -> None:
        valid = """\
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" specVersion="1.5">
  <metadata><component><version>0.7.0</version></component></metadata>
</bom>
"""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "valid.cdx.xml"
            path.write_text(valid, encoding="utf-8")
            verify_xml_sbom(path, "0.7.0")

    def test_expected_assets_cover_five_binaries_sbom_checksums_and_quality(self) -> None:
        assets = expected_assets()
        self.assertEqual(len(assets), 13)
        self.assertEqual(len([name for name in assets if name.endswith(".tar.gz")]), 6)
        self.assertEqual(len([name for name in assets if name.endswith(".sha256")]), 6)
        self.assertIn("sbomqs-results.json", assets)

    def test_release_asset_names_are_order_independent(self) -> None:
        self.assertEqual(
            release_asset_names({"assets": [{"name": "b"}, {"name": "a"}]}),
            ("a", "b"),
        )

    def test_exact_amd64_arm64_index_passes_with_attestation_manifests(self) -> None:
        self.assertEqual(
            platform_digests(
                {
                    "manifests": [
                        {
                            "digest": "sha256:amd64",
                            "platform": {"os": "linux", "architecture": "amd64"},
                        },
                        {
                            "digest": "sha256:provenance",
                            "platform": {"os": "unknown", "architecture": "unknown"},
                        },
                        {
                            "digest": "sha256:arm64",
                            "platform": {"os": "linux", "architecture": "arm64"},
                        },
                    ]
                }
            ),
            {"linux/amd64": "sha256:amd64", "linux/arm64": "sha256:arm64"},
        )

    def test_missing_duplicate_or_extra_platform_fails_closed(self) -> None:
        invalid_indexes = [
            {
                "manifests": [
                    {
                        "digest": "sha256:amd64",
                        "platform": {"os": "linux", "architecture": "amd64"},
                    }
                ]
            },
            {
                "manifests": [
                    {
                        "digest": "sha256:amd64",
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "digest": "sha256:amd64-again",
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                ]
            },
            {
                "manifests": [
                    {
                        "digest": "sha256:amd64",
                        "platform": {"os": "linux", "architecture": "amd64"},
                    },
                    {
                        "digest": "sha256:arm64",
                        "platform": {"os": "linux", "architecture": "arm64"},
                    },
                    {
                        "digest": "sha256:s390x",
                        "platform": {"os": "linux", "architecture": "s390x"},
                    },
                ]
            },
        ]
        for index in invalid_indexes:
            with self.subTest(index=index), self.assertRaises(VerificationError):
                platform_digests(index)


if __name__ == "__main__":
    unittest.main()
