from sbom_package_history.kosli_normalizing import (
    normalize_event,
    normalize_baseline_artifact,
    sbom_packages_from_attestation,
)

FP = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
IMAGE = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/differ:8beff99@sha256:{FP}"

PACKAGES = [
    {"name": "rack",    "version": "3.0.0",            "license": "MIT",     "purl": "pkg:gem/rack@3.0.0"},
    {"name": "openssl", "version": "3.0.11-1~deb12u2", "license": "OpenSSL", "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64"},
]


def test_b7e0d401():
    """A raw environment event maps to the core's normalized event shape."""
    raw = {
        "environment_name": "aws-prod",
        "snapshot_index": 4988,
        "artifact_name": IMAGE,
        "sha256": FP,
        "description": "3 instances started running (from 0 to 3)",
        "reported_at": 1783832698.6549723,
        "pipeline": "differ-ci",
        "type": "started-compliant",
        "artifact_compliance": True,
    }
    assert normalize_event(raw) == {
        "fingerprint": FP,
        "image_name": IMAGE,
        "type": "started-compliant",
        "reported_at": 1783832698.6549723,
        "flow": "differ-ci",
    }


def test_b7e0d402():
    """A raw snapshot artifact maps to the core's normalized baseline shape."""
    raw = {
        "name": IMAGE,
        "compliant": True,
        "fingerprint": FP,
        "creationTimestamp": [1783757709, 1783757715, 1783757716],
        "flow_name": "differ-ci",
        "git_commit": "8beff9901ac67acb7afcab3408106208571a1124",
    }
    assert normalize_baseline_artifact(raw) == {
        "fingerprint": FP,
        "image_name": IMAGE,
        "flow": "differ-ci",
    }


def test_b7e0d403():
    """An attestation returned as an object yields its packages list."""
    raw = {
        "schema_version": 1,
        "attestation_name": "sbom-facts",
        "type_name": "sbom-facts",
        "repo_info": {"name": "differ"},
        "attestation_data": {
            "spec_version": "SPDX-2.3",
            "created": "2026-04-10T09:12:00Z",
            "creators": ["Tool: syft-1.0.0"],
            "relationship_count": 214,
            "packages": PACKAGES,
        },
    }
    assert sbom_packages_from_attestation(raw) == PACKAGES


def test_b7e0d404():
    """An attestation returned wrapped in a single-element array yields its packages list."""
    raw = [{
        "attestation_name": "sbom-facts",
        "attestation_data": {"spec_version": "SPDX-2.3", "packages": PACKAGES},
    }]
    assert sbom_packages_from_attestation(raw) == PACKAGES


def test_b7e0d405():
    """An attestation without attestation_data yields an empty packages list."""
    raw = {"attestation_name": "sbom-facts", "type_name": "sbom-facts"}
    assert sbom_packages_from_attestation(raw) == []


def test_b7e0d406():
    """An empty array (no attestation present) yields an empty packages list."""
    assert sbom_packages_from_attestation([]) == []
