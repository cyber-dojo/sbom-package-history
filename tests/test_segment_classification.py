from sbom_package_history.segment_classification import classify_segment

FP = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
IMAGE = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/differ:8beff99@sha256:{FP}"
JUN_01 = 1780272000
JUN_08 = 1780876800

SEGMENT = {"fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08}

PACKAGES = [
    {"name": "rack",    "version": "3.0.0", "license": "MIT",     "purl": "pkg:gem/rack@3.0.0"},
    {"name": "openssl", "version": "3.0.11", "license": "OpenSSL", "purl": "pkg:deb/debian/openssl@3.0.11"},
]

ANY_RACK = {"name": "rack", "purl": None, "version": None}


def test_8d1c6f01():
    """A segment whose SBOM could not be fetched is classified unknown."""
    assert classify_segment(SEGMENT, None, ANY_RACK) == {
        "fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08,
        "status": "unknown", "version": None,
    }


def test_8d1c6f02():
    """A segment whose SBOM contains the package is present with the SBOM's actual version."""
    assert classify_segment(SEGMENT, PACKAGES, ANY_RACK) == {
        "fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08,
        "status": "present", "version": "3.0.0",
    }


def test_8d1c6f03():
    """A segment whose SBOM lacks the package is classified absent."""
    spec = {"name": "leftpad", "purl": None, "version": None}
    assert classify_segment(SEGMENT, PACKAGES, spec) == {
        "fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08,
        "status": "absent", "version": None,
    }


def test_8d1c6f04():
    """A matching version filter reports present with the concrete SBOM version."""
    spec = {"name": "rack", "purl": None, "version": "3.0"}
    assert classify_segment(SEGMENT, PACKAGES, spec) == {
        "fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08,
        "status": "present", "version": "3.0.0",
    }


def test_8d1c6f05():
    """A version filter that no package satisfies is classified absent."""
    spec = {"name": "rack", "purl": None, "version": "3.1"}
    assert classify_segment(SEGMENT, PACKAGES, spec) == {
        "fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08,
        "status": "absent", "version": None,
    }
