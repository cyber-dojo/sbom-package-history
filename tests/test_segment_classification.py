from sbom_package_history.segment_classification import classify_segment

FP = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
IMAGE = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/differ:8beff99@sha256:{FP}"
JUN_01 = 1780272000
JUN_08 = 1780876800

SEGMENT = {"fingerprint": FP, "image_name": IMAGE, "start": JUN_01, "end": JUN_08}

PACKAGES = [
    {"name": "rack",    "version": "3.0.0",  "license": "MIT",     "purl": "pkg:gem/rack@3.0.0"},
    {"name": "openssl", "version": "3.0.11", "license": "OpenSSL", "purl": "pkg:deb/debian/openssl@3.0.11"},
]

ANY_RACK = {"name": "rack", "purl": None, "version": None}


def _expected(category, status, version):
    """The classified segment expected for the shared SEGMENT with these labels."""
    return {**SEGMENT, "category": category, "status": status, "version": version}


def test_8d1c6f01():
    """An image with no provenance is category no-provenance and status unknown."""
    assert classify_segment(SEGMENT, False, None, ANY_RACK) == _expected("no-provenance", "unknown", None)


def test_8d1c6f02():
    """Provenance but an unfetchable SBOM (None) is no-sbom / unknown."""
    assert classify_segment(SEGMENT, True, None, ANY_RACK) == _expected("no-sbom", "unknown", None)


def test_8d1c6f03():
    """Provenance but an empty SBOM ([]) is no-sbom / unknown, never a false absent."""
    assert classify_segment(SEGMENT, True, [], ANY_RACK) == _expected("no-sbom", "unknown", None)


def test_8d1c6f04():
    """An SBOM containing the package is in-sbom / present with the SBOM's version."""
    assert classify_segment(SEGMENT, True, PACKAGES, ANY_RACK) == _expected("in-sbom", "present", "3.0.0")


def test_8d1c6f05():
    """An SBOM lacking the package is not-in-sbom / absent."""
    spec = {"name": "leftpad", "purl": None, "version": None}
    assert classify_segment(SEGMENT, True, PACKAGES, spec) == _expected("not-in-sbom", "absent", None)


def test_8d1c6f06():
    """A matching version filter is in-sbom / present with the concrete version."""
    spec = {"name": "rack", "purl": None, "version": "3.0"}
    assert classify_segment(SEGMENT, True, PACKAGES, spec) == _expected("in-sbom", "present", "3.0.0")


def test_8d1c6f07():
    """A version filter that no package satisfies is not-in-sbom / absent."""
    spec = {"name": "rack", "purl": None, "version": "3.1"}
    assert classify_segment(SEGMENT, True, PACKAGES, spec) == _expected("not-in-sbom", "absent", None)
