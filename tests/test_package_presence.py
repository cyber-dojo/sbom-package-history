from sbom_package_history.package_presence import package_present

PACKAGES = [
    {"name": "rack",    "version": "3.0.0",            "license": "MIT",     "purl": "pkg:gem/rack@3.0.0"},
    {"name": "sinatra", "version": "3.1.0",            "license": "MIT",     "purl": "pkg:gem/sinatra@3.1.0"},
    {"name": "rackup",  "version": "2.1.0",            "license": "MIT",     "purl": "pkg:gem/rackup@2.1.0"},
    {"name": "openssl", "version": "3.0.11-1~deb12u2", "license": "OpenSSL", "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64"},
]


def test_7c1d3e01():
    """A purl identity with no version returns the matching package."""
    assert package_present(PACKAGES, purl="pkg:gem/rack") == [PACKAGES[0]]


def test_7c1d3e02():
    """A purl identity with a matching component-prefix version is present."""
    assert package_present(PACKAGES, purl="pkg:gem/rack", version="3.0") == [PACKAGES[0]]


def test_7c1d3e03():
    """A purl identity with a non-matching version is absent."""
    assert package_present(PACKAGES, purl="pkg:gem/rack", version="3.1") == []


def test_7c1d3e04():
    """A bare name identity returns the matching package."""
    assert package_present(PACKAGES, name="rack") == [PACKAGES[0]]


def test_7c1d3e05():
    """A purl identity ignores the version and qualifiers on the SBOM package's purl."""
    assert package_present(PACKAGES, purl="pkg:deb/debian/openssl") == [PACKAGES[3]]


def test_7c1d3e06():
    """A package not in the SBOM is absent."""
    assert package_present(PACKAGES, name="leftpad") == []


def test_7c1d3e07():
    """A fully-specified version pins to that exact build when present."""
    assert package_present(PACKAGES, purl="pkg:gem/sinatra", version="3.1.0") == [PACKAGES[1]]


def test_7c1d3e08():
    """A fully-specified version that no package has is absent."""
    assert package_present(PACKAGES, purl="pkg:gem/sinatra", version="3.1.2") == []


def test_7c1d3e09():
    """A bare name does not match a different package that contains it as a substring."""
    matched_names = [p["name"] for p in package_present(PACKAGES, name="rack")]
    assert matched_names == ["rack"]
