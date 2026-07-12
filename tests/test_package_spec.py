from sbom_package_history.package_spec import parse_package_spec


def test_2c8e5a01():
    """A bare name with no version parses to a name-only spec."""
    assert parse_package_spec("rack") == {"name": "rack", "purl": None, "version": None}


def test_2c8e5a02():
    """A bare name with a full version parses the name and the exact version."""
    assert parse_package_spec("rack@3.1.2") == {"name": "rack", "purl": None, "version": "3.1.2"}


def test_2c8e5a03():
    """A bare name with a partial version keeps the partial version for prefix matching."""
    assert parse_package_spec("rack@3.1") == {"name": "rack", "purl": None, "version": "3.1"}


def test_2c8e5a04():
    """A purl with no version parses to a purl-only spec."""
    assert parse_package_spec("pkg:gem/rack") == {"name": None, "purl": "pkg:gem/rack", "version": None}


def test_2c8e5a05():
    """A purl with a version parses the purl identity and the version separately."""
    assert parse_package_spec("pkg:gem/rack@3.1") == {"name": None, "purl": "pkg:gem/rack", "version": "3.1"}


def test_2c8e5a06():
    """A namespaced deb purl with no version parses to a purl-only spec."""
    assert parse_package_spec("pkg:deb/debian/openssl") == {"name": None, "purl": "pkg:deb/debian/openssl", "version": None}
