from sbom_package_history.version_matching import version_matches


def test_4b2e9a01():
    """A fully-specified query equals only that exact version."""
    assert version_matches(query="3.1.2", actual="3.1.2") is True


def test_4b2e9a02():
    """A different exact version does not match."""
    assert version_matches(query="3.1.2", actual="3.0.0") is False


def test_4b2e9a03():
    """A shorter query is a component prefix: 3.1 matches 3.1.2."""
    assert version_matches(query="3.1", actual="3.1.2") is True


def test_4b2e9a04():
    """The component-aware crux: 3.1 does not match 3.10.0."""
    assert version_matches(query="3.1", actual="3.10.0") is False


def test_4b2e9a05():
    """A single leading component matches any version under it: 3 matches 3.1.2."""
    assert version_matches(query="3", actual="3.1.2") is True


def test_4b2e9a06():
    """A query longer than the actual version cannot be a prefix."""
    assert version_matches(query="3.1.2", actual="3.1") is False


def test_4b2e9a07():
    """An omitted version (None) matches any actual version."""
    assert version_matches(query=None, actual="3.1.2") is True


def test_4b2e9a08():
    """Component prefix works on a Debian-style version with dots inside a segment."""
    assert version_matches(query="1.1.1f-1ubuntu2", actual="1.1.1f-1ubuntu2.16") is True
