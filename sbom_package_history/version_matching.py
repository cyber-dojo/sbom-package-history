def version_matches(query, actual):
    """Return True if query is a dot-component prefix of actual.

    query is the user-entered version (or None to match any version); actual is
    the version taken from an SBOM package. The match is component-aware: query
    and actual are split on ".", and each component of query must equal the
    component of actual at the same position. query may have fewer components
    than actual (a genuine prefix, so "3.1" matches "3.1.2"), but "3.1" does not
    match "3.10.0" because the second components "1" and "10" differ. A None
    query matches any actual version. A query with more components than actual
    cannot be a prefix and does not match.
    """
    if query is None:
        return True
    query_components = query.split(".")
    actual_components = actual.split(".")
    if len(query_components) > len(actual_components):
        return False
    return query_components == actual_components[:len(query_components)]
