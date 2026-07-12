def parse_package_spec(package):
    """Parse a --package argument into a {name, purl, version} spec.

    A value starting with "pkg:" is a purl and fills the purl key; anything else
    is a bare package name and fills the name key. The version is whatever
    follows an "@", or None when there is none, so "rack" and "pkg:gem/rack"
    match any version while "rack@3.1" and "pkg:gem/rack@3.1" carry a version for
    component-prefix matching. The returned dict is shaped to splat directly into
    package_present.
    """
    identity_key = "purl" if package.startswith("pkg:") else "name"
    identity, separator, version = package.partition("@")
    spec = {"name": None, "purl": None, "version": version if separator else None}
    spec[identity_key] = identity
    return spec
