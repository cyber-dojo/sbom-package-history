from sbom_package_history.version_matching import version_matches


def purl_identity(purl):
    """Reduce a purl to its identity: the type/namespace/name portion, with the
    version, qualifiers and subpath removed. For example
    'pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64' becomes
    'pkg:deb/debian/openssl'.
    """
    return purl.split("@")[0].split("?")[0].split("#")[0]


def package_present(packages, name=None, purl=None, version=None):
    """Return the SBOM packages that match a package query.

    Identity is given by exactly one of purl or name. A purl query matches a
    package whose purl identity (version, qualifiers and subpath stripped) equals
    the query's purl identity. A name query matches a package whose name is
    exactly equal, so 'rack' does not match 'rackup'. The optional version
    further filters by the component-prefix rule in version_matches; a None
    version matches any version. Returns the list of matching package dicts,
    which is empty when the package is absent.
    """
    matches = []
    wanted_purl = purl_identity(purl) if purl is not None else None
    for package in packages:
        if wanted_purl is not None:
            if purl_identity(package.get("purl", "")) != wanted_purl:
                continue
        else:
            if package.get("name", "") != name:
                continue
        if version_matches(query=version, actual=package.get("version", "")):
            matches.append(package)
    return matches
