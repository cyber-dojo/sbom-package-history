from sbom_package_history.package_presence import package_present


def classify_segment(segment, sbom_packages, spec):
    """Classify a running-image segment by whether it contained the package.

    segment is a {fingerprint, image_name, start, end} interval. sbom_packages is
    that image's SBOM package list, or None when its SBOM could not be fetched or
    parsed. spec is a {name, purl, version} package query. When sbom_packages is
    None the segment is "unknown" (fail toward possibly-present, never a silent
    "absent"). Otherwise the package query is run: a match makes the segment
    "present" with the SBOM's concrete version, and no match makes it "absent".
    Returns the segment with added status and version keys, ready for
    build_timeline.
    """
    if sbom_packages is None:
        status, version = "unknown", None
    else:
        matches = package_present(sbom_packages, **spec)
        if matches:
            status, version = "present", matches[0]["version"]
        else:
            status, version = "absent", None
    return {**segment, "status": status, "version": version}
