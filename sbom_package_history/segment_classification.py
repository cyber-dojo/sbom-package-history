from sbom_package_history.package_presence import package_present


def classify_segment(segment, has_provenance, sbom_packages, spec):
    """Classify a running-image segment into a category (and status) for the package.

    segment is a {fingerprint, image_name, start, end, ...} interval.
    has_provenance says whether the image has any Kosli provenance (a build flow).
    sbom_packages is the image's SBOM package list, or None when it has no usable
    SBOM. spec is the {name, purl, version} package query. The four categories:
      no-provenance - the image has no provenance at all
      no-sbom       - it has provenance but no usable sbom-facts attestation
      not-in-sbom   - it has an SBOM and the package is not in it
      in-sbom       - it has an SBOM and the package is in it
    A matched version is carried for in-sbom. status is the coarser present /
    absent / unknown used by the timeline: in-sbom -> present, not-in-sbom ->
    absent, the other two -> unknown (never a false absent). Returns the segment
    with added category, status and version.
    """
    if not has_provenance:
        category, status, version = "no-provenance", "unknown", None
    elif not sbom_packages:
        category, status, version = "no-sbom", "unknown", None
    else:
        matches = package_present(sbom_packages, **spec)
        if matches:
            category, status, version = "in-sbom", "present", matches[0]["version"]
        else:
            category, status, version = "not-in-sbom", "absent", None
    return {**segment, "category": category, "status": status, "version": version}
