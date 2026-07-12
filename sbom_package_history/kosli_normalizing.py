def normalize_event(raw):
    """Normalize a raw `kosli log environment` event into the core's event shape.

    The raw event carries the fingerprint as sha256, the image ref as
    artifact_name, and the flow as pipeline, among many other fields. Returns
    {fingerprint, image_name, type, reported_at, flow} - the flow lets a later
    step fetch this fingerprint's SBOM with the correct --flow, read from the
    record rather than from user input.
    """
    return {
        "fingerprint": raw["sha256"],
        "image_name": raw["artifact_name"],
        "type": raw["type"],
        "reported_at": raw["reported_at"],
        "flow": raw["pipeline"],
    }


def normalize_baseline_artifact(raw):
    """Normalize a raw `kosli get snapshot` artifact into the core's baseline shape.

    The raw artifact carries the image ref as name and the flow as flow_name.
    Returns {fingerprint, image_name, flow} for an image running when the range
    opens.
    """
    return {
        "fingerprint": raw["fingerprint"],
        "image_name": raw["name"],
        "flow": raw["flow_name"],
    }


def sbom_packages_from_attestation(raw):
    """Extract the packages list from a raw `kosli get attestation sbom-facts` result.

    The result may be a bare attestation object or a single-element array
    wrapping one. The packages live at attestation_data.packages. Returns that
    list, or an empty list when the attestation, its attestation_data, or its
    packages are absent, so a missing or malformed SBOM reads as no packages
    found rather than raising.
    """
    if isinstance(raw, list):
        if not raw:
            return []
        raw = raw[0]
    return raw.get("attestation_data", {}).get("packages", [])
