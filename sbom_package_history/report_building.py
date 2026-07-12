from sbom_package_history.kosli_normalizing import (
    attestation_html_url,
    normalize_baseline_artifact,
    normalize_event,
    sbom_packages_from_attestation,
)
from sbom_package_history.package_spec import parse_package_spec
from sbom_package_history.segment_reconstruction import reconstruct_segments
from sbom_package_history.segment_classification import classify_segment
from sbom_package_history.service_timelines import group_into_service_timelines


def _snapshot_url(host, org, environment, snapshot_index):
    """Build the Kosli UI URL for an environment snapshot by its index."""
    return f"{host}/{org}/environments/{environment}/snapshots/{snapshot_index}"


def build_report(reader, environment, from_ts, to_ts, package, host, org):
    """Build the package-history report for a package over a range in an environment.

    Orchestrates the whole pipeline through the injected reader: read the baseline
    running images at from_ts (skipped when from_ts predates history), read the
    range's environment events, reconstruct each image's running segments, fetch
    and cache each distinct image's SBOM via the flow recorded for its
    fingerprint, classify every segment present/absent/unknown against the parsed
    package spec, and enrich it with the URL of the snapshot proving it ran and
    the URL of the SBOM attestation. Grouping into per-service timelines then
    annotates each run with the evidence of the images that ran during it. host
    and org are used to build the snapshot URLs. Returns the report dict
    {package, from, to, services}.
    """
    spec = parse_package_spec(package)

    baseline = []
    fingerprint_flow = {}
    baseline_index = reader.baseline_snapshot_index(environment, from_ts)
    if baseline_index is not None:
        for raw_artifact in reader.snapshot_artifacts(environment, baseline_index):
            image = normalize_baseline_artifact(raw_artifact)
            image["snapshot_index"] = baseline_index
            baseline.append(image)
            fingerprint_flow[image["fingerprint"]] = image["flow"]

    events = [normalize_event(raw) for raw in reader.environment_events(environment, from_ts, to_ts)]
    for event in events:
        fingerprint_flow.setdefault(event["fingerprint"], event["flow"])

    segments = reconstruct_segments(baseline, events, from_ts, to_ts)

    provenance_by_fingerprint = {}
    sbom_by_fingerprint = {}
    attestation_url_by_fingerprint = {}
    for fingerprint in {segment["fingerprint"] for segment in segments}:
        flow = fingerprint_flow.get(fingerprint)
        # An empty or missing flow means Kosli has no provenance for the image.
        has_provenance = bool(flow)
        provenance_by_fingerprint[fingerprint] = has_provenance
        if not has_provenance:
            sbom_by_fingerprint[fingerprint] = None
            attestation_url_by_fingerprint[fingerprint] = None
            continue
        raw = reader.sbom_attestation(flow, fingerprint)
        packages = sbom_packages_from_attestation(raw) if raw is not None else None
        # An empty package list means no usable SBOM (a missing attestation returns
        # []), so treat it like a failed fetch: no-sbom, never a definitive absent.
        sbom_by_fingerprint[fingerprint] = packages if packages else None
        attestation_url_by_fingerprint[fingerprint] = attestation_html_url(raw) if raw is not None else None

    classified = []
    for segment in segments:
        fingerprint = segment["fingerprint"]
        enriched = classify_segment(
            segment, provenance_by_fingerprint[fingerprint], sbom_by_fingerprint[fingerprint], spec
        )
        enriched["snapshot_url"] = _snapshot_url(host, org, environment, segment["snapshot_index"])
        enriched["attestation_url"] = attestation_url_by_fingerprint[fingerprint]
        classified.append(enriched)

    return {
        "package": package,
        "from": from_ts,
        "to": to_ts,
        "services": group_into_service_timelines(classified),
    }
