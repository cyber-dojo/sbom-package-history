from sbom_package_history.kosli_normalizing import (
    normalize_baseline_artifact,
    normalize_event,
    sbom_packages_from_attestation,
)
from sbom_package_history.package_spec import parse_package_spec
from sbom_package_history.segment_reconstruction import reconstruct_segments
from sbom_package_history.segment_classification import classify_segment
from sbom_package_history.service_timelines import group_into_service_timelines


def build_report(reader, environment, from_ts, to_ts, package):
    """Build the package-history report for a package over a range in an environment.

    Orchestrates the whole pipeline through the injected reader: read the baseline
    running images at from_ts (skipped when from_ts predates history), read the
    range's environment events, reconstruct each image's running segments, fetch
    and cache each distinct image's SBOM via the flow recorded for its
    fingerprint, classify every segment present/absent/unknown against the parsed
    package spec, then group the segments into per-service timelines. Returns the
    report dict {package, from, to, services} that report_formatting renders.
    """
    spec = parse_package_spec(package)

    baseline = []
    fingerprint_flow = {}
    baseline_index = reader.baseline_snapshot_index(environment, from_ts)
    if baseline_index is not None:
        for raw_artifact in reader.snapshot_artifacts(environment, baseline_index):
            image = normalize_baseline_artifact(raw_artifact)
            baseline.append(image)
            fingerprint_flow[image["fingerprint"]] = image["flow"]

    events = [normalize_event(raw) for raw in reader.environment_events(environment, from_ts, to_ts)]
    for event in events:
        fingerprint_flow.setdefault(event["fingerprint"], event["flow"])

    segments = reconstruct_segments(baseline, events, from_ts, to_ts)

    sbom_by_fingerprint = {}
    for fingerprint in {segment["fingerprint"] for segment in segments}:
        flow = fingerprint_flow.get(fingerprint)
        if flow is None:
            sbom_by_fingerprint[fingerprint] = None
        else:
            raw = reader.sbom_attestation(flow, fingerprint)
            sbom_by_fingerprint[fingerprint] = None if raw is None else sbom_packages_from_attestation(raw)

    classified = [
        classify_segment(segment, sbom_by_fingerprint[segment["fingerprint"]], spec)
        for segment in segments
    ]

    return {
        "package": package,
        "from": from_ts,
        "to": to_ts,
        "services": group_into_service_timelines(classified),
    }
