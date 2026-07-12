from sbom_package_history.service_label import service_label_from_image_ref
from sbom_package_history.timeline_building import build_timeline

_EVIDENCE_KEYS = ("image_name", "fingerprint", "status", "version", "snapshot_url", "attestation_url")


def _segment_evidence(segment):
    """Project a classified segment to the evidence carried in a run's images list."""
    return {key: segment[key] for key in _EVIDENCE_KEYS}


def _run_images(run, segments):
    """Return the evidence of the distinct segments running during the run.

    A segment ran during the run if its interval overlaps [run start, run end).
    Segments are already ordered by (start, fingerprint), so the returned
    evidence keeps that order; a fingerprint that ran twice (a flip) appears once
    per running interval.
    """
    images = {}
    for segment in segments:
        if segment["start"] < run["end"] and segment["end"] > run["start"]:
            key = (segment["fingerprint"], segment["start"], segment["end"])
            images.setdefault(key, _segment_evidence(segment))
    return list(images.values())


def group_into_service_timelines(classified_segments):
    """Group classified segments by service and fold each into a timeline.

    Each segment is a classified, evidence-enriched running interval
    {fingerprint, image_name, start, end, status, version, snapshot_url,
    attestation_url}. Segments are grouped by the service label derived from
    their image ref, and each group is folded into a present/absent timeline by
    build_timeline. Every run is annotated with an images list: the evidence of
    the distinct images that ran during it (present, absent and unknown alike),
    so a viewer can prove what was running and where the SBOM evidence came from.
    For every service the present-interval union is the (start, end) pairs of its
    present runs. Returns a list of {service, timeline, present_intervals}, one
    per service, sorted by service name.
    """
    by_service = {}
    for segment in classified_segments:
        service = service_label_from_image_ref(segment["image_name"])
        by_service.setdefault(service, []).append(segment)
    result = []
    for service in sorted(by_service):
        service_segments = by_service[service]
        timeline = build_timeline(service_segments)
        for run in timeline:
            run["images"] = _run_images(run, service_segments)
        present_intervals = [
            (run["start"], run["end"]) for run in timeline if run["status"] == "present"
        ]
        result.append({
            "service": service,
            "timeline": timeline,
            "present_intervals": present_intervals,
        })
    return result
