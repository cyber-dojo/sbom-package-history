from sbom_package_history.service_label import service_label_from_image_ref
from sbom_package_history.timeline_building import build_timeline


def _occurrence(segment):
    """Project a classified segment to a per-run occurrence record.

    One occurrence per run (a fingerprint's contiguous appearance): the image, its
    4-way category, the run's first and last dates, the snapshot URL proving it
    ran, and the attestation URL (TAU) the SBOM evidence came from.
    """
    return {
        "image_name": segment["image_name"],
        "fingerprint": segment["fingerprint"],
        "category": segment["category"],
        "first_date": segment["start"],
        "last_date": segment["end"],
        "snapshot_url": segment["snapshot_url"],
        "attestation_url": segment["attestation_url"],
    }


def group_into_service_timelines(classified_segments):
    """Group classified segments by service into timelines and occurrences.

    Each segment is a classified, enriched running interval. Segments are grouped
    by the service label derived from their image ref. Per service:
      - timeline: the present/absent/unknown runs from build_timeline (the sweep),
        used by the text view;
      - present_intervals: the (start, end) pairs of the present runs;
      - occurrences: one record per run (see _occurrence), used by the HTML view
        to place each artifact-run in its category tab.
    Returns a list of {service, timeline, present_intervals, occurrences}, one per
    service, sorted by service name.
    """
    by_service = {}
    for segment in classified_segments:
        service = service_label_from_image_ref(segment["image_name"])
        by_service.setdefault(service, []).append(segment)
    result = []
    for service in sorted(by_service):
        service_segments = by_service[service]
        timeline = build_timeline(service_segments)
        present_intervals = [
            (run["start"], run["end"]) for run in timeline if run["status"] == "present"
        ]
        result.append({
            "service": service,
            "timeline": timeline,
            "present_intervals": present_intervals,
            "occurrences": [_occurrence(segment) for segment in service_segments],
        })
    return result
