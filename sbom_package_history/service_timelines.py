from sbom_package_history.service_label import service_label_from_image_ref
from sbom_package_history.timeline_building import build_timeline


def group_into_service_timelines(classified_segments):
    """Group classified segments by service and fold each into a timeline.

    Each segment is a classified running interval {fingerprint, image_name,
    start, end, status, version}. Segments are grouped by the service label
    derived from their image ref, and each group is folded into a present/absent
    timeline by build_timeline. For every service the present-interval union is
    the (start, end) pairs of its present runs, so unknown and absent stretches
    are excluded. Returns a list of {service, timeline, present_intervals}, one
    per service, sorted by service name.
    """
    by_service = {}
    for segment in classified_segments:
        service = service_label_from_image_ref(segment["image_name"])
        by_service.setdefault(service, []).append(segment)
    result = []
    for service in sorted(by_service):
        timeline = build_timeline(by_service[service])
        present_intervals = [
            (run["start"], run["end"]) for run in timeline if run["status"] == "present"
        ]
        result.append({
            "service": service,
            "timeline": timeline,
            "present_intervals": present_intervals,
        })
    return result
