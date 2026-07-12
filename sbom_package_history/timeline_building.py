def _aggregate_status(active_segments):
    """Return the service status for a set of concurrently-running segments.

    A service runs several images at once (multiple tasks, and old plus new
    during a rolling deploy), so at any instant its status is the aggregate of
    every image running then: present if any image is present, otherwise unknown
    if any is unknown (it might have held the package), otherwise absent.
    """
    statuses = {segment["status"] for segment in active_segments}
    if "present" in statuses:
        return "present"
    if "unknown" in statuses:
        return "unknown"
    return "absent"


def _present_versions(active_segments):
    """Return the sorted distinct versions of the present segments in the set."""
    return sorted({
        segment["version"]
        for segment in active_segments
        if segment["status"] == "present" and segment["version"] is not None
    })


def build_timeline(segments):
    """Fold a service's running-image segments into a chronological timeline.

    A segment is one image's running interval {fingerprint, image_name, start,
    end, status, version}, and segments can OVERLAP because a service runs
    several images concurrently. The timeline is built by an interval sweep: the
    distinct segment start and end times cut the range into sub-intervals within
    which the set of running images is constant. Each sub-interval takes the
    aggregate status of the images running across it (present if any is present,
    else unknown if any is unknown, else absent) and, when present, the union of
    those images' versions. Sub-intervals with no running image are gaps: they
    are dropped and break a run. Contiguous sub-intervals of the same status are
    merged, pooling present versions. Returns the runs, each {start, end, status,
    versions}, in chronological order.
    """
    if not segments:
        return []
    boundaries = sorted(
        {segment["start"] for segment in segments} | {segment["end"] for segment in segments}
    )
    runs = []
    for start, end in zip(boundaries, boundaries[1:]):
        active = [s for s in segments if s["start"] <= start and s["end"] >= end]
        if not active:
            continue
        status = _aggregate_status(active)
        versions = _present_versions(active)
        if runs and runs[-1]["status"] == status and runs[-1]["end"] == start:
            runs[-1]["end"] = end
            runs[-1]["versions"] = sorted(set(runs[-1]["versions"]) | set(versions))
        else:
            runs.append({"start": start, "end": end, "status": status, "versions": versions})
    return runs
