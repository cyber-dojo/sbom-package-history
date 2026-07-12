from operator import itemgetter

# The authoritative event-type vocabulary, from the Kosli server's
# environment_consts.py. A started-type event moves a fingerprint from 0 running
# instances to some, opening a running interval; exited moves it back to 0,
# closing the interval. Every other event type (scaled, became-compliant,
# became-non-compliant, changed, updated-provenance, unchanged) leaves the same
# fingerprint running and does not move an interval boundary.
STARTED_EVENT_TYPES = (
    "started",  # deprecated, kept for historical ranges
    "started-compliant",
    "started-non-compliant",
    "started-unknown",
)
EXITED_EVENT_TYPE = "exited"


def reconstruct_segments(baseline, events, range_from, range_to):
    """Reconstruct the running-image segments across an environment over a range.

    baseline is the list of images running when the range opens, each
    {fingerprint, image_name}; their intervals start at range_from. events is the
    normalized list of environment events, each {fingerprint, image_name, type,
    reported_at}, and is sorted here by reported_at before processing. A
    started-type event opens an interval for its fingerprint at reported_at (if
    that fingerprint is not already running); an exited event closes the open
    interval for its fingerprint at reported_at; all other event types are
    ignored. The same fingerprint can start, exit, then start again, producing
    several segments. Any interval still open when the range closes ends at
    range_to. Returns the segments, each {fingerprint, image_name, start, end},
    sorted by (start, fingerprint).
    """
    open_intervals = {}
    for image in baseline:
        open_intervals[image["fingerprint"]] = {
            "image_name": image["image_name"],
            "start": range_from,
        }
    segments = []
    for event in sorted(events, key=itemgetter("reported_at")):
        fingerprint = event["fingerprint"]
        if event["type"] in STARTED_EVENT_TYPES:
            if fingerprint not in open_intervals:
                open_intervals[fingerprint] = {
                    "image_name": event["image_name"],
                    "start": event["reported_at"],
                }
        elif event["type"] == EXITED_EVENT_TYPE:
            opened = open_intervals.pop(fingerprint, None)
            if opened is not None:
                segments.append({
                    "fingerprint": fingerprint,
                    "image_name": opened["image_name"],
                    "start": opened["start"],
                    "end": event["reported_at"],
                })
    for fingerprint, opened in open_intervals.items():
        segments.append({
            "fingerprint": fingerprint,
            "image_name": opened["image_name"],
            "start": opened["start"],
            "end": range_to,
        })
    segments.sort(key=itemgetter("start", "fingerprint"))
    return segments
