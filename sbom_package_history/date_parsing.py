from datetime import datetime, timezone

_FORMATS = (
    "%Y-%m-%d",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
)


def parse_date_to_epoch(text):
    """Parse a user-supplied date or datetime string into UTC epoch seconds.

    Accepts a bare date (YYYY-MM-DD, interpreted as 00:00 UTC), a date and time
    (space or ISO T separated, with optional seconds), always interpreted in UTC.
    Returns the integer Unix timestamp. Raises ValueError when the string matches
    none of the accepted formats, so the CLI can report a clean error.
    """
    for fmt in _FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return int(parsed.replace(tzinfo=timezone.utc).timestamp())
    raise ValueError(f"unrecognized date/time: {text!r}")
