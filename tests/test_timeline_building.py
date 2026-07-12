from sbom_package_history.timeline_building import build_timeline

# Realistic aws-prod-style Unix-second timestamps, one week apart, in June 2026.
JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600
JUN_22 = 1782086400


def test_9e4f7a01():
    """A present, then absent, then present sequence yields three separate runs."""
    segments = [
        {"fingerprint": "f3c1", "start": JUN_01, "end": JUN_08, "status": "present", "version": "3.0.0"},
        {"fingerprint": "a97e", "start": JUN_08, "end": JUN_15, "status": "absent",  "version": None},
        {"fingerprint": "88b7", "start": JUN_15, "end": JUN_22, "status": "present", "version": "3.1.2"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
        {"start": JUN_08, "end": JUN_15, "status": "absent",  "versions": []},
        {"start": JUN_15, "end": JUN_22, "status": "present", "versions": ["3.1.2"]},
    ]


def test_9e4f7a02():
    """Two time-adjacent present images with different versions merge into one run."""
    segments = [
        {"fingerprint": "f3c1", "start": JUN_01, "end": JUN_08, "status": "present", "version": "3.0.0"},
        {"fingerprint": "b2d4", "start": JUN_08, "end": JUN_15, "status": "present", "version": "3.0.1"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0", "3.0.1"]},
    ]


def test_9e4f7a03():
    """A time gap between two present images keeps them as two runs, not merged."""
    segments = [
        {"fingerprint": "f3c1", "start": JUN_01, "end": JUN_08, "status": "present", "version": "3.0.0"},
        {"fingerprint": "88b7", "start": JUN_15, "end": JUN_22, "status": "present", "version": "3.0.0"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
        {"start": JUN_15, "end": JUN_22, "status": "present", "versions": ["3.0.0"]},
    ]


def test_9e4f7a04():
    """An unknown image between two present images breaks the run into three."""
    segments = [
        {"fingerprint": "f3c1", "start": JUN_01, "end": JUN_08, "status": "present", "version": "3.0.0"},
        {"fingerprint": "a97e", "start": JUN_08, "end": JUN_15, "status": "unknown", "version": None},
        {"fingerprint": "88b7", "start": JUN_15, "end": JUN_22, "status": "present", "version": "3.0.0"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
        {"start": JUN_08, "end": JUN_15, "status": "unknown", "versions": []},
        {"start": JUN_15, "end": JUN_22, "status": "present", "versions": ["3.0.0"]},
    ]


def test_9e4f7a05():
    """Segments given out of chronological order are sorted before folding."""
    segments = [
        {"fingerprint": "88b7", "start": JUN_08, "end": JUN_15, "status": "present", "version": "3.0.1"},
        {"fingerprint": "f3c1", "start": JUN_01, "end": JUN_08, "status": "present", "version": "3.0.0"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0", "3.0.1"]},
    ]


def test_9e4f7a06():
    """A single present image yields a single present run."""
    segments = [
        {"fingerprint": "f3c1", "start": JUN_01, "end": JUN_08, "status": "present", "version": "3.0.0"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
    ]


def test_9e4f7a07():
    """Two time-adjacent absent images collapse into a single absent run."""
    segments = [
        {"fingerprint": "a97e", "start": JUN_01, "end": JUN_08, "status": "absent", "version": None},
        {"fingerprint": "c1b5", "start": JUN_08, "end": JUN_15, "status": "absent", "version": None},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_15, "status": "absent", "versions": []},
    ]


def test_9e4f7a08():
    """Two overlapping present images merge into one present run pooling their versions."""
    segments = [
        {"fingerprint": "aaaa", "start": JUN_01, "end": JUN_15, "status": "present", "version": "3.0.0"},
        {"fingerprint": "bbbb", "start": JUN_08, "end": JUN_22, "status": "present", "version": "3.1.0"},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["3.0.0", "3.1.0"]},
    ]


def test_9e4f7a09():
    """While a present image overlaps an absent one, the overlapping interval is present."""
    segments = [
        {"fingerprint": "aaaa", "start": JUN_01, "end": JUN_15, "status": "present", "version": "3.0.0"},
        {"fingerprint": "bbbb", "start": JUN_08, "end": JUN_22, "status": "absent", "version": None},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0"]},
        {"start": JUN_15, "end": JUN_22, "status": "absent", "versions": []},
    ]


def test_9e4f7a0a():
    """While a present image overlaps an unknown one, the overlapping interval is present."""
    segments = [
        {"fingerprint": "aaaa", "start": JUN_01, "end": JUN_15, "status": "present", "version": "3.0.0"},
        {"fingerprint": "bbbb", "start": JUN_08, "end": JUN_22, "status": "unknown", "version": None},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0"]},
        {"start": JUN_15, "end": JUN_22, "status": "unknown", "versions": []},
    ]


def test_9e4f7a0b():
    """While an unknown image overlaps an absent one, the overlapping interval is unknown."""
    segments = [
        {"fingerprint": "aaaa", "start": JUN_01, "end": JUN_15, "status": "unknown", "version": None},
        {"fingerprint": "bbbb", "start": JUN_08, "end": JUN_22, "status": "absent", "version": None},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_15, "status": "unknown", "versions": []},
        {"start": JUN_15, "end": JUN_22, "status": "absent", "versions": []},
    ]


def test_9e4f7a0c():
    """Two images running the whole interval, one present and one absent, read as present."""
    segments = [
        {"fingerprint": "aaaa", "start": JUN_01, "end": JUN_22, "status": "present", "version": "4.0.0"},
        {"fingerprint": "bbbb", "start": JUN_01, "end": JUN_22, "status": "absent", "version": None},
    ]
    assert build_timeline(segments) == [
        {"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["4.0.0"]},
    ]
