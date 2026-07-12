from sbom_package_history.report_text import format_report_text

JUN_01 = 1780272000  # 2026-06-01 00:00 UTC
JUN_08 = 1780876800  # 2026-06-08 00:00 UTC
JUN_15 = 1781481600  # 2026-06-15 00:00 UTC
JUN_22 = 1782086400  # 2026-06-22 00:00 UTC


def test_7a3e1c01():
    """Never-present services group first with an indented label; present services show only present runs."""
    report = {
        "package": "pkg:gem/rack",
        "from": JUN_01,
        "to": JUN_22,
        "services": [
            {"service": "creator",
             "timeline": [{"start": JUN_01, "end": JUN_22, "status": "absent", "versions": []}],
             "present_intervals": []},
            {"service": "differ",
             "timeline": [{"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["1.0.0"]}],
             "present_intervals": [[JUN_01, JUN_22]]},
            {"service": "nginx",
             "timeline": [{"start": JUN_01, "end": JUN_22, "status": "absent", "versions": []}],
             "present_intervals": []},
            {"service": "saver",
             "timeline": [
                 {"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["2.0.0"]},
                 {"start": JUN_15, "end": JUN_22, "status": "absent", "versions": []},
             ],
             "present_intervals": [[JUN_01, JUN_15]]},
        ],
    }
    assert format_report_text(report) == (
        "package: pkg:gem/rack\n"
        "range:   2026-06-01 00:00 .. 2026-06-22 00:00 UTC\n"
        "\n"
        "creator, nginx\n"
        "  never present\n"
        "\n"
        "differ\n"
        "  present  2026-06-01 00:00 .. 2026-06-22 00:00  (1.0.0)\n"
        "\n"
        "saver\n"
        "  present  2026-06-01 00:00 .. 2026-06-15 00:00  (2.0.0)"
    )


def test_7a3e1c02():
    """A service that is unknown (not absent) is shown, never folded into never present."""
    report = {
        "package": "openssl",
        "from": JUN_01,
        "to": JUN_22,
        "services": [
            {"service": "web",
             "timeline": [{"start": JUN_01, "end": JUN_22, "status": "unknown", "versions": []}],
             "present_intervals": []},
        ],
    }
    assert format_report_text(report) == (
        "package: openssl\n"
        "range:   2026-06-01 00:00 .. 2026-06-22 00:00 UTC\n"
        "\n"
        "web\n"
        "  unknown  2026-06-01 00:00 .. 2026-06-22 00:00"
    )


def test_7a3e1c03():
    """A present service drops its absent runs but keeps its unknown runs."""
    report = {
        "package": "openssl",
        "from": JUN_01,
        "to": JUN_22,
        "services": [
            {"service": "saver",
             "timeline": [
                 {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                 {"start": JUN_08, "end": JUN_15, "status": "absent", "versions": []},
                 {"start": JUN_15, "end": JUN_22, "status": "unknown", "versions": []},
             ],
             "present_intervals": [[JUN_01, JUN_08]]},
        ],
    }
    assert format_report_text(report) == (
        "package: openssl\n"
        "range:   2026-06-01 00:00 .. 2026-06-22 00:00 UTC\n"
        "\n"
        "saver\n"
        "  present  2026-06-01 00:00 .. 2026-06-08 00:00  (3.0.0)\n"
        "  unknown  2026-06-15 00:00 .. 2026-06-22 00:00"
    )


def test_7a3e1c04():
    """A report with no services renders only the header block."""
    report = {"package": "rack", "from": JUN_01, "to": JUN_22, "services": []}
    assert format_report_text(report) == (
        "package: rack\n"
        "range:   2026-06-01 00:00 .. 2026-06-22 00:00 UTC"
    )


def test_7a3e1c05():
    """When every service is present there is no never-present block."""
    report = {
        "package": "rack",
        "from": JUN_01,
        "to": JUN_22,
        "services": [
            {"service": "differ",
             "timeline": [{"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["1.0.0"]}],
             "present_intervals": [[JUN_01, JUN_22]]},
        ],
    }
    assert format_report_text(report) == (
        "package: rack\n"
        "range:   2026-06-01 00:00 .. 2026-06-22 00:00 UTC\n"
        "\n"
        "differ\n"
        "  present  2026-06-01 00:00 .. 2026-06-22 00:00  (1.0.0)"
    )
