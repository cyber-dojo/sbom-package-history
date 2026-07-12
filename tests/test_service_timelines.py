from sbom_package_history.service_timelines import group_into_service_timelines

JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600
JUN_22 = 1782086400

FP_A = "0d1130ca799b9445061410a917d8c53ea99fc20bd04c5114187300f0cf3f94bb"
FP_B = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
FP_C = "822ea1b3b65f224d2a1154c1bd088f2790639375c570aefa054ef4211b73f000"


def _seg(service, fingerprint, start, end, status, version):
    """Build a classified segment for the given service and interval."""
    image = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/{service}:tag@sha256:{fingerprint}"
    return {
        "fingerprint": fingerprint, "image_name": image,
        "start": start, "end": end, "status": status, "version": version,
    }


def test_5f3b9001():
    """A single service flipping present, absent, present yields its timeline and interval union."""
    segments = [
        _seg("saver", FP_A, JUN_01, JUN_08, "present", "3.0.0"),
        _seg("saver", FP_B, JUN_08, JUN_15, "absent", None),
        _seg("saver", FP_C, JUN_15, JUN_22, "present", "3.1.2"),
    ]
    assert group_into_service_timelines(segments) == [
        {
            "service": "saver",
            "timeline": [
                {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                {"start": JUN_08, "end": JUN_15, "status": "absent", "versions": []},
                {"start": JUN_15, "end": JUN_22, "status": "present", "versions": ["3.1.2"]},
            ],
            "present_intervals": [(JUN_01, JUN_08), (JUN_15, JUN_22)],
        },
    ]


def test_5f3b9002():
    """Multiple services are grouped independently and returned sorted by service name."""
    segments = [
        _seg("runner", FP_A, JUN_01, JUN_22, "present", "3.0.0"),
        _seg("differ", FP_B, JUN_01, JUN_22, "absent", None),
    ]
    assert group_into_service_timelines(segments) == [
        {
            "service": "differ",
            "timeline": [{"start": JUN_01, "end": JUN_22, "status": "absent", "versions": []}],
            "present_intervals": [],
        },
        {
            "service": "runner",
            "timeline": [{"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["3.0.0"]}],
            "present_intervals": [(JUN_01, JUN_22)],
        },
    ]


def test_5f3b9003():
    """Adjacent present images in one service merge into a single present interval."""
    segments = [
        _seg("web", FP_A, JUN_01, JUN_08, "present", "3.0.0"),
        _seg("web", FP_B, JUN_08, JUN_15, "present", "3.0.1"),
    ]
    assert group_into_service_timelines(segments) == [
        {
            "service": "web",
            "timeline": [{"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0", "3.0.1"]}],
            "present_intervals": [(JUN_01, JUN_15)],
        },
    ]


def test_5f3b9004():
    """An unknown interval is kept in the timeline but excluded from the present-interval union."""
    segments = [
        _seg("nginx", FP_A, JUN_01, JUN_08, "present", "3.0.0"),
        _seg("nginx", FP_B, JUN_08, JUN_15, "unknown", None),
    ]
    assert group_into_service_timelines(segments) == [
        {
            "service": "nginx",
            "timeline": [
                {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                {"start": JUN_08, "end": JUN_15, "status": "unknown", "versions": []},
            ],
            "present_intervals": [(JUN_01, JUN_08)],
        },
    ]
