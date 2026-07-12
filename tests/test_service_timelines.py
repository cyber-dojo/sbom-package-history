from sbom_package_history.service_timelines import group_into_service_timelines

JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600
JUN_22 = 1782086400

FP_A = "0d1130ca799b9445061410a917d8c53ea99fc20bd04c5114187300f0cf3f94bb"
FP_B = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
FP_C = "822ea1b3b65f224d2a1154c1bd088f2790639375c570aefa054ef4211b73f000"

ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"


def _seg(service, fingerprint, start, end, status, version, category, snapshot):
    """Build a classified, enriched segment for a service and interval."""
    return {
        "fingerprint": fingerprint,
        "image_name": f"{ECR}/{service}:tag@sha256:{fingerprint}",
        "start": start,
        "end": end,
        "status": status,
        "version": version,
        "category": category,
        "snapshot_url": f"https://app.kosli.com/cyber-dojo/environments/aws-prod/snapshots/{snapshot}",
        "attestation_url": f"https://app.kosli.com/cyber-dojo/flows/{service}-ci/trails/T?attestation_id={fingerprint[:8]}",
    }


def _occ(segment):
    """The occurrence record expected in a service's occurrences list."""
    return {
        "image_name": segment["image_name"],
        "fingerprint": segment["fingerprint"],
        "category": segment["category"],
        "first_date": segment["start"],
        "last_date": segment["end"],
        "snapshot_url": segment["snapshot_url"],
        "attestation_url": segment["attestation_url"],
    }


def test_5f3b9001():
    """A single service flip yields the timeline, present union, and one occurrence per run."""
    a = _seg("saver", FP_A, JUN_01, JUN_08, "present", "3.0.0", "in-sbom", 10)
    b = _seg("saver", FP_B, JUN_08, JUN_15, "absent", None, "not-in-sbom", 11)
    c = _seg("saver", FP_C, JUN_15, JUN_22, "present", "3.1.2", "in-sbom", 12)
    assert group_into_service_timelines([a, b, c]) == [
        {
            "service": "saver",
            "timeline": [
                {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                {"start": JUN_08, "end": JUN_15, "status": "absent", "versions": []},
                {"start": JUN_15, "end": JUN_22, "status": "present", "versions": ["3.1.2"]},
            ],
            "present_intervals": [(JUN_01, JUN_08), (JUN_15, JUN_22)],
            "occurrences": [_occ(a), _occ(b), _occ(c)],
        },
    ]


def test_5f3b9002():
    """Multiple services are grouped independently and sorted by service name."""
    r = _seg("runner", FP_A, JUN_01, JUN_22, "present", "3.0.0", "in-sbom", 20)
    d = _seg("differ", FP_B, JUN_01, JUN_22, "absent", None, "not-in-sbom", 21)
    assert group_into_service_timelines([r, d]) == [
        {
            "service": "differ",
            "timeline": [{"start": JUN_01, "end": JUN_22, "status": "absent", "versions": []}],
            "present_intervals": [],
            "occurrences": [_occ(d)],
        },
        {
            "service": "runner",
            "timeline": [{"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["3.0.0"]}],
            "present_intervals": [(JUN_01, JUN_22)],
            "occurrences": [_occ(r)],
        },
    ]


def test_5f3b9003():
    """A merged present run still reports each underlying run as its own occurrence."""
    a = _seg("web", FP_A, JUN_01, JUN_08, "present", "3.0.0", "in-sbom", 30)
    b = _seg("web", FP_B, JUN_08, JUN_15, "present", "3.0.1", "in-sbom", 31)
    assert group_into_service_timelines([a, b]) == [
        {
            "service": "web",
            "timeline": [{"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0", "3.0.1"]}],
            "present_intervals": [(JUN_01, JUN_15)],
            "occurrences": [_occ(a), _occ(b)],
        },
    ]


def test_5f3b9004():
    """An unknown (no-sbom) run is excluded from the present union but kept as an occurrence."""
    a = _seg("nginx", FP_A, JUN_01, JUN_08, "present", "3.0.0", "in-sbom", 40)
    b = _seg("nginx", FP_B, JUN_08, JUN_15, "unknown", None, "no-sbom", 41)
    assert group_into_service_timelines([a, b]) == [
        {
            "service": "nginx",
            "timeline": [
                {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                {"start": JUN_08, "end": JUN_15, "status": "unknown", "versions": []},
            ],
            "present_intervals": [(JUN_01, JUN_08)],
            "occurrences": [_occ(a), _occ(b)],
        },
    ]
