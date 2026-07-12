from sbom_package_history.service_timelines import group_into_service_timelines

JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600
JUN_22 = 1782086400

FP_A = "0d1130ca799b9445061410a917d8c53ea99fc20bd04c5114187300f0cf3f94bb"
FP_B = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
FP_C = "822ea1b3b65f224d2a1154c1bd088f2790639375c570aefa054ef4211b73f000"

ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"

_EVIDENCE_KEYS = ("image_name", "fingerprint", "status", "version", "snapshot_url", "attestation_url")


def _seg(service, fingerprint, start, end, status, version, snapshot):
    """Build a classified, evidence-enriched segment for a service and interval."""
    return {
        "fingerprint": fingerprint,
        "image_name": f"{ECR}/{service}:tag@sha256:{fingerprint}",
        "start": start,
        "end": end,
        "status": status,
        "version": version,
        "snapshot_url": f"https://app.kosli.com/cyber-dojo/environments/aws-prod/snapshots/{snapshot}",
        "attestation_url": f"https://app.kosli.com/cyber-dojo/flows/{service}-ci/trails/T?attestation_id={fingerprint[:8]}",
    }


def _evidence(segment):
    """The evidence projection expected in a run's images list."""
    return {key: segment[key] for key in _EVIDENCE_KEYS}


def test_5f3b9001():
    """Each run carries the evidence of the segment(s) running during it."""
    a = _seg("saver", FP_A, JUN_01, JUN_08, "present", "3.0.0", 10)
    b = _seg("saver", FP_B, JUN_08, JUN_15, "absent", None, 11)
    c = _seg("saver", FP_C, JUN_15, JUN_22, "present", "3.1.2", 12)
    assert group_into_service_timelines([a, b, c]) == [
        {
            "service": "saver",
            "timeline": [
                {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"], "images": [_evidence(a)]},
                {"start": JUN_08, "end": JUN_15, "status": "absent", "versions": [], "images": [_evidence(b)]},
                {"start": JUN_15, "end": JUN_22, "status": "present", "versions": ["3.1.2"], "images": [_evidence(c)]},
            ],
            "present_intervals": [(JUN_01, JUN_08), (JUN_15, JUN_22)],
        },
    ]


def test_5f3b9002():
    """Multiple services are grouped independently and sorted by service name."""
    r = _seg("runner", FP_A, JUN_01, JUN_22, "present", "3.0.0", 20)
    d = _seg("differ", FP_B, JUN_01, JUN_22, "absent", None, 21)
    assert group_into_service_timelines([r, d]) == [
        {
            "service": "differ",
            "timeline": [{"start": JUN_01, "end": JUN_22, "status": "absent", "versions": [], "images": [_evidence(d)]}],
            "present_intervals": [],
        },
        {
            "service": "runner",
            "timeline": [{"start": JUN_01, "end": JUN_22, "status": "present", "versions": ["3.0.0"], "images": [_evidence(r)]}],
            "present_intervals": [(JUN_01, JUN_22)],
        },
    ]


def test_5f3b9003():
    """A merged present run carries the evidence of every image that ran during it."""
    a = _seg("web", FP_A, JUN_01, JUN_08, "present", "3.0.0", 30)
    b = _seg("web", FP_B, JUN_08, JUN_15, "present", "3.0.1", 31)
    assert group_into_service_timelines([a, b]) == [
        {
            "service": "web",
            "timeline": [
                {"start": JUN_01, "end": JUN_15, "status": "present", "versions": ["3.0.0", "3.0.1"],
                 "images": [_evidence(a), _evidence(b)]},
            ],
            "present_intervals": [(JUN_01, JUN_15)],
        },
    ]


def test_5f3b9004():
    """An unknown run carries its image's evidence and is excluded from the present union."""
    a = _seg("nginx", FP_A, JUN_01, JUN_08, "present", "3.0.0", 40)
    b = _seg("nginx", FP_B, JUN_08, JUN_15, "unknown", None, 41)
    assert group_into_service_timelines([a, b]) == [
        {
            "service": "nginx",
            "timeline": [
                {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"], "images": [_evidence(a)]},
                {"start": JUN_08, "end": JUN_15, "status": "unknown", "versions": [], "images": [_evidence(b)]},
            ],
            "present_intervals": [(JUN_01, JUN_08)],
        },
    ]
