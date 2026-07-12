from sbom_package_history.segment_reconstruction import reconstruct_segments

# Realistic aws-prod-style Unix-second timestamps, one week apart, in June 2026.
JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600
JUN_22 = 1782086400

# Baseline images are proved by the baseline snapshot; events by their own snapshot.
BASELINE = 900

ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"

FP_RUNNER      = "0d1130ca799b9445061410a917d8c53ea99fc20bd04c5114187300f0cf3f94bb"
FP_RUNNER_PREV = "822ea1b3b65f224d2a1154c1bd088f2790639375c570aefa054ef4211b73f000"
FP_DIFFER      = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
FP_DIFFER_NEW  = "a1b2c3d4e5f607182a3b4c5d6e7f8091a2b3c4d5e6f70819aabbccddeeff0011"
FP_NGINX       = "112233445566778899aabbccddeeff00fedcba9876543210abcdef0123456789"
FP_WEB         = "0f1e2d3c4b5a69788796a5b4c3d2e1f00011223344556677889900aabbccddee"


def _image(service, tag, fingerprint):
    """Build an ECR image ref of the shape aws-prod snapshots and events use."""
    return f"{ECR}/{service}:{tag}@sha256:{fingerprint}"


def test_d5b8c201():
    """A baseline image with only an ignored event runs the whole range."""
    image = _image("runner", "88b7eea", FP_RUNNER)
    baseline = [{"fingerprint": FP_RUNNER, "image_name": image, "snapshot_index": BASELINE}]
    events = [{"fingerprint": FP_RUNNER, "image_name": image, "type": "updated-provenance", "reported_at": JUN_08, "snapshot_index": 901}]
    assert reconstruct_segments(baseline, events, JUN_01, JUN_22) == [
        {"fingerprint": FP_RUNNER, "image_name": image, "start": JUN_01, "end": JUN_22, "snapshot_index": BASELINE},
    ]


def test_d5b8c202():
    """An image that starts within the range runs until the range end."""
    image = _image("differ", "8beff99", FP_DIFFER)
    events = [{"fingerprint": FP_DIFFER, "image_name": image, "type": "started-compliant", "reported_at": JUN_08, "snapshot_index": 910}]
    assert reconstruct_segments([], events, JUN_01, JUN_22) == [
        {"fingerprint": FP_DIFFER, "image_name": image, "start": JUN_08, "end": JUN_22, "snapshot_index": 910},
    ]


def test_d5b8c203():
    """A baseline image that exits within the range ends at the exit time."""
    image = _image("differ", "8beff99", FP_DIFFER)
    baseline = [{"fingerprint": FP_DIFFER, "image_name": image, "snapshot_index": BASELINE}]
    events = [{"fingerprint": FP_DIFFER, "image_name": image, "type": "exited", "reported_at": JUN_08, "snapshot_index": 902}]
    assert reconstruct_segments(baseline, events, JUN_01, JUN_22) == [
        {"fingerprint": FP_DIFFER, "image_name": image, "start": JUN_01, "end": JUN_08, "snapshot_index": BASELINE},
    ]


def test_d5b8c204():
    """An image that starts and exits within the range spans exactly that interval."""
    image = _image("nginx", "abc1234", FP_NGINX)
    events = [
        {"fingerprint": FP_NGINX, "image_name": image, "type": "started-compliant", "reported_at": JUN_08, "snapshot_index": 920},
        {"fingerprint": FP_NGINX, "image_name": image, "type": "exited", "reported_at": JUN_15, "snapshot_index": 921},
    ]
    assert reconstruct_segments([], events, JUN_01, JUN_22) == [
        {"fingerprint": FP_NGINX, "image_name": image, "start": JUN_08, "end": JUN_15, "snapshot_index": 920},
    ]


def test_d5b8c205():
    """The same fingerprint starting, exiting, then starting again yields two segments."""
    image = _image("runner", "88b7eea", FP_RUNNER)
    events = [
        {"fingerprint": FP_RUNNER, "image_name": image, "type": "started-compliant", "reported_at": JUN_01, "snapshot_index": 930},
        {"fingerprint": FP_RUNNER, "image_name": image, "type": "exited", "reported_at": JUN_08, "snapshot_index": 931},
        {"fingerprint": FP_RUNNER, "image_name": image, "type": "started-compliant", "reported_at": JUN_15, "snapshot_index": 932},
    ]
    assert reconstruct_segments([], events, JUN_01, JUN_22) == [
        {"fingerprint": FP_RUNNER, "image_name": image, "start": JUN_01, "end": JUN_08, "snapshot_index": 930},
        {"fingerprint": FP_RUNNER, "image_name": image, "start": JUN_15, "end": JUN_22, "snapshot_index": 932},
    ]


def test_d5b8c206():
    """Scaled and became-non-compliant events do not close a running interval."""
    image = _image("web", "deadbee", FP_WEB)
    baseline = [{"fingerprint": FP_WEB, "image_name": image, "snapshot_index": BASELINE}]
    events = [
        {"fingerprint": FP_WEB, "image_name": image, "type": "scaled", "reported_at": JUN_08, "snapshot_index": 903},
        {"fingerprint": FP_WEB, "image_name": image, "type": "became-non-compliant", "reported_at": JUN_15, "snapshot_index": 904},
    ]
    assert reconstruct_segments(baseline, events, JUN_01, JUN_22) == [
        {"fingerprint": FP_WEB, "image_name": image, "start": JUN_01, "end": JUN_22, "snapshot_index": BASELINE},
    ]


def test_d5b8c207():
    """The started-non-compliant and started-unknown variants both open intervals."""
    image_n = _image("differ", "8beff99", FP_DIFFER)
    image_u = _image("nginx", "abc1234", FP_NGINX)
    events = [
        {"fingerprint": FP_DIFFER, "image_name": image_n, "type": "started-non-compliant", "reported_at": JUN_01, "snapshot_index": 940},
        {"fingerprint": FP_NGINX, "image_name": image_u, "type": "started-unknown", "reported_at": JUN_08, "snapshot_index": 941},
    ]
    assert reconstruct_segments([], events, JUN_01, JUN_22) == [
        {"fingerprint": FP_DIFFER, "image_name": image_n, "start": JUN_01, "end": JUN_22, "snapshot_index": 940},
        {"fingerprint": FP_NGINX, "image_name": image_u, "start": JUN_08, "end": JUN_22, "snapshot_index": 941},
    ]


def test_d5b8c208():
    """The deprecated started opens an interval and the deprecated changed is ignored."""
    image = _image("saver", "abc0001", FP_RUNNER_PREV)
    events = [
        {"fingerprint": FP_RUNNER_PREV, "image_name": image, "type": "started", "reported_at": JUN_01, "snapshot_index": 950},
        {"fingerprint": FP_RUNNER_PREV, "image_name": image, "type": "changed", "reported_at": JUN_08, "snapshot_index": 951},
    ]
    assert reconstruct_segments([], events, JUN_01, JUN_22) == [
        {"fingerprint": FP_RUNNER_PREV, "image_name": image, "start": JUN_01, "end": JUN_22, "snapshot_index": 950},
    ]


def test_d5b8c209():
    """Concurrent services are reconstructed independently by fingerprint."""
    image_r = _image("runner", "88b7eea", FP_RUNNER)
    image_d1 = _image("differ", "8beff99", FP_DIFFER)
    image_d2 = _image("differ", "c0ffee1", FP_DIFFER_NEW)
    baseline = [
        {"fingerprint": FP_RUNNER, "image_name": image_r, "snapshot_index": BASELINE},
        {"fingerprint": FP_DIFFER, "image_name": image_d1, "snapshot_index": BASELINE},
    ]
    events = [
        {"fingerprint": FP_DIFFER, "image_name": image_d1, "type": "exited", "reported_at": JUN_08, "snapshot_index": 905},
        {"fingerprint": FP_DIFFER_NEW, "image_name": image_d2, "type": "started-compliant", "reported_at": JUN_08, "snapshot_index": 905},
    ]
    assert reconstruct_segments(baseline, events, JUN_01, JUN_22) == [
        {"fingerprint": FP_RUNNER, "image_name": image_r, "start": JUN_01, "end": JUN_22, "snapshot_index": BASELINE},
        {"fingerprint": FP_DIFFER, "image_name": image_d1, "start": JUN_01, "end": JUN_08, "snapshot_index": BASELINE},
        {"fingerprint": FP_DIFFER_NEW, "image_name": image_d2, "start": JUN_08, "end": JUN_22, "snapshot_index": 905},
    ]


def test_d5b8c210():
    """Events supplied out of chronological order are sorted before reconstruction."""
    image = _image("nginx", "abc1234", FP_NGINX)
    events = [
        {"fingerprint": FP_NGINX, "image_name": image, "type": "exited", "reported_at": JUN_15, "snapshot_index": 961},
        {"fingerprint": FP_NGINX, "image_name": image, "type": "started-compliant", "reported_at": JUN_08, "snapshot_index": 960},
    ]
    assert reconstruct_segments([], events, JUN_01, JUN_22) == [
        {"fingerprint": FP_NGINX, "image_name": image, "start": JUN_08, "end": JUN_15, "snapshot_index": 960},
    ]
