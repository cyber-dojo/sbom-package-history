from fake_kosli_cli import FakeKosliCli
from sbom_package_history.kosli_reader import KosliReader
from sbom_package_history.report_building import build_report

ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"
HOST = "https://app.kosli.com"
ORG = "cyber-dojo"
JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600

FP_S1 = "1a" + "1" * 62
FP_R1 = "2b" + "2" * 62
FP_S2 = "3c" + "3" * 62
FP_D = "4d" + "4" * 62
FP_W = "5e" + "5" * 62

SAVER_1 = f"{ECR}/saver:aaa@sha256:{FP_S1}"
SAVER_2 = f"{ECR}/saver:ccc@sha256:{FP_S2}"
RUNNER_1 = f"{ECR}/runner:bbb@sha256:{FP_R1}"
DIFFER_1 = f"{ECR}/differ:ddd@sha256:{FP_D}"
WEB_1 = f"{ECR}/web:eee@sha256:{FP_W}"

URL_S1 = f"{HOST}/{ORG}/flows/saver-ci/trails/t-s1?attestation_id=s1"
URL_S2 = f"{HOST}/{ORG}/flows/saver-ci/trails/t-s2?attestation_id=s2"
URL_R1 = f"{HOST}/{ORG}/flows/runner-ci/trails/t-r1?attestation_id=r1"
URL_D = f"{HOST}/{ORG}/flows/differ-ci/trails/t-d?attestation_id=d1"


def _snap(index):
    """Build the expected snapshot URL for an environment snapshot index."""
    return f"{HOST}/{ORG}/environments/aws-prod/snapshots/{index}"


def _sbom(name, version, purl, html_url):
    """Build a raw sbom-facts attestation carrying a single package and its URL."""
    return {
        "html_url": html_url,
        "attestation_data": {"packages": [{"name": name, "version": version, "license": "MIT", "purl": purl}]},
    }


def _occ(image_name, fingerprint, category, first_date, last_date, snapshot_url, attestation_url):
    """Build an expected occurrence record."""
    return {
        "image_name": image_name, "fingerprint": fingerprint, "category": category,
        "first_date": first_date, "last_date": last_date,
        "snapshot_url": snapshot_url, "attestation_url": attestation_url,
    }


def test_a4c7d901():
    """A saver redeploy dropping rack, alongside a runner without it, builds timelines and occurrences."""
    cli = FakeKosliCli(
        baseline_events=[{"snapshot_index": 100, "sha256": FP_R1, "type": "exited",
                          "pipeline": "runner-ci", "reported_at": JUN_01 - 3600}],
        snapshots={100: {"index": 100, "artifacts": [
            {"name": SAVER_1, "fingerprint": FP_S1, "flow_name": "saver-ci"},
            {"name": RUNNER_1, "fingerprint": FP_R1, "flow_name": "runner-ci"},
        ]}},
        range_pages=[[
            {"sha256": FP_S1, "artifact_name": SAVER_1, "type": "exited",
             "pipeline": "saver-ci", "reported_at": JUN_08, "snapshot_index": 101},
            {"sha256": FP_S2, "artifact_name": SAVER_2, "type": "started-compliant",
             "pipeline": "saver-ci", "reported_at": JUN_08, "snapshot_index": 101},
        ]],
        attestations={
            FP_S1: _sbom("rack", "3.0.0", "pkg:gem/rack@3.0.0", URL_S1),
            FP_S2: _sbom("sinatra", "3.1.0", "pkg:gem/sinatra@3.1.0", URL_S2),
            FP_R1: _sbom("nginx", "1.25.0", "pkg:deb/debian/nginx@1.25.0", URL_R1),
        },
    )
    report = build_report(KosliReader(cli), "aws-prod", JUN_01, JUN_15, "pkg:gem/rack", HOST, ORG)
    assert report == {
        "package": "pkg:gem/rack",
        "from": JUN_01,
        "to": JUN_15,
        "services": [
            {
                "service": "runner",
                "timeline": [{"start": JUN_01, "end": JUN_15, "status": "absent", "versions": []}],
                "present_intervals": [],
                "occurrences": [_occ(RUNNER_1, FP_R1, "not-in-sbom", JUN_01, JUN_15, _snap(100), URL_R1)],
            },
            {
                "service": "saver",
                "timeline": [
                    {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                    {"start": JUN_08, "end": JUN_15, "status": "absent", "versions": []},
                ],
                "present_intervals": [(JUN_01, JUN_08)],
                "occurrences": [
                    _occ(SAVER_1, FP_S1, "in-sbom", JUN_01, JUN_08, _snap(100), URL_S1),
                    _occ(SAVER_2, FP_S2, "not-in-sbom", JUN_08, JUN_15, _snap(101), URL_S2),
                ],
            },
        ],
    }


def test_a4c7d902():
    """With no baseline, a service starting mid-range is reported as an in-sbom occurrence."""
    cli = FakeKosliCli(
        baseline_events=[],
        range_pages=[[
            {"sha256": FP_D, "artifact_name": DIFFER_1, "type": "started-compliant",
             "pipeline": "differ-ci", "reported_at": JUN_08, "snapshot_index": 50},
        ]],
        attestations={FP_D: _sbom("rack", "3.2.0", "pkg:gem/rack@3.2.0", URL_D)},
    )
    report = build_report(KosliReader(cli), "aws-prod", JUN_01, JUN_15, "rack", HOST, ORG)
    assert report == {
        "package": "rack",
        "from": JUN_01,
        "to": JUN_15,
        "services": [
            {
                "service": "differ",
                "timeline": [{"start": JUN_08, "end": JUN_15, "status": "present", "versions": ["3.2.0"]}],
                "present_intervals": [(JUN_08, JUN_15)],
                "occurrences": [_occ(DIFFER_1, FP_D, "in-sbom", JUN_08, JUN_15, _snap(50), URL_D)],
            },
        ],
    }


def test_a4c7d903():
    """An image whose sbom-facts attestation is absent ([]) is no-sbom, not not-in-sbom."""
    cli = FakeKosliCli(
        baseline_events=[],
        range_pages=[[
            {"sha256": FP_W, "artifact_name": WEB_1, "type": "started-compliant",
             "pipeline": "web-ci", "reported_at": JUN_08, "snapshot_index": 60},
        ]],
        attestations={FP_W: []},
    )
    report = build_report(KosliReader(cli), "aws-prod", JUN_01, JUN_15, "rack", HOST, ORG)
    assert report == {
        "package": "rack",
        "from": JUN_01,
        "to": JUN_15,
        "services": [
            {
                "service": "web",
                "timeline": [{"start": JUN_08, "end": JUN_15, "status": "unknown", "versions": []}],
                "present_intervals": [],
                "occurrences": [_occ(WEB_1, FP_W, "no-sbom", JUN_08, JUN_15, _snap(60), None)],
            },
        ],
    }
