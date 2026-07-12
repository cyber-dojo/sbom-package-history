from fake_kosli_cli import FakeKosliCli
from sbom_package_history.kosli_reader import KosliReader
from sbom_package_history.report_building import build_report

ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"
JUN_01 = 1780272000
JUN_08 = 1780876800
JUN_15 = 1781481600

FP_S1 = "1a" + "1" * 62
FP_R1 = "2b" + "2" * 62
FP_S2 = "3c" + "3" * 62
FP_D = "4d" + "4" * 62

SAVER_1 = f"{ECR}/saver:aaa@sha256:{FP_S1}"
SAVER_2 = f"{ECR}/saver:ccc@sha256:{FP_S2}"
RUNNER_1 = f"{ECR}/runner:bbb@sha256:{FP_R1}"
DIFFER_1 = f"{ECR}/differ:ddd@sha256:{FP_D}"


def _sbom(name, version, purl):
    """Build a raw sbom-facts attestation carrying a single package."""
    return {"attestation_data": {"packages": [{"name": name, "version": version, "license": "MIT", "purl": purl}]}}


def test_a4c7d901():
    """A saver redeploy dropping rack, alongside a never-present runner, builds the full report."""
    cli = FakeKosliCli(
        baseline_events=[{"snapshot_index": 100, "sha256": FP_R1, "type": "exited",
                          "pipeline": "runner-ci", "reported_at": JUN_01 - 3600}],
        snapshots={100: {"index": 100, "artifacts": [
            {"name": SAVER_1, "fingerprint": FP_S1, "flow_name": "saver-ci"},
            {"name": RUNNER_1, "fingerprint": FP_R1, "flow_name": "runner-ci"},
        ]}},
        range_pages=[[
            {"sha256": FP_S1, "artifact_name": SAVER_1, "type": "exited",
             "pipeline": "saver-ci", "reported_at": JUN_08},
            {"sha256": FP_S2, "artifact_name": SAVER_2, "type": "started-compliant",
             "pipeline": "saver-ci", "reported_at": JUN_08},
        ]],
        attestations={
            FP_S1: _sbom("rack", "3.0.0", "pkg:gem/rack@3.0.0"),
            FP_S2: _sbom("sinatra", "3.1.0", "pkg:gem/sinatra@3.1.0"),
            FP_R1: _sbom("nginx", "1.25.0", "pkg:deb/debian/nginx@1.25.0"),
        },
    )
    reader = KosliReader(cli)
    report = build_report(reader, "aws-prod", JUN_01, JUN_15, "pkg:gem/rack")
    assert report == {
        "package": "pkg:gem/rack",
        "from": JUN_01,
        "to": JUN_15,
        "services": [
            {
                "service": "runner",
                "timeline": [{"start": JUN_01, "end": JUN_15, "status": "absent", "versions": []}],
                "present_intervals": [],
            },
            {
                "service": "saver",
                "timeline": [
                    {"start": JUN_01, "end": JUN_08, "status": "present", "versions": ["3.0.0"]},
                    {"start": JUN_08, "end": JUN_15, "status": "absent", "versions": []},
                ],
                "present_intervals": [(JUN_01, JUN_08)],
            },
        ],
    }


def test_a4c7d902():
    """With no baseline (from predates history), a service starting mid-range is still reported."""
    cli = FakeKosliCli(
        baseline_events=[],
        range_pages=[[
            {"sha256": FP_D, "artifact_name": DIFFER_1, "type": "started-compliant",
             "pipeline": "differ-ci", "reported_at": JUN_08},
        ]],
        attestations={FP_D: _sbom("rack", "3.2.0", "pkg:gem/rack@3.2.0")},
    )
    reader = KosliReader(cli)
    report = build_report(reader, "aws-prod", JUN_01, JUN_15, "rack")
    assert report == {
        "package": "rack",
        "from": JUN_01,
        "to": JUN_15,
        "services": [
            {
                "service": "differ",
                "timeline": [{"start": JUN_08, "end": JUN_15, "status": "present", "versions": ["3.2.0"]}],
                "present_intervals": [(JUN_08, JUN_15)],
            },
        ],
    }
