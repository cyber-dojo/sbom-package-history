from fake_kosli_cli import FakeKosliCli
from sbom_package_history.kosli_cli import KosliCliError
from sbom_package_history.kosli_reader import KosliReader

FP_DIFFER = "7e2d411aedcf779dc4be7da47957f698696df954a7f557688d0052e9a18218fc"
FP_RUNNER = "cf3f94bb0d1130ca799b94450614109a917d8c53ea99fc20bd04c51141873fcf"
ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"


def test_e1f4a201():
    """baseline_snapshot_index returns the snapshot_index of the latest event before from_ts."""
    cli = FakeKosliCli(baseline_events=[
        {"snapshot_index": 4989, "sha256": FP_RUNNER, "type": "exited",
         "pipeline": "runner-ci", "reported_at": 1783757818.55},
    ])
    reader = KosliReader(cli)
    assert reader.baseline_snapshot_index("aws-prod", 1783832240) == 4989


def test_e1f4a202():
    """baseline_snapshot_index returns None when no event precedes from_ts."""
    reader = KosliReader(FakeKosliCli(baseline_events=[]))
    assert reader.baseline_snapshot_index("aws-prod", 1783832240) is None


def test_e1f4a203():
    """snapshot_artifacts returns the artifacts list from the snapshot object."""
    artifacts = [
        {"name": f"{ECR}/runner:88b7eea@sha256:{FP_RUNNER}", "fingerprint": FP_RUNNER, "flow_name": "runner-ci"},
        {"name": f"{ECR}/differ:8beff99@sha256:{FP_DIFFER}", "fingerprint": FP_DIFFER, "flow_name": "differ-ci"},
    ]
    cli = FakeKosliCli(snapshots={4990: {"index": 4990, "artifacts": artifacts}})
    reader = KosliReader(cli)
    assert reader.snapshot_artifacts("aws-prod", 4990) == artifacts


def test_e1f4a204():
    """environment_events returns a single page when it is shorter than the page limit."""
    events = [
        {"sha256": FP_RUNNER, "type": "started-compliant", "pipeline": "runner-ci", "reported_at": 1783832100.0},
        {"sha256": FP_DIFFER, "type": "exited", "pipeline": "differ-ci", "reported_at": 1783832200.0},
    ]
    reader = KosliReader(FakeKosliCli(range_pages=[events]))
    assert reader.environment_events("aws-prod", 1783832000, 1783832400) == events


def test_e1f4a205():
    """environment_events concatenates pages, stopping once a short page arrives."""
    page1 = [
        {"sha256": f"{i:064x}", "type": "started-compliant", "pipeline": "runner-ci", "reported_at": 1783832000.0 + i}
        for i in range(100)
    ]
    page2 = [
        {"sha256": f"{i:064x}", "type": "exited", "pipeline": "runner-ci", "reported_at": 1783832000.0 + i}
        for i in range(100, 103)
    ]
    reader = KosliReader(FakeKosliCli(range_pages=[page1, page2]))
    assert reader.environment_events("aws-prod", 1783832000, 1783900000) == page1 + page2


def test_e1f4a206():
    """sbom_attestation returns the attestation JSON on success."""
    attestation = {"attestation_name": "sbom-facts", "attestation_data": {"packages": []}}
    cli = FakeKosliCli(attestations={FP_DIFFER: attestation})
    reader = KosliReader(cli)
    assert reader.sbom_attestation("differ-ci", FP_DIFFER) == attestation


def test_e1f4a207():
    """sbom_attestation returns None when the CLI raises KosliCliError."""
    cli = FakeKosliCli(attestations={FP_DIFFER: KosliCliError("no such attestation")})
    reader = KosliReader(cli)
    assert reader.sbom_attestation("differ-ci", FP_DIFFER) is None
