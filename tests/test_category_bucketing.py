from sbom_package_history.category_bucketing import bucket_occurrences_by_category

ECR = "244531986313.dkr.ecr.eu-central-1.amazonaws.com"


def _occ(service, fingerprint, category):
    """Build an occurrence record; only category matters to bucketing, the rest rides along."""
    return {
        "image_name": f"{ECR}/{service}:tag@sha256:{fingerprint}",
        "fingerprint": fingerprint,
        "category": category,
        "first_date": 1780272000,
        "last_date": 1780876800,
        "snapshot_url": f"https://app.kosli.com/cyber-dojo/environments/aws-prod/snapshots/{fingerprint}",
        "attestation_url": None,
    }


D1 = _occ("differ", "d1", "in-sbom")
D2 = _occ("differ", "d2", "not-in-sbom")
S1 = _occ("saver", "s1", "in-sbom")
S2 = _occ("saver", "s2", "no-sbom")
W1 = _occ("web", "w1", "no-provenance")


def _report(services):
    """Wrap service records in a minimal report for bucketing."""
    return {"package": "pkg:gem/rack", "from": 1780272000, "to": 1782086400, "services": services}


def test_3d7f8a01():
    """Occurrences are bucketed into the four categories, services within a category in report order."""
    report = _report([
        {"service": "differ", "occurrences": [D1, D2]},
        {"service": "saver", "occurrences": [S1, S2]},
        {"service": "web", "occurrences": [W1]},
    ])
    assert bucket_occurrences_by_category(report) == [
        {"category": "no-provenance", "services": [{"service": "web", "occurrences": [W1]}]},
        {"category": "no-sbom", "services": [{"service": "saver", "occurrences": [S2]}]},
        {"category": "not-in-sbom", "services": [{"service": "differ", "occurrences": [D2]}]},
        {"category": "in-sbom", "services": [
            {"service": "differ", "occurrences": [D1]},
            {"service": "saver", "occurrences": [S1]},
        ]},
    ]


def test_3d7f8a02():
    """Every category is present even when it has no occurrences (empty services list)."""
    report = _report([{"service": "differ", "occurrences": [D1]}])
    assert bucket_occurrences_by_category(report) == [
        {"category": "no-provenance", "services": []},
        {"category": "no-sbom", "services": []},
        {"category": "not-in-sbom", "services": []},
        {"category": "in-sbom", "services": [{"service": "differ", "occurrences": [D1]}]},
    ]


def test_3d7f8a03():
    """A service's multiple occurrences in one category are kept together in order."""
    a = _occ("saver", "a", "in-sbom")
    b = _occ("saver", "b", "in-sbom")
    report = _report([{"service": "saver", "occurrences": [a, b]}])
    in_sbom = bucket_occurrences_by_category(report)[3]
    assert in_sbom == {"category": "in-sbom", "services": [{"service": "saver", "occurrences": [a, b]}]}
