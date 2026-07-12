from sbom_package_history.service_label import service_label_from_image_ref

DIGEST = "cf3f94bb0d1130ca799b94450614109a917d8c53ea99fc20bd04c51141873fcf"


def test_3f9a7101():
    """A standard ECR ref yields the repository name as the service label."""
    ref = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:88b7eea@sha256:{DIGEST}"
    assert service_label_from_image_ref(ref) == "runner"


def test_3f9a7102():
    """A different service's ref yields that service's name."""
    ref = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/differ:8beff99@sha256:{DIGEST}"
    assert service_label_from_image_ref(ref) == "differ"


def test_3f9a7103():
    """A namespaced repository path yields only its last segment."""
    ref = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/cyber-dojo/runner:88b7eea@sha256:{DIGEST}"
    assert service_label_from_image_ref(ref) == "runner"


def test_3f9a7104():
    """A ref without a digest still yields the service label."""
    ref = "244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:88b7eea"
    assert service_label_from_image_ref(ref) == "runner"


def test_3f9a7105():
    """A ref without a tag (digest only) still yields the service label."""
    ref = f"244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner@sha256:{DIGEST}"
    assert service_label_from_image_ref(ref) == "runner"


def test_3f9a7106():
    """A registry host carrying a port does not leak into the service label."""
    ref = f"localhost:5000/runner:88b7eea@sha256:{DIGEST}"
    assert service_label_from_image_ref(ref) == "runner"
