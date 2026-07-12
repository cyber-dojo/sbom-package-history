def service_label_from_image_ref(image_ref):
    """Derive a service label from a container image ref.

    An image ref has the shape registry-host/repository-path:tag@sha256:digest,
    where the repository path may carry a namespace and the registry host may
    carry a port. The service label is the last segment of the repository path,
    so "244531986313.dkr.ecr.eu-central-1.amazonaws.com/runner:88b7eea@sha256:..."
    yields "runner". The digest and tag are removed, then the last path segment
    is taken, so a namespaced path or a host:port never leaks into the label.
    This label is used only to group and present results, never to decide which
    images to inspect.
    """
    without_digest = image_ref.split("@")[0]
    last_path_segment = without_digest.split("/")[-1]
    return last_path_segment.split(":")[0]
