# The four top-level tabs, in display order.
CATEGORIES = ("no-provenance", "no-sbom", "not-in-sbom", "in-sbom")


def bucket_occurrences_by_category(report):
    """Regroup a report's occurrences by category for the four HTML tabs.

    report is the {package, from, to, services} report. Each service's
    occurrences are split by their category. Returns a list with one entry per
    category, in CATEGORIES (tab) order and always all four present, each
    {category, services}. services lists only the services that have an
    occurrence in that category, in the report's (sorted) service order, each
    {service, occurrences} keeping the occurrences of that category in their
    original order.
    """
    buckets = {category: [] for category in CATEGORIES}
    for service in report["services"]:
        by_category = {}
        for occurrence in service["occurrences"]:
            by_category.setdefault(occurrence["category"], []).append(occurrence)
        for category in CATEGORIES:
            if category in by_category:
                buckets[category].append({
                    "service": service["service"],
                    "occurrences": by_category[category],
                })
    return [{"category": category, "services": buckets[category]} for category in CATEGORIES]
