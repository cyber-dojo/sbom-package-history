import html
from datetime import datetime, timezone

from sbom_package_history.category_bucketing import bucket_occurrences_by_category


def _fmt_ts(ts):
    """Format a Unix-second timestamp as a UTC 'YYYY-MM-DD HH:MM' string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def _link(url, text):
    """Render an anchor to url that opens in a new tab, or an em-dash when there is no url."""
    if not url:
        return "&mdash;"
    return f'<a href="{html.escape(url, quote=True)}" target="_blank" rel="noopener">{html.escape(text)}</a>'


def _row(occurrence):
    """Render one occurrence as a table row."""
    dates = f"{_fmt_ts(occurrence['first_date'])} .. {_fmt_ts(occurrence['last_date'])}"
    return (
        "<tr>"
        f"<td class='when'>{html.escape(dates)}</td>"
        f"<td class='mono'>{html.escape(occurrence['image_name'])}</td>"
        f"<td class='mono'>{html.escape(occurrence['fingerprint'])}</td>"
        f"<td>{_link(occurrence['snapshot_url'], 'snapshot')}</td>"
        f"<td>{_link(occurrence['attestation_url'], 'attestation')}</td>"
        "</tr>"
    )


def _panel(bucket):
    """Render a category's panel: one section per service, each a table of rows."""
    category = bucket["category"]
    parts = [f"<div class='panel' id='panel-{category}'>"]
    if not bucket["services"]:
        parts.append("<p class='none'>(no artifacts in this category)</p>")
    for service_entry in bucket["services"]:
        parts.append(f"<h2>{html.escape(service_entry['service'])}</h2>")
        parts.append(
            "<table><thead><tr>"
            "<th>ran</th><th>image</th><th>fingerprint</th><th>snapshot</th><th>attestation</th>"
            "</tr></thead><tbody>"
        )
        parts.extend(_row(occurrence) for occurrence in service_entry["occurrences"])
        parts.append("</tbody></table>")
    parts.append("</div>")
    return "".join(parts)


def _count(bucket):
    """Total occurrences across the services in a category bucket."""
    return sum(len(service_entry["occurrences"]) for service_entry in bucket["services"])


def format_report_html(report):
    """Render a package-history report as a self-contained HTML document.

    Shows the package and UTC range, then four top-level tabs (no provenance,
    no sbom, not in sbom, in sbom). Each tab lists, per service, one row per
    occurrence: the run's dates, image name, fingerprint, and links to the
    snapshot that proves it ran and the sbom-facts attestation the evidence came
    from. All CSS and JS are inlined so the file works offline. The page opens on
    the in-sbom tab.
    """
    buckets = bucket_occurrences_by_category(report)
    # Open on in-sbom: the "where is the package actually present" view.
    default = "in-sbom"
    from_label = f"{_fmt_ts(report['from'])} UTC"
    to_label = f"{_fmt_ts(report['to'])} UTC"

    tabs = "".join(
        f"<button class='tab' id='tab-{b['category']}' onclick=\"show('{b['category']}')\">"
        f"{html.escape(b['category'])} ({_count(b)})</button>"
        for b in buckets
    )
    panels = "".join(_panel(b) for b in buckets)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>sbom-package-history: {html.escape(report['package'])}</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
  .meta {{ margin-bottom: 1.5rem; }}
  .meta div {{ padding: 0.1rem 0; }}
  .meta .label {{ display: inline-block; width: 5rem; color: #666; }}
  .tab {{ font: inherit; padding: 0.4rem 0.8rem; margin-right: 0.25rem; border: 1px solid #ccc;
          background: #f4f4f4; cursor: pointer; border-radius: 4px 4px 0 0; }}
  .tab.active {{ background: #fff; border-bottom-color: #fff; font-weight: 600; }}
  .panel {{ display: none; border: 1px solid #ccc; padding: 1rem; }}
  h2 {{ font-size: 1rem; margin: 1rem 0 0.3rem; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 0.5rem; }}
  th, td {{ text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.85rem; }}
  th {{ color: #666; font-weight: 600; }}
  .mono {{ font-family: ui-monospace, monospace; word-break: break-all; }}
  .when {{ white-space: nowrap; }}
  .none {{ color: #888; }}
</style>
</head>
<body>
<div class="meta">
<div><span class="label">package:</span> {html.escape(report['package'])}</div>
<div><span class="label">from:</span> {html.escape(from_label)}</div>
<div><span class="label">to:</span> {html.escape(to_label)}</div>
</div>
<div class="tabs">{tabs}</div>
{panels}
<script>
function show(category) {{
  document.querySelectorAll('.panel').forEach(function (p) {{ p.style.display = 'none'; }});
  document.querySelectorAll('.tab').forEach(function (t) {{ t.classList.remove('active'); }});
  document.getElementById('panel-' + category).style.display = 'block';
  document.getElementById('tab-' + category).classList.add('active');
}}
show('{default}');
</script>
</body>
</html>
"""
