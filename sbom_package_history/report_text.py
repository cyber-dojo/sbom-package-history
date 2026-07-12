from datetime import datetime, timezone


def _fmt_ts(ts):
    """Format a Unix-second timestamp as a UTC 'YYYY-MM-DD HH:MM' string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def _fmt_interval(start, end):
    """Format a start/end timestamp pair as 'start .. end' in UTC."""
    return f"{_fmt_ts(start)} .. {_fmt_ts(end)}"


def _run_line(run):
    """Format one timeline run as an indented status line.

    Present runs are annotated with their versions in parentheses.
    """
    line = f"  {run['status']:<7}  {_fmt_interval(run['start'], run['end'])}"
    if run["status"] == "present" and run["versions"]:
        line += f"  ({', '.join(run['versions'])})"
    return line


def _is_never_present(service):
    """Return True if every run in the service's timeline is absent.

    Such a service never held the package (as opposed to unknown, where a missing
    SBOM leaves it uncertain), so it can be grouped under the never-present list.
    """
    return all(run["status"] == "absent" for run in service["timeline"])


def format_report_text(report):
    """Render a package-history report as plain text.

    report is {package, from, to, services}. The header names the package and the
    UTC range. Services that never held the package (every run absent) are listed
    together by name, followed by a single indented "never present" line, and
    come first. The remaining services follow, each under its name showing only
    its non-absent runs (present runs with their versions, and any unknown runs);
    absent runs are omitted since the shown runs already say when the package was
    there. A report with no services renders only the header block.
    """
    lines = [
        f"package: {report['package']}",
        f"range:   {_fmt_interval(report['from'], report['to'])} UTC",
    ]
    never_present = [s for s in report["services"] if _is_never_present(s)]
    shown = [s for s in report["services"] if not _is_never_present(s)]

    if never_present:
        lines.append("")
        lines.append(", ".join(service["service"] for service in never_present))
        lines.append("  never present")

    for service in shown:
        lines.append("")
        lines.append(service["service"])
        for run in service["timeline"]:
            if run["status"] != "absent":
                lines.append(_run_line(run))
    return "\n".join(lines)
