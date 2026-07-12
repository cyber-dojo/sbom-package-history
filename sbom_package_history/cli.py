import argparse
import json
import sys

from sbom_package_history.date_parsing import parse_date_to_epoch
from sbom_package_history.kosli_cli import KosliCli, KosliCliError
from sbom_package_history.kosli_reader import KosliReader
from sbom_package_history.report_building import build_report

_EXAMPLE = """\
Example:
  sbom-package-history --package pkg:gem/rack --from 2026-06-01 --to 2026-07-01

The package may be a purl (pkg:gem/rack, pkg:gem/rack@3.1) or a bare name
(rack, rack@3.1.2). A version is matched as a dot-component prefix, so 3.1
matches 3.1.x but not 3.10.0. Dates are UTC (YYYY-MM-DD or YYYY-MM-DD HH:MM).
"""


def _build_parser():
    """Build the argument parser for the sbom-package-history CLI."""
    parser = argparse.ArgumentParser(
        prog="sbom-package-history",
        description=(
            "Report which production services contained a given software package,\n"
            "and over what time periods."
        ),
        epilog=_EXAMPLE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--package", required=True,
                        help="the library, as a purl (pkg:gem/rack[@ver]) or a bare name (rack[@ver])")
    parser.add_argument("--from", dest="from_date", required=True, metavar="DATE",
                        help="start of the range, UTC (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
    parser.add_argument("--to", dest="to_date", required=True, metavar="DATE",
                        help="end of the range, UTC (YYYY-MM-DD or YYYY-MM-DD HH:MM)")
    parser.add_argument("--environment", default="aws-prod",
                        help="the Kosli environment to inspect (default: aws-prod)")
    parser.add_argument("--org", default="cyber-dojo",
                        help="the Kosli org (default: cyber-dojo)")
    parser.add_argument("--host", default="https://app.kosli.com",
                        help="the Kosli host (default: https://app.kosli.com)")
    parser.add_argument("--api-token", dest="api_token", default="read-only-throwaway",
                        help="Kosli API token; read-only, any string works for GET (default: a throwaway)")
    parser.add_argument("--progress", action="store_true",
                        help="print a dot to stderr for each Kosli CLI call as it runs")
    return parser


def _dot_progress():
    """Print a single dot to stderr and flush it, one per Kosli CLI call."""
    sys.stderr.write(".")
    sys.stderr.flush()


def main(argv=None):
    """Run the CLI: parse args, build the report, print it as JSON, return an exit code.

    Reads --package, --from, --to and the Kosli connection options, builds the
    package-history report through a real KosliCli, and prints it as JSON on
    stdout (render it with report_to_text or report_to_markdown). Returns 0 on
    success, 1 when a kosli command fails, and 2 (via argparse) on bad arguments
    or an unparseable date.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        from_ts = parse_date_to_epoch(args.from_date)
        to_ts = parse_date_to_epoch(args.to_date)
    except ValueError as error:
        parser.error(str(error))

    on_call = _dot_progress if args.progress else None
    reader = KosliReader(KosliCli(args.org, args.host, args.api_token, on_call=on_call))
    try:
        report = build_report(reader, args.environment, from_ts, to_ts, args.package)
    except KosliCliError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if args.progress:
        sys.stderr.write("\n")
        sys.stderr.flush()
    print(json.dumps(report, indent=2))
    return 0
