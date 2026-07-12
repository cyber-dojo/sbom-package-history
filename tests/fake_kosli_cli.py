from sbom_package_history.kosli_cli import KosliCliError


class FakeKosliCli:
    """Stub of KosliCli returning canned responses instead of running kosli.

    Injected in place of a real KosliCli so the whole stack above it (KosliReader
    and the orchestration) can be tested with canned kosli responses and no
    network. Constructed with the canned data each kind of query should return.
    """

    def __init__(self, baseline_events=None, range_pages=None, snapshots=None, attestations=None):
        """Store the canned responses for each kind of kosli query.

        baseline_events is the response for the --page-limit 1 baseline query.
        range_pages is one event list per --page of the range query. snapshots
        maps a snapshot index to its snapshot object. attestations maps a
        fingerprint to its attestation object, or to an Exception to raise.
        """
        self._baseline_events = baseline_events or []
        self._range_pages = range_pages or []
        self._snapshots = snapshots or {}
        self._attestations = attestations or {}

    def run_json(self, args):
        """Return the canned response matching the kosli args, mimicking KosliCli."""
        if args[0] == "log" and args[1] == "environment":
            if "--start-ts" in args:
                page = int(args[args.index("--page") + 1])
                return self._range_pages[page - 1] if page - 1 < len(self._range_pages) else []
            return self._baseline_events
        if args[0] == "get" and args[1] == "snapshot":
            return self._snapshots[int(args[2].split("#")[1])]
        if args[0] == "get" and args[1] == "attestation":
            response = self._attestations[args[args.index("--fingerprint") + 1]]
            if isinstance(response, Exception):
                raise response
            return response
        raise AssertionError(f"unexpected args: {args}")
