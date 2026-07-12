from sbom_package_history.kosli_cli import KosliCliError


class KosliReader:
    """The tool's read queries, built on an injected KosliCli.

    Holds a KosliCli (or any object with a run_json(args) method) and turns it
    into the four queries the tool needs. All the logic here (baseline-index
    extraction, event pagination, artifact extraction, SBOM-fail handling) is
    unit-tested by injecting a stub cli, so nothing here touches the network
    directly.
    """

    def __init__(self, cli):
        """Store the KosliCli used to run every query."""
        self._cli = cli

    def baseline_snapshot_index(self, environment, from_ts):
        """Return the snapshot index active at from_ts, or None if none precedes it.

        Reads the latest event at or before from_ts; its snapshot_index is the
        snapshot running at from_ts, since it is the most recent change before it
        and snapshots persist between events. Returns None when no event precedes
        from_ts, meaning from_ts is before the environment's recorded history.
        """
        events = self._cli.run_json([
            "log", "environment", environment,
            "--end-ts", str(from_ts),
            "--page-limit", "1",
        ])
        if not events:
            return None
        return events[0]["snapshot_index"]

    def snapshot_artifacts(self, environment, index):
        """Return the raw artifacts list of the given environment snapshot."""
        snapshot = self._cli.run_json(["get", "snapshot", f"{environment}#{index}"])
        if isinstance(snapshot, list):
            snapshot = snapshot[0]
        return snapshot.get("artifacts", [])

    def environment_events(self, environment, from_ts, to_ts):
        """Return all raw environment events in [from_ts, to_ts], paging as needed."""
        events = []
        page = 1
        while True:
            batch = self._cli.run_json([
                "log", "environment", environment,
                "--start-ts", str(from_ts),
                "--end-ts", str(to_ts),
                "--page-limit", "100",
                "--page", str(page),
            ])
            if not batch:
                break
            events.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return events

    def sbom_attestation(self, flow, fingerprint):
        """Return the raw sbom-facts attestation for a fingerprint, or None on failure.

        Fetches the sbom-facts attestation from the given flow. Returns None when
        the command fails (missing attestation, unknown flow, and so on) so the
        caller can classify the image as unknown rather than absent.
        """
        try:
            return self._cli.run_json([
                "get", "attestation", "sbom-facts",
                "--flow", flow,
                "--fingerprint", fingerprint,
            ])
        except KosliCliError:
            return None
