import json
import os
import subprocess


class KosliCliError(RuntimeError):
    """Raised when a kosli command exits non-zero."""


class KosliCli:
    """The lowest-level boundary: runs a read-only kosli CLI command as JSON.

    Holds the org, host and API token, and exposes a single method that shells
    out to `kosli ... --output json` and returns the parsed result. This is the
    only code in the tool that touches the network, so a stub of this class lets
    the whole stack above it be tested with canned responses. A read-only (GET)
    API token is sufficient.

    The subprocess runs with a scrubbed environment containing only PATH, so that
    ambient KOSLI_* variables (org, host, and especially KOSLI_API_TOKEN) and the
    ~/.kosli config cannot silently change the CLI's behaviour. Everything the
    command needs is passed explicitly as flags.
    """

    def __init__(self, org, host, api_token, on_call=None):
        """Store the org, host and read-only API token used for every command.

        on_call, if given, is a no-argument callable invoked once at the start of
        every command, so a caller can show progress (one tick per kosli call).
        """
        self.org = org
        self.host = host
        self.api_token = api_token
        self._on_call = on_call

    def run_json(self, args):
        """Run a kosli subcommand with JSON output and return the parsed result.

        args is the kosli subcommand and its arguments; the org, host, token and
        --output json flags are appended here. The subprocess runs with only PATH
        in its environment. An empty stdout yields an empty list. Raises
        KosliCliError when the command exits non-zero, carrying its stderr. Calls
        the on_call hook first, if one was given, for progress reporting.
        """
        if self._on_call is not None:
            self._on_call()
        command = [
            "kosli", *args,
            "--org", self.org,
            "--host", self.host,
            "--api-token", self.api_token,
            "--output", "json",
        ]
        clean_env = {"PATH": os.environ.get("PATH", "")}
        completed = subprocess.run(command, capture_output=True, text=True, env=clean_env)
        if completed.returncode != 0:
            raise KosliCliError(completed.stderr.strip() or f"kosli {' '.join(args)} failed")
        if not completed.stdout.strip():
            return []
        return json.loads(completed.stdout)
