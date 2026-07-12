# sbom-package-history

A tool that answers: **over a given date range, in which production services was
a given software package present, and over what time periods?**

The answer is, per service, a chronological present/absent timeline. It can flip
as a service's running image changes over the range, and because an old and new
image briefly overlap during a rolling deploy, the status at any instant is the
aggregate of the images running then: present if any of them held the package.

## Inputs

All required:

- `--package` - the library, as `NAME[@VERSION]` or a full purl.
  - `rack` or `pkg:gem/rack` - any version
  - `rack@3.1` or `pkg:gem/rack@3.1` - version 3.1.x (component prefix)
  - `rack@3.1.2` - exactly 3.1.2
- `--from` / `--to` - the date range to inspect.

There is deliberately no `--service` input. See "Why no service filter".

## Governing constraints

Two constraints shape the whole design:

1. **Kosli has no query that takes a package name and returns which artifacts
   contain it.** The package identity lives only inside each artifact's SBOM
   data. The tool cannot push the query into Kosli; it must **pull** each
   relevant image's SBOM out and scan it client-side. The real problem is
   "enumerate the right images, fetch and cache their SBOMs, fold the matches
   into a timeline", not "query".

2. **Flow (pipeline) names are mutable and have changed over time.** Filtering by
   a user-supplied service name mapped to a flow name (`<service>-ci`) would
   silently miss a service's history from before a rename - a false "absent",
   which the robustness rule forbids. So service name is never a filter.

## Why no service filter

The stable identity of a running image is its **fingerprint** (image digest):
immutable and unique. Enumeration, interval reconstruction, and SBOM fetching all
key on the fingerprint, never on a flow name.

The tool therefore enumerates **every** image that ran in production over the
range, across all services, and derives a **service label** for reporting from
the image ref (the ECR repo segment, e.g. `runner` in
`...dkr.ecr...amazonaws.com/runner:88b7eea@sha256:...`). That label is more
stable than the flow name and is used only to group and present results, never
to decide what to inspect.

The flow name is still needed for one thing: fetching an image's SBOM
(`kosli get attestation` requires `--flow`). That flow name is read from the
snapshot/event record for each fingerprint at query time, so a rename does not
break retrieval - it is never taken from user input.

## Scope of this version

Production runtime only, driven from the `aws-prod` Kosli environment. A later
variant will add build-history (driven from the CI flows directly). The design
keeps image-enumeration separate from the SBOM-match core so that second front
end can reuse the core unchanged.

## Data model (verified live against the cyber-dojo org)

- Org `cyber-dojo`, host `https://app.kosli.com`.
- Environment `aws-prod` (ECS), snapshotted frequently (observed ~120s apart).
- Each image is built into a CI flow, fingerprint = image digest, with a custom
  attestation named `sbom-facts` whose `attestation_data` is
  `{spec_version, created, creators, relationship_count,
  packages: [{name, version, license, purl}]}`.

### Verified CLI shapes (all read-only, `--output json`)

A GET-only throwaway token is sufficient for all of these.

1. Baseline snapshot index: `kosli log environment aws-prod --end-ts <F>
   --page-limit 1` -> the latest event at or before `--from`. Its
   `snapshot_index` is the snapshot active at `--from`, because it is the most
   recent change before it and snapshots persist between events. An empty result
   means `--from` predates all history, so there is no baseline.

2. Snapshot contents: `kosli get snapshot aws-prod#<index>`
   -> `.artifacts[]` each with `fingerprint`, `name` (full image ref, source of
   the service label), `flow_name`, `flows[]`, `git_commit`. The baseline
   inventory of what is running when the range opens.

3. Environment events: `kosli log environment aws-prod --start-ts <F> --end-ts <T>`
   -> per-event `sha256` (fingerprint), `artifact_name` (image ref),
   `pipeline` (flow name), `reported_at`, `snapshot_index`, `type`. Only
   changes, not every snapshot. Paginated, max 100 per page.

4. SBOM for an image: `kosli get attestation sbom-facts --flow <flow_name>
   --fingerprint <fp>` -> `attestation_data.packages[] {name, version, license,
   purl}`, plus `html_url` (the attestation's UI link, used as the evidence URL).
   The `<flow_name>` comes from the fingerprint's own event/snapshot record. An
   image with no such attestation returns an empty `[]` with exit 0 (see
   Robustness). The snapshot URL is
   `<host>/<org>/environments/<env>/snapshots/<index>` (also in each event's
   `_links.snapshot.html`).

### Event-type vocabulary (authoritative, from server `environment_consts.py`)

Interval boundaries are driven only by these. Sampling the live API would miss
the rarer and deprecated ones, so the vocabulary is taken from the source.

- **Opens** a running interval (fingerprint 0 -> N), `STARTED_EVENT_TYPES`:
  `started` (deprecated), `started-compliant`, `started-non-compliant`,
  `started-unknown`.
- **Closes** a running interval (fingerprint N -> 0): `exited`.
- **Ignored** (same fingerprint keeps running; count/compliance/metadata only):
  `changed` (deprecated), `scaled`, `became-compliant`, `became-non-compliant`,
  `updated-provenance`, `unchanged`.

Compliance is irrelevant to whether an image is running: every `started-*`
variant opens an interval.

### Provenance and categories (authoritative, from server `environment_artifact.py`)

An artifact's `sbom-facts` lives in its **build flow** - the artifact's primary
flow in a snapshot record, `flows[0]` (= the top-level `flow_name`, the
`<service>-ci` flow). A fingerprint is usually in several flows (the build flow
plus `snyk-*` and `production-promotion`), but only the build flow carries
`sbom-facts`, so category resolution reads the build flow and ignores the others.
Empirically `flows[0]` is the `-ci` build flow for every cyber-dojo service.

- **no provenance**: the snapshot record has no flows for the image
  (`has_provenance = flows != []`) - no build flow, no SBOM.
- **no sbom**: a build flow exists but has no usable `sbom-facts` (a missing
  attestation returns `[]` with exit 0).
- **not in sbom** / **in sbom**: `sbom-facts` present, package absent / present.

Binary-reproducibility (the same fingerprint built from two commits, so its build
flow holds two trails) is set aside: the build flow is read as a single trail.
Within a flow the server already resolves the fingerprint to its most-recent
trail (`find_by_fingerprint` returns the latest by `created_at`); across flows,
`flows[0]` is the build flow, never a most-recent-by-time pick.

## Algorithm

1. **Baseline.** Read the latest event at or before `--from`
   (`log environment --end-ts <from> --page-limit 1`) and take its
   `snapshot_index`; fetch that snapshot's artifacts. They are every image
   running when the range opens, each with fingerprint, image ref, and flow
   name. Their intervals start clamped to `--from`. An empty event result means
   `--from` predates all history, so the baseline is empty.

2. **Events.** Walk `kosli log environment aws-prod` across `[from, to]`. A
   started-type event opens an interval for its fingerprint at `reported_at`; an
   `exited` event closes it. The same fingerprint can start, exit, then start
   again, producing multiple intervals (the flip case). Intervals still open at
   `--to` are clamped to `--to`.

3. **Segments.** The result is a list of running-image segments, each
   `{fingerprint, image_name, start, end, snapshot_index}`, across all services.
   The snapshot_index (the opening event's, or the baseline snapshot's) is the
   proof the image was running.

4. **Classify each distinct image into one of four categories** (see Provenance
   and categories). Resolve its build flow (the artifact's primary flow) and
   fetch `sbom-facts` from it once, cached by fingerprint (the same call yields
   the attestation's `html_url`). `no-provenance` (no build flow) / `no-sbom`
   (build flow but empty or missing `sbom-facts`) / `not-in-sbom` (SBOM present,
   package absent) / `in-sbom` (SBOM present, package present, with its version).
   A coarser status (in-sbom -> present, not-in-sbom -> absent, the other two ->
   unknown) drives the timeline.

5. **Enrich.** Each segment carries `snapshot_url` (built from snapshot_index)
   and `attestation_url` (the `sbom-facts` html_url, or null).

6. **Group.** Group segments by service label (image repo name). Per service:
   a present/absent/unknown **timeline** built by an interval sweep (segments can
   overlap; the distinct start/end times cut the range into sub-intervals whose
   status is the aggregate of the images running across it - present if any is
   present, else unknown if any is unknown, else absent - with contiguous
   same-status sub-intervals merged and gaps breaking a run); the union of
   present intervals; and an **occurrences** list, one record per run, for the
   tab views.

## Output

The CLI emits the report as **JSON** on stdout; separate formatters render it -
`report_to_text` and `report_to_html`, each a thin `bin/` script over a pure
formatter - so a new view needs no change to the tool. Progress dots
(`--progress`) go to stderr, keeping stdout pipe-clean.

JSON contract:

```
{
  "package": "<the --package string>",
  "from": <unix seconds>,
  "to": <unix seconds>,
  "services": [
    {
      "service": "<image-repo label>",
      "timeline": [                        # swept present/absent/unknown, for text
        {"start": <unix>, "end": <unix>,
         "status": "present | absent | unknown",
         "versions": ["<present-run versions>"]}
      ],
      "present_intervals": [[start, end]],  # union of present runs
      "occurrences": [                       # one per run, for the tab views
        {
          "image_name": "<ecr image ref>",
          "fingerprint": "<sha256>",
          "category": "no-provenance | no-sbom | not-in-sbom | in-sbom",
          "first_date": <unix seconds>,      # run start
          "last_date": <unix seconds>,       # run end
          "snapshot_url": "<Kosli snapshot proving it ran>",
          "attestation_url": "<Kosli sbom-facts attestation, or null>"
        }
      ]
    }
  ]
}
```

`timeline` is the aggregated present/absent view (a present run means any image
running then held the package). `occurrences` is the raw per-run layer: one
record per contiguous run of a fingerprint, with its 4-way category and evidence
links; a fingerprint's several runs (e.g. a rollback) appear as several
occurrences.

**Text** (`report_to_text`): a collapsed view - never-present services grouped
first under one indented `never present` line, then present services showing only
their non-absent runs, one line per run.

```
package: pkg:gem/rack
range:   2026-06-01 00:00 .. 2026-07-01 00:00 UTC

creator, runner
  never present

saver
  present  2026-06-01 00:00 .. 2026-06-08 00:00  (3.0.0)
  present  2026-06-20 00:00 .. 2026-07-01 00:00  (3.1.2)
```

**HTML** (`report_to_html`): a self-contained page - the package and range, then
four top-level tabs (no provenance / no sbom / not in sbom / in sbom, each with a
count), listing per service one row per occurrence: dates, image, fingerprint,
and links to the snapshot and the `sbom-facts` attestation (blank for
no-provenance / no-sbom). CSS and tab JS are inlined so it works offline.

## Package matching

Identity (which package) is separate from version (which build of it).

- **Identity**: match by `purl` when the input is a purl (ecosystem-qualified,
  unambiguous; the SBOM package's purl is reduced to its identity by stripping
  version, qualifiers and subpath); otherwise by exact `name` (so `rack` does not
  match `rackup`, with the caveat that a bare name can collide across ecosystems:
  gem vs deb vs npm).

  A real example from `aws-prod`: querying the bare name `openssl` reports the
  Ruby services as present at version `4.0.0` and nginx as absent. That is
  correct but easy to misread. The `4.0.0` is the Ruby gem `pkg:gem/openssl`, not
  the OS library; nginx (Alpine, no Ruby) has no package literally named
  `openssl`, though it does ship the OS TLS library as `libssl3` / `libcrypto3`
  (`pkg:apk/alpine/libssl3`, with `upstream=openssl` in the purl). So a bare
  `openssl` answers "which services bundle a package named openssl", which here
  means the gem. To hunt the OS library, query by purl: `pkg:deb/debian/openssl`
  on the Debian services, `pkg:apk/alpine/libssl3` on nginx. Matching the purl's
  `upstream=` qualifier to catch OS-level OpenSSL across distros regardless of
  package name is a possible future enhancement.

- **Version**: the entered version is treated as a **dot-component prefix**,
  compared component-by-component against the SBOM package's `version` field,
  never as a raw string prefix.
  - `3.1.2` matches only `3.1.2` (a complete prefix is an exact match).
  - `3.1` matches `3.1.0`, `3.1.2`, `3.1.9`.
  - `3.1` does NOT match `3.10.0` (component-aware: `[3,1]` vs `[3,10,0]`).
  - omitted version matches any version.

- **Not** a semver range comparator: no `>=` / `<` ranges. Odd ecosystem
  versions (`1.1.1f-1ubuntu2.16`, epochs like `2:1.2.3`) split sensibly on `.`
  but "the third number" only has its intuitive meaning for dotted versions.

## Robustness

Fail toward "present / unknown", never silently toward "absent". If an image's
`sbom-facts` cannot be fetched or parsed, or its flow cannot be resolved, its
interval is reported as `unknown` (possibly present), not `absent`. A missing
SBOM must never read as "the package was not there". In particular,
`get attestation` for an image with no `sbom-facts` returns an empty `[]` with
exit 0; since a real container SBOM always has packages, an empty package list
means no usable SBOM and is treated as `unknown`, not `absent`.

## Implementation

Python, structured so all logic is unit-tested without the network. The only
code that touches the network is one low-level class, stubbed in tests so the
whole stack above it runs on canned responses.

- **Pure core** (fully unit-tested):
  - `version_matching.version_matches` - component-prefix version rule.
  - `package_presence.package_present` - purl/name identity plus version filter.
  - `package_spec.parse_package_spec` - parse `NAME[@VERSION]` or a purl.
  - `service_label.service_label_from_image_ref` - derive the service label.
  - `segment_reconstruction.reconstruct_segments` - baseline plus started/exited
    events into per-image segments, with the event vocabulary as an explicit
    constant.
  - `segment_classification.classify_segment` - the 4-way category (and coarser
    status) plus the matched version.
  - `timeline_building.build_timeline` - interval sweep folding segments into runs.
  - `service_timelines.group_into_service_timelines` - group by service into a
    timeline, present-interval union, and per-run occurrences.
  - `category_bucketing.bucket_occurrences_by_category` - regroup occurrences into
    the four tabs (all present, in order).
  - `kosli_normalizing` - normalize raw kosli JSON into the core's shapes.
  - `date_parsing.parse_date_to_epoch` - `--from`/`--to` into UTC epoch seconds.
  - `report_building.build_report` - orchestrate the pipeline into the report dict.
  - `report_text.format_report_text` - render the report as text.
  - `report_html.format_report_html` - render the report as a self-contained HTML page.
- **Kosli I/O**:
  - `kosli_cli.KosliCli` - the sole network boundary: runs a read-only `kosli`
    command as JSON, in a scrubbed environment (only PATH) so ambient KOSLI_*
    variables cannot leak in. Stubbed by `tests/fake_kosli_cli.py`.
  - `kosli_reader.KosliReader` - the four queries built on an injected KosliCli.
- **CLI and scripts**:
  - `cli.main` (via `bin/sbom-package-history`) - argparse, long flags, `-h` with
    an example, `--progress` dots on stderr; emits the report as JSON.
  - `bin/report_to_text`, `bin/report_to_html` - render JSON from stdin as text
    or a self-contained HTML page.
  - `bin/cares_text_demo`, `bin/cares_html_demo` - the c-ares supersession demo
    (text and HTML), also exposed as `make` targets.

### Assumptions and the tests that prove them

- Component-prefix version matching (`3.1` not `3.10.0`): `test_version_matching`.
- Package identity (`rack` not `rackup`, purl qualifier stripping):
  `test_package_presence`, `test_package_spec`.
- Interval reconstruction from the started/exited vocabulary:
  `test_segment_reconstruction`.
- Concurrency-aware sweep and per-run occurrences: `test_timeline_building`,
  `test_service_timelines`.
- 4-way categorisation and fail-toward-unknown for missing/empty SBOMs:
  `test_segment_classification`, `test_report_building`.
- Bucketing occurrences into the four tabs: `test_category_bucketing`.
- The whole stack on canned kosli responses: `test_kosli_reader`,
  `test_report_building` (via the FakeKosliCli stub).
- CLI JSON shapes: proven live against the cyber-dojo org during investigation.
