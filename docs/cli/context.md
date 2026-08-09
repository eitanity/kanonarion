# `kanonarion context` - Module context for AI agents

## Synopsis

```
kanonarion context <module>@<version> [flags]
kanonarion context [--gomod <path>] [flags]
kanonarion context --walk-id <id> [flags]
```

## Description

`context` aggregates every stored record for a module - verification,
provenance, direct dependencies, license, public interface, call graph,
examples, and vulnerabilities - into a single response. It is the primary entry point for
an agent that needs to understand a dependency before using or modifying it.

With no positional module and no `--walk-id`, `context` defaults to
`--gomod ./go.mod` and emits one context entry per module in the project's
dependency **scope** - NDJSON with `--json`, text blocks otherwise. The scope is
consistent with every other go.mod command: the default is the project's own
**code** dependencies (`go list -deps -test ./...`); `--tool` selects the
tooling supply chain; `--project` the complete set (code + tooling). `--tool`
and `--project` are mutually exclusive. See
[`walk` Scopes](walk.md#scopes-code-tool-complete). This is the same module set
a bare `kanonarion inspect` walks, extracts, and vuln-scans, so the no-arg pair
composes: `kanonarion inspect` followed by `kanonarion context` covers every
enumerated module. To cover a full transitive closure of an arbitrary walk use
`context --walk-id <id>` instead.

All sections are always present in the output. A section that has not been
run yet reports `"status": "not_run"` rather than being absent. A section
that encountered a store error reports `"status": "read_error"` with an
`"error"` field. This makes the output structurally stable: a consumer can
always read `out.dependencies.status` without checking whether the key
exists.

The `dependencies` section is drawn from the most recent walk where this
module was the root target. If no such walk exists it reports `not_run`.
Other sections (license, interface, call graph, examples, vulnerabilities)
are drawn from the extraction pipeline and are independent of walk records.

## Output format

### Text (default)

Full mode (`--full`) renders each section with a heading and detail:

```
go.uber.org/goleak@v1.3.0

=== Verification ===
Status:     Verified
Fetched At: 2026-04-30T09:51:11Z
Git URL:    https://github.com/uber-go/goleak

=== Provenance ===
Fork Heuristic: none (name-path heuristic, catalogue 1.0.0)

=== Dependencies ===
Status:  succeeded
Walk ID: 01KQN2KMSRQ6EJHMAYBG8139NG
Frame:   linux/amd64
  github.com/davecgh/go-spew@v1.1.1
  github.com/kr/pretty@v0.1.0
  github.com/pmezard/go-difflib@v1.0.0
  github.com/stretchr/testify@v1.8.0
  gopkg.in/check.v1@v1.0.0-20180628173108-788fd7840127
  gopkg.in/yaml.v3@v3.0.1

=== License ===
SPDX:         MIT
Status:       Detected
Extracted At: 2026-05-02T19:29:14Z

=== Interface ===
(not run)

=== Call Graph ===
Status:       Extracted
Extracted At: 2026-05-02T19:29:15Z
Algorithm:    CHA
Nodes:        93
Edges:        134
Entry Points by Package:
  go.uber.org/goleak: 11

=== Examples ===
Status:       None
Extracted At: 2026-05-02T19:29:15Z

=== Vulnerabilities ===
Status:       Clean
Scanned At:   2026-04-30T09:54:43Z
Walk ID:      01KQEWSFEAK5RZFVKMQX6MJA5M
Snapshot:     2026-04-21T18:59:51Z
```

Compact mode (the default) renders one line per section:

```
go.uber.org/goleak@v1.3.0
  Verification:    Verified (git: https://github.com/uber-go/goleak)
  Provenance:      no fork indicators (name-path heuristic, catalogue 1.0.0)
  Dependencies:    6 direct (succeeded)
  License:         MIT
  Interface:       (not run)
  Call Graph:      93 nodes, 134 edges (Extracted)
  Examples:        0 (None)
  Vulnerabilities: Clean
```

#### Failure and partial reasons

The License, Interface, Call Graph and Examples sections print the reason the
record recorded for its status, in the same `(status: reason)` shape the store
read-error branches use for `(failed: …)`:

```
  License:         MIT (Partial: vendor/LICENSE unreadable)
  Interface:       315 package(s), 1034 symbol(s) (Partial: parse failures in 11 package(s): golang.org/x/tools/go/loader/testdata: go/loader/testdata/badpkgdecl.go:1:34: expected 'package', found 'EOF' (+10 more package(s)))
  Call Graph:      0 nodes, 0 edges (LoadFailed: meta load: err: exit status 1: stderr: go: missing go.sum entry for go.mod file)
  Examples:        0 (ExtractionFailed: zip corrupt)
```

This is the same fact `--json` carries in each section's `error` field, so the
two outputs no longer disagree about what is known. It matters for telling an
unusable analysis environment from a fault in the module: both render as the
same status word, and only the reason separates them.

A record that recorded no reason prints the bare status word — `(LoadFailed)`.
That is not a rendering gap: records written before a stage recorded its reason
state nothing, and no reason is invented for them. The reason is a fact about the
record, not about the coordinate, so re-deriving the record is what supplies one.

A multi-line reason is folded onto the section's single row. It is never
truncated.

### JSON (`--json`)

```json
{
  "module": {
    "path": "go.uber.org/goleak",
    "version": "v1.3.0"
  },
  "verification": {
    "extracted_at": "2026-04-30T09:51:11Z",
    "status": "Verified",
    "git_url": "https://github.com/uber-go/goleak"
  },
  "provenance": {
    "fork_heuristic": {
      "status": "none",
      "catalogue_version": "1.0.0"
    }
  },
  "dependencies": {
    "status": "succeeded",
    "walk_id": "01KQN2KMSRQ6EJHMAYBG8139NG",
    "frame": "linux/amd64",
    "count": 6,
    "dependencies": [
      { "path": "github.com/davecgh/go-spew", "version": "v1.1.1" },
      { "path": "github.com/kr/pretty",       "version": "v0.1.0" },
      { "path": "github.com/pmezard/go-difflib", "version": "v1.0.0" },
      { "path": "github.com/stretchr/testify",   "version": "v1.8.0" },
      { "path": "gopkg.in/check.v1",  "version": "v1.0.0-20180628173108-788fd7840127" },
      { "path": "gopkg.in/yaml.v3",   "version": "v3.0.1" }
    ]
  },
  "license": {
    "extracted_at": "2026-05-02T19:29:14Z",
    "spdx": "MIT",
    "status": "Detected"
  },
  "interface": {
    "status": "not_run"
  },
  "call_graph": {
    "extracted_at": "2026-05-02T19:29:15Z",
    "status": "Extracted",
    "algorithm": "CHA",
    "node_count": 93,
    "edge_count": 134,
    "entry_points_by_package": {
      "go.uber.org/goleak": 11
    }
  },
  "examples": {
    "extracted_at": "2026-05-02T19:29:15Z",
    "status": "None",
    "count": 0
  },
  "vulnerabilities": {
    "extracted_at": "2026-04-30T09:54:43Z",
    "status": "Clean",
    "walk_id": "01KQEWSFEAK5RZFVKMQX6MJA5M",
    "snapshot_version": "2026-04-21T18:59:51Z"
  }
}
```

## Section field reference

### `dependencies`

Direct dependencies drawn from the most recent walk where this module was the
root target. Versions are the MVS-selected versions recorded in that walk, not
the `require` versions from `go.mod` (which may differ after minimum version
selection). The list is sorted lexicographically by module path.

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / walk status (`succeeded`, `partial`, `failed`, `cancelled`) |
| `walk_id` | string | ID of the walk record this was drawn from |
| `frame` | string | `GOOS/GOARCH` that walk resolved for, or `unrecorded` for a walk taken before the frame was recorded |
| `count` | int | Number of direct dependencies |
| `partial` | bool | True when the walk graph was partial - some transitive deps could not be resolved, so the direct dep list may be incomplete |
| `dependencies` | array | Direct dependencies sorted by path |
| `dependencies[].path` | string | Module import path |
| `dependencies[].version` | string | MVS-selected version |
| `error` | string | Set when `status` is `read_error` |

The dependency list is the list for one platform: `GOOS` gates which files
build. `context` answers from the most recent walk of the module whatever its
platform, so `frame` says which one answered.

The `walk_id` field is present so an agent can call `kanonarion walk-show
<walk_id>` to retrieve the full transitive closure, or `kanonarion dependents
<module>@<version> --walk-id <walk_id>` to find reverse-dependency
relationships within that walk.

### `verification`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_fetched` / `read_error` / verification status (e.g. `Verified`) |
| `extracted_at` | string | RFC3339 fetch timestamp |
| `git_url` | string | Resolved VCS URL |
| `retracted` | bool | True when the version is retracted |
| `error` | string | Set when `status` is `read_error` |

### `provenance`

Fork/copy provenance facts about the module's identity, computed fresh from
the module path on every run (no stored record). Today this holds only the
cheap-tier name-path fork heuristic; see
[`provenance.md`](provenance.md) for the heuristic's semantics and the
standalone query command. A `path_match` is a **caveated inference** - *"path
suggests a fork of `<canonical>` - verify"* - never a verdict.

| Field | Type | Description |
|---|---|---|
| `fork_heuristic.status` | string | `none` (analysed, no name collision) / `path_match` (collision with a catalogued canonical) / `not_analysed` (heuristic not run; never emitted by `context` itself) |
| `fork_heuristic.catalogue_version` | string | Version of the static canonical-module catalogue |
| `fork_heuristic.fork_indicators` | array | Present when `status` is `path_match`; sorted by canonical path |
| `fork_heuristic.fork_indicators[].canonical` | string | Catalogued canonical module path the name collides with |
| `fork_heuristic.fork_indicators[].statement` | string | Caveated human-readable inference |

### `license`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / detector status (e.g. `Detected`, `Unclassified`) |
| `spdx` | string | Primary SPDX identifier; empty when `status` is `Unclassified` |
| `low_confidence_spdx` | string | A recognisable but sub-threshold licence fragment, set only when `spdx` is empty. Present when a root licence file was found and a known licence was partially matched but coverage fell below the substantive floor - e.g. a truncated AGPL-3.0 whose only matching span is the "how to apply" appendix |
| `low_confidence_coverage` | float | Coverage fraction (0.0-1.0) of the `low_confidence_spdx` match |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `error` | string | Set when `status` is `read_error` or extraction detail |

An `Unclassified` status means a licence file **was** found at the module root
but could not be confidently classified - it is never shown as a blank
`License:` line, which would read as "no licence found". When a fragment was
recognised, the summary surfaces it as a caveat rather than a verdict:

```
  License:         Unclassified - license file present; low-confidence AGPL-3.0-or-later match (~3% coverage)
```

This is a *caveated inference*, not a classification: the file is AGPL-shaped
but its licence text is incomplete, so kanonarion reports what it matched and
the coverage it saw, never a confident SPDX it cannot stand behind.

### `interface`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / extractor status |
| `packages` | array | Public packages (internal and `main` packages excluded) |
| `packages[].import_path` | string | Package import path |
| `packages[].types` | array | Exported type signatures (doc comment included only with `--full`) |
| `packages[].funcs` | array | Exported function signatures |
| `packages[].consts` | array | Exported constant names (with type if present) |
| `packages[].vars` | array | Exported variable names (with type if present) |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `error` | string | Set when `status` is `read_error` |

### `call_graph`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / extractor status |
| `algorithm` | string | Analysis algorithm used (e.g. `CHA`) |
| `node_count` | int | Total call graph nodes |
| `edge_count` | int | Total call graph edges |
| `entry_points_by_package` | object | Count of exported API entry points per package |
| `entry_points` | array | Flat list of entry point IDs (only with `--entry-points-full`) |
| `entry_point_count` | int | Total entry points (only with `--package` filter) |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `error` | string | Set when `status` is `read_error` |

### `examples`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / `Found` / `None` |
| `count` | int | Number of examples (after any `--package` filter) |
| `examples` | array | Example entries |
| `examples[].name` | string | Example function name |
| `examples[].symbol` | string | Associated symbol (if any) |
| `examples[].body` | string | Example body (truncated at 500 chars unless `--full`) |
| `examples[].output` | string | `// Output:` block contents |
| `examples[].doc` | string | Doc comment (omitted unless `--full`) |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `error` | string | Set when `status` is `read_error` |

### `vulnerabilities`

When `context` is invoked with `--walk-id`, or with `--gomod` on a project that
has a walk, every module's `vulnerabilities` section is answered in that build's
frame and read from that walk's runs. On a store holding scans of more than one
project this is what keeps a report about your build from carrying another
project's verdict for a shared dependency; `frame` on each section names the
frame the served record was measured in.

A bare `context <module>@<version>` names no build. It serves the best-founded
consumer-frame record the ledger holds for the coordinate, and then reads the
rest of the section — the walk status word, the coverage caveat, the
`[walk: affected via …]` annotation — from the walk that record was measured in.
That walk is stated: `walk_basis_id` and `walk_basis_frame` name it and the
frame it was rooted at, and the text output prints a `Walk basis:` line beneath
the verdict. `walk_basis_id` always equals the section's own `walk_id`, so every
field under one heading describes one build. The pair is set only on this
unanchored form; `--walk-id` and `--gomod` name their build themselves.

The run context — the walk status word, the coverage caveat, the affected-peer
annotation — is read from the **10 most recent walks**, a recency window that
keeps the report from reading every walk's runs on every invocation. The verdict
itself does not come from that window, so the window cannot make a module look
clean; what it can do is leave a verdict without its run context. When that is
why the context is missing, the section says so:

```
  Walk basis:      no run context: this record was measured in a walk outside the 10 most recent this report loaded runs for
```

JSON carries the same statement as `walk_window_note`. It is emitted only when
the window was smaller than the store: on a store holding 10 walks or fewer the
window covered everything and there is nothing to disclose.

`--gomod` names it on stderr, and says what the naming does not prove:

```
notice: vulnerability verdicts read in walk "01KZ3VA296P8KTP265M6CDBCHB" (frame linux/amd64); ./go.mod was not re-resolved for this read, so an edit made to it since that walk is not reflected — kanonarion walk --gomod ./go.mod records the current resolution
```

The walk is found by the module path the manifest declares, and a survey does
not pay a re-resolution to check that the walk still describes the manifest.
`vuln-scan --gomod` does pay it and re-walks on drift; run it (or `walk --gomod`)
when the tree has moved since the walk this notice names. The notice is on
stderr, so `--json` / `--stream` stdout is unaffected.

Read the annotation accordingly: `[walk: affected via …]` names affected peers in
the closure of the build that produced this verdict, not in the newest build that
happens to cover the module. Another walk may hold a different answer for the
same module; the answer moves only when better-founded evidence lands, not when a
neighbouring project walks a tree containing it. A walk older than the ten most
recent — the window whose runs are loaded — still serves its record and names
itself as the basis, but has no run context to report, so no walk status word or
peer annotation appears. To ask about a specific build, pass `--walk-id` or
`--gomod`.

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / scan status (`Clean`, `Affected`, `Withdrawn`, `Unscannable`, `ScanFailed`) |
| `findings` | array | CVE findings |
| `findings[].id` | string | Primary CVE / GHSA identifier |
| `findings[].aliases` | array | Alternative identifiers |
| `findings[].summary` | string | One-line description |
| `findings[].fixed_in` | string | Earliest version with a fix |
| `findings[].score` | float | CVSS score |
| `findings[].withdrawn_at` | string | Retraction timestamp, present **only** on an advisory retracted upstream. Absent means live — the retraction is a fact on the finding, never something to infer from the `WITHDRAWN: ` prefix upstream puts on the summary |
| `findings[].reachable` | bool | Reachability verdict (null if not analysed) |

A retracted advisory stays in `findings` as the historical fact, so a module whose
every advisory was withdrawn reports `status: Withdrawn` with its findings intact
rather than reading as never-affected. It does **not** appear in any peer's
`walk_affected`, which names only modules something must be done about. In text
output the tally beside the status counts the two apart — `Withdrawn (1 retracted)`,
or `Affected (2 finding(s), 1 retracted)` for a mixture.
| `walk_status` | string | The walk run's collapsed `overall_status` (`AllClean` / `Affected` / `Partial` / `ScanFailed`), carried as a compatibility summary. It collapses two independent axes into one word, so read `walk_coverage` for coverage rather than deriving it here |
| `walk_coverage` | string | The coverage axis of the walk run, set only when the run left modules unanalysed (`Partial` or `Failed`). Independent of findings: it surfaces alongside `walk_affected`, so an incomplete-coverage run that also carries an affected peer states both |
| `walk_affected` | array | Affected walk peers (`module@version`) that lie in **this module's own transitive dependency closure**, sorted; empty/omitted when no affected peer is reachable from this module |
| `walk_error` | string | Set when a walk-peer's verdict could not be read from the store while resolving `walk_affected`. The peer set may be incomplete; the fault is surfaced rather than fabricated into an affected verdict or misattributed to this module's own status |
| `walk_id` | string | Walk used for reachability analysis |
| `walk_basis_id` | string | The walk whose scan run answered, when the answer came from the walk window rather than a build named with `--walk-id` / `--gomod`. Omitted on those anchored forms |
| `walk_basis_frame` | string | The frame that walk was rooted at (e.g. `target-rooted:example.com/app@v1.0.0`). Omitted when the walk record is no longer in the store, which loses the frame but not the walk's identity |
| `walk_window_note` | string | Why this section carries no run context: the record's walk falls outside the 10-walk recency window the report loaded runs for. Omitted whenever the window covered every walk in the store |
| `snapshot_version` | string | Vulnerability database snapshot date |
| `extracted_at` | string | RFC3339 scan timestamp |
| `error` | string | Set when `status` is `read_error` |

The walk-level annotation carries two independent axes and prints each when it
says something this module's own line does not, together when both do:

- **Findings** are **filtered by the module's transitive dependency closure**. A
  clean module is only flagged when an affected peer is actually reachable from
  it through the stored walk graph - the annotation then names the specific
  coordinate(s) (`[walk: affected via x@v]`, or `+N more` when several). A module
  with no affected peer in its closure shows no findings annotation, rather than
  a generic walk-wide warning that implies a relationship which does not exist.
  This is driven by the run's findings axis, not its collapsed status, so a run
  left `Partial` by an unscannable module still names a reachable affected peer.
- **Coverage** surfaces `Partial` / `Failed` runs
  (`[walk coverage: Partial — other modules unscanned]`), warning that the
  broader scan could not confirm the peers.

The two answer different questions, so neither suppresses the other: a `Partial`
run that also carries an affected peer in this module's closure prints both. A
fully-clean, complete walk adds no annotation to a clean module.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | false | Emit context as JSON to stdout |
| `--compact` | true | Strip doc comments from signatures; truncate example bodies at 500 chars (the default) |
| `--full` | false | Include full doc comments and complete example bodies; overrides `--compact` |
| `--size-only` | false | Print estimated token count and byte size of the full JSON context, then exit. Multi-module forms (`--gomod`, `--walk-id`) print a total plus a per-module breakdown |
| `--entry-points-full` | false | Include flat `entry_points` list alongside `entry_points_by_package` |
| `--package <path>` | | Restrict `interface`, `call_graph`, and `examples` sections to a single import path |
| `--gomod <path>` | `./go.mod` when no module/`--walk-id` given | Emit context for every module in the `go.mod`'s code scope as NDJSON |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` tool directives' closure). Mutually exclusive with `--project`. `--gomod` only: refused by name on the coordinate, `--walk-id` and local-path forms |
| `--project` | false | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool`. `--gomod` only: refused by name on the coordinate, `--walk-id` and local-path forms |
| `--walk-id <id>` | | Emit context for every module in the walk as NDJSON |
| `--stream` | false | With `--walk-id` or `--gomod`: emit NDJSON (one document per module) without `--json`. Refused on the coordinate and local-path forms, which emit one document |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--log-level <level>` | `warn` | Log verbosity: `debug` \| `info` \| `warn` \| `error` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| non-zero | Store open error or invalid coordinate |

## Examples

```sh
# Compact one-liner summary per section (the default)
kanonarion context go.uber.org/goleak@v1.3.0

# Full context in human-readable form
kanonarion context go.uber.org/goleak@v1.3.0 --full

# Machine-readable JSON for an agent
kanonarion context go.uber.org/goleak@v1.3.0 --json

# Gauge token budget before sending to an LLM
kanonarion context go.uber.org/goleak@v1.3.0 --size-only

# Extract just the dependencies section
kanonarion context go.uber.org/goleak@v1.3.0 --json | jq '.dependencies'

# Extract all findings with a fix available
kanonarion context github.com/foo/bar@v1.0.0 --json \
  | jq '[.vulnerabilities.findings[] | select(.fixed_in != "")]'

# Restrict to a single package (reduces token count for large modules)
kanonarion context github.com/spf13/cobra@v1.8.1 --json \
  --package github.com/spf13/cobra

# Walk the transitive closure after inspecting direct deps
kanonarion context go.uber.org/goleak@v1.3.0 --json \
  | jq -r '.dependencies.walk_id' \
  | xargs kanonarion walk-show
```

## Relationship to other commands

- **Requires:** at minimum a fetched module (`kanonarion fetch`). Run
  `kanonarion extract` to populate interface, call graph, examples, and
  vulnerability sections.
- **`dependencies` section requires:** a stored walk where this module was the
  root target (`kanonarion walk <module>@<version>`).
- **Drill deeper:** use `walk_id` from the `dependencies` section with
  `kanonarion walk-show` (full transitive closure) or `kanonarion dependents`
  (reverse dependency query).
- **See also:** `kanonarion context --size-only` before sending output to an
  LLM to avoid exceeding context windows.

## Notes

- A flag that does not apply to the form in use — for example `--package` on a
  local path, or `--symbol` outside one — is refused with a message naming the
  form that honours it, rather than accepted and ignored.
- The `Context size` line under a text block reports the size of the module's
  full JSON document — the same figure `--size-only` prints — not the size of
  the text summary on screen.
- The `dependencies` section shows direct dependencies only - modules that
  appear as `require` directives in this module's `go.mod`. For the full
  transitive closure use `kanonarion walk-show <walk_id>`.
- Under a `+incompatible` coordinate the dependencies section carries a caveat:
  the go command ignores such a module's `go.mod`, so `(no direct dependencies)`
  is an absence of resolution rather than a measurement. Under `--json` it is the
  section's `pre_modules_caveat` object. See
  [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
- If multiple walks exist for the same module, the most recent one (by
  `started_at`) is used.
- All section timestamps are UTC RFC3339.
- Compact output is the default, designed for inline agent prompts where token
  budget is tight. For storage or detailed review, pass `--full` to restore full
  doc comments and complete example bodies.
