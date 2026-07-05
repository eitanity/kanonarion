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
| `count` | int | Number of direct dependencies |
| `partial` | bool | True when the walk graph was partial - some transitive deps could not be resolved, so the direct dep list may be incomplete |
| `dependencies` | array | Direct dependencies sorted by path |
| `dependencies[].path` | string | Module import path |
| `dependencies[].version` | string | MVS-selected version |
| `error` | string | Set when `status` is `read_error` |

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

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / scan status (e.g. `Clean`, `Vulnerable`) |
| `findings` | array | CVE findings |
| `findings[].id` | string | Primary CVE / GHSA identifier |
| `findings[].aliases` | array | Alternative identifiers |
| `findings[].summary` | string | One-line description |
| `findings[].fixed_in` | string | Earliest version with a fix |
| `findings[].score` | float | CVSS score |
| `findings[].reachable` | bool | Reachability verdict (null if not analysed) |
| `walk_status` | string | Walk-wide scan status, set only when it adds information this module's own `status` does not (e.g. `Partial` when the walk scan was incomplete) |
| `walk_affected` | array | Affected walk peers (`module@version`) that lie in **this module's own transitive dependency closure**, sorted; empty/omitted when no affected peer is reachable from this module |
| `walk_id` | string | Walk used for reachability analysis |
| `snapshot_version` | string | Vulnerability database snapshot date |
| `extracted_at` | string | RFC3339 scan timestamp |
| `error` | string | Set when `status` is `read_error` |

The walk-level annotation is **filtered by the module's transitive dependency
closure**. A clean module is only flagged when an affected peer is actually
reachable from it through the stored walk graph - the annotation then names the
specific coordinate(s) (`[walk: affected via x@v]`, or `+N more` when several).
A module with no affected peer in its closure shows no walk annotation at all,
rather than a generic walk-wide warning that implies a relationship which does
not exist. A fully-clean walk likewise adds no annotation to a clean module;
only incompleteness statuses (`Partial`, `ScanFailed`) still surface, since
they warn that the broader scan could not confirm the peers.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | false | Emit context as JSON to stdout |
| `--compact` | true | Strip doc comments from signatures; truncate example bodies at 500 chars (the default) |
| `--full` | false | Include full doc comments and complete example bodies; overrides `--compact` |
| `--size-only` | false | Print estimated token count and byte size, then exit |
| `--entry-points-full` | false | Include flat `entry_points` list alongside `entry_points_by_package` |
| `--package <path>` | | Restrict `interface`, `call_graph`, and `examples` sections to a single import path |
| `--gomod <path>` | `./go.mod` when no module/`--walk-id` given | Emit context for every module in the `go.mod`'s code scope as NDJSON |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` tool directives' closure). Mutually exclusive with `--project` |
| `--project` | false | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--walk-id <id>` | | Emit context for every module in the walk as NDJSON |
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

- The `dependencies` section shows direct dependencies only - modules that
  appear as `require` directives in this module's `go.mod`. For the full
  transitive closure use `kanonarion walk-show <walk_id>`.
- If multiple walks exist for the same module, the most recent one (by
  `started_at`) is used.
- All section timestamps are UTC RFC3339.
- Compact output is the default, designed for inline agent prompts where token
  budget is tight. For storage or detailed review, pass `--full` to restore full
  doc comments and complete example bodies.
