# `kanonarion context` - Module context for AI agents

## Synopsis

```
kanonarion context <module>@<version> [flags]
kanonarion context [--gomod <path>] [--tool | --project] [--exclude-tests] [flags]
kanonarion context --walk-id <id> [flags]
kanonarion context <dir> [--symbol] [--reachability] [--exclude-tests] [flags]
```

## Description

`context` aggregates every stored record for a module - verification,
provenance, direct dependencies, license, public interface, call graph,
examples, and vulnerabilities - into a single response. It is the primary entry point for
an agent that needs to understand a dependency before using or modifying it.

With no positional module and no `--walk-id`, `context` defaults to
`--gomod ./go.mod` and emits one context entry per module in the project's
dependency **scope** - one JSON object with the documents in `modules` under
`--json`, text blocks otherwise. The scope is
consistent with every other go.mod command: the default is the project's own
**code** dependencies (`go list -deps -test ./...`); `--tool` selects the
tooling supply chain; `--project` the complete set (code + tooling). `--tool`
and `--project` are mutually exclusive. `--exclude-tests` narrows the `code`
scope to production packages; the answer states which axis it used on stderr and
in a `dependency_scope` field on every document, whichever scope was asked for.
See
[`walk` Scopes](walk.md#scopes-code-tool-complete) and
[Test scope](walk.md#test-scope---exclude-tests). This is the same module set
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

The `dependencies` section is drawn from the walk the rest of the document is
based on - the walk the vulnerability section names as its `walk basis`, the
walk `--walk-id` names, or the project walk `--gomod` anchors to - wherever that
walk holds the module. One document therefore reports one build. Where the
document names no walk at all, the section falls back to the walks rooted at the
module itself and picks the one the shared default rule picks. It reports
`not_run` only when no walk in either route holds the module, and
`not_in_basis_walk` when the document's build did not contain it.
Other sections (license, interface, call graph, examples, vulnerabilities)
are drawn from the extraction pipeline and are independent of walk records.

## Working-tree form (`<dir>`)

A positional argument that looks like a path - `.`, `..`, `./x` or an absolute
path - analyses that working tree instead of reading stored records. It answers
which dependency modules the tree's own code uses, and carries none of the
stored-record sections, so the flags that shape those sections are refused here
by name.

Two analysis levels:

| Level | How | Reports |
|---|---|---|
| `import` (default) | `go list` | Modules the tree's files import |
| `symbol` (`--symbol`) | go/packages type-check, ~2-5s | Modules whose exported symbols the tree references, plus the symbol list |

The two answer different questions and the count line names which: `module(s)
imported` at import level, `module(s) referenced` at symbol level. A blank
import (`_ "modernc.org/sqlite"`) is imported while referencing no symbol, so
its module appears at import level and not at symbol level. Neither is a subset
of the other - a module reached only through a dependency's exported types (for
example `spf13/pflag` through `cobra`) is referenced without being imported.

Both levels include dependency users declared in `_test.go` files and external
test packages, and tag a module only test code reaches with `[test]`. The
`Test scope` line states this on every answer, narrowed or not.

```
$ kanonarion context . --symbol
github.com/eitanity/kanonarion
  Root:            /home/mb/dev/kanonarion
  Version:         local-7c28ebbc23b3709a...
  Analysis level:  symbol
  Test scope:      included — users declared only in test files are tagged [test]
  Dependencies:    12 module(s) referenced
    github.com/rogpeppe/go-internal@v1.15.0  (1 package(s), 8 symbol(s))  [test]
    github.com/spf13/cobra@v1.10.2  (1 package(s), 37 symbol(s))
    ...
```

`--exclude-tests` narrows the answer to what production files reach: packages
and symbols only test code references are removed, and a module left with
nothing is dropped. The result is always a subset of the default answer - the
analysis itself is unchanged, so a symbol count can only fall.

```
$ kanonarion context . --symbol --exclude-tests
  Test scope:      excluded — production code only (--exclude-tests was given)
  Dependencies:    10 module(s) referenced
```

`--exclude-tests` acts on the reported dependency list only. The
`--reachability` probe is scoped to the modules the build links into the
artefact, which never included test-only dependencies, so its module count does
not move with the flag.

Under `--json` the working-tree document carries `workspace.tests_excluded` and
a per-dependency `test_only`, both emitted always, `false` included:

```json
{
  "workspace": {
    "root": "/home/mb/dev/kanonarion",
    "module": "github.com/eitanity/kanonarion",
    "version_id": "local-7c28ebbc23b3709a...",
    "analysis_level": "symbol",
    "tests_excluded": false
  },
  "dependencies": [
    {
      "path": "go.uber.org/goleak",
      "version": "v1.3.0",
      "imported_packages": ["go.uber.org/goleak"],
      "used_symbols": ["go.uber.org/goleak.VerifyTestMain"],
      "test_only": true
    }
  ]
}
```

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
  Dependencies:    6 direct (succeeded) [walk 01M0VG1267S1XDJGDFZTVRPM84, frame target-rooted:github.com/cortezaproject/corteza/server@local]
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

#### Top-level shape

The top-level JSON type is **one object**, decided by the command - never by the
form invoked and never by the number of modules the answer holds. The per-module
documents are its `modules` member:

| Form | Top-level type |
|---|---|
| `context <module>@<version> --json` | one object; `modules` holds the one document |
| `context --gomod <path> --json` | one object; `modules` is `[]` when the scope is empty |
| `context --walk-id <id> --json` | one object; `modules` is `[]` when every module is filtered out |
| `context --size-only --json` | one object: the size report |
| `context <dir> --json` | one object: the **working-tree** document, which reports a tree rather than a set of modules and has its own shape (see [Working-tree form](#working-tree-form-dir)) |

Beside `modules`, the object states the facts about the run - which a bare array
had nowhere to put:

| Key | Meaning |
| --- | --- |
| `dependency_scope` | The go.mod dependency scope that selected the documents (`code`, `tool` or `complete`) and the test axis it applied (`included`, `excluded` or `unavailable`). **`null`** on the coordinate and `--walk-id` forms, which project no go.mod scope. |
| `module_count` | How many modules the answer is over. On `--gomod` it is the count the `notice:` line on stderr states; a module that failed to render is missing from `modules`, named on stderr, and the run exits non-zero. |
| `narrow_with` | The flag that narrows this scope, as data: `"--exclude-tests"`. Absent where nothing narrows the answer. |
| `rooting` | The build the vulnerability answers were read in, and **how that build was arrived at** - see [Rooting](#rooting). `null` on the forms that anchor nothing for the run. |
| `modules` | The per-module documents, unchanged. |

`--stream` selects a different framing for the `--gomod` and `--walk-id` forms:
the per-module documents newline-delimited, one compact object per line (NDJSON),
and zero bytes when there is nothing to emit. There is no envelope on the stream
- a stream is not one document - so the run-level facts stay on stderr there. Use
it to read modules as they arrive instead of waiting for the whole answer.

> **Breaking change:** the `--gomod` and `--walk-id` forms used to print NDJSON
> under `--json`, then a bare array; the coordinate form printed the per-module
> document itself. All of them now print the envelope. The per-module documents
> are unchanged - only the framing moved. A consumer that read
> `context --gomod --json | jq '.[]'` must read `jq '.modules[]'`; one that read
> `context <module>@<version> --json | jq '.dependencies'` must read
> `jq '.modules[0].dependencies'`; and one that split the old NDJSON on newlines
> can pass `--stream` to keep that framing.

#### Rooting

A vulnerability answer is a property of one build. When you name a walk with
`--walk-id`, that is the build. When you do not, kanonarion picks one out of
however many the store holds - and `rooting` says so, in fields, so an agent
reading these answers can tell a build it asked for from one that was chosen for it.
The walk id alone cannot: it looks the same either way.

| Key | Meaning |
| --- | --- |
| `basis` | `"named"` when the caller pinned the build with `--walk-id`, `"chosen"` when kanonarion picked one, `"none"` when nothing anchored the answers (`reason` says why). |
| `walk_id`, `walk_scope`, `walk_frame` | The build itself: the walk, the dependency scope it covered, the platform it resolved for. |
| `toolchain` | The Go toolchain that walk was resolved by - the standard library the answers are about. `"unrecorded"` when the walk records none. |
| `gomod` | The manifest that named the build. Absent on a pinned read, where no manifest was consulted. |
| `manifest_reresolved` | Always `false`: this read compares the manifest's `require` directives against the walk's recorded resolution, it does not put the manifest back through the toolchain. A walk taken before the last `go.mod` edit can answer here. |
| `pin_with` | `"--walk-id"` - the flag that takes the choice back. |
| `walk_selection` | The selector's own account: `rule` (`pinned`, `sole`, `manifest-match`, `recency-no-match`, `recency-unchecked`), `candidates` (how many walks it chose from; `null` for a pinned read, where nothing was enumerated), `candidate_set`, `manifest_path`, `disagreements`, `toolchain_divergence`. |

```json
{
  "basis": "chosen",
  "walk_id": "01K4ZQ0J6H8T2W3X4Y5Z6A7B8C",
  "walk_scope": "code scope",
  "walk_frame": "linux/amd64",
  "toolchain": "go1.26.6",
  "gomod": "/src/myproject/go.mod",
  "manifest_reresolved": false,
  "pin_with": "--walk-id",
  "walk_selection": {
    "rule": "manifest-match",
    "candidates": 3,
    "candidate_set": "in the code scope on linux/amd64 under go1.26.6",
    "manifest_path": "/src/myproject/go.mod"
  }
}
```

Each element of `modules`, and the whole document the coordinate form used to
print, has this shape:

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
    "rooting": "target-rooted:example.com/app@local",
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

## Replaced modules (`--gomod`)

A `go.mod` `replace` directive routes the build to a different module. Every
section of the document — verification, licence, dependencies, call graph,
vulnerabilities — is a fact about the module that **compiles**, so that is the
module the document is headed by, and the require entry the directive acted on
is stated beside it:

```
==> github.com/cortezaproject/gval@v1.2.4
github.com/cortezaproject/gval@v1.2.4
  Replace:         replaces github.com/PaesslerAG/gval@v1.2.1 under a go.mod replace directive
  Verification:    Verified (git: https://github.com/cortezaproject/gval)
  License:         BSD-3-Clause
```

In JSON it is `module.replace`:

```json
"module": {
  "path": "github.com/cortezaproject/gval",
  "version": "v1.2.4",
  "replace": {
    "require_module": "github.com/PaesslerAG/gval",
    "require_version": "v1.2.1"
  }
}
```

The key is **absent** where no directive applies, and on the coordinate and
`--walk-id` forms, which read no manifest.

Headed by the require entry instead — which is what the scope resolution used to
report — every section of the document answered about a coordinate the store
holds nothing under: `not_fetched`, `license: not_run`, and `the walk does not
hold github.com/PaesslerAG/gval@v1.2.1`, for a module that build had fetched,
licensed and scanned under its replacement.

A `replace` to a **local path** has no replacement coordinate at all: the module
is named by its require entry, and `replace.local_path` names the directory the
build compiles instead.

## Section field reference

### `dependencies`

Direct dependencies drawn from the walk this document is based on. Versions are
the MVS-selected versions recorded in that walk, not the `require` versions from
`go.mod` (which may differ after minimum version selection). The list is sorted
lexicographically by module path.

The set is frame-dependent, and the difference is not cosmetic: a library walked
on its own resolves its test-only dependencies and its own declared versions,
while a build that consumes it resolves neither - measured, 15 dependencies for
one module in its own walk against 10 in a project that uses it, with one shared
dependency at `v1.7.0` in the first and `v1.10.0` in the second. `walk_id` and
`rooting` name the build the count is for.

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `not_in_basis_walk` / `read_error` / walk status (`succeeded`, `partial`, `failed`, `cancelled`) |
| `walk_id` | string | ID of the walk record this was drawn from |
| `frame` | string | `GOOS/GOARCH` that walk resolved for, or `not-platform-scoped` for a module-rooted walk |
| `frame_basis` | string | `platform`, `not_platform_scoped` or `unrecorded` |
| `rooting` | string | The answering walk's root, in the same words `vulnerabilities.walk_basis_frame` uses, so the two sections can be compared without recognising a walk id |
| `count` | int | Number of direct dependencies. Always present; `0` is the measurement that the module has none |
| `partial` | bool | True when the walk graph was partial - some transitive deps could not be resolved, so the direct dep list may be incomplete. Always present; `false` is the measurement that the graph resolved completely |
| `dependencies` | array | Direct dependencies sorted by path |
| `dependencies[].path` | string | Module import path |
| `dependencies[].version` | string | MVS-selected version |
| `error` | string | Set when `status` is `read_error` |

The dependency list is the list for one platform: `GOOS` gates which files
build, so `frame` says which platform answered.

`not_run` means no walk in the store holds the module, and its remedy is to walk
it. `not_in_basis_walk` means the build this document reports on did not contain
the module - a walk was measured and this module was not in it, which is a
different fact and a different remedy.

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
| `retracted` | bool | True when the version is retracted. Always present; `false` is the measurement that the author has not withdrawn it |
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
| `low_confidence_coverage` | float\|null | Coverage fraction (0.0-1.0) of the `low_confidence_spdx` match. Always present; `null` when no sub-threshold fragment was matched, which is every confidently classified module |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `custody` | object | Standard library only - the chain of custody its licence identity comes from (see below) |
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

#### Standard library

The `stdlib` node holds no licence record - it ships with the toolchain rather
than through the module proxy, so nothing fetches or extracts it. Its section is
answered from the chain of custody the walk stage records, and is never
`not_run`: that value means nothing looked, and here something did.

```
  License:         BSD-3-Clause
    basis:         extracted from the acquired source tree's LICENSE file (VerifiedGoDevChecksum)
```

`status` is `Detected` when the identifier was extracted from the acquired
source, `Known` when it is the `BSD-3-Clause` the Go project publishes and no
measurement carried one - the same two words `audit` prints for the same node.

| `custody` field | Type | Description |
|---|---|---|
| `basis` | string | `stdlib-tarball` (extracted evidence) or `stdlib-known` (published knowledge) |
| `verification` | string | The recorded stdlib verification status - `VerifiedGoDevChecksum`, `VerifiedLocalToolchain`, `GoDevChecksumMismatch`, `UnverifiedGoDevUnavailable`. **Absent when nothing has been acquired for this toolchain**, which is a different statement from `stdlib-known` |
| `detail` | string | The verification summary: checksum source and, when resolved, the googlesource commit |
| `route` | string | `godev` (published tarball) or `local-toolchain` (`$GOROOT`) |
| `source_url`, `vcs_url`, `vcs_ref`, `vcs_commit`, `sha256` | string | The acquired artefact and its VCS anchor |
| `acquired_at` | string | RFC3339 acquisition timestamp |
| `statement` | string | What the answer rests on, in one clause; on an unestablished chain it names the command that would establish one |

### `interface`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `superseded` / `read_error` / extractor status |
| | | `superseded`: every stored generation predates this build's extraction logic, so none is served. `error` carries the statement and the re-extraction to run. |
| `packages` | array | Public packages (internal, `main` and out-of-frame excluded) |
| `packages[].import_path` | string | Import path |
| `packages[].types` | array | Exported type signatures (doc only with `--full`) |
| `packages[].methods` | array | Methods on those types (doc only with `--full`) |
| `packages[].funcs` | array | Exported function signatures |
| `packages[].consts` | array | Exported constant names, with type if present |
| `packages[].vars` | array | Exported variable names, with type if present |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `build_frame` | string | The build the API was measured in, or `unrecorded` |
| `error` | string | Set when `status` is `read_error` |

### `call_graph`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / extractor status |
| `algorithm` | string | Analysis algorithm used (e.g. `CHA`) |
| `node_count` | int | Total call graph nodes. Always present; `0` is a real extraction result — a module analysed at a fidelity that records no nodes |
| `edge_count` | int | Total call graph edges. Always present at `0` for the same reason as `node_count` |
| `entry_points_by_package` | object | Count of exported API entry points per package |
| `entry_points` | array | Flat list of entry point IDs (only with `--entry-points-full`) |
| `entry_point_count` | int\|null | Entry points in the package `--package` named. Always present; `null` without that flag, where no single-package count is derived and `entry_points_by_package` carries the breakdown |
| `extracted_at` | string | RFC3339 extraction timestamp |
| `error` | string | Set when `status` is `read_error` |

### `examples`

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `read_error` / `Found` / `None` |
| `count` | int | Number of examples (after any `--package` filter). Always present; `0` is the measurement that the module has none |
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
project's status for a shared dependency; `frame` on each section names the
frame the served record was measured in.

A bare `context <module>@<version>` names no build. It serves the best-founded
consumer-frame record the ledger holds for the coordinate, and then reads the
rest of the section — the walk status word, the coverage caveat, the
`[walk: affected via …]` annotation — from the walk that record was measured in.
That walk is stated: `walk_basis_id` and `walk_basis_frame` name it and the
frame it was rooted at, and the text output prints a `Walk basis:` line beneath
the status. `walk_basis_id` always equals the section's own `walk_id`, so every
field under one heading describes one build. The pair is set only on this
unanchored form; `--walk-id` and `--gomod` name their build themselves.

The run context — the walk status word, the coverage caveat, the affected-peer
annotation — is read from the **10 most recent walks**, a recency window that
keeps the report from reading every walk's runs on every invocation. The status
itself does not come from that window, so the window cannot make a module look
clean; what it can do is leave a status without its run context. When that is
why the context is missing, the section says so:

```
  Walk basis:      no run context: this record was measured in a walk outside the 10 most recent this report loaded runs for
```

JSON carries the same statement as `walk_window_note`. It is emitted only when
the window was smaller than the store: on a store holding 10 walks or fewer the
window covered everything and there is nothing to disclose.

`--gomod` names it on stderr, and says what the naming does not prove:

```
notice: vulnerability verdicts read in walk "01KZ3VA296P8KTP265M6CDBCHB" (code scope, frame linux/amd64); ./go.mod was not re-resolved for this read, so an edit made to it since that walk is not reflected — kanonarion walk --gomod ./go.mod records the current resolution
```

The anchoring walk is the one of the **scope this invocation asked for** —
`--tool` and `--project` select it, as they already select the module set printed
below — resolved for this platform. Anchoring `--tool` answers to a code walk
that happened to be walked more recently reports one build's dependencies against
another build's scan, so the notice names the scope it anchored in.

A survey is not refused for want of a walk of that scope: it prints its sections
unanchored and says which walk it could not find, so the reader can take it.

```
notice: no walk anchors these vulnerability verdicts: no succeeded tool project walk for example.com/myapp on linux/amd64, though the store holds 1 succeeded walk(s) of it (code on linux/amd64); a walk of another scope or platform is a different build, so it does not answer here — run: kanonarion walk --gomod ./go.mod --tool
```

The walk is found by the module path the manifest declares, and a survey does
not pay a re-resolution to check that the walk still describes the manifest.
`vuln-scan --gomod` does pay it and re-walks on drift; run it (or `walk --gomod`)
when the tree has moved since the walk this notice names. The notice is on
stderr, so `--json` / `--stream` stdout is unaffected.

Read the annotation accordingly: `[walk: affected via …]` names affected peers in
the closure of the build that produced this answer, not in the newest build that
happens to cover the module. Another walk may hold a different answer for the
same module; the answer moves only when better-founded evidence lands, not when a
neighbouring project walks a tree containing it. A walk older than the ten most
recent — the window whose runs are loaded — still serves its record and names
itself as the basis, but has no run context to report, so no walk status word or
peer annotation appears. To ask about a specific build, pass `--walk-id` or
`--gomod`.

| Field | Type | Description |
|---|---|---|
| `status` | string | `not_run` / `superseded` / `read_error` / scan status (`Clean`, `Affected`, `Withdrawn`, `Unscannable`, `ScanFailed`) |
| | | `superseded`: the store holds records for this module only at pipeline versions this build no longer serves. `error` carries the statement, the generations held, and the re-scan to run. It is not `not_run`: the scan ran. |
| `findings` | array | CVE findings |
| `findings[].id` | string | Primary CVE / GHSA identifier |
| `findings[].aliases` | array | Alternative identifiers |
| `findings[].summary` | string | One-line description |
| `findings[].fixed_in` | string | Earliest version with a fix |
| `findings[].score` | float\|null | CVSS base score. Always present; `null` when the advisory publishes no severity, which is different from a published `0.0` |
| `findings[].withdrawn_at` | string | Retraction timestamp, present **only** on an advisory retracted upstream. Absent means live — the retraction is a fact on the finding, never something to infer from the `WITHDRAWN: ` prefix upstream puts on the summary |
| `findings[].reachability_state` | string | The reachability answer as one word: `reachable`, `not_reachable`, `package_level_only`, `withdrawn`, `not_determined`, `not_computed` or `not_analysed`. **Always present**, whatever the value. Derived at read time, so it is on records scanned long before the field existed. It is the field to read: `reachable` below is the stored bit, which has two positions for a question with more answers than two — a finding whose advisory names no symbol for this module path is `package_level_only`, and the bit reads `true` for some of them |
| `findings[].reachable` | bool\|null | reachability answer. Always present; `null` when no reachability analysis answered for this finding — `soundness` cannot stand in for it, since it reads `not stated` for a positive answer too |
| `findings[].soundness` | string | How thorough the search behind a **negative** was: `confirmed`, `inferred`, `unconfirmed`, `unsearchable`, `disputed`, or `not stated` where there is no absence to qualify. Always present. Derived at read time, so it is on records scanned long before the field existed. See [reachability](reachability.md#a-negative-states-how-sound-the-search-behind-it-was) |
| `findings[].soundness_reason` | string | The basis for that rung in the producing analyser's own terms. Absent where no rung is stated |

A retracted advisory stays in `findings` as the historical fact, so a module whose
every advisory was withdrawn reports `status: Withdrawn` with its findings intact
rather than reading as never-affected. It does **not** appear in any peer's
`walk_affected`, which names only modules something must be done about. In text
output the tally beside the status counts the two apart — `Withdrawn (1 retracted)`,
or `Affected (2 finding(s), 1 retracted)` for a mixture.
| `walk_status` | string | The walk run's collapsed `overall_status` (`AllClean` / `Affected` / `Partial` / `ScanFailed`), carried as a compatibility summary. It collapses two independent axes into one word, so read `walk_coverage` for coverage rather than deriving it here |
| `walk_coverage` | string | The coverage axis of the walk run, set only when the run left modules unanalysed (`Partial` or `Failed`). Independent of findings: it surfaces alongside `walk_affected`, so an incomplete-coverage run that also carries an affected peer states both |
| `walk_affected` | array | Affected walk peers (`module@version`) that lie in **this module's own transitive dependency closure**, sorted; empty/omitted when no affected peer is reachable from this module |
| `walk_error` | string | Set when a walk-peer's status could not be read from the store while resolving `walk_affected`. The peer set may be incomplete; the fault is surfaced rather than fabricated into an affected status or misattributed to this module's own status |
| `walk_id` | string | Walk used for reachability analysis |
| `walk_basis_id` | string | The walk whose scan run answered, when the answer came from the walk window rather than a build named with `--walk-id` / `--gomod`. Omitted on those anchored forms |
| `walk_basis_frame` | string | The frame that walk was rooted at (e.g. `target-rooted:example.com/app@v1.0.0`). Omitted when the walk record is no longer in the store, which loses the frame but not the walk's identity |
| `walk_window_note` | string | Why this section carries no run context: the record's walk falls outside the 10-walk recency window the report loaded runs for. Omitted whenever the window covered every walk in the store |
| `snapshot_version` | string | Vulnerability database snapshot date |
| `snapshot_retrieved_at` | string | When that snapshot was fetched. Absent when the record's snapshot carries no retrieval time |
| `snapshot_age_days` | int\|null | How old the snapshot was when the answer was validated. Always present; `0` is the freshest answer the field has — validated against a snapshot pulled the same day — and `null` means the snapshot carries no retrieval time to measure from |
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
| `--json` | false | Emit context as JSON to stdout. Always one object, with the per-module documents in `modules`. See [Top-level shape](#top-level-shape) |
| `--compact` | true | Strip doc comments from signatures; truncate example bodies at 500 chars (the default) |
| `--full` | false | Include full doc comments and complete example bodies; overrides `--compact` |
| `--size-only` | false | Print estimated token count and byte size of the full JSON context, then exit. Multi-module forms (`--gomod`, `--walk-id`) print a total plus a per-module breakdown |
| `--entry-points-full` | false | Include flat `entry_points` list alongside `entry_points_by_package` |
| `--package <path>` | | Restrict `interface`, `call_graph`, and `examples` sections to a single import path |
| `--gomod <path>` | `./go.mod` when no module/`--walk-id` given | Emit context for every module in the `go.mod`'s code scope; under `--json` that is one object with the documents in `modules` |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` tool directives' closure). Mutually exclusive with `--project`. `--gomod` only: refused by name on the coordinate, `--walk-id` and local-path forms |
| `--project` | false | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool`. `--gomod` only: refused by name on the coordinate, `--walk-id` and local-path forms |
| `--walk-id <id>` | | Emit context for every module in the walk; under `--json` that is one object with the documents in `modules` |
| `--direct-only` | false | With `--walk-id`: emit context only for direct dependencies of the walk root |
| `--affected-only` | false | With `--walk-id`: emit context only for modules the walk's most recent scan run found affected. See [Narrowing a walk](#narrowing-a-walk) |
| `--modules <path>` | | With `--walk-id`: emit context only for the `module@version` coordinates listed in this file, one per line. See [Narrowing a walk](#narrowing-a-walk) |
| `--stream` | false | With `--walk-id` or `--gomod`: emit NDJSON (one compact per-module document per line) instead of the `--json` envelope, and without needing `--json`. Refused on the coordinate and local-path forms, which emit one document |
| `--symbol` | false | With a local path: type-check the tree and report referenced symbols instead of imports. Local path only: refused by name on the other three forms |
| `--reachability` | false | With a local path: build the tree's binaries and probe their symbol tables for CVE-affected symbols (~30s). Local path only: refused by name on the other three forms |
| `--exclude-tests` | false | Narrow to production code. With `--gomod`: resolve the `code` scope without test imports, and say so; on `--tool` it is accepted and changes nothing, because the scope already excludes them, and the answer says so. With a local path: omit dependency users declared in `_test.go` files and external test packages. Refused by name on the coordinate and `--walk-id` forms, which name a module set fixed elsewhere, and against `--project`, whose build list carries no test partition. See [Working-tree form](#working-tree-form-dir) and [Test scope](walk.md#test-scope---exclude-tests) |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--log-level <level>` | `warn` | Log verbosity: `debug` \| `info` \| `warn` \| `error` |

### Narrowing a walk

`--walk-id` emits one document per module in the walk, which for a full project
closure is more context than a question usually needs. Three filters cut it
down, and they compose - a module must pass every filter that is set:

| Filter | Keeps |
|---|---|
| `--direct-only` | Modules that are direct dependencies of the walk root |
| `--affected-only` | Modules the walk's most recent scan run found affected |
| `--modules <file>` | Modules whose `module@version` coordinate is listed in the file, one per line; blank lines are ignored |

All three act **only** on the `--walk-id` form. Passed on a coordinate, a
`--gomod` scope or a local path they are refused by name rather than silently
ignored, and the message says which form does read them.

`--affected-only` is read from the findings axis of the walk's latest scan run,
in that walk's own frame: a module matched by an advisory is kept whether or not
its source could be analysed, and another project's scan of a shared dependency
does not decide it. A walk with no scan run yet yields nothing rather than
everything - an empty result means "no affected module recorded for this walk",
so run `vuln-scan` on the walk first.

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
kanonarion context go.uber.org/goleak@v1.3.0 --json | jq '.modules[0].dependencies'

# Extract all findings with a fix available
kanonarion context github.com/foo/bar@v1.0.0 --json \
  | jq '[.modules[0].vulnerabilities.findings[] | select(.fixed_in != "")]'

# Restrict to a single package (reduces token count for large modules)
kanonarion context github.com/spf13/cobra@v1.8.1 --json \
  --package github.com/spf13/cobra

# Walk the transitive closure after inspecting direct deps
kanonarion context go.uber.org/goleak@v1.3.0 --json \
  | jq -r '.modules[0].dependencies.walk_id' \
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
