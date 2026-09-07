# `kanonarion usage` - What your code uses from one dependency

## Synopsis

```
kanonarion usage <module>@<version> [flags]
```

## Description

`usage` reports what one project's own code uses from one of its dependencies:
which symbols, at how many sites, in which files, and which of the module's
public API it never calls.

It answers from two stored call graphs - the project's and the module's - and
parses no source. Run [`local`](local.md) for the project and
[`callgraph`](callgraph.md) for the module first.

The project is named the way [`context`](context.md) names it: `--gomod` for a
manifest, `--walk-id` for a walk. With neither, `./go.mod` in the working
directory is used.

## Only a Direct edge is use

**This is the distinction the whole report rests on.** A `Direct` edge names a
unique concrete callee. An edge of any other confidence is a dispatch the
analysis could not resolve, and it names **every type-compatible function in the
module** rather than the one that runs - on one project, four call sites named
fourteen symbols each.

So over-approximated edges are a class of their own. They are never counted as
use, never merged into a usage total, and never dropped either: the project does
dispatch into the module, and a migration has to know that.

See [`callgraph`](callgraph.md) for the confidence vocabulary.

## Production and test are two counts

Every count is split and the two are never summed. A field carrying a merged
total does not exist, in text or in JSON: a migration scoped from one moves the
wrong amount of code. There is no flag to drop the test surface, because the
split is structural.

## What the report holds

| Section | What it is |
|---|---|
| **Used** | Symbols reached by a `Direct` edge, with each site's file and line, and whether the site is production or test |
| **Reached only through unresolved dispatch** | Symbols an over-approximated edge names. Not use; listed with the sites the edges leave from |
| **Linked but not called** | The project's packages that import the module. An edge into the module's own `init` says the package is linked and its initialiser ran - the same distinction [`capability`](capability.md) records as `linkage_only` |
| **Unreached** | Symbols in the module's public API with no `Direct` edge from the project. Drawn from the module's own call graph; a test declaration is not API |
| **Interfaces declared by the module** | Named, because satisfaction is what a text search cannot see. Whether the project's types satisfy one is **not measured** - see below |
| **Unmeasured** | Types, constants and variables have no call-graph node, so no use of one appears anywhere in the report |

A site is labelled `call` or `reference`. A reference is the function taken as a
value rather than invoked: use of the symbol, never an invocation.

## Interface satisfaction is not measured

The satisfaction relation is computed within a single module, on both sides, so
no stored record holds it across the project/dependency boundary. `implementers`
states the same limit and reports `cross_module_types_measured: false`.

The interfaces the module declares are therefore named rather than resolved. The
embedding case - a project type that satisfies a dependency's interface through
an embedded type, declaring no method itself - is the one this leaves for a
human, and it is also the one no text search finds.

## The answer

Every run ends on the same three-valued line the edge queries use:

| Answer | Meaning |
|---|---|
| `RESOLVED-PRESENT` | At least one `Direct` edge reaches the module |
| `RESOLVED-ABSENT` | No recorded call edge does, the module's public API **was** enumerated, and nothing about the project's analysis leaves room for a missing one. The line names the edge population it was measured over |
| `UNRESOLVED` | No `Direct` edge, and the absence is not proven. The line names what blocked it: an unresolved dispatch into the module, a package that did not typecheck, an axis the project's analysis never measured, or no stored call graph for the module at any version |

A site the graph could not resolve is always named, never dropped.

**`RESOLVED-ABSENT` requires that the module was enumerable.** With no stored
call graph for the path at any version, nothing about the module was measured -
its public API was never listed - so the answer is `UNRESOLVED` and the exit is
`1`. A misspelt module path lands here rather than passing as a clean zero:

```
$ kanonarion usage github.com/spf13/corba@v1.10.2 --gomod ./go.mod
answer: UNRESOLVED — … module-surface-unenumerated at github.com/spf13/corba
        (the store holds no call graph for any version of github.com/spf13/corba,
         so its public API was never enumerated and nothing about the module was
         measured; check the module path, then run: kanonarion callgraph …)
```

So a migration is finished when the module you migrated off is still enumerable
and reaches nothing:

```
kanonarion usage <module>@<version> --json | jq -e '.answer == "RESOLVED-ABSENT"'
```

That predicate now fails on a typo. It keeps working for the real case, because
a module you have stopped calling still has the stored call graph you analysed
it with.

## Which version was measured

The edge join is keyed on module paths, which carry no version; the public API
comes from a stored call graph, which exists only at the versions someone
analysed. One coordinate is resolved for both, and the report names it - in the
header, in the answer line, and in `version` in JSON.

When the version asked for has no stored call graph, the report measures another
version of the same path and says so on its own line and in the answer sentence:

| `version_basis` | Which version answered |
|---|---|
| `as_requested` | The version asked for; the store holds a call graph for it |
| `build_resolved` | The version the build resolves - also the version the project's own edges were recorded against |
| `highest_stored` | Neither of those has a stored graph; the newest version of the path the store holds |
| `none_stored` | No version has one, so nothing was measured and the answer is `UNRESOLVED` |

`requested_version` appears in JSON only when it differs from `version`. Reading
`version` alone always reads a version that was measured.

```
$ kanonarion usage github.com/spf13/cobra@v9.9.9 --gomod ./go.mod
usage of github.com/spf13/cobra@v1.4.0 by example.com/app@local
version: github.com/spf13/cobra@v9.9.9 has no stored call graph, so nothing below
  was measured against it. This report measures github.com/spf13/cobra@v1.4.0 — the
  version the build above resolves … To measure the version you asked for, run:
  kanonarion callgraph github.com/spf13/cobra@v9.9.9
…
answer: RESOLVED-PRESENT — … reaches 11 symbols of github.com/spf13/cobra@v1.4.0 at
  136 sites (136 production, 0 test); the version asked for, v9.9.9, has no stored
  call graph and was not measured
```

## Which build, which checkout

The walk names the build the answer is scoped to, and the answer states it.

A module the build does not contain at any version is still answered, and the
caveat says so: asking what your code already does with a module you have not
adopted is the migration question this command exists for. [`callers`](callgraph.md)
refuses that same coordinate, because it is a symbol query scoped to a walk, and
its refusal names `usage` as the command that answers across stored versions.
The policy difference is deliberate; both commands state it.

Where the build resolves the path at a version other than the one measured, the
caveat says that instead: the sites were recorded against one version of the
module and its public API enumerated from another.

`module_in_build` is whether the build resolves the measured coordinate;
`module_path_in_build` whether it contains the path at all.

Which modules own which symbols is resolved over the modules the build resolves,
the module paths the store has analysed at any version, and the foreign modules
the graph records having built. Nothing is inferred from a package path: a module
boundary is not readable off one, and `…/aws/signer/v4` is a package of
`aws-sdk-go-v2`, not a `v4` module. A nested module that is in neither the build
nor the store is therefore not distinguishable from its parent - analyse it, or
name it in the build, and it is.

Where the store holds more than one analysed working tree of the project, the
run states which one replied - the same disclosure `callers` and `implementers`
make. The `graph:` line names the record by content hash, node count and edge
count.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--gomod` | `./go.mod` | Restrict to the latest code-scope project walk for this manifest |
| `--walk-id` | _(none)_ | Restrict to the resolved version set of this walk |
| `--toolchain` | _(none)_ | Restrict to graphs built by one Go toolchain, in `go env GOVERSION` form |
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit the report as JSON |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

`--gomod` and `--walk-id` are mutually exclusive: both name a build.

## Report

```
$ kanonarion usage github.com/spf13/cast@v1.7.0 --gomod ./go.mod
usage of github.com/spf13/cast@v1.7.0 by example.com/app@local
notice: results restricted to the 128 module versions resolved by walk "01M0VG1267S1XDJGDFZTVRPM84" (code scope, frame linux/amd64)
graph: sha256:211ecd8…, Extracted, BUILT_WITH_BODIES, 25485 node(s), 235968 edge(s)

Used — reached by a Direct edge from example.com/app own code (23 symbols, 324 sites: 308 production, 16 test):
  established use is a Direct call edge: one that names a unique concrete callee. …
  github.com/spf13/cast.ToString — 41 sites (39 production, 2 test)
      production pkg/report/frame.go:118  [call]  example.com/app/pkg/report.(*frame).cell
      …

Reached only through unresolved dispatch — not established use (3 symbols, 17 edges from 17 sites: 8 production, 9 test):
  The project does dispatch into this module at these sites. Which of the symbols below each site reaches was not resolved, …
      production store/filter.go:515  [call]  example.com/app/store.generateSorting
      …
  github.com/spf13/cast.ToBool — 2 edges (2 production, 0 test)

Linked but not called (50 packages of this project import the module):
      example.com/app/auth
      …

Unreached — in the module's public API, with no Direct edge from this project (36 of 59):
      github.com/spf13/cast.ToBoolSlice
      …

answer: RESOLVED-PRESENT — example.com/app own code reaches 23 symbols of github.com/spf13/cast@v1.7.0 at 324 sites (308 production, 16 test)
```

## JSON

`--json` emits one document. Alongside the build fields (`walk_id`,
`walk_frame`, `walk_scope`, `walk_selection`, `scope_size`, `module_in_build`,
`module_path_in_build`, `version`, `requested_version`, `version_basis`,
`module_call_graph_found`)
and the project's graph (`call_graph_content_hash`, `call_graph_status`,
`call_graph_node_count`, `call_graph_edge_count`, `dropped_packages`):

```json
{
  "used": [
    {
      "node_id": "github.com/spf13/cast.ToString",
      "production_sites": 39,
      "test_sites": 2,
      "reference_sites": 0,
      "sites": [
        {"caller": "example.com/app/pkg/report.(*frame).cell", "file": "pkg/report/frame.go", "line": 118, "is_test": false, "kind": "call"}
      ]
    }
  ],
  "used_symbol_count": 23,
  "used_production_sites": 308,
  "used_test_sites": 16,
  "unresolved_dispatch": {
    "symbol_count": 3,
    "edge_count": 17,
    "site_count": 17,
    "production_edges": 8,
    "test_edges": 9,
    "establishes_use": false
  },
  "linked_not_called_package_count": 50,
  "unreached_public_api": ["github.com/spf13/cast.ToBoolSlice"],
  "public_api_count": 59,
  "declared_interfaces": ["github.com/spf13/cast.float64Provider"],
  "interface_satisfaction_measured": false,
  "unmeasured_kinds": ["type", "const", "var"],
  "answer": "RESOLVED-PRESENT"
}
```

`establishes_use` is `false` on every answer: it is the distinction a consumer
merging the two arrays would otherwise lose. Every scalar is present at its
zero, and every array is an array at every count - see
[conventions](conventions.md#measured-zeros-in-json).

## Exit codes

`0` for `RESOLVED-PRESENT` and for `RESOLVED-ABSENT`: both are completed
measurements, and the polarity is read off `answer`. `1` for `UNRESOLVED` - the
report is printed in full and is known-incomplete. `1` also for a module with no stored call
graph at any version, which is `UNRESOLVED`. `4` when the PROJECT has no stored
call graph; the message names `kanonarion local .`. See the
[exit-code table](conventions.md#exit-codes).

## Relation to other stages

- **Requires:** [`local`](local.md) for the project's call graph, and
  [`callgraph`](callgraph.md) for the module's.
- **See also:** [`interface-diff --used-by`](interface-diff.md) joins the same
  project graph against a version delta rather than a whole surface;
  [`callers`](callgraph.md) answers for one symbol;
  [`capability`](capability.md) reports what a module's own code can do.
