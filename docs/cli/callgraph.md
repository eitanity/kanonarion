# `kanonarion callgraph` — Call graph extraction and query

## Synopsis

```
kanonarion callgraph <module>@<version> [flags]
kanonarion callgraph-show <module>@<version> [flags]
kanonarion callgraph-list [<module>] [flags]
kanonarion callers <symbol-id> [flags]
kanonarion callees <symbol-id> [flags]
kanonarion implementers <interface-id> [flags]
```

## Description

The `callgraph` family extracts and queries the static call graph of Go
modules. For each module it produces a `CallGraphRecord` holding every call node
(function or method), every call edge (caller → callee), and the interface types
the module declares together with the concrete types that satisfy them.

Extraction runs `golang.org/x/tools/go/callgraph/cha` over an SSA program built
from `go/packages`. The module's source is type-checked; no code from it is
executed.

To analyse a published module, fetch it first (`kanonarion fetch`). To analyse a
working tree — including this repository — use [`kanonarion local`](local.md),
which indexes the directory in place.

### What the answers claim

Every query in this family reports a **three-valued verdict**, because an empty
answer has two very different causes and conflating them is the failure mode the
whole design exists to prevent:

| Verdict | Meaning |
|---|---|
| `RESOLVED-PRESENT` | Edges (or implementers) were found. |
| `RESOLVED-ABSENT` | A measurement: nothing was found across a fully-built path, with no soundness sink in the way. |
| `UNRESOLVED` | The graph could not decide. The absence is not proven — an edge may simply be missing. |

`RESOLVED-ABSENT` is a real answer. `UNRESOLVED` is not; it names the sinks that
forced the downgrade, so a reader can act on them:

```
verdict: UNRESOLVED — callers of pkg.(*T).Do cannot be confirmed absent:
  test-scope-unmeasured at pkg.(*T).Do (_test.go declarations were not analysed for this module)
```

## Test scope

`_test.go` declarations are part of the graph. A module's fakes and
table-driven callers are a large, systematic share of what a signature change
has to touch, so omitting them made "no callers" a confident false negative for
every test-only consumer.

- Test-declared nodes carry `is_test`, and are shown with a `[test]` tag.
- `--exclude-tests` narrows a query to production code. It is **opt-in**: the
  default answer covers the whole graph, because a hidden test caller is a false
  negative dressed as a measurement, while an unwanted one is visible and easy
  to discount.
- Every record states whether the axis was measured at all. Where analysing test
  files was not viable for a module, an empty answer is downgraded to
  `UNRESOLVED` naming `test-scope-unmeasured`, rather than reported as an
  absence it cannot substantiate.

When you pass `--exclude-tests`, the verdict line says so, so a narrowed answer
is never read as a wider one:

```
verdict: RESOLVED-ABSENT — no callers of pkg.(*T).Do across a fully-built path (production only; --exclude-tests was given)
```

## Commands

### `callgraph`

Extract and print a summary of a module's call graph.

```
kanonarion callgraph <module>@<version> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Re-extract even if a cached record exists |
| `--go-binary` | _(from `PATH`)_ | Path to the `go` binary if not on `PATH` |
| `--json` | `false` | Emit the record as JSON to stdout |

```
$ kanonarion callgraph golang.org/x/mod@v0.30.0
golang.org/x/mod@v0.30.0: Extracted — 1039 nodes, 4201 edges [CHA]
```

A second run is served from the store and says so with `(cached)`; `--force`
re-extracts.

### `callgraph-show`

Show the full call graph record for a module, optionally filtered.

```
kanonarion callgraph-show <module>@<version> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--node` | _(all)_ | Filter to nodes/edges whose symbol contains this substring |
| `--limit-nodes` | `50` | Maximum nodes to print (`0` = unlimited) |
| `--limit-edges` | `100` | Maximum edges to print (`0` = unlimited) |
| `--history` | `false` | List every stored generation for the module instead of the composed answer |
| `--source` | _(default)_ | Restrict to graphs built from one source: `zip` or `worktree` |

```
$ kanonarion callgraph-show golang.org/x/mod@v0.30.0 --limit-nodes 2 --limit-edges 2
golang.org/x/mod@v0.30.0  [CHA]  Extracted
  fidelity: BUILT_WITH_BODIES   source: zip
  test scope: analysed — 290 of 1039 nodes are test declarations
  interfaces: 11 declared, 29 implementations recorded (query with 'kanonarion implementers')
Legend: [api] exported symbol  [external] outside this module  [test] declared in a _test.go file  (no tag) unexported

Nodes (1039 total, showing 2):
  ...

Edges (4201 total, showing 2):
  golang.org/x/mod/gosumcheck.(*clientOps).Log → log.Print  [Direct]
  ...
```

The `test scope:` line is printed on every record, including when the axis was
not measured — silence there would read as "there was no test code".

The `fidelity:` line reports how much of the module was actually built and what
the analysis read. Both matter to how an empty answer should be taken: only
`BUILT_WITH_BODIES` supports a confident negative, and a `worktree` graph
describes a directory on disk rather than the published module of that version. A
record written before the source was recorded prints `source: not recorded`,
which is a statement rather than a default.

##### Modules published before Go modules

A module published before Go modules ships no `go.mod` in its zip. Extracted into
a bare directory it would load outside any module — no package would carry the
module's import path, nothing would be recognised as the target, and the record
would be an empty graph. For those, and only those, kanonarion writes a minimal
`go.mod` into the extraction directory before loading:

* the module path is the coordinate's path **verbatim**, never derived from the
  version. A `+incompatible` module publishes a v2-or-later version under a path
  with no `/vN` suffix, and adding one would produce a graph whose every node ID
  named a module that does not exist;
* the `go` directive is pinned to `1.16` — exactly what the toolchain already
  assumes when a `go.mod` states none — because a directive of 1.22 or later
  changes loop-variable scoping, hence the SSA, hence the call graph;
* a zip that ships its own `go.mod` is **never** touched. Modules that publish
  one and still fail to load are failing for their own reasons, and overwriting
  the published file would hide that;
* if the module also ships a `vendor/` directory, vendor mode is explicitly
  disabled for the load, so the graph describes the module rather than vendored
  copies of its dependencies.

The record says so. `fidelity:` gains a `[synthesised go.mod (module …, go …)]`
note, `--history` appends it to the artefact the generation was computed from,
and `--json` carries a `synthesised_go_mod` object. The analysis is of the
published bytes **plus a file kanonarion invented**, and a record that did not
state that would be claiming to describe the artefact it was sealed against. The
field is absent — not empty — on every graph analysed as published.

#### Generations

`callgraph_records` is an append-only ledger: re-analysing a module adds a
generation rather than replacing one. `--history` lists them oldest first and
marks the one the composed read serves.

```
$ kanonarion callgraph-show example.com/mod@local --history
2 generation(s) for example.com/mod@local at pipeline 0.3.0:
  2026-01-01T10:00:00Z  Extracted        BUILT_WITH_BODIES 8334 node(s) / 89058 edge(s)
    source:   worktree
    from:     tree sha256:020268b3...
    graph:    sha256:7e1b556a...
    record:   sha256:286f5597...
* 2026-01-01T10:02:00Z  Extracted        BUILT_WITH_BODIES 8335 node(s) / 89102 edge(s)
    source:   worktree
    from:     tree sha256:1c48c5a1...
    graph:    sha256:a5f1f9e3...
    record:   sha256:a03186a6...

* served by the composed read (highest completeness, then most recent, within one analysis source)
```

The `graph:` digest is what each record says the graph **is**, with the
measurement time and the fetch provenance blanked. It is there because the
`record:` hash cannot answer "do these two agree": two analyses a second apart
that produced the identical graph carry different record hashes, so a comparison
on those would report every re-analysis as a disagreement.

#### Composition

A read returns one answer composed from the generations, on a stated ordering:

1. **Highest completeness**, then
2. **most recent**, then
3. the record's own content hash, only so the served record does not depend on
   row order.

Recency is never the authority. A `METADATA_ONLY` graph appended after a
`BUILT_WITH_BODIES` one analysed less of the same module, so it is a weaker
measurement rather than a newer answer, and it does not displace its better.

The **analysis source is not on that ladder**. A zip graph and a worktree graph
answer different questions about different bytes, so composition never serves one
for the other; a read that names no source is answered from the zip records,
because that is what a coordinate-keyed walk writes. `--source worktree` asks for
the other one.

Two disagreements are reported rather than resolved by picking: two analyses of
one pinned version that name **different artefacts**, and two records at the
**same completeness** that disagree about the graph (the narrow case that
indicates non-determinism in the analyser). A disputed module is reported on its
own row in `callgraph-list` rather than failing the whole listing. Every such
refusal prints the commands that address it — a refusal the append-only ledger
makes permanent and that names no route out is a dead end.

A generation that says **nothing** about a field has not disagreed with one that
does. Records are compared over the fields they all state, so a generation
written before a field existed — and a generation whose value for an optional
field is simply absent — is superseded by the newer one rather than reported as
in conflict with it, and the newest generation answers. The comparison is over
field presence rather than over any particular field name, so a field added in a
later release behaves the same way without further work. What it does not relax
is a disagreement between two generations that both state a field: node and edge
sets are stated by every generation, as empty when there are none, so a graph
against an empty one is still a conflict.

### `callgraph-list`

List modules with extracted call graph records, newest first. The optional
`<module>` argument filters to one module path.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `20` | Maximum records to show (`0` = unlimited) |
| `--offset` | `0` | Skip this many records before listing |

### `callers`

Find every recorded call site where a symbol is the callee.

```
kanonarion callers <symbol-id> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--exclude-tests` | `false` | Omit callers declared in `_test.go` files and external test packages |
| `--transitive` | `false` | Follow reachable edges transitively instead of only direct call sites |
| `--depth` | `0` | Maximum traversal depth for `--transitive` (`0` = unlimited) |
| `--gomod` | `./go.mod` | Restrict results to the latest project walk for this `go.mod` |
| `--walk-id` | _(none)_ | Restrict results to the resolved version set of this walk |

```
$ kanonarion callers 'github.com/org/repo/internal/license/adapters/store/sqlite.(*Store).PutLicenseRecord'
10 callers of github.com/org/repo/internal/license/adapters/store/sqlite.(*Store).PutLicenseRecord:
  github.com/org/repo/internal/license/application.(*ExtractLicenseUseCase).Execute  [CHA-overapprox]  (github.com/org/repo@v0.0.0)
  github.com/org/repo/internal/license/adapters/store/sqlite_test.TestPutAndGet  [Direct]  [test]  (github.com/org/repo@v0.0.0)
  ...

$ kanonarion callers '...sqlite.(*Store).PutLicenseRecord' --exclude-tests
1 caller of ...:
  github.com/org/repo/internal/license/application.(*ExtractLicenseUseCase).Execute  [CHA-overapprox]  (github.com/org/repo@v0.0.0)
```

### `callees`

Find every recorded call site where a symbol is the caller. Same flags as
`callers`.

### `implementers`

List the concrete types whose method sets satisfy an interface.

```
kanonarion implementers <interface-id> [flags]
```

This is the *type* question a port-signature change raises: which method sets
must change together. The edge queries cannot answer it — an interface method
has no callers, because calls go to implementations — and a text grep for the
method name cannot tell an implementation from a call, and misses embedded and
wrapper implementations entirely.

Two forms are accepted:

| Form | Example |
|---|---|
| the interface type | `pkg/path.Name` |
| one interface method | `pkg/path.(Name).Method` |

The method form resolves each implementer to the concrete node supplying that
method — an ID `callers` and `callees` also accept.

| Flag | Default | Description |
|------|---------|-------------|
| `--exclude-tests` | `false` | Omit implementations declared in `_test.go` files |
| `--gomod` | `./go.mod` | Restrict results to the latest project walk for this `go.mod` |
| `--walk-id` | _(none)_ | Restrict results to the resolved version set of this walk |
| `--json` | `false` | Emit the result, verdict and scope as JSON |

```
$ kanonarion implementers 'github.com/org/repo/internal/vuln/ports.VulnerabilityStore'
7 implementers of github.com/org/repo/internal/vuln/ports.VulnerabilityStore:
  github.com/org/repo/internal/vuln/adapters/store/sqlite.(*Store)  (github.com/org/repo@v0.0.0)
  github.com/org/repo/internal/vuln/application_test.(*fakeVulnStore)  [test]  (github.com/org/repo@v0.0.0)
  ...
scope: concrete types declared in github.com/org/repo; types in other modules that satisfy this interface are not measured
verdict: RESOLVED-PRESENT — 7 concrete types satisfy github.com/org/repo/internal/vuln/ports.VulnerabilityStore
```

An implementer that satisfies the interface through an embedded type is
reported against the declaration you would actually edit:

```
  ...application_test.(*fakeVulnStore).List...  [test]  (promoted into ...application_test.(*listRecordsErrAfterN))
```

**Scope.** The relation is computed over the analysed module's own declarations
on both sides. A type in a *different* module that satisfies the same interface
is not recorded — computing satisfaction against every type in the dependency
graph is a much larger measurement. That scope is printed on every answer, so an
empty list is read as the answer to the question that was actually asked.

Three failure modes are kept distinct rather than collapsed into an empty list:

| Situation | Result |
|---|---|
| The module was never analysed | error directing you to `local` or `callgraph` |
| The name is not an interface the module declares | error naming the module and how to list what was analysed |
| The interface declares no such method | error listing the methods it does declare |

## Symbol IDs

| Kind | Format |
|------|--------|
| Free function | `import/path.FuncName` |
| Method (pointer receiver) | `import/path.(*TypeName).MethodName` |
| Method (value receiver) | `import/path.(TypeName).MethodName` |
| Closure | the enclosing function's ID plus the SSA marker, e.g. `import/path.(*T).M$1` |
| Interface type | `import/path.TypeName` |
| Interface method | `import/path.(TypeName).MethodName` |

Note that an interface method and a *value-receiver* concrete method share a
spelling; `implementers` reads the ID as an interface method, the edge queries
read it as a node. Discover exact IDs with `callgraph-show --json` rather than
constructing them by hand.

## Node facts

| Field | Meaning |
|-------|---------|
| `is_external` | The node is outside the analysed module |
| `is_exported_api` | The node is part of the module's public API |
| `is_test` | The node is declared in a `_test.go` file or an external test package |
| `uses_unsafe_pointer` | The body performs an `unsafe.Pointer` conversion |
| `is_assembly_or_linkname` | The function has no Go body (assembly or `//go:linkname`) |
| `uses_plugin` | The body references the Go `plugin` package |

The last three are body-level facts a callee-identity map cannot witness. They
are used by [`capability`](capability.md) analysis and by the verdict layer,
where each is a leaf soundness sink that downgrades a negative answer.

## Edge confidence

| Value | Meaning |
|-------|---------|
| `Direct` | A statically-known call to a unique concrete callee, including an interface site devirtualised to its sole implementer |
| `CHA-overapprox` | An unrefined Class Hierarchy Analysis over-approximation of an interface dispatch: every type-compatible method is a possible callee |
| `VTA` | An interface dispatch narrowed to the types that actually flow to the call site |
| `Framework` | An edge bound by a framework model or thunk rather than observed in source |
| `Unknown` | An edge the analyser cannot resolve. A soundness sink: a verdict reaching one is `UNRESOLVED` |

Reflect-dispatched calls carry `Unknown` plus a separate `reflect_dispatch`
attribute, so the reflect provenance is preserved without inventing a
confidence rank for it.

## Overall status

| Value | Meaning |
|-------|---------|
| `Extracted` | Every package loaded and the graph was built |
| `Partial` | Some packages failed to typecheck; `failed_packages` names them and their edges were dropped |
| `LoadFailed` | `go/packages` failed; no graph produced |
| `OutOfMemory` | Extraction hit the configured memory limit |
| `ExtractionFailed` | Infrastructure error (zip extraction, temp dir) |
| `Cancelled` | Context cancelled before or during extraction |
| `ExcludedByConfig` | Module skipped because it matches a `callgraph.exclude` policy entry |

A query whose root symbol lies in a failed package is refused outright rather
than answered: that package's edges were dropped, so any "none" would be a false
negative.

## Storage

Records live in `<store-root>/mirror.db` (SQLite):

- `callgraph_records` — an append-only ledger keyed on
  `(module_path, module_version, pipeline_version, extracted_at, content_hash)`.
  One serialised blob per generation, holding the nodes, the interface relation
  and the test-scope axis, alongside `completeness`, `analysis_source` and
  `worktree_digest` columns so the fidelity and the source are queryable without
  decoding a blob. Nothing is ever updated; writing the same record twice is a
  no-op.
- `callgraph_edges` — edge rows keyed on the **parent record's** content hash,
  plus denormalised coordinate columns and `is_test` (true when either endpoint
  is a test node, which is what `--exclude-tests` filters on), with two covering
  indices:
  - `callgraph_edges_to_idx ON (to_id, pipeline_version)` — used by `callers`
  - `callgraph_edges_from_idx ON (from_id, pipeline_version)` — used by `callees`

Edges are keyed on the parent rather than the coordinate because a coordinate now
names every generation at once. `callers` and `callees` resolve the served
generation first and answer from its edges alone, so a superseded generation's
edges stay in the table as history and answer nothing.

The callgraph schema is tracked in the shared `schema_migrations` table under
module key `callgraph` (current version: 8). A record whose `schema_version`
differs from the binary's is treated as not found, so a schema bump is
self-enforcing: stale records are re-derived rather than read with later fields
silently zeroed.

That read gate is also why the ledger does not purge. Four of the first seven
migrations deleted both tables wholesale on an analyser shape change; the gate
achieves what those purges were for — a stale-shape record answers nothing —
without deleting the evidence, so the row survives for a history read.

## Relation to other stages

- **Requires:** `kanonarion fetch` — the module zip must exist in the blob store.
  `kanonarion local` bypasses this for a working tree.
- **Feeds:** [`capability`](capability.md), [`reachability`](reachability.md),
  and the vulnerability reachability tier.

## See also

- [`kanonarion local`](local.md) — index a working tree so its own symbols are queryable
- [`kanonarion capability`](capability.md) — capability analysis over the graph
- [`kanonarion reachability`](reachability.md) — reachability from roots
- [`kanonarion interface`](interface.md) — extract the public interface
