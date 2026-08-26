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

## Calls and references

Two things can connect a caller to a function, and they are not the same fact.

- A **call** transfers control: `h.Confirm(w, r)`.
- A **reference** takes the function's value: `r.Get("/confirm", h.Confirm)`.
  Nothing is invoked at that line — a value is handed to a router, a framework,
  a callback slot — and whether it is ever called is not something the graph
  witnesses.

Both are edges. Every edge states its `kind` in JSON — `"Call"` or
`"Reference"`, spelled out on both so a consumer never has to infer one from a
missing field — and a reference carries a label in the text output:

```
1 caller of pkg.(*H).confirmEmail:
  pkg.(*H).MountRoutes  [Direct]  [reference — the symbol's value is taken here, not called]  (example.com/app@local)
```

This is the answer to the most common shape of "nothing calls this handler". A
method registered with a router has no call edge, and before references were
recorded `callers` reported that as `RESOLVED-ABSENT` — a measured absence for a
function an HTTP request drives on every hit.

What is recorded as a reference: a method value (`h.Method`), a method
expression (`T.Method`), a plain function passed or stored as a value, and a
closure. For a method value on a **concrete** type, the synthetic wrapper Go's
SSA form materialises is resolved through, so the answer names the method you
wrote, not a `$bound` symbol nobody wrote. For a method value taken on an
**interface** — `s.Save` where `s` is an interface — there is no single written
method to resolve to, so the reference names the wrapper; the `$bound` symbol
spells out the interface and method you wrote, and its own callees are the
implementations.

**A reference never counts as a call.** `--transitive` follows both, but a path
that crosses a reference is not a chain of invocations, and the
[reachability](reachability.md) entry-point distance says so on the line.

### The wrapper hop

A method value that is later invoked — `h(1)` on a func the router stored —
reaches the method through the `$bound` wrapper, and both hops are recorded:

```
$ kanonarion callees 'example.com/app.(*Router).Serve'
  (*example.com/app.Handlers).ConfirmEmail$bound  [Unknown]

$ kanonarion callees '(*example.com/app.Handlers).ConfirmEmail$bound'
  example.com/app.(*Handlers).ConfirmEmail  [Direct]
```

Two things follow for a query:

- `callers` of a method invoked through a method value lists the `$bound`
  wrapper alongside the registration site. Ask `callers` of the wrapper, or use
  `--transitive`, to reach whoever invokes it. A concrete method value that is
  only ever registered, never invoked, has no wrapper in the answer at all — the
  registration already names the method.
- the wrapper is a hop of its own, so `--depth 1` stops on it and a
  [reachability](reachability.md) entry-point distance across a method value
  counts one more hop than the source suggests.

Confidence is per hop and the two hops rarely match. A wrapper over a concrete
method calls exactly one function, so its outgoing edge is `Direct`; a wrapper
over an interface method calls whatever implements that interface, so its
outgoing edges are `CHA-overapprox`, one per implementation. The hop *into* the
wrapper is usually `Unknown` — the call site holds a func value, not a name. A
path is only as strong as its weakest hop.

Records state whether the axis was measured. A graph extracted before references
existed downgrades an empty `callers` answer to `UNRESOLVED` naming
`reference-scope-unmeasured`, rather than claiming an absence it could not have
seen. Re-extract the module (`kanonarion callgraph <module>@<version>`, or
`kanonarion local .` for a working tree) to get the measured answer.

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

When you pass `--exclude-tests`, the answer says so, so a narrowed answer is
never read as a wider one. An empty answer says it on the verdict line:

```
verdict: RESOLVED-ABSENT — no callers of pkg.(*T).Do across a fully-built path (production only; --exclude-tests was given)
```

A non-empty answer says it on a `scope:` line under the list — "1 caller" is
otherwise indistinguishable from an unnarrowed query that found one caller:

```
scope: test callers omitted (--exclude-tests was given)
```

`--transitive --json` carries the same statement in its `scope` field, which is
always present and empty when you did not narrow the query. The single-hop
`callers`/`callees` `--json` output is a bare array of edges with nowhere to put
it: pass `--transitive` (with `--depth 1` for the single hop) when a consumer
needs the narrowing in machine-readable form.

A **test entry point** — `TestX`, `BenchmarkX`, `FuzzX`, `ExampleX`, `TestMain`
— never has a caller in the graph, because the `go test` harness invokes it
through a `main` package the go command synthesises at build time and the
analysis does not read. `callers` on one answers `UNRESOLVED` naming
`test-harness-entry`, not a confident absence:

```
verdict: UNRESOLVED — callers of pkg.TestThing cannot be confirmed absent:
  test-harness-entry at pkg.TestThing (the go test harness invokes it through a synthesised main package that is not part of the analysed graph)
```

A method on a test fake is not an entry point — it is reached by dispatch or not
at all — so its absence is still a measurement.

## Commands

### `callgraph`

Extract and print a summary of a module's call graph.

```
kanonarion callgraph <module>@<version> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--force` | `false` | Re-extract even if a cached record exists |
| `--from-walk` | _(auto-discovered)_ | Pin a pre-modules module's `require` directives to the versions this walk resolved. Unset, the walk of a build that consumes the module is used; where the store holds it in more than one build, no build list is discovered and the builds are named on stderr so you can pin one. See [Modules published before Go modules](#modules-published-before-go-modules). |
| `--go-binary` | _(from `PATH`)_ | Path to the `go` binary if not on `PATH` |
| `--json` | `false` | Emit the record as JSON to stdout |

```
$ kanonarion callgraph golang.org/x/mod@v0.30.0
golang.org/x/mod@v0.30.0: Extracted — 1039 nodes, 4201 edges [CHA]
```

### Exit codes

`callgraph` and [`local`](local.md) exit on what the extraction **established**:

| Code | Meaning |
|---|---|
| `0` | `Extracted`: the graph covers every package the module builds |
| `1` | `Partial`: a graph exists and is known-incomplete, with its incompleteness scoped to the packages named on the `failed packages` line |
| `2` | No graph at all: `LoadFailed`, or a `Partial` that measured no functions. The message repeats the recorded failure detail |
| `3` | `Cancelled`: the run ended before the graph was walked |
| `10` | Two stored records for this coordinate disagree, or one failed its content-hash check. The message names what differs and the remedy, `callgraph-show --diff` |

`ExcludedByConfig` exits `0`: the module is listed in `callgraph.exclude`, so the
absent graph is the outcome the operator asked for rather than one the run failed
to produce. Every other status that produced no graph — `LoadFailed`,
`OutOfMemory`, `ExtractionFailed` — exits `2`.

A `Partial` graph is an answer, and `1` is [the code for an answer that is
known-incomplete](conventions.md#exit-codes) — the same code a partial walk and a
licence-incomplete SBOM use, so a caller for which an incomplete graph will do
accepts `0` and `1` alike. A `Partial` carrying zero nodes is not an answer at
all: nothing was measured, so it exits `2` alongside `LoadFailed`. Whether an
incomplete or unanalysable dependency should fail a build is a policy question
this command does not answer — it reports which of the three it has.

### When a module does not load

A load failure names its own cause on the record, and `callgraph-show` reprints
it. The causes that recur:

| Message | What it means |
|---|---|
| `no go.mod was synthesised: … imports packages outside the standard library: …` | A module published before Go modules whose imports no build list in this store resolves. Name a build that does with `--from-walk`, or walk a project that uses it |
| `no package under <path>: the loader resolved N package(s) (…)` | Nothing the loader returned belongs to the module. The named packages say what it found instead — a nested module's `replace` target absent from the published zip is the usual reason |
| `no packages found for <goos>/<goarch> …` | The module ships no Go source this platform compiles. A Windows-only module has no graph on Linux, and that is a joint fact about the module and the frame |
| `none of the N package(s) under <path> type-checked: …` | The packages were found and the type-check failed; the loader's own errors follow |
| `the loader reported: … missing go.sum entry for module providing package …; to add: …` | The tree's `go.sum` does not cover a module the load needs. `go mod tidy`, then re-analyse. A local analysis is read-only: it reports the gap rather than closing it in the tree it was asked to measure |

Package membership is decided by the module path the analysed tree **declares**,
not by the coordinate it was published under. A fork republished at a new path
that never rewrote its own `module` directive — and which consumers therefore
reach through a `replace` — has all its packages under the declared path, and
its nodes carry that path.

The load does not require the artefact to ship a `go.sum` covering its own
module graph: `go.sum` is an obligation of whatever is being *built*, and the
artefact's own integrity was established by the fetch that stored it.

A second run is served from the store and says so with `(cached)`; `--force`
re-extracts. A record the environment cut short is never served from cache, so a
repeat re-analyses; a re-analysis that comes back identical appends nothing and
says so.

### `callgraph-show`

Show the full call graph record for a module, optionally filtered.

```
kanonarion callgraph-show <module>@<version> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--node` | _(all)_ | Filter to nodes whose fully-qualified ID contains this substring (case-insensitive), plus everything directly connected to them |
| `--limit-nodes` | `50` | Maximum nodes to print (`0` = unlimited) |
| `--limit-edges` | `100` | Maximum edges to print (`0` = unlimited) |
| `--history` | `false` | List every stored generation for the module instead of the composed answer |
| `--diff` | `false` | Report what the distinct stored measurements for the module differ about, instead of the composed answer |
| `--source` | _(default)_ | Restrict to graphs built from one source: `zip` or `worktree` |
| `--toolchain` | _(default)_ | Restrict to graphs built by one Go toolchain, in `go env GOVERSION` form (e.g. `go1.26.6`). A coordinate holding none of them reports no record |

```
$ kanonarion callgraph-show golang.org/x/mod@v0.30.0 --limit-nodes 2 --limit-edges 2
golang.org/x/mod@v0.30.0  [CHA]  Extracted
  fidelity: BUILT_WITH_BODIES   source: zip   toolchain: go1.26.6
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

A `reference scope:` line is printed on every record for the same reason, and it
is the axis a confident negative rests on:

```
  reference scope: analysed — 1818 of 165766 edges record a function value being taken, not called
```

A record that never looked says so, and says what that costs:

```
  reference scope: not recorded — this record never looked for function-value
  references, so an empty callers answer over it is UNRESOLVED, not a measured absence
```

In JSON the axis is `reference_scope` (empty when unmeasured) beside
`reference_edge_count`, both always present.

A `module membership:` line appears only when the record needed it:

```
  module membership: 2 package(s) attributed by PATH PREFIX — the toolchain placed
  them in no module: example.com/legacy, example.com/legacy/util
```

Which module a package belongs to is normally taken from the Go toolchain's own
answer, which matters because module paths nest: `cloud.google.com/go/auth` is a
separate module from `cloud.google.com/go`, not a part of it, and a record that
decided membership by path prefix would report one module's code — and its
exported API — as the other's. The prefix rule survives only for packages the
toolchain places in no module at all, which is what a pre-modules module's
packages come back as, and this line names every package decided that way. No
line means every in-module package was named by the build. On a record written
before the line existed, its absence says nothing either way: those records
decided every package by prefix and had nowhere to record it.

`--node` is compared against the **fully-qualified node ID** — the package path
plus the symbol, e.g. `example.com/mod/render.(*Engine).Render` — so a module
path, a package path and a bare symbol name all select the nodes a reader
expects from one flag. Filtering by the dependency you care about
(`--node example.com/tmpl`) is therefore as valid a question as filtering by a
function name (`--node Render`).

A pattern that matches nothing says so, and says what it was compared against,
rather than serving an empty graph that reads as an empty region:

```
$ kanonarion callgraph-show example.com/mod@v1.0.0 --node example.com/absent
...
Nodes (0 total, showing 0):

Edges (0 total, showing 0):

no node matched "example.com/absent" — the pattern is compared, case-insensitively
and as a substring, against the fully-qualified node ID (package path + symbol) of
all 1039 node(s) in this record, not against the bare symbol name (e.g.
example.com/mod/render.(*Engine).Render)
  to list every node: kanonarion callgraph-show example.com/mod@v1.0.0 --limit-nodes 0
```

Under `--json` the same statement is the `node_filter` object (`pattern`,
`compared_against`, `candidate_nodes`, `matched_nodes`), present only when
`--node` was given.

The `fidelity:` line reports how much of the module was actually built and what
the analysis read. Both matter to how an empty answer should be taken: only
`BUILT_WITH_BODIES` supports a confident negative, and a `worktree` graph
describes a directory on disk rather than the published module of that version. A
record written before the source was recorded prints `source: not recorded`,
which is a statement rather than a default.

The `toolchain:` line names the Go toolchain that built the graph — `go env
GOVERSION` of the process the loader drove, not the toolchain kanonarion was
compiled with and not the module's own `go` directive. A record written before
the toolchain was recorded prints what its own stdlib positions still show: the
version when the stdlib came from a toolchain downloaded as a module (`go1.26.6
(from the recorded stdlib path)`), the directory when it came from an installed
GOROOT (`unnamed version at GOROOT /usr/local/go`, which names no version because
a GOROOT is upgraded in place), and `not recorded` when the graph carries no
stdlib path at all. Under `--json`, `toolchain` carries that identity and
`toolchain_stated` is `null` unless the record itself named one.

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
* the `go` directive is pinned to `1.17`, the lowest version that works: below
  it the toolchain loads the complete, unpruned module graph and the load fails
  on a version nothing in the build compiles, and at 1.22 loop-variable scoping
  changes the SSA and with it the call graph;
* a zip that ships its own `go.mod` is **never** touched. Modules that publish
  one and still fail to load are failing for their own reasons, and overwriting
  the published file would hide that;
* if the module also ships a `vendor/` directory, vendor mode is explicitly
  disabled for the load, so the graph describes the module rather than vendored
  copies of its dependencies;
* if the module's own packages import third-party code, the `require` directives
  are taken from the resolved build list of the walk named by `--from-walk` —
  the versions that build actually selected. The load then runs with
  `GOPROXY=off` against the local module cache, so a version nobody chose can
  never enter the graph. Without `--from-walk`, or when the build list does not
  provide *every* one of those imports, synthesis is refused outright and the
  module is left failing: a file naming some dependencies still sends the loader
  hunting for the rest. The refusal is on **the record**, naming the imports
  that could not be pinned and the build list that failed to pin them, and it
  records **no failure cause** — a build list can arrive tomorrow, so the
  refusal states nothing about the artefact and must never be cached as though
  it did.

The walk stages pass `--from-walk` to the callgraph subprocess automatically, so
a module analysed as part of `kanonarion walk` already gets its build list.

Asked for a single coordinate with no `--from-walk`, `callgraph` finds one
itself: the most recent walk in the store that resolved this module supplies the
pins, and the command says on stderr which walk it chose and how many versions
that walk resolved. `--from-walk` always wins where it is given. The search runs
before the analysis, not as a retry after one failed: analysing twice would
persist two failure generations differing only in which build list they were
denied.

The record says so. `fidelity:` gains a `[synthesised go.mod (module …, go …)]`
note naming how many `require` directives were pinned, `--history` appends it to
the artefact the generation was computed from, and `--json` carries a
`synthesised_go_mod` object whose `requires` list and `build_list_source` name
the pins and the walk they came from. Those requires are **scan inputs** — what
the analysis was pointed at — and are never resolved dependency edges of the
module; no answer surface presents them as such. Two analyses of the same bytes
pinned to different versions are two different graphs and carry different graph
digests, while identical pins from two different walks do not. The analysis is of the
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
    toolchain: go1.26.6
    from:     tree sha256:020268b3...
    graph:    sha256:7e1b556a...
    record:   sha256:286f5597...
* 2026-01-01T10:02:00Z  Extracted        BUILT_WITH_BODIES 8335 node(s) / 89102 edge(s)
    source:   worktree
    toolchain: go1.26.6
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

A generation whose analysis failed carries a `failure:` line between `from:` and
`graph:`, naming the recorded cause and detail:

```
    failure:  environment: lib/hooks.go:10:2: could not import example.com/dep
```

Generations that did not record a failure print no such line. Positions in a
failure are module-relative; the directory a zip is staged in is gone by the
time anyone reads the record.

#### Composition

A read returns one answer composed from the generations, on a stated ordering:

1. **Highest completeness**, then
2. a graph the **module** limited over one **this host** limited, then
3. **most recent**, then
4. the record's own content hash, only so the served record does not depend on
   row order.

Recency is never the authority. A `METADATA_ONLY` graph appended after a
`BUILT_WITH_BODIES` one analysed less of the same module, so it is a weaker
measurement rather than a newer answer, and it does not displace its better. A
graph cut short by a cold module cache is weaker at one level too, because
`BUILT_WITH_BODIES` says how the loaded packages were analysed and not how much
of the module was reached. It ranks below a complete analysis of the same
artefact and never conflicts with one, so warming the cache and re-running is
enough. Where no graph was produced the rung decides nothing and the newest
account of the failure answers.

The **Go toolchain is not on that ladder either**. A graph carries the
toolchain's own stdlib and its vendored trees, so two toolchains that produced
DIFFERENT graphs produced two answers about two builds and neither supersedes the
other: composition names the toolchain and refuses rather than serving whichever
ran last. `--toolchain go1.26.6` asks for one of them, and `callers`, `callees`,
`implementers` and `interface-diff` take it too.

The graph difference is what makes it a disagreement. Two toolchains that
produced the **same** nodes and edges produced the same answer, so the read
composes and the served record names its own toolchain — a patch bump moves no
release tag and routinely produces byte-identical graphs. A record that
establishes no toolchain at all is never read as a toolchain of its own: an
unnamed GOROOT says where the stdlib was read, not which version read it, so it
ladders **below** a record that names one rather than conflicting with it, and it
is never read as "any toolchain" and never as the reading host's.

The **analysis source is not on that ladder**. A zip graph and a worktree graph
answer different questions about different bytes, so composition never serves one
for the other; a read that names no source is answered from the zip records,
because that is what a coordinate-keyed walk writes — unless you are standing in
a checkout the ledger has analysed, and then that tree answers. A zip record at a
project's own coordinate is a by-product of its own extraction rather than a
competing analysis. `--source worktree` asks for the other one.

A call graph is an analysis of a module resolved against a **build list**, and
`build_list_source` names the walk that supplied it. Two generations offered
different build lists were handed different dependency closures, so they answer
different questions and are never compared for agreement — the ladder still ranks
them, and the served record names its own build list. A generation that names no
build list cannot be shown to have been asked a different question, so it goes on
comparing against every other.

Three disagreements are reported rather than resolved by picking: two analyses of
one pinned version that name **different artefacts**, two built by **different Go
toolchains** that describe different graphs, and two records at the **same
completeness**, offered the **same build list**, that disagree about the graph
(the narrow case that indicates non-determinism in the analyser). The toolchain
check runs first and across build lists, because the two axes are independent —
generations offered different build lists are never compared with each other, so
a toolchain difference between them would otherwise go unreported. A disputed module is reported on its
own row in `callgraph-list` rather than failing the whole listing. Every such
refusal prints the commands that address it — a refusal the append-only ledger
makes permanent and that names no route out is a dead end.

The graph comparison is over the **graph** and nothing else: the node, edge,
interface and implementation collections and the counts stated with them. Where
a node **outside** the analysed module is declared is not part of it: that is a
path in the analysing host's toolchain and module cache, so the same stdlib
symbol comes back under whichever `GOROOT` loaded it. The module's own
declaration positions are relative to its root and are compared. Two
generations that recorded the same graph and described their run differently —
different `failure_cause`, `failure_detail` or failed-package set — are **not**
in conflict, because no answer the tool serves depends on the difference. It is
not thrown away: `--history` prints each generation's failure on its own line.

A generation that says **nothing** about a field has not disagreed with one that
does. Records are compared over the fields they all state, so a generation
written before a field existed — or whose optional value is simply absent — is
superseded by the newer one rather than reported as in conflict with it. It does
not relax a disagreement between two generations that both state a graph field:
node and edge sets are stated by every generation, as empty when there are none,
so a graph against an empty one is still a conflict.

Re-analysis clears a graph conflict only by getting **further** than the
disagreeing generations did: the ledger is append-only and composition compares
every generation at the highest completeness present, so an analysis landing at
the same completeness adds a third and the disagreement stands. The refusal names
`kanonarion callgraph <module> --force` where a higher completeness is still
available, and where the pair is already `BUILT_WITH_BODIES` it sends you to
`--diff` to decide which measurement to trust instead.

`callgraph-show --diff` is the instrument those refusals name. It groups the
generations by what they measured, validates each by its own content hash — the
hash is sealed over `extracted_at`, so it can answer "is this record intact" and
never "do these two agree" — and then reports the record fields, nodes, edges,
interfaces and implementations the first two measurements differ about. Where
the graphs agree and only the inputs differ, it says so.

### `callgraph-list`

List modules with extracted call graph records, newest first. The optional
`<module>` argument filters to one module path, matched for **exact equality** —
`github.com/spf13/cobra` matches, `github.com/spf13` does not.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit` | `20` | Maximum records to show (`0` = unlimited) |

When the limit bites, the listing says so on both output paths and names the
invocation that lifts it, per [Truncated listings](conventions.md#truncated-listings).
| `--offset` | `0` | Skip this many records before listing |

A zero result names its own scope — whether the store is empty, the filter
matched nothing, or `--offset` skipped past the end — per
[Zero-result listings](conventions.md#zero-result-listings):

```
$ kanonarion callgraph-list no-such-module-anywhere
no call graph record matched module path "no-such-module-anywhere" — the value is compared against the module path, compared for exact equality, of all 312 call graph record(s) in the store (e.g. github.com/spf13/cobra)
  to list every call graph record: kanonarion callgraph-list
```

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
| `--gomod <path>` | _(none; unrestricted)_ | Restrict results to the latest **code-scope** project walk for this `go.mod`, resolved for this platform. Takes a path, e.g. `--gomod ./go.mod`. Refuses, naming the scopes the store does hold, rather than answering from a walk of another scope or platform. The scope notice names that walk, its scope, the `GOOS/GOARCH` it resolved for, and that the `go.mod` was not re-resolved for the read (an edit made since that walk is not reflected; `walk --gomod` records the current resolution) |
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
scope: test callers omitted (--exclude-tests was given)
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
| `--gomod <path>` | _(none; unrestricted)_ | Restrict results to the latest **code-scope** project walk for this `go.mod`, resolved for this platform. Takes a path, e.g. `--gomod ./go.mod`. Refuses, naming the scopes the store does hold, rather than answering from a walk of another scope or platform. The scope notice names that walk, its scope, the `GOOS/GOARCH` it resolved for, and that the `go.mod` was not re-resolved for the read (an edit made since that walk is not reflected; `walk --gomod` records the current resolution) |
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
| `is_exported_api` | The node is part of the module's public API: an exported symbol of the analysed module, in a package a consumer can import (not `internal`, not `main`), and not a closure or a synthesised bound-method or thunk symbol |
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

Confidence answers *how was the target resolved*, a different question from
*what kind of edge is it*. A reference edge is usually `Direct` — the analyser
knows whose value was taken — and that is not a claim that a call happens. Read
`kind` alongside `confidence`; a path is a chain of resolved calls only when
every hop is `Direct` **and** no hop is a reference.

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

A query whose root symbol lies in a failed package still answers, and says what
it could not measure. That package produced no SSA, so edges with an end inside
it were dropped and the symbol is not a node in its own module's graph — but
edges INTO it recorded in a consumer's complete graph are unaffected, and those
are what the answer lists. The output carries a `notice: unmeasured on one
side …` line naming the package, and an empty answer is `verdict: UNRESOLVED`
with a `dropped-package-edges` sink.

The remedy the notice names depends on whose module failed: a project
coordinate's package is yours to fix, so it names `local`; a fetched
dependency's failure is in its own sources, and the notice names
`callgraph-show` to see it and `callgraph … --force` to measure it again.

`interface-diff --used-by` discloses the same condition for the *consumer's*
own packages: its reach counts join against the consumer's graph, and a call
site in a package that never compiled cannot appear in one.

## Storage

Records live in `<store-root>/mirror.db` (SQLite):

- `callgraph_records` — an append-only ledger keyed on
  `(module_path, module_version, pipeline_version, extracted_at, content_hash)`.
  One serialised blob per generation, holding the nodes, the interface relation
  and the test-scope axis, alongside `completeness`, `analysis_source`,
  `worktree_digest` and `analysis_root` columns so the fidelity, the source and
  the working tree are queryable without decoding a blob. Nothing is ever
  updated; writing the same record twice is a no-op.
- `callgraph_edges` — edge rows keyed on the **parent record's** content hash,
  plus denormalised coordinate columns and `is_test` (true when either endpoint
  is a test node, which is what `--exclude-tests` filters on), with two covering
  indices:
  - `callgraph_edges_to_idx ON (to_id, pipeline_version)` — used by `callers`
  - `callgraph_edges_from_idx ON (from_id, pipeline_version)` — used by `callees`

Edges are keyed on the parent rather than the coordinate because a coordinate
names every generation at once. `callers` and `callees` resolve the served
generation first and answer from its edges alone, so a superseded generation's
edges stay in the table and answer nothing.

### After a pipeline-version bump

A record is served only at the pipeline version the binary was built with. When
the extraction pipeline is bumped, every stored record for a coordinate becomes
unreachable until it is re-analysed, and a query for one does not answer empty —
`callers`, `callees`, their `--transitive` forms and `implementers` refuse with
exit 20, naming the versions the store holds and the command that re-derives
them:

```
$ kanonarion callers 'github.com/golang-jwt/jwt/v4.(*Parser).ParseUnverified'
error: symbol "…ParseUnverified" belongs to module "github.com/golang-jwt/jwt/v4",
whose every stored call graph was produced by superseded extraction logic: this
build serves pipeline 0.5.0 and the store holds v4.5.0, v4.5.1, v4.5.2 at
pipeline 0.3.0, 0.4.1. …
  kanonarion callgraph github.com/golang-jwt/jwt/v4@v4.5.0
```

`callgraph-show` and `callgraph-show --history` say the same thing for the
coordinate they were asked about. A module the store holds at both a superseded
and the serving version is answered normally from the served generation.

The callgraph schema is tracked in the shared `schema_migrations` table under
module key `callgraph` (current version: 13). A record whose `schema_version`
differs from the binary's is treated as not found, so a schema bump is
self-enforcing: stale records are re-derived rather than read with later fields
silently zeroed.

That read gate is also why the ledger does not purge: it achieves what a
wholesale delete was for — a stale-shape record answers nothing — without
deleting the evidence, so the row survives for a history read.

## Which working tree answered

A local coordinate is shared by every checkout of the module path, so a project
checked out twice has generations from both. A query about such a symbol is
answered from **the working tree you are standing in**: the read resolves the
current directory to its module root and serves the newest generation analysed
in that directory.

Standing somewhere the ledger has no generation of — a fresh clone, or anywhere
outside the module — the read falls back to the newest generation of any tree.
Nothing returns empty because of routing.

The decision is printed, once, whenever there is one to see:

```
notice: answered from the working tree you are in, /src/feature (tree analysed-sha256:5252…);
        the ledger holds 2 working trees for example.com/mod@local
```

```
notice: NOT answered from the working tree you are in: /src/fresh-clone has no analysed
        generation, so the answer comes from the working tree at /src/main (tree analysed-sha256:0aae…);
        the ledger holds 2 working trees for example.com/mod@local. Analyse this tree to be
        answered from it:
          kanonarion local /src/fresh-clone
```

A single analysed checkout has no decision to show and prints nothing. A
generation that states no tree is named for what it is — one written before the
directory was recorded, or an analysis of the published zip, which reads no tree
at all — rather than attributed to a checkout it may not be from.

Routing is on the analysed **directory**, not on the worktree digest: the digest
hashes content, so the tree in front of a developer with one uncommitted edit
matches no stored generation. The digest still says WHICH tree answered, which is
what the notice reports.

`callgraph-show --history` is unaffected: it lists every generation of every
tree, marking the one the composed read serves.

## Assurance log

Each persisted generation appends one `callgraph_extracted` event to the
append-only audit log (`{store-root}/audit.jsonl`): module, version, pipeline
version, completeness level, overall status, `analysis_source`, node and edge
counts, the record's content hash, and either the artefact identity the analysis
read or - on the `kanonarion local` route - the worktree digest. A module skipped
by `callgraph.exclude` appends one too: the decision that these bytes were not
analysed is also worth anchoring. A cache hit re-serves the stored record without
re-extracting, so it appends nothing.

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

### Naming a toolchain on a query

`callers`, `callees`, `implementers` and `interface-diff` accept `--toolchain`
alongside `--walk-id` and `--gomod`. It behaves differently from
`callgraph-show --toolchain`, and the difference is deliberate.

`callgraph-show` names one coordinate, so the flag **restricts** the read: a
coordinate the ledger holds no such generation of reports no record, which is the
answer the reader asked for.

A query spans every module in scope, almost none of which state a toolchain, so
there the flag **disambiguates** rather than restricts. It is consulted only where
one coordinate's generations disagree about the toolchain; every other module is
served exactly as it would be without the flag. Restricting such a read would
report "no record" for hundreds of modules and turn a disambiguation into a
silently short answer.

```
$ kanonarion callers 'golang.org/x/tools/go/packages.Load'
error: ... toolchain disagrees ([GOROOT usr/local/go go1.26.6]) ...

$ kanonarion callers 'golang.org/x/tools/go/packages.Load' --toolchain go1.26.6
297 callers of golang.org/x/tools/go/packages.Load:
  ...
```
