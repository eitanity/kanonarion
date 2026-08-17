# `kanonarion local` - Ingest the working tree's call graph

## Synopsis

```
kanonarion local [dir] [--force] [--go-binary <path>] [--json]
```

## Description

`local` analyses the Go module rooted at `[dir]` (default `.`) and persists its
call graph into the store. Unlike `callgraph <module@version>`, which only sees
**fetched external modules**, `local` ingests the project's own **internal
packages**, so `callers` / `callees` can answer questions about symbols defined
in the working tree.

The tree is stored under the module's own path at the version `local`. The
record additionally names its **analysis source** as `worktree`, carries a
**worktree digest** and records the **directory it analysed**, so two checkouts
of the same module path are two records rather than one overwritten row.

The digest is a hash over the source the loader actually resolved - symlinks
followed, build tags applied, `testdata` and nested modules excluded - so it
moves when the analysed code moves and not otherwise. It carries a scheme
prefix: `analysed-sha256:` for that list, `scanned-sha256:` when the load failed
before resolving any files and the tree had to be scanned instead, and a bare
`sha256:` on records written before the schemes existed. The three are never
compared.

A second digest, taken by scanning the tree before the analysis runs, records
which tree the run was handed. It makes reuse possible - see
[Unchanged trees](#unchanged-trees) - and is always `scanned-sha256:`.

The directory is what a query routes on. A `callers` query run inside a checkout
is answered from the generation analysed in THAT directory rather than from
whichever checkout ran `local` most recently - see
[`callgraph`](callgraph.md#which-working-tree-answered).

## Unchanged trees

A tree that has not changed since the last run is not analysed again. `local`
scans the tree first, and when the scan matches the tree a stored record was
taken of - the same directory, the same contents - that record is served and
nothing is appended.

The run says which happened, on **stderr**, in both text and `--json` mode -
the same stream and the same `derivation:` block [`audit`](audit.md) uses:

```
derivation:
  call graph: derived by this run
```
```
derivation:
  call graph: re-read the working tree and found it identical to the tree
  analysed 2026-08-12T00:48:14Z; that record was reused (--force to re-measure)
```

stdout carries the result only: the summary line, or under `--json` the record
document alone. To capture the answer and keep the statement, redirect them
separately (`kanonarion local . --json > graph.json 2> derivation.txt`); to
discard the statement, `2>/dev/null`.

The `(cached)` marker on the summary line is on stdout with the rest of the
result: it is a property of the answer, not a statement about it.

What the scan sees: every `.go` file under the directory plus `go.mod` and
`go.sum`, following symlinks to source files. `.git` is ignored, so committing,
fetching or switching the index does not by itself force a re-analysis.

What it does **not** see, and when to use `--force`:

- a different Go toolchain
- a module cache that has gained or lost dependencies (the graph's
  devirtualisation depends on how much of the closure could be built)
- source reached through a symlinked **directory**

A record the environment limited is never served back, so a bad run does not
become permanent and `--force` is not needed to clear it: a failure with no
usable toolchain, a cancelled run, or an incomplete graph whose loader reported
`module lookup disabled by GOPROXY=off`. That last is a cold module cache - the
summary says so and names `go mod download all`; re-running without the flag
re-analyses. A graph the tree's own compile errors left incomplete is
served: fixing them moves the digest.

Records written before this digest, or before a run recorded what limited it,
state nothing, so the first `local` run after upgrading re-analyses and later
runs reuse.

## Output

Prints the same call-graph summary as `callgraph` (node/edge counts and status;
`--json` for the full record). After it runs, query internal symbols directly:

```sh
kanonarion local
kanonarion callers 'example.com/mod/internal/cli.runScanRescan'
```

The tree's `_test.go` declarations are analysed too, so a symbol only tests
exercise has callers rather than a confident empty answer. Add `--exclude-tests`
to any query for the production-only view; see
[`callgraph`](callgraph.md#test-scope).

Interfaces the module declares become addressable, so a port-signature change
can be scoped with one query instead of a grep:

```sh
kanonarion implementers 'example.com/mod/internal/vuln/ports.VulnerabilityStore'
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `[dir]` | `.` | Directory of the Go module to analyse (must contain `go.mod`) |
| `--force` | false | Re-analyse even when the tree is unchanged since the stored record |
| `--go-binary <path>` | _(PATH)_ | Path to the `go` binary if it is not on `PATH` |
| `--json` | false | Emit the call-graph record as JSON |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |

## Assurance log

Every run that analyses the tree appends one `callgraph_extracted` event to
the append-only audit log
(`{store-root}/audit.jsonl`): module, version, pipeline version, completeness
level, overall status, `analysis_source` (`worktree`), node and edge counts, the
record's content hash, and the worktree digest. A run that served a stored
record appends nothing, to either the log or the ledger: it wrote no
generation.

## Relationship to other commands

- **Enables:** `callers` / `callees` / `implementers` over first-party symbols
  (without `local` they resolve only fetched external modules).
- **Complementary:** `callgraph <module@version>` for external modules;
  `reachability --local <dir>` for a live working-tree vulnerability probe.

## Notes

- Requires a `go.mod` at `[dir]`; the declared module path becomes the record's
  coordinate path.
- Re-run after editing source; an edited tree is always re-analysed.
- Several generations of one tree state - which `--force` is how you get - are
  ordered by completeness before recency, so a re-analysis that came back with
  less than an earlier one does not become the answer.

See also: [`callgraph`](callgraph.md), [`reachability`](reachability.md).
