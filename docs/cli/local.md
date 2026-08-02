# `kanonarion local` - Ingest the working tree's call graph

## Synopsis

```
kanonarion local [dir] [--go-binary <path>] [--json]
```

## Description

`local` analyses the Go module rooted at `[dir]` (default `.`) and persists its
call graph into the store. Unlike `callgraph <module@version>`, which only sees
**fetched external modules**, `local` ingests the project's own **internal
packages**, so `callers` / `callees` can answer questions about symbols defined
in the working tree.

The tree is stored under the module's own path at the version `local` - a
working tree has no semver to pin, and `local` is the marker a project walk
already uses for the module nothing published. The record additionally names
its **analysis source** as `worktree` and carries a **worktree digest**, a hash
over the Go source the analysis could see, so two checkouts of the same module
path are two records rather than one overwritten row.

This record carries **no freshness meaning**: a tree mutates between runs, so
`local` always re-analyses and never serves a cached result. (This is the same
"local source is never cached" rule the `reachability --local` probe relies
on.)

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
| `--go-binary <path>` | _(PATH)_ | Path to the `go` binary if it is not on `PATH` |
| `--json` | false | Emit the call-graph record as JSON |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |

## Assurance log

Every run appends one `callgraph_extracted` event to the append-only audit log
(`{store-root}/audit.jsonl`): module, version, pipeline version, completeness
level, overall status, `analysis_source` (`worktree`), node and edge counts, the
record's content hash, and the worktree digest. Because `local` never serves a
cached result, every invocation appends a line - so a run of `local` is visible
in the log as well as in the call-graph ledger.

## Relationship to other commands

- **Enables:** `callers` / `callees` / `implementers` over first-party symbols
  (without `local` they resolve only fetched external modules).
- **Complementary:** `callgraph <module@version>` for external modules;
  `reachability --local <dir>` for a live working-tree vulnerability probe.

## Notes

- Requires a `go.mod` at `[dir]`; the declared module path becomes the record's
  coordinate path.
- Re-run after editing source - the record is intentionally never cached.

See also: [`callgraph`](callgraph.md), [`reachability`](reachability.md).
