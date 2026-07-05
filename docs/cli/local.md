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

The tree is stored under the module's own path at the synthetic version
`local` (`v0.0.0` internally) - a working tree has no semver to pin. This
record carries **no freshness meaning**: a tree mutates between runs, so
`local` always re-analyses and never serves a cached result. (This is the same
"local source is never cached" rule the `reachability --local` probe relies
on.)

## Output

Prints the same call-graph summary as `callgraph` (node/edge counts and status;
`--json` for the full record). After it runs, query internal symbols directly:

```sh
kanonarion local
kanonarion callers 'github.com/eitanity/kanonarion/internal/cli.runScanRescan'
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `[dir]` | `.` | Directory of the Go module to analyse (must contain `go.mod`) |
| `--go-binary <path>` | _(PATH)_ | Path to the `go` binary if it is not on `PATH` |
| `--json` | false | Emit the call-graph record as JSON |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |

## Relationship to other commands

- **Enables:** `callers` / `callees` over first-party symbols (without `local`
  they resolve only fetched external modules).
- **Complementary:** `callgraph <module@version>` for external modules;
  `reachability --local <dir>` for a live working-tree vulnerability probe.

## Notes

- Requires a `go.mod` at `[dir]`; the declared module path becomes the record's
  coordinate path.
- Re-run after editing source - the record is intentionally never cached.

See also: [`callgraph`](callgraph.md), [`reachability`](reachability.md).
