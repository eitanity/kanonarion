# `kanonarion dependents` - Reverse dependency query

## Synopsis

```
kanonarion dependents <module>@<version> --walk-id <id> [flags]
```

## Description

`dependents` answers the pre-upgrade question: **"if I update this dependency,
which modules in my closure will be affected?"**

It scans the stored walk graph for every module that has a direct import edge to
the target coordinate and returns them sorted lexicographically. Because a walk
captures the full transitive closure - including the versions actually selected
by MVS - the results reflect what is real in that specific resolved graph, not
what is theoretically possible.

The walk root module (typically your own module) is excluded by default. It is
the subject of the walk, not a dependent in the usual sense, and including it
unconditionally produces noise on every query. Pass `--include-root` to include
it; it always sorts first and is annotated `[root]`.

## Output format

### Text

```
N module(s) in walk <id> depend on <target>:
  github.com/caddyserver/caddy/v2@v2.11.2      [root]
  github.com/caddyserver/certmagic@v0.25.2     [direct]
  cloud.google.com/go/auth@v0.18.1             [direct]
  github.com/google/s2a-go@v0.1.9
  ...
```

**Annotation key**

| Annotation | Meaning |
|---|---|
| `[root]` | The walk root module itself. Only shown with `--include-root`. Sorts first. |
| `[direct]` | A direct dependency of the walk root - listed in its `go.mod`. |
| _(none)_ | A transitive dependency; not in the walk root's `go.mod`. |

### JSON (`--json`)

```json
{
  "walk_id": "01KQKHYNTDYYQET4D1EZZ8E79E",
  "target":  "golang.org/x/net@v0.51.0",
  "dependents": [
    {
      "module":  "github.com/caddyserver/caddy/v2",
      "version": "v2.11.2",
      "direct":  false,
      "root":    true
    },
    {
      "module":  "github.com/caddyserver/certmagic",
      "version": "v0.25.2",
      "direct":  true,
      "root":    false
    },
    {
      "module":  "github.com/google/s2a-go",
      "version": "v0.1.9",
      "direct":  false,
      "root":    false
    }
  ]
}
```

**Field reference**

| Field | Type | Description |
|---|---|---|
| `walk_id` | string | The walk record that was queried |
| `target` | string | The queried coordinate (`module@version`) |
| `dependents` | array | All modules with an edge to the target, sorted by path |
| `dependents[].module` | string | Module import path |
| `dependents[].version` | string | MVS-selected version in this walk |
| `dependents[].direct` | bool | True when this module is in the walk root's `go.mod` |
| `dependents[].root` | bool | True when this module IS the walk root |

`direct` and `root` are mutually exclusive: a module is either the root or a
dependency, not both. To find all first-party-relevant entries, filter on
`root || direct`.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--walk-id <id>` | _(required)_ | Walk record ID to query |
| `--direct-only` | false | Only return direct dependencies of the walk root |
| `--include-root` | false | Include the walk root module if it has an edge to the target |
| `--json` | false | Emit results as JSON to stdout |
| `--store-root <path>` | `~/.kanonarion` | Root directory for SQLite |

## Flag combinations

| Flags | What you get | Best for |
|---|---|---|
| _(default)_ | All dependents; root excluded | Seeing the full closure impact |
| `--include-root` | All dependents; root shown as `[root]` | Full picture including your own module |
| `--direct-only` | Only `[direct]` entries; root excluded | Upgrade coordination: which direct deps need updating? |
| `--direct-only --include-root` | `[direct]` + `[root]` | Pre-upgrade checklist - the complete actionable set |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (zero results is not an error) |
| 10 | Walk record integrity check failed |
| 20 | Walk ID not found |

## Examples

```sh
# Full blast radius for an x/net upgrade
kanonarion dependents golang.org/x/net@v0.51.0 \
  --walk-id 01KQKHYNTDYYQET4D1EZZ8E79E

# Pre-upgrade checklist: direct deps and your own module, concise
kanonarion dependents golang.org/x/net@v0.51.0 \
  --walk-id 01KQKHYNTDYYQET4D1EZZ8E79E \
  --direct-only --include-root

# Does your module depend on certmagic directly?
kanonarion dependents github.com/caddyserver/certmagic@v0.25.2 \
  --walk-id 01KQKHYNTDYYQET4D1EZZ8E79E \
  --include-root

# Machine-readable output; filter to first-party entries with jq
kanonarion dependents golang.org/x/net@v0.51.0 \
  --walk-id 01KQKHYNTDYYQET4D1EZZ8E79E \
  --include-root --json \
  | jq '[.dependents[] | select(.direct or .root)]'

# Count how many modules in the closure depend on a target
kanonarion dependents golang.org/x/crypto@v0.48.0 \
  --walk-id 01KQKHYNTDYYQET4D1EZZ8E79E \
  --json | jq '.dependents | length'
```

## Relationship to other commands

- **Requires:** a stored `WalkRecord` - run `kanonarion walk` first.
- **Complementary:** `kanonarion callers` finds callers of a specific *symbol*;
  `dependents` works at module granularity.
- **See also:** `kanonarion walk-diff` to compare two walks after an upgrade.

## Notes

- The target version must match exactly the MVS-selected version recorded in the
  walk. If the walk selected `v0.51.0` and you query `v0.50.0`, you will get zero
  results - which is the correct answer for that walk.
- A zero-result response is not an error (exit 0). It means either the module is
  not present in the walk, or it is only the walk root (which is excluded by
  default).
- The `direct` field reflects `GraphNode.DirectDependency`: true when the node
  appears as a `require` directive in the walk root's `go.mod`. The root module
  itself always has `direct: false` regardless of how many things it requires;
  use the `root` field to identify it.
