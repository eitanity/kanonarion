# `kanonarion dependents` - Reverse dependency query

## Synopsis

```
kanonarion dependents <module>@<version> [--walk-id <id>] [flags]
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
N module(s) in walk <id> (frame linux/amd64) depend on <target>:
  github.com/caddyserver/caddy/v2@v2.11.2      [root]
  github.com/caddyserver/certmagic@v0.25.2     [direct]
  cloud.google.com/go/auth@v0.18.1             [direct]
  github.com/google/s2a-go@v0.1.9
  ...
```

`frame` is the `GOOS/GOARCH` the answering walk resolved for, or
`not-platform-scoped` for a module-rooted walk. Without `--walk-id` it comes
from the walk the search chose, whatever its platform.
JSON carries `walk_frame` and `walk_frame_basis`.

### Without `--walk-id`: which walk answers

Who depends on a module is a property of one build, so the search picks the walk
of a build that **consumes** the target. A walk rooted at the target itself is
passed over while any other walk holds it: that walk holds the target's own
dependency closure, so it answers with the target's own dependencies rather than
with anything that depends on it. The answer says so:

```
notice: no walk was named; walk 01M0VG1267S1XDJGDFZTVRPM84 was chosen because it
is rooted at github.com/cortezaproject/corteza/server@local, which builds
golang.org/x/net@v0.33.0 — 1 walk(s) rooted at golang.org/x/net@v0.33.0 itself
were passed over, since a module has no dependents inside its own graph; pin one
with --walk-id (kanonarion walk-list lists them)
```

Where the target's own walk is the **only** walk holding it — a module vetted in
isolation and walked nowhere else — it still answers, and states what the answer
is about:

```
notice: the only walk holding github.com/spf13/cobra@v1.8.1 in this store is
rooted at github.com/spf13/cobra@v1.8.1 itself, so the answer below is drawn from
that module's own dependency graph and names no consuming build; walk
01KZWK6GHN7CK9Y54YTHMTNRKJ
```

Several walks of one build are not a choice between builds: the most recent of
them answers.

### Without `--walk-id`: two builds is a refusal, not a coin toss

Where more than one build holds the target, there is no answer that is not about
somebody's build, so the command refuses (exit 20) and names the candidates —
the same refusal `vuln-show` gives for two consumer frames:

```
the store holds github.com/pkg/errors@v0.9.1 in 3 builds, and this question names none:
  walk 01M0VG1267S1XDJGDFZTVRPM84  rooted at github.com/cortezaproject/corteza/server@local
  walk 01M0ABH9573T0TW1BBRSQ7KCZ1  rooted at github.com/eitanity/kanonarion@local
  walk 01M04P06Y1GJKX225K01M22E4Q  rooted at ragflow@local
what a coordinate is surrounded by is a property of one build, so name the build you mean:
  kanonarion dependents github.com/pkg/errors@v0.9.1 --walk-id <walk of that build>
kanonarion walk-list lists every walk in the store
```

`--walk-id` overrides the ranking entirely: a named walk is queried as named.

### Without `--walk-id`: the search is bounded, and says so

The containment search reads the **50 most recent walks**. When it finds no walk
containing the target, the failure states which of two things happened:

```
no walk in this store contains example.com/dep@v1.2.3 (all 14 walk(s) searched)
```

The store held fewer walks than the bound, so the search exhausted it: this is a
plain absence.

```
no walk containing example.com/dep@v1.2.3 among the 50 most recent walks searched
 — the store holds 132; name the walk to query with --walk-id, or list them with:
kanonarion walk-list --limit 0
```

The bound stopped the search first, so the coordinate may sit in an older walk.
A negative that has not exhausted the population is never phrased as a plain
absence.

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
  "walk_frame": "linux/amd64",
  "walk_frame_basis": "platform",
  "walk_selection": {
    "rule": "consumer-rooted",
    "root": "github.com/caddyserver/caddy/v2@v2.11.2",
    "self_rooted_passed_over": 1
  },
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
| `walk_frame` | string | The `GOOS/GOARCH` that walk resolved for, or a token standing for the reason there is none |
| `walk_frame_basis` | string | The same fact as data: `platform`, `not_platform_scoped`, `unrecorded` |
| `walk_selection.rule` | string | How that walk was reached: `pinned` (you named it), `consumer-rooted` (a build that consumes the target), `self-rooted-only` (the only walks holding the target are rooted at the target, so the answer is from its own graph) |
| `walk_selection.root` | string | The answering walk's target: the build the answer is about |
| `walk_selection.self_rooted_passed_over` | int | How many walks rooted at the queried coordinate a consuming build outranked |
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
| `--walk-id <id>` | _(chosen for you)_ | Walk record ID to query. Unset, the walk of a build that consumes the target is chosen — see [which walk answers](#without---walk-id-which-walk-answers). |
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
| 4 | Walk ID not found |
| 10 | Walk record integrity check failed |
| 20 | Malformed invocation; no walk in the store contains the target; or no `--walk-id` and the store holds the target in more than one build |

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
- Without `--walk-id` the answer is about one build, and which build is stated on
  every surface — in the answer line, in the notice above it, and as
  `walk_selection` under `--json`. Relaying the count without the build it came
  from drops the half of the answer that makes it true.
- A module in the walk that resolved under pre-modules semantics can never
  appear as a dependent, in either direction of the question: the go command
  ignores its `go.mod`, so no requirement edge was resolved under it. The answer
  states this and names the coordinates — see
  [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
  Under `--json` it is the `pre_modules_caveat` object.
- The `direct` field reflects `GraphNode.DirectDependency`: true when the node
  appears as a `require` directive in the walk root's `go.mod`. The root module
  itself always has `direct: false` regardless of how many things it requires;
  use the `root` field to identify it.
