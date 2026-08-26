# `kanonarion dependents` - Reverse dependency query

## Synopsis

```
kanonarion dependents <module>@<version> [--gomod <path>] [--tool|--project] [flags]
kanonarion dependents <module>@<version> --walk-id <id> [flags]
kanonarion dependents <module>@<version> --any-build [flags]
```

## Description

`dependents` answers the pre-upgrade question: **"if I update this dependency,
which modules in my closure will be affected?"**

It scans the stored walk graph for every module that has a direct import edge to
the target coordinate and returns them sorted lexicographically. Because a walk
captures the full transitive closure - including the versions actually selected
by MVS - the results reflect what is real in that specific resolved graph, not
what is theoretically possible.

What a coordinate is surrounded by is a property of **one build**, so the build
is part of the question. Run inside a project and the answer is about that
project, with no flag. See [rooting the question](#rooting-the-question).

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
`not-platform-scoped` for a module-rooted walk. A `--gomod` or working-directory
read selects on the platform, so the frame is this host's; `--walk-id` and
`--any-build` take whatever the named or found walk resolved for.
JSON carries `walk_frame` and `walk_frame_basis`.

## Rooting the question

The build is resolved in this order, and the first one available wins:

| | Where the build comes from |
|---|---|
| `--walk-id <id>` | that stored walk, queried as named |
| `--gomod <path>` | the latest succeeded project walk for that `go.mod`, in the scope asked for |
| _(none of them)_ | the `go.mod` in the working directory, on the same terms |

`--gomod` uses the same selector as `vuln-show`, `context` and `reachability`:
among the walks of the module that manifest declares, it takes the requested
**scope** on this **platform**, prefers one resolved by the **toolchain** the
project resolves today, and prefers one whose recorded resolution still agrees
with the manifest's `require` directives. See
[conventions](conventions.md#the-build-frame) for the shared rule.

The scope defaults to **code** - the modules the project's own code builds
against. `--tool` selects the tooling closure (the `go.mod` `tool` directives)
and `--project` the complete set. They are different builds holding different
modules: on this repository the code walk holds 22 module versions and the tool
walk 246, 235 of which the code walk does not contain. A linter is answerable
under `--tool` and is genuinely not in your code build.

The answer states which build it is about, above the rows:

```
notice: ./go.mod names the build, so the answer below is walk
01M0RGVEZH7BN09G63JX3B1X88 (code scope, frame linux/amd64) rooted at
github.com/eitanity/kanonarion@local; the require directives in ./go.mod agree
with that walk, though the manifest was not re-resolved through the toolchain
for this read
3 module(s) in walk 01M0RGVEZH7BN09G63JX3B1X88 (frame linux/amd64) depend on
golang.org/x/mod@v0.40.0 (the walk root does; it is excluded by default — pass
--include-root):
  github.com/rogpeppe/go-internal@v1.15.0  [direct]
  golang.org/x/tools@v0.49.0               [direct]
  modernc.org/libc@v1.73.5
```

### When no build can be resolved

With no `--walk-id`, no `--gomod` and no `go.mod` in the working directory there
is nothing for the question to be about, so the command refuses (exit 20) and
names the three ways to give it one. It does **not** search:

```
what a coordinate is surrounded by is a property of one build, and this question
names none: no --walk-id, no --gomod, and no go.mod in the working directory.
Name the build you mean:
  --gomod ./go.mod    answer from the latest project walk for that go.mod (add --tool or --project for another scope)
  --walk-id <id>      answer from one stored walk (kanonarion walk-list lists them)
  --any-build         search this store for a build that holds golang.org/x/mod@v0.40.0
```

### When the build does not contain the module

Asked about a module the resolved build does not hold, the command says so and
names the builds of the same project that **do** hold it, narrowest first, with
the flag that selects one (exit 20). It never reports the module as having no
dependents, and it never widens the scope on your behalf:

```
walk 01M0RGVEZH7BN09G63JX3B1X88 (code scope, frame linux/amd64), rooted at
github.com/eitanity/kanonarion@local, does not contain
4d63.com/gochecknoglobals@v0.2.2; the store holds it in the tool scope on
linux/amd64 (walk 01M0AFRTTC8DF0JQAFHB7RZM8N) and complete scope on linux/amd64
(walk 01M0ABH9573T0TW1BBRSQ7KCZ1) of github.com/eitanity/kanonarion@local — ask
there:
  kanonarion dependents 4d63.com/gochecknoglobals@v0.2.2 --gomod ./go.mod --tool
```

A version the build resolved differently is named the same way, because that is
usually what the question was:

```
... does not contain golang.org/x/sync@v0.21.0; it resolved golang.org/x/sync at
v0.22.0; no current build of github.com/eitanity/kanonarion@local holds it
either — the newest walk of each scope and platform was checked, and an older one
still may, so search them all with:
  kanonarion dependents golang.org/x/sync@v0.21.0 --any-build
```

Only the newest walk of each scope-and-platform is read, so the sentence says so
rather than claiming the store has never held the coordinate.

## `--any-build`: which of my projects uses this

`--any-build` searches the store instead of rooting at a project. It answers a
different question - "which of my projects uses this at all" - and it is not the
default.

Candidates are ranked by **rooting** first and by recency only within a rooting:
a walk rooted at a build that consumes the target outranks a walk rooted at the
target itself, because the self-rooted walk holds the target's own dependency
closure and answers with the target's own dependencies. The answer says so:

```
notice: no walk was named; walk 01M0VG1267S1XDJGDFZTVRPM84 was chosen because it
is rooted at github.com/cortezaproject/corteza/server@local, which builds
golang.org/x/net@v0.33.0 — 1 walk(s) rooted at golang.org/x/net@v0.33.0 itself
were passed over, since a module has no dependents inside its own graph; pin one
with --walk-id (kanonarion walk-list lists them)
```

Where the target's own walk is the **only** walk holding it - a module vetted in
isolation and walked nowhere else - it still answers, and states what the answer
is about:

```
notice: the only walk holding github.com/spf13/cobra@v1.8.1 in this store is
rooted at github.com/spf13/cobra@v1.8.1 itself, so the answer below is drawn from
that module's own dependency graph and names no consuming build; walk
01KZWK6GHN7CK9Y54YTHMTNRKJ
```

Several walks of one build are not a choice between builds: the most recent of
them answers.

### `--any-build`: two builds is a refusal, not a coin toss

Where more than one build holds the target, there is no answer that is not about
somebody's build, so the command refuses (exit 20) and names the candidates -
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

A **rooted** question never hits this: one project's build holds a coordinate
once. Standing in corteza, the same coordinate answers `11`; in ragflow, `5`;
in this repository's complete scope, `2`.

### `--any-build`: the search is bounded, and says so

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
    "rule": "gomod-rooted",
    "root": "github.com/caddyserver/caddy/v2@v2.11.2",
    "self_rooted_passed_over": 0,
    "gomod": "./go.mod",
    "scope": "code",
    "choice": {
      "rule": "manifest-match",
      "candidates": 2,
      "candidate_set": "in the code scope on linux/amd64 under go1.26.6",
      "manifest_path": "./go.mod"
    }
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
| `walk_selection.rule` | string | How that walk was reached: `gomod-rooted` (a manifest named the build), `pinned` (you named the walk), `consumer-rooted` (`--any-build` found a build that consumes the target), `self-rooted-only` (`--any-build`, and the only walks holding the target are rooted at the target, so the answer is from its own graph) |
| `walk_selection.root` | string | The answering walk's target: the build the answer is about |
| `walk_selection.self_rooted_passed_over` | int | How many walks rooted at the queried coordinate a consuming build outranked. Always 0 outside `--any-build` |
| `walk_selection.gomod` | string | The manifest that named the build. `gomod-rooted` only |
| `walk_selection.scope` | string | The dependency scope it was projected into: `code`, `tool` or `complete`. `gomod-rooted` only |
| `walk_selection.choice` | object | The selector's account of which of the project's walks answered - `rule`, `candidates`, `candidate_set`, `manifest_path`, and where they apply `disagreements`, `reason` and `toolchain_divergence`. Same object the other `--gomod` reads publish. `gomod-rooted` only |
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
| `--gomod <path>` | `./go.mod` | Answer from the latest project walk for this manifest — see [rooting the question](#rooting-the-question) |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` `tool` directives' closure) |
| `--project` | false | Scope to the complete set: the project's code AND tooling |
| `--walk-id <id>` | _(unset)_ | Walk record ID to query, in place of a manifest. Overrides the manifest rooting |
| `--any-build` | false | Search the store for a build that holds the target instead of rooting at a project — see [`--any-build`](#--any-build-which-of-my-projects-uses-this) |
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

`--tool`, `--project` and `--gomod` project a manifest into one of its build
scopes, so `--walk-id` and `--any-build` - neither of which reads a manifest -
refuse them rather than accepting and discarding them.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (zero results is not an error) |
| 4 | Walk ID not found |
| 10 | Walk record integrity check failed |
| 20 | Malformed invocation; no build could be resolved; the resolved build does not contain the target; a flag the dispatch path cannot act on; under `--any-build`, no walk contains the target or more than one build holds it |

## Examples

```sh
# Full blast radius for an x/net upgrade, in the build you are standing in
kanonarion dependents golang.org/x/net@v0.51.0

# A linter is in the tooling closure, not the code build
kanonarion dependents 4d63.com/gochecknoglobals@v0.2.2 --tool

# Another project's build, without leaving this one
kanonarion dependents github.com/pkg/errors@v0.9.1 \
  --gomod ../corteza/server/go.mod

# Which of my projects uses this at all
kanonarion dependents github.com/pkg/errors@v0.9.1 --any-build

# One stored walk, queried as named
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
  --include-root --json \
  | jq '[.dependents[] | select(.direct or .root)]'

# Count how many modules in the closure depend on a target
kanonarion dependents golang.org/x/crypto@v0.48.0 \
  --json | jq '.dependents | length'

# Which build answered, and how it was rooted
kanonarion dependents golang.org/x/crypto@v0.48.0 --json \
  | jq '{walk_id, rooting: .walk_selection.rule, build: .walk_selection.root}'
```

## Relationship to other commands

- **Requires:** a stored `WalkRecord` - run `kanonarion walk` first.
- **Complementary:** `kanonarion callers` finds callers of a specific *symbol*;
  `dependents` works at module granularity.
- **See also:** `kanonarion walk-diff` to compare two walks after an upgrade.

## Notes

- The target version must match exactly the MVS-selected version recorded in the
  walk. A rooted read refuses and names the version the build did resolve; under
  `--walk-id` a version the walk does not hold gives zero results, which is the
  correct answer for that walk.
- A zero-result response is not an error (exit 0). It means the module is in the
  build but nothing in it has an edge to the module, or the only thing that does
  is the walk root (which is excluded by default). "Not in this build" is a
  refusal, not a zero.
- The answer is always about one build, and which build is stated on every
  surface — in the answer line, in the notice above it, and as `walk_selection`
  under `--json`. Relaying the count without the build it came from drops the
  half of the answer that makes it true.
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
