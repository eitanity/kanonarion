# `kanonarion interface-diff` - Exported API Changes Between Two Versions

Compares two stored interface records and reports the exported declarations
**added**, **removed**, **changed**, and **respelt** between them - and, across a
major-version path pair, the ones that only moved to a new import path. With
`--used-by` it joins the delta against a project's stored call graph and reports
which of the breaking changes that project's own code actually calls.

## What the answer is, and what it is not

`interface-diff` counts **exported Go signatures**. It does not measure
behaviour, and it never says a version bump is safe.

A measured zero-breaking bump (`github.com/spf13/cast` v1.4.1 → v1.10.0) changed
38 behavioural outcomes while changing no signature at all. The headline states
the fact and the scope it holds over, and nothing more:

```
0 breaking change(s) among exported Go declarations (github.com/spf13/cast@v1.4.1 → github.com/spf13/cast@v1.10.0); behaviour and string-keyed registries are outside this comparison
```

When that zero sits on top of a delta that is **not** empty - anything respelt,
added, or carried to a new import path - the output says so where the zero is
printed, not in the footer:

```
a zero here is not reassurance. This comparison reads exported signatures, so it cannot see behaviour: a release that changes no signature at all can still change what your calls return. A zero-breaking bump is the case that most needs checking against something this command does not measure.
  what would answer it: exercise your own tests over the call sites this bump touches. Pass --used-by ./go.mod to have them enumerated here.
```

With `--used-by` the second line is replaced by the measurement: how many of the
declarations this bump moved the project's own code calls, and at how many
recorded call sites. With no stored call graph, that line says the reach could
not be measured and names `kanonarion local .` rather than reporting zero.

A **genuinely empty** delta keeps the terse two-line output.

## Prerequisites

Both records must be extracted before diffing:

```
kanonarion interface github.com/example/lib@v1.0.0
kanonarion interface github.com/example/lib@v2.0.0
```

A missing record is reported as an absence with the command that produces it -
never as "no change".

## Usage

```
kanonarion interface-diff <module>@<versionA> <module>@<versionB> [--used-by <path-to-go.mod>] [--json]
```

The usage line reads `<moduleA>@<versionA> <moduleB>@<versionB>` because the two
paths need not match. They can be the same module at two versions (the normal
case) or a **major-version path pair** - `example.com/lib` against
`example.com/lib/v2` - which is how a major-version migration is sized. See
[cross-major pairs](#cross-major-pairs) for what changes in that case.

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--used-by` | (unset) | Join the delta against the stored call graph of the project this `go.mod` declares. Takes its value as the next argument. |
| `--json` | false | Emit the structured diff |
| `--log-level` | `warn` | Log verbosity: `debug`, `info`, `warn`, `error` |

## The four categories

| Category | Meaning | Counted as breaking |
|----------|---------|---------------------|
| `added` | Declaration present only in B | no |
| `removed` | Declaration present only in A | **yes** |
| `changed` | Signature differs in a way the language does not treat as identical | **yes** |
| `spelling` | Signature text differs, meaning does not | no |
| `renamed-path` | Same declaration, same signature, new import path (cross-major pairs only) | no |

`breaking_count` is `removed + changed`. Spelling and renamed-path are excluded
by construction. The `renamed-path` count is printed only for a cross-major pair,
which is the only comparison that can produce one.

### What counts as spelling

A signature is a spelling change when the two texts denote the same Go
declaration. The comparison parses both with `go/parser`, rewrites the tree, and
prints it back, so a nested spelling (`map[string]interface{}`) is reached as
reliably as a bare one. Exactly three things are collapsed:

- **the predeclared aliases** - `interface{}` and `any`, `byte` and `uint8`,
  `rune` and `int32` are the same types, not merely convertible ones;
- **parameter and result names** - they are not part of a function's type, so a
  signature that stops naming its results has the type it always had;
- **source layout**.

Nothing else. A renamed struct field, a changed struct tag, an added parameter,
a different argument type: each of those can break a consumer, and each survives
normalisation. A signature that will not parse is never reported as
spelling-equivalent - an unreadable signature is not evidence of sameness.

Source **positions are not compared at all**: a declaration that moved down its
file is the same declaration. `github.com/golang-jwt/jwt/v4` v4.5.1 → v4.5.2
moves five declarations and changes nothing, and reads as zero deltas.

## Cross-major pairs

Two coordinates whose module paths are equal once a trailing `/vN` is stripped -
`github.com/Masterminds/sprig` and `github.com/Masterminds/sprig/v3`, or
`.../jwt/v4` and `.../jwt/v5` - are a **major-version path pair**. Only `/v2` and
above are module path suffixes; a trailing `/v0`, `/v1` or `/vNext` is an
ordinary path element and does not pair.

Across such a pair every import path changes. Declarations are therefore matched
by **package-relative path, kind and name** rather than by import path, and the
output differs from a same-path comparison in four ways:

- declarations that carried over with an identical signature are reported as
  `renamed-path` and are **not** breaking - the consumer owes an import rewrite,
  not a search for a symbol that is gone;
- a declaration that matched on identity but whose signature really changed is
  **one** `changed` entry naming both identities (`old.Parse (func) → new.Parse
  (func)`), not a removal plus an addition;
- declarations that genuinely disappeared or appeared are still `removed` and
  `added`, and still count;
- the pair's own `package removed` / `package added` lines are suppressed. A
  subpackage that really was dropped or introduced is still reported, under the
  import path the side it exists on spells.

A line above the delta states the pair and what it costs:

```
cross-major pair: the module path changes from github.com/Masterminds/sprig to github.com/Masterminds/sprig/v3, so every import of it must be rewritten — including the 7 declaration(s) that carried over otherwise unchanged (renamed-path: an import rewrite, not a breaking change). Declarations are matched by package-relative path, kind and name rather than by import path.
```

`--used-by` is unaffected: it still enumerates the breaking deltas and still
exits 5 when the project's own code calls one. A rename the consumer must
perform is work, but it is not a broken build, and it does not fire the gate.

## Blind spots the output names

**String-keyed registries.** A package that exports a `template.FuncMap`,
a `map[string]any`, or any other string-keyed table of functions has a contract
this command cannot see: the keys are strings resolved at run time, so a key
renamed or dropped changes what consumers get while every signature stays
identical. Such a surface is **flagged** whenever either record exports one, as a
variable, a constant or a function result. Detection only: the keys are never
read and never diffed.

**A build frame mismatch.** Every record names the build it was measured in, and
the output opens with that frame. When the two sides disagree — different
platforms, or one record too old to name a frame — the line says so, because a
declaration in one platform's build and not the other's is reported as `removed`
or `changed` by a comparison that cannot see why. The pre-frame records are the
worst case: they hold every platform's declarations at once and pick between
duplicates arbitrarily, which once made 36 of 37 reported breaking changes on
one real version pair artefacts of the pick. Re-extract both sides.

**`testdata` packages.** Packages under a `testdata` directory are excluded from
the comparison on both sides. The go tool does not build them and no consumer
can import them, so a version that carries one more is not a version that added
a package (measured on `golang.org/x/text`, which carries four). The excluded
paths are listed rather than dropped silently.

## `--used-by`: does MY code call any of it?

`--used-by ./go.mod` resolves the module that `go.mod` declares to the **latest
succeeded code-scope project walk** for it, on this platform - the same
resolution `callers --gomod` performs - and asks the **stored** call graph which
of the breaking deltas the project's own code calls. It never re-parses the
consumer's source, so the answer cannot disagree with what `callers` says about
the same symbol.

The code scope is the question: this asks what the consumer's own code calls, so
it is answered in the build that code compiles into. A project walked only in
another scope is refused, naming the scopes the store holds and the `walk`
command that produces the missing one. The section header names the scope of the
walk that answered, beside its frame; `walk_scope` carries the same fact in the
JSON.

The walk is found by the module path the `go.mod` declares, and the `go.mod` is
not re-resolved for the read: the section header says so beneath itself, because
"your code does not call the removed symbol" is the answer a scope taken before
your last dependency edit gets wrong quietly. `walk --gomod` records the current
resolution. `gomod` in the JSON is the manifest path that was resolved to find
the walk.

For each breaking delta the output reports one of three things:

- `!` - reached: the number of recorded call sites, and each calling function
  with the file and line it is declared at;
- `·` - no call edge recorded from the consumer's own module;
- `?` - unmeasured: types, constants and variables have no call-graph node, so
  the call graph cannot answer the question for them.

Edges owned by other dependencies are excluded: a call the consumer did not
write is not a call it can fix.

### Coverage note

```
coverage: reached/not-reached is measured over recorded CALL EDGES in the stored call graph. Method values (a method referenced as a value rather than called) are not recorded as edges, so a symbol shown as not reached may still be referenced that way. Types, constants and variables have no call-graph node at all and are reported as unmeasured rather than as unreached.
```

If the project has no stored call graph at all, the run says so and points at
`kanonarion local .` - the silence that follows is an absence of evidence, not
evidence of absence.

## Examples

```sh
# Size an upgrade
kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0

# Size a major-version migration (a cross-major pair)
kanonarion interface-diff github.com/golang-jwt/jwt/v4@v4.5.1 github.com/golang-jwt/jwt/v5@v5.3.1

# A pre-modules major against a proper /vN one - also a pair
kanonarion interface-diff github.com/Masterminds/sprig@v2.22.0+incompatible github.com/Masterminds/sprig/v3@v3.3.0

# Does my project actually touch any of what broke?
kanonarion interface-diff github.com/golang-jwt/jwt/v4@v4.5.1 github.com/golang-jwt/jwt/v5@v5.3.1 \
  --used-by ./go.mod

# Machine-readable, for CI or an agent
kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0 --json
```

## JSON output

`--json` emits a single deterministic object. **The declaration kinds use the
interface record's own short names** - `func`, `type`, `method`, `const`, `var`,
matching what `interface-show --json` emits. Guessing them wrong produces a
silent zero-declaration comparison.

| Field | Type | Description |
|-------|------|-------------|
| `module_a` | string | First coordinate (`path@version`) |
| `module_b` | string | Second coordinate (`path@version`) |
| `breaking_count` | number | `removed` + `changed` |
| `scope` | string | The standing statement of what is and is not compared |
| `packages_added` | array of strings | Import paths only B has |
| `packages_removed` | array of strings | Import paths only A has |
| `added` | array | `{package, kind, name, signature}` |
| `removed` | array | `{package, kind, name, signature}` |
| `changed` | array | `{package, kind, name, from, to}` |
| `spelling` | array | `{package, kind, name, from, to}` - not breaking |
| `major_path_pair` | bool | The two coordinates are one module's two majors |
| `renamed_path` | array | `{package, kind, name, moved_to_package, signature}` - not breaking |
| `zero_breaking_advisory` | string or absent | Present exactly when the text output prints the zero-breaking statement |
| `registries` | array | `{package, kind, name, shape, side}` - `side` is `A`, `B` or `both` |
| `excluded_testdata_packages` | array of strings | Paths dropped from the comparison |
| `build_frame_a` | string | Frame A was measured in, or `unrecorded` |
| `build_frame_b` | string | Frame B was measured in, or `unrecorded` |
| `frame_mismatch` | bool | The two sides are not the same build |
| `used_by` | object or absent | Present only with `--used-by` |

`used_by` carries `gomod`, `walk_id`, `walk_frame` (the `GOOS/GOARCH` that
walk resolved for, or `not-platform-scoped`), `walk_frame_basis`, `consumer`,
`scope_size`,
`call_graph_found`, `reached_count`, `coverage`, and `symbols` - each
`{package, kind, name, class, node_id, measurable, sites, callers}` with
`callers` as `{id, file, line}`. Every collection is emitted as `[]` when empty,
never as `null`.

It also carries `touched`, `touched_reached_count` and `touched_call_sites`: the
non-breaking declarations this bump moved - respellings and path renames - joined
against the same call graph. They are populated only when the zero-breaking
statement applies, they are named on the **A-side** identity (what the consumer
calls today), and they never affect the exit code. `changed` and `renamed_path`
rows carry `moved_to_package` when the declaration moved as well.

```json
{
  "module_a": "github.com/example/lib@v1.0.0",
  "module_b": "github.com/example/lib@v2.0.0",
  "breaking_count": 1,
  "packages_added": [],
  "packages_removed": [],
  "added": [],
  "removed": [
    { "package": "github.com/example/lib", "kind": "func", "name": "Gone", "signature": "func Gone() error" }
  ],
  "changed": [],
  "spelling": [
    { "package": "github.com/example/lib", "kind": "func", "name": "Cast",
      "from": "func Cast(i interface{}) error", "to": "func Cast(i any) error" }
  ],
  "major_path_pair": false,
  "renamed_path": [],
  "registries": [],
  "excluded_testdata_packages": []
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | The comparison ran; any breaking changes it found are not called by the project (or `--used-by` was not passed) |
| 4 | One or both interface records are not in the store |
| 5 | `--used-by` found a breaking change **within the used set**: the project's own code calls it |
| 20 | Malformed invocation - an unparseable coordinate, a missing value for a flag |

## Scope notes

- The comparison is a pure function over two records. Two runs over the same
  pair produce byte-identical output.
- Both records are read at the current pipeline version. A record extracted with
  an older one will not be found; re-run `kanonarion interface` to refresh it.
- Churn across a series of versions is not measured here: `interface-diff`
  compares exactly two records.
- A cross-major pair is recognised from the module **paths** alone. The version
  strings are never consulted for it, so a `+incompatible` side pairs with a
  `/vN` side exactly as two `/vN` sides do.
- Packages under `internal/` **are** compared: their declarations are exported
  Go declarations and appear in the record.

See also: [`interface`](interface.md), [`callgraph`](callgraph.md),
[`local`](local.md), [`license-diff`](license-diff.md).

## Modules resolved under pre-modules semantics

A `+incompatible` coordinate resolves no requirement edges at all, so what this command can show about such a version is bounded — the two coordinates being compared are not two points on one module's version line the way the rest of the output implies. The answer states that and names the coordinates responsible; see [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
