# `kanonarion interface-diff` - Exported API Changes Between Two Versions

Compares two stored interface records and reports the exported declarations
**added**, **removed**, **changed**, and **respelt** between them. With
`--used-by` it joins the delta against a project's stored call graph and reports
which of the breaking changes that project's own code actually calls.

## What the answer is, and what it is not

`interface-diff` counts **exported Go signatures**. It does not measure
behaviour, and it never says a version bump is safe.

That distinction is not pedantry. A measured zero-breaking bump
(`github.com/spf13/cast` v1.4.1 → v1.10.0) changed 38 behavioural outcomes while
changing no signature at all. The headline therefore states the fact and the
scope it holds over on one line, and nothing more:

```
0 breaking change(s) among exported Go declarations (github.com/spf13/cast@v1.4.1 → github.com/spf13/cast@v1.10.0); behaviour and string-keyed registries are outside this comparison
```

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

The two coordinates can be the same module at two versions (the normal case) or
different module paths entirely - comparing `example.com/lib` with
`example.com/lib/v2` is how a major-version migration is sized.

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

`breaking_count` is `removed + changed`. Spelling is excluded by construction.

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

## Blind spots the output names

**String-keyed registries.** A package that exports a `template.FuncMap`,
a `map[string]any`, or any other string-keyed table of functions has a contract
this command cannot see: the keys are strings resolved at run time, so a key
renamed or dropped changes what consumers get while every signature stays
identical. Such a surface is **flagged** whenever either record exports one -
as a variable, a constant, or the result of a function, which is how
`github.com/Masterminds/sprig` publishes its. Detection only: the keys are never
read and never diffed.

**`testdata` packages.** Packages under a `testdata` directory are excluded from
the comparison on both sides. The go tool does not build them and no consumer
can import them, so a version that carries one more is not a version that added
a package (measured on `golang.org/x/text`, which carries four). The excluded
paths are listed rather than dropped silently.

## `--used-by`: does MY code call any of it?

`--used-by ./go.mod` resolves the module that `go.mod` declares to the **latest
succeeded project walk** for it - the same resolution `callers --gomod`
performs - and asks the **stored** call graph which of the breaking deltas the
project's own code calls. It never re-parses the consumer's source, so the
answer cannot disagree with what `callers` says about the same symbol.

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

# Size a major-version migration
kanonarion interface-diff github.com/golang-jwt/jwt/v4@v4.5.1 github.com/golang-jwt/jwt/v5@v5.3.1

# Does my project actually touch any of what broke?
kanonarion interface-diff github.com/golang-jwt/jwt/v4@v4.5.1 github.com/golang-jwt/jwt/v5@v5.3.1 \
  --used-by ./go.mod

# Machine-readable, for CI or an agent
kanonarion interface-diff github.com/spf13/cast@v1.4.1 github.com/spf13/cast@v1.10.0 --json
```

## JSON output

`--json` emits a single deterministic object. **The declaration kinds use the
interface record's own short names** - `func`, `type`, `method`, `const`, `var`,
matching the `funcs` / `consts` / `vars` collections `interface-show --json`
emits. Guessing them wrong produces a silent zero-declaration comparison, so
they are stated here rather than left to be inferred.

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
| `registries` | array | `{package, kind, name, shape, side}` - `side` is `A`, `B` or `both` |
| `excluded_testdata_packages` | array of strings | Paths dropped from the comparison |
| `used_by` | object or absent | Present only with `--used-by` |

`used_by` carries `gomod`, `walk_id`, `walk_frame` (the `GOOS/GOARCH` that
walk resolved for, or `unrecorded`), `consumer`, `scope_size`,
`call_graph_found`, `reached_count`, `coverage`, and `symbols` - each
`{package, kind, name, class, node_id, measurable, sites, callers}` with
`callers` as `{id, file, line}`. Every collection is emitted as `[]` when empty,
never as `null`.

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

Exit 5 is the policy code because the command ran to completion, measured the
stored evidence, and the gate the caller asked for fired on a real finding. That
is the gate working, and CI must be able to route it to a human rather than to
whoever fixes broken invocations.

## Scope notes

- The comparison is a pure function over two records. Two runs over the same
  pair produce byte-identical output.
- Both records are read at the current pipeline version. A record extracted with
  an older one will not be found; re-run `kanonarion interface` to refresh it.
- Churn across a series of versions is not measured here: `interface-diff`
  compares exactly two records.
- Packages under `internal/` **are** compared. Their declarations are exported
  Go declarations and appear in the record; that they are not importable from
  outside the module is not something this command's counts distinguish.

See also: [`interface`](interface.md), [`callgraph`](callgraph.md),
[`local`](local.md), [`license-diff`](license-diff.md).
