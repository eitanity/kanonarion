# `kanonarion directives`

Detect, classify and policy-check every `replace` and `exclude` directive in a
project's `go.mod` (and adjacent `go.work`).

```
kanonarion directives [--gomod ./go.mod] [--json]
```

## Why this exists

`replace` and `exclude` modify dependency resolution **without changing the
import graph**, so they are invisible to anyone reading import statements:

- a `replace` → **local path** has no remote checksum to verify against;
- a `replace` → **different module path** silently substitutes a fork that
  still satisfies the original import;
- an `exclude` of a version **newer** than the resolved one can force
  resolution off a CVE-patched release.

`directives` makes them first-class facts: enumerated with file/line, risk
classified, policy-evaluated, and recorded as audit events.

## Risk classification

| Directive                                   | Class    |
|---------------------------------------------|----------|
| `replace` → local path                      | highest  |
| `replace` → different module path (fork)    | high     |
| `replace` → different version, same module  | medium   |
| `exclude` of version newer than resolved    | high     |
| `exclude` of version older than resolved    | low      |
| `exclude` whose resolved version is unknown | high (fails safe - absence is surfaced, never assumed clean) |

Directives that do not affect the current build (e.g. a `go.mod` replace
overridden by a `go.work` replace) are recorded with `"applied": false` -
never silently dropped.

## Policy & exit code

Each directive is evaluated against the `directive_policy` governance block
(config schema v2). The default policy flags **local-path replace**
(`warn`). When any directive resolves to `warn`, the command exits **20**
(`ExitConfig`) - suitable as a CI gate. Per-org overrides/waivers are
Enterprise.

## Output

`--json` emits the deterministic top-level `directives` section
(`schema_version`, `ecosystem`, `pipeline_version`, `project`, `content_hash`,
`directives[]`). `ecosystem` is always `"go"` - it declares the schema's scope
(kanonarion is fitted for Go), not a polyglot mode. Each entry carries
`classification`, `applied`,
`reachability_target` and `policy_outcome` so an agent can reason about
whether a replacement is approved. The same section appears in
`kanonarion inspect --gomod … --json` as the aggregate surface.

## Scan history

```
kanonarion directives list [--project <module>] [--gomod ./go.mod] [--limit <n>] [--offset <n>] [--json]
```

Prints the directive scan history for a project, newest first. `--project` is
inferred from `./go.mod` when omitted.

| Flag | Default | Description |
|------|---------|-------------|
| `--project` | inferred from `go.mod` | Project module path |
| `--gomod` | `./go.mod` | `go.mod` used to infer `--project` |
| `--limit` | `20` | Maximum number of scans to list (0 = unlimited) |
| `--offset` | `0` | Skip this many scans before listing |

When the limit bites, the listing says so on both output paths and names the
invocation that lifts it, per [Truncated listings](conventions.md#truncated-listings).

An empty history distinguishes the project from the store. Where the project has
scans, the count is that project's and the remaining cause is paging; where it
has none, the count is the whole store's, so a mistyped `--project` over a
stocked store reads differently from a store nothing has ever been scanned into:

```
$ kanonarion directives list --project example.com/typo
no directive scan matched project "example.com/typo" — the value is compared for exact equality
against the project module path of all 7 directive scan(s) in the store
  to list every directive scan: kanonarion directives list --project <module-path>
```

Every read is keyed on a project, so there is no invocation that lists the store
unfiltered; the remedy names the `--project` slot instead.

`directives show <scan-id>` answers a scan id it does not hold the same way, on
one line, exiting `4`.

## Scope notes

- The scan records each replace's `reachability_target` (the module/local path
  whose code actually compiles). Re-targeting walk/callgraph reachability to
  it is a planned follow-up.
- The scan-to-scan directive diff (added/removed change events) is available
  via `directives diff`.
- Resolved versions used for `exclude` newer/older come from the project
  `go.mod` require set; full MVS-closure resolution is a planned follow-up.

## Audit

Every directive is appended to `audit.jsonl` as a
`replace_directive_observed` / `exclude_directive_observed` event with
classification and policy verdict.
