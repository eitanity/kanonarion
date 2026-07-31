# `kanonarion latest` - Latest published version lookup

## Synopsis

```
kanonarion latest <module> [<module>...]
kanonarion latest [--gomod <path>] [flags]
```

## Description

`latest` queries the Go module proxy for the latest published version of one or
more modules.

With `--gomod` (or from a directory containing `go.mod`), it resolves the
project's dependency **scope** and reports the pinned version of each module
against the latest available - letting you see version staleness across your
dependency tree in a single call. The scope is consistent with every other
go.mod command: the default is the project's own **code** dependencies (`go list
-deps -test ./...`); `--tool` reports the tooling supply chain; `--project`
reports the complete set (code + tooling, the full Go build list). `--tool` and
`--project` are mutually exclusive. See
[`walk` Scopes](walk.md#scopes-code-tool-complete).

Without a module argument or `--gomod`, `latest` defaults to `./go.mod` in the
current directory. If no `go.mod` exists there, it returns an error.

Without `--gomod`, one or more module paths may be passed as positional
arguments and the result shows the latest version with its release date
for each. With a single module, `--json` emits an object; with multiple,
`--json` emits an array (matching the `--gomod` shape) so the output is
trivially `jq`-pipeable. Argument order is preserved.

### Two facts, never merged

A Go module's next **major** version lives at a *different* module path
(`.../v4` -> `.../v5`, or a bare path -> `.../v2`). A query on the path as
written can therefore never see it, and a dependency pinned several majors
behind resolves as the latest version of its own path - `current`, the strongest
answer the column has - while being the most stale kind of dependency there is.

`latest` reports both, as separate fields:

- **latest** - the newest version at the module path itself (`latest`,
  `latest_date`, `is_latest`). Unchanged.
- **newer major** - the newest major-suffixed path above the pinned major that
  resolves, with its version and date (`newer_major_module`,
  `newer_major_latest`, `newer_major_date`).

The probe starts one major above the **pinned version's** major - not above the
path suffix, because a `+incompatible` pin carries its major in the version
while living at the unsuffixed path - and stops at the first major that does not
resolve. `major_probed` distinguishes "probed, nothing newer" from "not probed"
(an offline run, or a probe whose request failed); a question that was never
asked is never rendered as a clean answer.

Whether the newer major is *adoptable* is a different question - a new major is
expected to be breaking. This only stops a several-majors-behind module reading
as up to date.

### The staleness ledger

Every successful `@latest` resolution - including the major probe, and including
the recorded negative "no newer major exists" - is written to a store-side
ledger keyed on module path. Any command that reports staleness (`latest`,
`audit`) serves a recording younger than `staleness.ttl` instead of re-querying,
so a `latest` run and an `audit` minutes later pay the proxy sweep once between
them rather than once each.

Every answer states the lookup time it used, so a served answer is never
mistaken for a live one. A table is dated by its **oldest** row: a run where
most rows were served and a few re-queried is only as current as the row asked
about longest ago.

A **failed** lookup is never written - failures are not cacheable facts. An
absent major path is not a failure: it is a definitive answer, it is what bounds
the probe, and it is recorded.

`staleness.ttl` is a config key (default `1h`; `0` disables serving). `--fresh`
bypasses the ledger for a single run and still records what it resolved.

### Integration with `fetch` and `audit`

Version staleness is baked into the two most common commands, so agents rarely
need to call `latest` directly:

- **`fetch <module@pinned>`** - annotates its output with `[latest: vX.Y.Z, N
  days ago]` when the pinned version is not the current latest.
- **`audit --gomod ./go.mod`** - includes a staleness column for every direct
  dependency alongside verification, license, and vulnerability status.

Use `latest` when you specifically want *only* version information, or when you
need the `--json` output for a structured pipeline.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--gomod` | `./go.mod` | Path to `go.mod`; report latest vs pinned for the project's code dependencies |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` tool directives' closure). Mutually exclusive with `--project` |
| `--project` | false | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the Go module proxy |
| `--fresh` | false | Re-query the proxy instead of serving recorded lookups from the store |
| `--json` | false | Emit output as JSON (global flag) |

## Text output

### Single module

```
github.com/spf13/cobra@v1.10.2 (released 45 days ago, 2025-03-28)  [as of 2026-07-31 09:14 UTC]
```

### `--gomod` table (one line per direct dependency)

```
github.com/CycloneDX/cyclonedx-go@v0.9.2      latest: v0.11.0 (released today)
github.com/google/licensecheck@v0.3.1          current
github.com/golang-jwt/jwt/v4@v4.5.1            latest: v4.5.2 (33 days ago); newer major: github.com/golang-jwt/jwt/v5@v5.3.1 (2025-11-04)
github.com/minio/minio-go/v6@v6.0.57           current; newer major: github.com/minio/minio-go/v7@v7.2.1 (2026-01-19)
golang.org/x/mod@v0.35.0                       latest: v0.36.0 (6 days ago)
modernc.org/sqlite@v1.50.0                     latest: v1.50.1 (3 days ago)

latest as of 2026-07-31 09:14 UTC (staleness.ttl 1h0m0s; --fresh to re-query)
```

`minio-go/v6` is the case this exists for: `current` is true of its own path and
a whole major line is available. The clause is appended, never substituted.

## JSON output

### Single module

```json
{
  "module": "github.com/spf13/cobra",
  "latest": "v1.10.2",
  "latest_date": "2025-03-28T...",
  "days_behind": 0,
  "is_latest": true,
  "major_probed": true,
  "looked_up_at": "2026-07-31T09:14:02Z",
  "served_from_store": false
}
```

### `--gomod` array

```json
[
  {
    "module": "golang.org/x/mod",
    "pinned": "v0.35.0",
    "latest": "v0.36.0",
    "latest_date": "2025-05-08T...",
    "days_behind": 6,
    "is_latest": false,
    "major_probed": true,
    "looked_up_at": "2026-07-31T09:14:02Z",
    "served_from_store": false
  },
  {
    "module": "github.com/minio/minio-go/v6",
    "pinned": "v6.0.57",
    "latest": "v6.0.57",
    "latest_date": "2020-12-21T...",
    "days_behind": 0,
    "is_latest": true,
    "newer_major_module": "github.com/minio/minio-go/v7",
    "newer_major_latest": "v7.2.1",
    "newer_major_date": "2026-01-19T...",
    "major_probed": true,
    "looked_up_at": "2026-07-31T09:14:02Z",
    "served_from_store": true
  }
]
```

`latest_date` is **omitted entirely** when the proxy supplied no publication date for
the version, rather than being emitted as the zero time. A module whose date is
unknown previously rendered `"latest_date": "0001-01-01T00:00:00Z"` — a fabricated
date offered where the honest answer is no date at all. Text output makes the same
distinction: such a module prints `module@version` with no "released …" clause.

## Agentic workflow

The recommended pattern for an agent answering "which of my deps need an
upgrade?":

```bash
# Step 1: get a full snapshot - versions, staleness, licenses, vulns - one call
kanonarion audit --gomod ./go.mod --json

# Step 2: for any dep where is_latest=false, fetch the candidate and compare
kanonarion fetch github.com/foo/bar@v1.5.0 --json
```

`audit` resolves staleness for every module in scope through the same ledger
`latest` writes, so running both back to back pays the proxy sweep once. Note
that `is_latest: true` is about the module *path*: check `newer_major_module`
as well, or a dependency a whole major line behind will read as up to date.

## Examples

```bash
# Latest version of a single module
kanonarion latest github.com/spf13/cobra

# Latest versions of multiple modules in one call
kanonarion latest github.com/spf13/cobra github.com/stretchr/testify

# Machine-readable version info (object for single, array for multiple)
kanonarion latest github.com/spf13/cobra --json
kanonarion latest github.com/spf13/cobra github.com/stretchr/testify --json

# Staleness report using ./go.mod (auto-detected from current directory)
kanonarion latest

# Staleness report with explicit path
kanonarion latest --gomod ./go.mod

# JSON staleness report for pipeline use
kanonarion latest --gomod ./go.mod --json

# Check staleness of the tooling supply chain
kanonarion latest --gomod ./go.mod --tool

# Check staleness of the complete set (code + tooling)
kanonarion latest --gomod ./go.mod --project

# Bypass the ledger and re-query the proxy for every module
kanonarion latest --gomod ./go.mod --fresh

# Every dependency with a newer major line available
kanonarion latest --gomod ./go.mod --json | jq '.[] | select(.newer_major_module != null)'
```

## See also

- [`audit`](audit.md) - full check suite including staleness, licenses, and vulns
- [`fetch`](fetch.md) - fetches a module and annotates staleness inline
