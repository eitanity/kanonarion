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

Each is a separate field:

- **latest** - the newest version at the module path itself (`latest`,
  `latest_date`, `is_latest`, `pin_ahead_of_latest`). The pin is placed against
  it with `semver`, so all three positions are reported: behind (`latest: vX
  (N days ago)`), level (`current`), and **ahead** (`ahead of latest tag: vX`,
  `pin_ahead_of_latest: true`). A pin sorts ahead for ordinary reasons — a
  pseudo-version taken after the last tag, a pre-modules `+incompatible` major
  above what the unsuffixed path serves — and there is nothing at that path to
  move to, so no target and no age are offered.

  `is_latest` and `pin_ahead_of_latest` are the three-valued answer between
  them: `false`/`false` behind, `true`/`false` level, `false`/`true` ahead. Both
  are emitted on every measured row, `false` included; both are `null` together
  where no comparison was made (a failed lookup, or a bare path with no pin).

  `latest_release_age_days` is emitted on every row and is **null on an ahead
  row**, where an age would read as "you are this far behind". Zero is a value.
  See [`latest_release_age_days`](#latest_release_age_days).
- **newer major** - the newest major-suffixed path ABOVE the pinned major that
  resolves, with its version and date (`newer_major_module`,
  `newer_major_latest`, `newer_major_date`).
- **same major republished** - the pinned major's OWN `/vN` publication, with its
  version and date (`republished_module`, `republished_latest`,
  `republished_date`). Only a `+incompatible` pin can have one.
- **deprecated** - the author's own `// Deprecated:` notice on their `go.mod`
  module directive (`deprecated`), reproduced verbatim. A separate claim: the
  successor a notice names is often at a path the `/vN` probe cannot reach —
  `google.golang.org/protobuf` succeeds `github.com/golang/protobuf` on another
  host. No successor is ever inferred from name similarity.

The probe walks upward from one major above the **pinned version's** major -
not the path suffix, since a `+incompatible` pin carries its major in the
version - and stops at the first major that does not resolve. `major_probed`
distinguishes "probed, nothing newer" from "not probed" (offline, or a failed
request); the text says `newer major: not probed` there, because an unasked
question is never rendered as a clean answer.

A `+incompatible` pin is asked one extra question first: whether its **own**
major is now published at the suffixed path -
`github.com/gavv/httpexpect@v2.0.0+incompatible` has
`github.com/gavv/httpexpect/v2` published and no `/v3` at all. An absent `/vN`
there is the ordinary case and does not stop the walk. A pin already on a `/vN`
path is asked nothing extra.

It is reported **separately from the newer major**: the major NUMBER is
unchanged, only the path moved, so it is a path migration and usually much
cheaper. It renders as `same major republished:` and reaches the JSON under
`republished_*`. `republished_probed` distinguishes "asked, not republished"
from "not asked".

When both hold, **both are reported, the republication first**:

```
github.com/go-chi/chi@v3.3.4+incompatible  ahead of latest tag: v1.5.5; same major republished: github.com/go-chi/chi/v3@v3.3.5 (2023-09-07); newer major: github.com/go-chi/chi/v5@v5.3.1 (2026-07-05)
```

Whether the newer major is *adoptable* is a different question; this only stops
a several-majors-behind module reading as up to date.

### Where the `--gomod` answer comes from

With `--gomod`, the latest version of every module in the scope comes from
**one** `go list -m -u` call, not one proxy request per module, and that call is
where the deprecation notice comes from. The newer-major probe stays
kanonarion's own — `go list -m -u` does not cross a major boundary — and is the
remaining per-module request; it runs in bounded parallel rounds
(`staleness.probe_concurrency`, default 16). That bound is a correctness
setting: past it the proxy answers `200` with an empty body, a lost answer
rather than an error.

A positional `latest <module>` resolves one path at a time and cannot see a
notice. Where the ledger already recorded one, that recorded answer is **carried
forward**, not replaced with `null`: a query never costs the store a fact. Only
a resolution that can establish the fact replaces it — including clearing a
notice the author has removed, which is a real event and is recorded as the
negative `""`. The same holds under `--fresh`, which suppresses serving the
recorded row, not knowing it.

The go command resolves within the pin's own major, with two consequences. A
`+incompatible` pin reports the newest version of THAT major —
`coreos/etcd@v3.3.10+incompatible` is offered `v3.3.27+incompatible`, not the
`v2.3.8+incompatible` the unsuffixed path serves. And a pin sitting ABOVE the
last tag comes back with no update, so those pins get `@latest` looked up
alongside the probe and keep `ahead of latest tag`; only prerelease and
`+incompatible` pins can be in that state, so only they are looked up.

Under `GOPROXY=off` the batched call is refused rather than run: it exits 0
there while reporting every module as current. Offline the ledger answers, as
below. The call warms `$GOMODCACHE`'s download cache; it writes nothing to
`go.mod`, `go.sum` or the store.

### The staleness ledger

Every successful `@latest` resolution - including the major probe, and including
the recorded negative "no newer major exists" - is written to a store-side
ledger keyed on module path. Any command that reports staleness (`latest`,
`audit`) serves a recording younger than `staleness.ttl` instead of re-querying,
so a `latest` run and an `audit` minutes later pay the sweep once between them.

Every answer states the lookup time it used, so a served answer is never taken
for a live one. A table is dated by its **oldest** row: a run where
most rows were served and a few re-queried is only as current as the row asked
about longest ago.

A **failed** lookup is never written - failures are not cacheable facts. An
absent major path is not a failure: it is a definitive answer, it bounds the
probe, and it is recorded. An answer that settles nothing - an empty body, a
timeout, a 429 or a 5xx - is asked again: four attempts, ten seconds each,
over about fourteen seconds of backoff, so a sweep can pause on a module the
proxy is slow for. A definitive answer is never retried.

`staleness.ttl` is a config key (default `1h`; `0` disables serving). `--fresh`
bypasses the ledger for a single run and still records what it resolved.

### Integration with `fetch` and `audit`

Version staleness is baked into the two most common commands, so agents rarely
need to call `latest` directly:

- **`fetch <module@pinned>`** - annotates its output with `[latest: vX.Y.Z, N
  days ago]` when the pinned version is not the current latest, and with
  `[staleness unmeasured (...)]` when the question was not answered - see
  [`fetch` staleness](fetch.md#staleness-annotation).
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
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the Go module proxy, honoured not rewritten. Under `off`, a lookup younger than `staleness.ttl` is served and nothing is written; without one, exit `20`. `direct` and `--fresh` refuse. See [`fetch`: `GOPROXY=off` and `direct`](fetch.md#goproxyoff-and-direct) |
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
github.com/pmezard/go-difflib@v1.0.1-0.20181226105442-5d4384ee4fb2  ahead of latest tag: v1.0.0
modernc.org/sqlite@v1.50.0                     latest: v1.50.1 (3 days ago)

latest as of 2026-07-31 09:14 UTC (staleness.ttl 1h0m0s; --fresh to re-query)
```

`minio-go/v6` is the case this exists for: `current` is true of its own path
while a whole major line is available. Clauses are appended, never substituted.
`go-difflib` is the other one: a pseudo-version taken after v1.0.0 sorts *above*
the tag, and `latest: v1.0.0` would name a downgrade as the target.

## JSON output

### Single module

```json
{
  "module": "github.com/spf13/cobra",
  "latest": "v1.10.2",
  "latest_date": "2025-03-28T...",
  "latest_release_age_days": 491,
  "is_latest": null,
  "staleness_unmeasured": "not_asked",
  "major_probed": true,
  "looked_up_at": "2026-07-31T09:14:02Z",
  "served_from_store": false
}
```

A bare module path names **no pin**, so there is nothing for `is_latest` to
compare against: it is `null` with `staleness_unmeasured: not_asked`. Pass the
version you care about through `--gomod` (or `audit`) to get the comparison
answered.

### `--gomod` array

```json
[
  {
    "module": "golang.org/x/mod",
    "pinned": "v0.35.0",
    "latest": "v0.36.0",
    "latest_date": "2025-05-08T...",
    "latest_release_age_days": 6,
    "is_latest": false,
    "major_probed": true,
    "deprecated": "",
    "looked_up_at": "2026-07-31T09:14:02Z",
    "served_from_store": false
  },
  {
    "module": "github.com/aws/aws-sdk-go",
    "pinned": "v1.55.8",
    "latest": "v1.55.8",
    "is_latest": true,
    "major_probed": true,
    "deprecated": "aws-sdk-go is deprecated. Use aws-sdk-go-v2.\nSee https://...",
    "looked_up_at": "2026-08-17T09:14:02Z",
    "served_from_store": false
  },
  {
    "module": "github.com/minio/minio-go/v6",
    "pinned": "v6.0.57",
    "latest": "v6.0.57",
    "latest_date": "2020-12-21T...",
    "latest_release_age_days": 2050,
    "is_latest": true,
    "newer_major_module": "github.com/minio/minio-go/v7",
    "newer_major_latest": "v7.2.1",
    "newer_major_date": "2026-01-19T...",
    "major_probed": true,
    "republished_probed": false,
    "looked_up_at": "2026-07-31T09:14:02Z",
    "served_from_store": true
  },
  {
    "module": "github.com/gavv/httpexpect",
    "pinned": "v2.0.0+incompatible",
    "latest": "v1.1.3",
    "is_latest": false,
    "pin_ahead_of_latest": true,
    "major_probed": true,
    "republished_module": "github.com/gavv/httpexpect/v2",
    "republished_latest": "v2.17.0",
    "republished_date": "2025-03-04T...",
    "republished_probed": true,
    "looked_up_at": "2026-07-31T09:14:02Z",
    "served_from_store": false
  },
  {
    "module": "example.com/mod",
    "pinned": "v1.0.0",
    "latest": "(error)",
    "is_latest": null,
    "staleness_unmeasured": "lookup_failed",
    "major_probed": false,
    "served_from_store": false
  }
]
```

`deprecated` is emitted on every row, with three states: `null` — not
established (a source that cannot see the notice, or a row recorded before the
question existed); `""` — established, none declared; the notice itself. `null`
is never "not deprecated".

### When the column was not measured

`is_latest` is **null**, never `false`, when nothing was measured. `false` is
the claim "your pin is behind", and a lookup that failed established no such
thing. `staleness_unmeasured` names why:

| Text output | `is_latest` | `staleness_unmeasured` |
|---|---|---|
| `current` / `latest: ...` | `true` / `false` | absent |
| `(error resolving latest)` | `null` | `lookup_failed` |
| no staleness clause (bare path, no pin) | `null` | `not_asked` |

The failing module is also named on **stderr**, one line per module; the sweep
continues over the rest. A reader filtering for upgrade work selects
`is_latest == false`, which excludes the rows nobody answered.

### `latest_release_age_days`

`latest_release_age_days` is **how long ago the latest release shipped** — the
age of `latest`, measured from `latest_date` to now.

It is not how far behind the pin is, and the two differ whenever a module's
release cadence differs from your upgrade cadence:

| module | pinned | latest | `latest_date` | `latest_release_age_days` | how far behind the pin is |
|---|---|---|---|---|---|
| `google.golang.org/grpc` | `v1.61.1` | `v1.83.0` | 2 days ago | `2` | ~18 months |
| `github.com/joho/godotenv` | `v1.5.1` | `v1.5.1` | 1272 days ago | `1272` | nothing — it is current |

A badly-stale pin on an actively released module reports a **small** number; a
perfectly current pin on a quiet module reports a **large** one. Do not sort by
this field to rank upgrade urgency — use the version distance (`pinned` vs
`latest`, `newer_major_module` and `republished_module`).

There is no `days_behind` field: the pin's own publication date is not available
offline or from the store.

`latest_date`, and this field with it, are **omitted entirely** when no
publication date was supplied, rather than emitted as the zero time — a
fabricated date where the honest answer is none. Text output matches: such a
module prints `module@version` with no "released …" clause.

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
and `republished_module` as well, or a dependency a whole major line behind — or
a `+incompatible` pin whose major now lives at `/vN` — will read as up to date. A
`null` there is not an answer at all — see
[When the column was not measured](#when-the-column-was-not-measured).

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

# Every +incompatible pin whose own major now lives at /vN — usually the cheapest move
kanonarion latest --gomod ./go.mod --json | jq '.[] | select(.republished_module != null)'
```

## See also

- [`audit`](audit.md) - full check suite including staleness, licenses, and vulns
- [`fetch`](fetch.md) - fetches a module and annotates staleness inline
