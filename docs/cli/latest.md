# `kanonarion latest` - Latest published version lookup

## Synopsis

```
kanonarion latest <module> [<module>...]
kanonarion latest [--gomod <path>] [flags]
```

## Description

`latest` asks the Go module proxy for the latest published version of one or
more modules.

With module paths as arguments, it shows the latest version and its release
date for each, in argument order.

With `--gomod`, or with no arguments (it then reads `./go.mod`, and errors if
there is none), it resolves the project's dependency scope and reports each
module's pinned version against the latest. The default scope is **code**
(`go list -deps -test ./...`); `--tool` is the tooling supply chain and
`--project` the complete set. See [`walk` Scopes](walk.md#scopes-code-tool-complete).
The run states the test axis on stderr, and every JSON answer carries it in
`dependency_scope`.

`--json` emits one object in every form, with the rows in `modules`. See
[JSON output](#json-output).

### What a row reports

A Go module's next **major** version lives at a different module path
(`.../v4` -> `.../v5`, or a bare path -> `.../v2`). A query on the path as
written cannot see it, so a dependency several majors behind reads `current` on
its own path. `latest` therefore reports separate facts, each in its own
fields:

- **latest** - the newest version at the module path itself (`latest`,
  `latest_date`, `is_latest`, `pin_ahead_of_latest`). The pin is placed against
  it with `semver`: behind (`latest: vX (N days ago)`), level (`current`), or
  **ahead** (`ahead of latest tag: vX`, `pin_ahead_of_latest: true`). A pin is
  ahead when it is a pseudo-version taken after the last tag, or a pre-modules
  `+incompatible` major above what the unsuffixed path serves. There is nothing
  at that path to move to, so no target and no age are offered.

  `is_latest` / `pin_ahead_of_latest` read `false`/`false` behind, `true`/`false`
  level, `false`/`true` ahead. Both are emitted on every measured row and are
  both `null` where no comparison was made (a failed lookup, or a bare path with
  no pin). `latest_release_age_days` is emitted on every row, is `null` on an
  ahead row, and zero is a value. See
  [`latest_release_age_days`](#latest_release_age_days).
- **newer major** - the newest major-suffixed path above the pinned major that
  resolves (`newer_major_module`, `newer_major_latest`, `newer_major_date`).
- **same major republished** - the pinned major's own `/vN` publication
  (`republished_module`, `republished_latest`, `republished_date`). Only a
  `+incompatible` pin can have one.
- **deprecated** - the author's `// Deprecated:` notice on their `go.mod` module
  directive (`deprecated`), verbatim. The successor a notice names may be at a
  path the `/vN` probe cannot reach (`google.golang.org/protobuf` succeeds
  `github.com/golang/protobuf`). No successor is ever inferred from name
  similarity.

The newer-major probe starts one major above the **pinned version's** major (not
the path suffix: a `+incompatible` pin carries its major in the version) and
stops at the first major that does not resolve. `major_probed` separates
"probed, nothing newer" from "not probed" (offline, or a request the proxy did
not answer within 4 minutes); the text then says `newer major: not probed`.

A `+incompatible` pin is first asked whether its **own** major is now published
at the suffixed path: `example.com/lib@v2.0.0+incompatible` has
`example.com/lib/v2` published and no `/v3`. An absent `/vN` there is ordinary
and does not stop the probe. A pin already on a `/vN` path is asked nothing
extra. The major number is unchanged, so this renders as `same major
republished:`, not `newer major:`; it is usually the cheaper move.
`republished_probed` separates "asked, not republished" from "not asked".

When both hold, both are reported, the republication first:

```
example.com/router@v3.3.4+incompatible  ahead of latest tag: v1.5.5; same major republished: example.com/router/v3@v3.3.5 (2023-09-07); newer major: example.com/router/v5@v5.3.1 (2026-07-05)
```

A newer major says nothing about whether it is adoptable.

### Replaced modules

A `go.mod` `replace` directive routes the build to another module. The row is
about the module that **compiles**: `module` and `pinned` name the replacement,
and `replace` carries the require entry the directive acted on:

```
example.com/fork/lib@v1.2.4   replaces example.com/upstream/lib@v1.2.1 (go.mod replace: bumping that require entry cannot take effect while it stands); current
```

```json
{
  "module": "example.com/fork/lib",
  "pinned": "v1.2.4",
  "latest": "v1.2.4",
  "is_latest": true,
  "replace": {
    "require_module": "example.com/upstream/lib",
    "require_version": "v1.2.1"
  }
}
```

The comparison is against the replacement's path. To adopt the version offered,
edit the `replace` line.

A `replace` to a **local path**, and a `go.work` member, compile a directory
with no published version. Nothing about either is asked of a proxy or of the go
command, and nothing is claimed:

```
example.com/dep@v1.0.0   compiled from ../dep (go.mod replace); unmeasured (local replace)
example.com/member@local unmeasured (workspace member)
```

`is_latest` is `null` there, with `staleness_unmeasured` `local_replace` (and
`replace.local_path` naming the directory) or `local_workspace_member`.

Rows keep the order of the require entries; `go.work` members follow them.

### Where the `--gomod` answer comes from

With `--gomod`, the latest version of every published module in the scope comes
from **one** `go list -m -u` call, which also supplies the deprecation notice.
The call warms `$GOMODCACHE`'s download cache and writes nothing to `go.mod`,
`go.sum` or the store. `go list -m -u` stays within the pin's major, so:

- a `+incompatible` pin is offered the newest version of that major
  (`example.com/legacy@v3.3.10+incompatible` is offered `v3.3.27+incompatible`,
  not the `v2.3.8+incompatible` the unsuffixed path serves);
- prerelease and `+incompatible` pins, the only ones that can sit above the last
  tag, also get `@latest` looked up so they keep `ahead of latest tag`.

The newer-major probe is kanonarion's own and is the one per-module request. It
runs in bounded parallel rounds (`staleness.probe_concurrency`, default 16).

A positional `latest <module>` resolves one path at a time and cannot see a
deprecation notice. If the ledger recorded one, it is carried forward rather
than replaced with `null`, also under `--fresh`. A resolution that can see the
notice replaces it, and records a removed notice as `""`.

Under `GOPROXY=off` the batched call is not run; the ledger answers, as below.

### Retries

For a path it has not looked up before (often an absent major in a large
multi-module repository), the proxy can hold the request for about a minute and
then answer `200` with an empty body, or time out. It keeps working, so a later
ask gets the real answer. An answer that settles nothing (an empty body, a
timeout, a 429 or a 5xx) is asked again every 20 seconds for up to 4 minutes
from the first ask. A probe round does not wait on such paths; after the round
they are asked again together, and stderr says so once per round that needs it:

```text
staleness progress: waiting on 19 module path(s) the proxy has not finished (re-asking every 20s, up to 4m0s)
```

A positional `latest <module>` waits the same way, one path at a time, with one
stderr line per retry. A run where every path answers first time does not wait.
A definitive answer, including the 404 that says a major does not exist, is
asked once.

A row still `newer major: not probed` (`major_probed: false`) after the wait is
one the proxy did not answer in 4 minutes; `staleness.latest.retries_exhausted`
on stderr names it with the window and the time spent. `--no-progress` or
`preferences.progress: false` silences the progress lines. At `--log-level info`
or `debug` they are omitted: the log carries each settle pass
(`staleness.latest.settling`, `staleness.latest.settled`) at info and each retry
at debug.

### Private modules

A module that matches `GONOPROXY`, or `GOPRIVATE` when `GONOPROXY` is not set,
is never named to a proxy, and neither is any `/vN` path guessed from it. Its
latest version comes from `go list -m -json <module>@latest`, which the go
command answers from the module's origin with your own credentials. The
newer-major probe is not run for it, so a resolved row says `newer major: not
probed`. Nothing about a private module is written to the staleness ledger, or
served from it.

When the go command cannot resolve it, the row is unmeasured, never `current`:

```
corp.example.com/a@v1.0.0                                unmeasured (private module)
```

`is_latest` is `null` and `staleness_unmeasured` is `private_module`, and the go
command's error is printed on stderr. `audit`'s staleness column and `fetch`'s
staleness note say the same.

### The staleness ledger

Every successful `@latest` resolution, including the major probe and the
recorded "no newer major exists", is written to a store-side ledger keyed on
module path. `latest` and `audit` serve a recording younger than
`staleness.ttl` instead of asking again, so a `latest` run and an `audit` soon
after pay for one sweep. A failed lookup is never written; an absent major path
is a definitive answer and is recorded.

Every answer states the lookup time it used. A table is dated by its **oldest**
row.

`staleness.ttl` is a config key (default `1h`; `0` disables serving). `--fresh`
bypasses the ledger for one run and still records what it resolved.

### Integration with `fetch` and `audit`

- **`fetch <module@pinned>`** adds `[latest: vX.Y.Z, N days ago]` when the pin is
  behind, and `[staleness unmeasured (...)]` when the question was not answered -
  see [`fetch` staleness](fetch.md#staleness-annotation).
- **`audit --gomod ./go.mod`** has a staleness column for every module in its
  scope, beside verification, licence and vulnerability status. It uses the same
  ledger.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--gomod` | `./go.mod` | Path to `go.mod`; report latest vs pinned for the project's code dependencies |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` tool directives' closure). Mutually exclusive with `--project` |
| `--project` | false | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the Go module proxy. `off` declares the same air gap as `GOPROXY=off`: a lookup younger than `staleness.ttl` is served and nothing is written; without one, exit `20`. `direct` refuses; `--fresh` under `off` refuses too, naming itself as what to drop. See [`fetch`: `GOPROXY=off` and `direct`](fetch.md#goproxyoff-and-direct) |
| `--exclude-tests` | false | With `--gomod`: resolve the `code` scope without test imports, and state the narrowing. On `--tool` it is accepted and changes nothing - the scope already excludes them - and the answer says so. Refused against `--project` (its build list carries no test partition) and against a positional module. See [Test scope](walk.md#test-scope---exclude-tests) |
| `--fresh` | false | Re-query the proxy instead of serving recorded lookups from the store |
| `--no-progress` | `false` | Suppress the stderr lines that say a probe is being asked again; results and warnings are unaffected |
| `--json` | false | Emit output as JSON (global flag). Always one object with the per-module rows in `modules`, whatever the form and the result count. See [JSON output](#json-output) |

## Text output

### Single module

```
github.com/spf13/cobra@v1.10.2 (released 45 days ago, 2025-03-28)  [as of 2026-07-31 09:14 UTC]
```

A module whose proxy gave no publication date prints `module@version` with no
"released …" clause.

### `--gomod` table (one line per module in the scope)

```
github.com/CycloneDX/cyclonedx-go@v0.9.2      latest: v0.11.0 (released today)
github.com/google/licensecheck@v0.3.1          current
example.com/auth/v4@v4.5.1                     latest: v4.5.2 (33 days ago); newer major: example.com/auth/v5@v5.3.1 (2025-11-04)
example.com/store/v6@v6.0.57                   current; newer major: example.com/store/v7@v7.2.1 (2026-01-19)
golang.org/x/mod@v0.35.0                       latest: v0.36.0 (6 days ago)
example.com/diff@v1.0.1-0.20181226105442-5d4384ee4fb2  ahead of latest tag: v1.0.0
modernc.org/sqlite@v1.50.0                     latest: v1.50.1 (3 days ago)

latest as of 2026-07-31 09:14 UTC (staleness.ttl 1h0m0s; --fresh to re-query)
```

`example.com/store/v6` is `current` on its own path while a whole major line is
available; clauses are appended, never substituted. `example.com/diff` is a
pseudo-version taken after v1.0.0, so it sorts above the tag.

## JSON output

The top level is **always one object**, with the rows in `modules` (`[]` when
the scope resolves to nothing). Beside `modules`:

| Key | Meaning |
| --- | --- |
| `dependency_scope` | The go.mod dependency scope that resolved the rows (`code`, `tool` or `complete`) and the test axis it applied (`included`, `excluded` or `unavailable`). **`null`** on the positional form, where you named the modules and no scope was projected. |
| `module_count` | How many modules the answer is over. On `--gomod` it is the count the `notice:` line on stderr states. |
| `narrow_with` | The flag that narrows this scope, as data: `"--exclude-tests"`. Absent where nothing narrows the answer. |
| `modules` | The per-module rows, unchanged. |

### Single module

```json
{
  "dependency_scope": null,
  "module_count": 1,
  "modules": [
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
  ]
}
```

A bare module path names **no pin**, so `is_latest` is `null` with
`staleness_unmeasured: not_asked`. Use `--gomod` (or `audit`) to compare a pin.

### `--gomod`

```json
{
  "dependency_scope": { "scope": "code", "test_scope": "included" },
  "module_count": 5,
  "narrow_with": "--exclude-tests",
  "modules": [
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
      "module": "example.com/old-sdk",
      "pinned": "v1.55.8",
      "latest": "v1.55.8",
      "is_latest": true,
      "major_probed": true,
      "deprecated": "old-sdk is deprecated. Use example.com/old-sdk-v2.\nSee https://...",
      "looked_up_at": "2026-08-17T09:14:02Z",
      "served_from_store": false
    },
    {
      "module": "example.com/store/v6",
      "pinned": "v6.0.57",
      "latest": "v6.0.57",
      "latest_date": "2020-12-21T...",
      "latest_release_age_days": 2050,
      "is_latest": true,
      "newer_major_module": "example.com/store/v7",
      "newer_major_latest": "v7.2.1",
      "newer_major_date": "2026-01-19T...",
      "major_probed": true,
      "republished_probed": false,
      "looked_up_at": "2026-07-31T09:14:02Z",
      "served_from_store": true
    },
    {
      "module": "example.com/lib",
      "pinned": "v2.0.0+incompatible",
      "latest": "v1.1.3",
      "is_latest": false,
      "pin_ahead_of_latest": true,
      "major_probed": true,
      "republished_module": "example.com/lib/v2",
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
}
```

`deprecated` is emitted on every row in three states: `null` (not established:
a source that cannot see the notice, or a row recorded before the question
existed), `""` (established, none declared), or the notice. `null` is never "not
deprecated".

### When the column was not measured

`is_latest` is **null**, never `false`, when nothing was measured: `false` means
"your pin is behind". `staleness_unmeasured` names why:

| Text output | `is_latest` | `staleness_unmeasured` |
|---|---|---|
| `current` / `latest: ...` | `true` / `false` | absent |
| `(error resolving latest)` | `null` | `lookup_failed` |
| no staleness clause (bare path, no pin) | `null` | `not_asked` |
| `unmeasured (private module)` | `null` | `private_module` - see [Private modules](#private-modules) |
| `unmeasured (local replace)` / `(workspace member)` | `null` | `local_replace` / `local_workspace_member` |

A failing module is also named on **stderr**, one line per module, and the sweep
continues. Selecting `is_latest == false` for upgrade work leaves out the rows
nobody answered.

### `latest_release_age_days`

`latest_release_age_days` is **how long ago the latest release shipped**,
from `latest_date` to now. It is not how far behind the pin is:

| module | pinned | latest | `latest_date` | `latest_release_age_days` | how far behind the pin is |
|---|---|---|---|---|---|
| `example.com/busy` | `v1.61.1` | `v1.83.0` | 2 days ago | `2` | ~18 months |
| `example.com/quiet` | `v1.5.1` | `v1.5.1` | 1272 days ago | `1272` | nothing — it is current |

Do not sort by it to rank upgrades; compare `pinned` with `latest`, and check
`newer_major_module` and `republished_module`. There is no `days_behind` field:
the pin's own publication date is not available offline or from the store.

`latest_date`, and this field with it, are **omitted** when the proxy gave no
publication date.

## Examples

```bash
# Latest version of one module, or several
kanonarion latest github.com/spf13/cobra
kanonarion latest github.com/spf13/cobra github.com/stretchr/testify --json

# Staleness report for ./go.mod (auto-detected), or an explicit path
kanonarion latest
kanonarion latest --gomod ./go.mod --json

# Tooling supply chain, or the complete set
kanonarion latest --gomod ./go.mod --tool
kanonarion latest --gomod ./go.mod --project

# Bypass the ledger and re-query the proxy for every module
kanonarion latest --gomod ./go.mod --fresh

# Every dependency with a newer major line available
kanonarion latest --gomod ./go.mod --json | jq '.modules[] | select(.newer_major_module != null)'

# Every +incompatible pin whose own major now lives at /vN — usually the cheapest move
kanonarion latest --gomod ./go.mod --json | jq '.modules[] | select(.republished_module != null)'
```

## See also

- [`audit`](audit.md) - full check suite including staleness, licenses, and vulns
- [`fetch`](fetch.md) - fetches a module and annotates staleness inline
