# `kanonarion audit` - Dependency audit from a go.mod file

## Synopsis

```
kanonarion audit [--gomod <path>] [flags]
```

## Description

`audit` resolves a `go.mod`'s dependency **scope** and, in one call, fetches,
extracts licences, scans for vulnerabilities and checks staleness for every
module in it. The default scope is **code** (`go list -deps -test ./...`);
`--tool` is the tooling supply chain (the `go.mod` `tool` directives' closure,
Go 1.24+) and `--project` the complete set (`go list -m all`). See
[`walk` Scopes](walk.md#scopes-code-tool-complete).

The scope is an **import closure** computed by `go list` in the project
directory, not a list of `require` lines: indirect modules the build uses are
included, and `require` entries nothing imports are not.

`audit` states the scope, its test axis and the count on stderr:

```
notice: code scope resolved 20 module(s); test-scope dependencies included
```

`--exclude-tests` is **refused by name**: `audit` records a walk, and a walk
record names its scope but not its test axis. Read a narrowed set with
`context --gomod --exclude-tests` or `latest --gomod --exclude-tests`. See
[Test scope](walk.md#test-scope---exclude-tests).

### Columns

Each module gets one line:

- **Coordinate** - `module@version`.
- **Verification** - the outcome of checksum-database and VCS
  cross-verification (`Verified`, `VerifiedBySumDBOnly`, `VerifiedByGoSum`,
  `UnverifiedNoSumDB`, etc.), as described in [`fetch`](fetch.md#description).
  For `VerifiedByGoSum` see [Local `go.sum` verification](#local-gosum-verification).
  Other cells:
  - `(set aside)` - every fetch record of the module was written in a shape this
    build cannot reproduce; stderr names each one.
  - `(integrity check failed)` - a stored fetch record was altered after it was
    written; the table is still printed, then `audit` exits `10` naming the
    record.
  - `(divergent fetch records)` - two of the module's fetch records disagree on
    a hash they both carry; the exit code is unaffected.
  - `(fetch record unreadable)` - any other read failure.
  - `(not fetched)` - the module could not be fetched (for example under
    [`GOPROXY=off`](fetch.md#goproxyoff-and-direct)).
- **License** - primary SPDX identifier, with the status when ambiguous (e.g.
  `Apache-2.0 [Multiple]`).
- **Staleness** - `current`, `latest: vX.Y.Z (N days ago)`, `latest: vX (today)`
  for a release shipped today, a bare `latest: vX` when the publication date is
  unknown, or `ahead of latest tag: vX.Y.Z` when the pin sorts above `@latest`
  (no target or age is offered). A newer major line or a republication is printed
  on a continuation line. See [`latest`: what a row reports](latest.md#what-a-row-reports)
  for the meaning of each fact and [When the column was not
  measured](#when-the-column-was-not-measured) for unmeasured cells.
- **Deprecation** - the author's `// Deprecated:` notice from their `go.mod`,
  verbatim, on the continuation line as `deprecated by its author: <notice>`.
  kanonarion never infers a successor from name similarity. In `--json`,
  `deprecated` is `null` where it was not established (an offline row, or one
  resolved a path at a time), `""` where the module declares none, or the notice.
  `null` is not "not deprecated".
- **Vuln status** - `Clean`, `Affected (N findings)`, `Withdrawn (N retracted)`,
  `Affected (N findings, M retracted)`, `ScanFailed`, or:
  - `(not scanned)` - no record exists at any pipeline version;
  - `(superseded)` - records exist only at pipeline versions this build no
    longer reads; the reason names the generations held and says to re-scan;
  - `(set aside)` - every record this build reads was written in a canonical
    shape it cannot reproduce; the reason names each by `content_hash` (see [A
    stored record this build cannot verify](vuln.md#a-stored-record-this-build-cannot-verify)).

  `Withdrawn` means every matched advisory was retracted upstream. The status
  comes from **one project-rooted scan** of the project's resolved, pruned build
  graph, not from scanning each dependency alone. Only a fault of the whole scan
  (no `go.mod`, an OOM kill, a build that does not compile) reads
  `Unscannable`/`ScanFailed`.

The vulnerability column answers in the frame of the walk this audit ran and
reads only records that walk's scans covered, so scans of another project in the
same store never set this project's status for a shared dependency.

### The standard library row

The scope always includes the Go standard library as a row (`stdlib@vX.Y.Z`).

- **Verification** reads `VerifiedGoDevChecksum` when the
  `go{VERSION}.src.tar.gz` from `go.dev/dl` matched Go's published checksum (a
  published checksum plus a `go.googlesource.com/go` tag/commit, never a
  `go.sum` entry). On a fully offline run (`--from-modcache`) it reads
  `(custody unavailable)`.
- **License** is `BSD-3-Clause` from the tarball's `LICENSE` (source
  `stdlib-tarball`). Offline it is `BSD-3-Clause` with source `stdlib-known` /
  status `Known`, as `sbom` and `license-compat` report for the same node. See
  [SBOM standard-library chain of custody](sbom.md#standard-library-chain-of-custody).
- **Vulnerability** comes from the same `govulncheck` call-graph analysis
  against the build toolchain as module rows, so a stdlib finding carries
  `Reachable` and `AffectedSymbols`. An advisory whose symbols the project does
  not reach reads `Clean`. Query one finding with
  `kanonarion reachability stdlib@vX.Y.Z --vuln <id>`.

## Prerequisites

The vulnerability scan runs `govulncheck`, which must be on `$PATH`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

If it is missing, the scan step fails with an error naming that command.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--gomod` | `./go.mod` | Path to the `go.mod` file to audit |
| `--target` | _(this host's platform)_ | Build target as `GOOS/GOARCH`, e.g. `wasip1/wasm`. The audit resolves the walk, the package closure and the vulnerability scan for this platform. Unknown pairs are refused against `go tool dist list`. `--goos`/`--goarch` set the two halves separately. See [Declaring the build target](walk.md#declaring-the-build-target---target). |
| `--tinygo` | _(none)_ | TinyGo target, e.g. `pico` or `wasip1`, as the `tinygo` command on `PATH` defines it. Mutually exclusive with `--target`, `--goos` and `--goarch`. See [Declaring a TinyGo target](walk.md#declaring-a-tinygo-target---tinygo). |
| `--tool` | `false` | Scope to the tooling supply chain (the `go.mod` `tool` directives' closure); tags walks `scope=tool`. Mutually exclusive with `--project` |
| `--project` | `false` | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--force` | `false` | Re-fetch and re-scan even if cached records exist |
| `--fresh` | `false` | Refresh the vulnerability advisory database. The published generation and, if it has moved on, the standalone module index are read first; the database body is downloaded only when an advisory listed for a module in this walk has changed. See [Refreshing the advisory database](#refreshing-the-advisory-database---fresh). Does not affect the staleness/latest column |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` node from the `go.mod` directive, not the live toolchain. See [Standard-library version](walk.md#standard-library-version---stdlib-from-gomod). |
| `--skip-vcs-verify` | `false` | Skip git cross-verification; the checksum-database check still runs. A sumdb-attested module then reports `VerifiedBySumDBOnly`, never the strongest `Verified` (the git leg never ran). Useful when auditing a large closure where git operations are rate-limited or unavailable |
| `--allow-verification-downgrade` | `false` | Permit a weaker re-measurement of a module to be recorded alongside a stronger stored one. Without it the weaker measurement is refused, the stronger record is kept and answers, and the run warns. See [Re-measuring with a weaker anchor](fetch.md#re-measuring-with-a-weaker-anchor---allow-verification-downgrade) |
| `--policy` | _(auto-discover `.kanonarion/policy.yaml`)_ | Depth policy file; its fetch stage governs traversal and the `allowed_vcs_hosts` forge allowlist |
| `--from-modcache[=dir]` | _(off)_ | Source modules from an existing Go module cache instead of the network proxy, verifying each against the local `go.sum`. Passed bare it uses `go env GOMODCACHE`; an optional value names the cache directory. See [Sourcing from an existing module cache](#sourcing-from-an-existing-module-cache---from-modcache) |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the Go module proxy. `off` declares the same air gap as `GOPROXY=off`, with or without `--from-modcache`: nothing is fetched or verified over the network, and the run proceeds, the staleness column answered from the ledger alone — a walk still needs its module bytes. `direct` refuses, exit `20`. See [`fetch`: `GOPROXY=off` and `direct`](fetch.md#goproxyoff-and-direct) |
| `--json` | `false` | Emit output as one JSON object: the rows in `modules`, the run's own facts beside them |
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |
| `--no-progress` | `false` | Suppress stderr progress output (the throttled heartbeat and any per-module progress lines); results and warnings are unaffected |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Every dependency resolved and no licence-policy block |
| `1` | The vulnerability scan failed or left modules unanalysed; the table is still printed |
| `3` | Interrupted (SIGINT, SIGTERM or SIGHUP) before it completed |
| `5` | The [licence gate](#the-unknown-licence-gate) fired or could not be evaluated; the table is still printed |
| `10` | A walk node, or a module's fetch or vulnerability record, failed its integrity check, or two vulnerability records conflict |
| `20` | Bad invocation, unresolvable `go.mod`, or a policy file that could not be read |

`10` outranks `5`, and `5` outranks `1`.

## Example - code dependencies (default)

```
kanonarion audit
kanonarion audit --gomod ./go.mod
```

```
github.com/CycloneDX/cyclonedx-go@v0.9.2                 Verified             Apache-2.0             latest: v0.11.0 (today)       Clean
github.com/google/licensecheck@v0.3.1                    Verified             BSD-3-Clause           current                       Clean
gopkg.in/yaml.v3@v3.0.1                                  VerifiedBySumDBOnly  Apache-2.0 [Multiple]  current                       Clean
golang.org/x/mod@v0.35.0                                 Verified             BSD-3-Clause           latest: v0.36.0 (6 days ago)  Clean
modernc.org/libc@v1.73.5                                 Verified             BSD-3-Clause           latest: v1.75.3 (5 days ago)  Clean
                                                                                                     newer major: modernc.org/libc/v2@v2.1.30
github.com/golang/protobuf@v1.5.4                        Verified             BSD-3-Clause           current                       Clean
                                                                                                     deprecated by its author: Use the "google.golang.org/protobuf" module instead.
```

Columns are sized to the widest value in the run. Newer-major, republication
and deprecation facts go on a continuation line under the staleness column.
`--json` carries them as fields.

## Example - complete set (code + tooling)

```
kanonarion audit --gomod ./go.mod --project
```

```
github.com/spf13/cobra@v1.10.2                           Verified  Apache-2.0    current  Clean
golang.org/x/mod@v0.35.0                                 Verified  BSD-3-Clause  current  Clean
github.com/golangci/golangci-lint/v2@v2.12.2             Verified  MIT           current  Clean
golang.org/x/vuln@v1.3.0                                 Verified  BSD-3-Clause  current  Clean
```

## Example - tool dependencies (Go 1.24+)

```
kanonarion audit --gomod ./go.mod --tool
```

```
golang.org/x/tools/cmd/stringer@v0.30.0                       Verified  BSD-3-Clause  current  Clean
github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2  Verified  MIT           current  Clean
```

## Example - JSON output

```
kanonarion audit --gomod ./go.mod --json
```

```json
{
  "dependency_scope": { "scope": "code", "test_scope": "included" },
  "module_count": 3,
  "walk": {
    "resolved": true,
    "id": "01HZZZZZZZZZZZZZZZZZZZZZZA",
    "reused": true,
    "completed_at": "2026-08-18T12:30:07Z"
  },
  "scan": {
    "answered": true,
    "run_id": "vscan-01HZZZZZZZZZZZZZZZZZZZZZZA-1700000000000000002",
    "reused": true,
    "snapshot": { "source": "vuln.go.dev", "version": "2026-08-14T16:22:54Z" }
  },
  "vulnerability_scan": { "status": "reused", "run": "vscan-01HZZZZZZZZZZZZZZZZZZZZZZA-1700000000000000002" },
  "reachability_basis": { "answers": 4, "source_read_by_this_run": false },
  "toolchain": {
    "judged": true,
    "status": "clear",
    "version": "go1.26.6",
    "snapshot": { "source": "vuln.go.dev", "version": "2026-08-14T16:22:54Z" },
    "reason": "",
    "advisories_judged": 32,
    "covering": [],
    "withdrawn_covering": [],
    "statement": "toolchain:\n  go1.26.6: none of the 32 toolchain advisories in vuln.go.dev@2026-08-14T16:22:54Z covers it"
  },
  "staleness": {
    "measured": true,
    "as_of": "2026-08-18T23:05:11Z",
    "age": "12m30s",
    "ttl": "1h0m0s",
    "refresh_with": "latest --fresh"
  },
  "modules": [
    {
      "coordinate": "github.com/spf13/cobra@v1.10.2",
      "verification": "Verified",
      "license": "Apache-2.0",
      "license_status": "Detected",
      "vuln_status": "Clean",
      "vuln_findings": 0,
      "is_latest": true,
      "staleness_source": "proxy",
      "major_probed": true
    },
    {
      "coordinate": "golang.org/x/mod@v0.35.0",
      "verification": "Verified",
      "license": "BSD-3-Clause",
      "license_status": "Detected",
      "vuln_status": "Clean",
      "vuln_findings": 0,
      "is_latest": false,
      "staleness_source": "ledger",
      "staleness_looked_up_at": "2026-08-03T09:41:02Z",
      "latest_version": "v0.36.0",
      "latest_release_age_days": 6
    },
    {
      "coordinate": "example.com/kv@v1.4.3",
      "verification": "Verified",
      "license": "MIT",
      "license_status": "Detected",
      "vuln_status": "Withdrawn",
      "vuln_findings": 1,
      "vuln_withdrawn": 1,
      "is_latest": false,
      "staleness_source": "proxy",
      "latest_version": "v1.5.0",
      "latest_release_age_days": 54
    }
  ]
}
```

`--json` emits **one object** at every count. Beside the `modules` rows:

| Key | Meaning |
| --- | --- |
| `dependency_scope` | The go.mod dependency scope that resolved the rows (`code`, `tool` or `complete`) and the test axis it applied (`included`, `excluded` or `unavailable`). Never null on `audit`, which always resolves a scope. |
| `module_count` | How many modules that scope resolved. It is the number the `notice:` line on stderr states. A module that failed to render is missing from `modules`, named on stderr, and the run exits non-zero. |
| `walk` | Which walk fixed the dependency set: `id`, `completed_at` (the record's date, RFC 3339), and `reused` - true when this run re-resolved the go.mod, found the resolution identical to a stored walk, and served that record. `resolved` is false when no walk was taken at all. |
| `scan` | Which vulnerability scan run filled the `vuln_status` column: `run_id`, `reused`, and the advisory `snapshot` it was judged against. `answered` is false when no run answered - an empty scope, or a failed scan leg. |
| `vulnerability_scan` | `{"status": "derived"}`, `{"status": "reused", "run": …}`, `{"status": "failed", "reason": …}`, or `{"status": "not_run", "reason": …}` when no dependency was audited; `partial: {analysed, modules}` on a partial run. See [Reuse and re-derivation](#reuse-and-re-derivation). |
| `reachability_basis` | How much of the answer depends on the project's own source: `answers` counts the findings carrying a reachability answer, and `source_read_by_this_run` is false on a served run, whose reachability answers came from source this invocation did not re-read. The same object `vuln-scan --json` publishes under the same key. |
| `toolchain` | The toolchain axis, in the shape [`vuln-scan --json`](vuln.md#vuln-scan) publishes: `judged`, `status`, the `version` judged, the `snapshot` it was judged against, `reason` when nothing was judged, the `covering` advisory ids, and `statement`, the sentence stderr shows, verbatim. The toolchain is not a dependency of the artefact: it is no row and is counted in no roll-up. |
| `staleness` | Dates the staleness column for the run as a whole - the machine-readable half of the table's `latest as of ...` footer, which the text form prints on stdout. `as_of` is the OLDEST lookup behind the column, `age` is how old it was when this run read it, `ttl` is the `staleness.ttl` in force in the same units, and `refresh_with` names the command that re-queries. `measured` is false when no row carries a lookup. |
| `native_coverage` | What the build compiles or links in from native source, in the shape `vuln-scan-show` publishes; see [`vuln`](vuln.md#the-scan-covers-go-code-and-says-where-it-does-not). |
| `config_hash` | The configuration the licence gate was evaluated under. Absent when no row was built. |
| `modules` | The per-module rows. `[]` when the scope resolved nothing - the empty answer is the same object, not a different shape. |

Every key above except `config_hash` is emitted on every run; an unmeasured axis says so in a value
(`"resolved": false`, `"judged": false`, `"measured": false`, with a `reason`
where there is one). There is no `narrow_with`, since `--exclude-tests` is
refused.

The rows above are abridged. Zero, `false` and `null` values are still emitted
(`vuln_findings: 0`, `vuln_withdrawn: 0`, `policy_blocking: false`,
`policy_unevaluated: false`, `pin_ahead_of_latest: false`,
`latest_release_age_days: null`, `deprecated: null`). Only string and list keys
that do not apply to the row are absent (`latest_version`, `newer_major_module`,
`republished_module`, `vuln_reason`, `staleness_unmeasured`,
`license_uncertainty`, `license_electable_arms`, `license_governing_arms`,
`scope`).

`vuln_findings` counts **every** advisory on the record, retracted ones
included; `vuln_withdrawn` is the retracted subset. Both are emitted on every
row, `0` included. A row with no scan reports `0` for both and names the absence
in `vuln_status` (`(not scanned)`, `(superseded)`, `(set aside)`, `(scan record
unreadable)`) and `vuln_reason`.

`latest_release_age_days` is how long ago the latest release shipped, not how
far behind the pin is; zero means today. See
[`latest`](latest.md#latest_release_age_days).

## Pipeline

`audit` runs one project walk and derives every row from that walk's graph:

1. `walk` - one project walk rooted at the local module (`modulePath@local`), as
   `walk --gomod` for the selected scope.
2. `extract --stages license` - licence records over that walk.
3. `vuln-scan` - one **project-rooted** scan of the live working tree:
   `govulncheck` runs once over the project's import graph from its entry
   points, and each finding is attributed to the module that owns the vulnerable
   symbol. It never selects a dependency version the build does not use.
4. Staleness - the latest version of each published module (under
   `--from-modcache`, the ledger alone; see [When the column was not
   measured](#when-the-column-was-not-measured)).
5. Report - one line per walk node except the local root.

Later runs reuse stored results unless `--force` is passed; see
[Reuse and re-derivation](#reuse-and-re-derivation).

The staleness column uses the same ledger as `latest`: a recording younger than
`staleness.ttl` (default `1h`) is served, and a failed lookup is never recorded.
The table states the lookup time it used (`latest as of ...`, dated by its oldest
row); under `--json` that is the `staleness` key. On a warm store the walk,
licence and advisory-database stages do no network I/O, but staleness may still
ask the proxy. `audit --fresh` does not
change that column; run `latest --fresh` to re-query it.

Retries follow [`latest`: Retries](latest.md#retries). stderr reports them once
per probe round and once per retry for a single lookup:

```text
staleness progress: waiting on 19 module path(s) the proxy has not finished (re-asking every 20s, up to 4m0s)
staleness progress: retrying example.com/mod/v2 (attempt 2, 0s of 4m0s)
```

### When the column was not measured

| Table cell | `is_latest` | `staleness_source` | `staleness_unmeasured` |
|---|---|---|---|
| `current` / `latest: ...` | `true` / `false` | `proxy` or `ledger` | absent |
| `unmeasured (offline)` | `null` | `unmeasured` | `offline_no_ledger_entry` |
| `unmeasured (lookup failed)` | `null` | `unmeasured` | `lookup_failed` |
| `unmeasured (toolchain-pinned)` | `null` | `unmeasured` | `toolchain_pinned` |
| `unmeasured (local replace)` / `(workspace member)` | `null` | `unmeasured` | `local_replace` / `local_workspace_member` |

`is_latest` is **null**, never `false`, on an unmeasured row. `staleness_source`
is `proxy` (asked upstream) or `ledger` (recorded inside `staleness.ttl`, dated
by `staleness_looked_up_at`). The standard library (`toolchain_pinned`) and a
module compiled from a directory (a local `replace` or a `go.work` member) have
no published `@latest`, so nothing is asked about them.

stderr states the column's **coverage**: measured, split into asked-upstream and
served-from-ledger, then a count per unmeasured reason. The measured line prints
even at zero:

```text
staleness coverage over 127 module(s):
  measured                               0    0.0%
  unmeasured (offline)                 127  100.0%
```

### The unknown-licence gate

`audit` enforces the licence policy. A default or `--project` run evaluates
every licence under the policy's `production` rule; `--tool` under `tool`. If no
rule matches the scope in force (possible with a hand-edited policy), the gate
reports itself **unevaluated**, naming that scope and the scopes that have rules,
and exits `5`. It never falls through to an allow.

Under `--json`, `policy_blocking` and `policy_unevaluated` are emitted on
**every** row, never `null` or omitted:

| `policy_blocking` | `policy_unevaluated` | The row |
|---|---|---|
| `false` | `false` | The policy was evaluated and nothing blocks |
| `true` | `false` | Evaluated, and this row is a hard compliance failure (an undetermined licence under `unknown_license: block`) |
| `true` | `true` | The scope in force matched no rule, so the gate decided nothing - reported and blocking, never an implicit allow |

A licence that resolves to no SPDX identifier is **undetermined**, governed by
`license_policy.rules[].unknown_license`, not by the rule's `default`. When that
key is `block` for the module's scope, `audit` prints the table and exits `5`,
naming every blocked module. Left unset it is `block` for `scope: production`
and `warn` for every other scope. `kanonarion config show` prints the value in
force per scope; see
[`config`](config.md#license_policyrulesunknown_license---the-unknown-licence-gate)
for the four values.

A `Multiple` licence status (detection found more than one licence identity) is
read four ways:

- **Choice** (`A OR B` of identified SPDX ids): the most favourable arm wins. One
  allowed arm reads `allow`; with none, a `warn` licence stays `warn`, never a
  block. The policy column names the arms - `allow [permissive] [electable:
  Apache-2.0 or MIT]` - and `--json` repeats them in `license_electable_arms`.
  The row is not an open item. A `license_overrides` entry for the elected arm
  still settles it, and the row is then evaluated under that licence.
- **Every arm** (`A AND B`): the least favourable arm binds. `Apache-2.0 AND MIT`
  reads `allow [permissive]`; a row worse than allow names the arm -
  `warn [strong_copyleft] [governing: GPL-3.0-only]` - and `--json` repeats it
  in `license_governing_arms`. An arm in no policy category makes the strictest
  arm unknown, so the row is carried as unresolved (below).
- **Single** licence: that licence is the resolution. A module whose one licence
  file bundles third-party texts reads `Multiple` while its expression names its
  own licence alone.
- **None identified**: the row is unresolved (uncertainty `multiple`) under
  every scope, governed by `unknown_license`, until a `license_overrides` entry
  is recorded. The SPDX in the licence column is then display only.

### Precursor to `sbom --package`

A completed `audit` leaves the project walk, licence records and vulnerability
records that `sbom --package` finds on its own, so no extra `walk` or `extract`
is needed:

```bash
kanonarion audit --gomod ./go.mod
kanonarion sbom --package ./cmd/kanonarion   # reuses audit's project walk
```

## Vendored builds

When `vendor/modules.txt` sits beside `go.mod`, the project compiles the bytes
under `vendor/`. `audit` describes the modules `go.mod` **resolves**, not those
bytes, and says so on stderr with the other basis lines (text and `--json`):

```
vendored build:
  …/vendor/modules.txt is present beside go.mod, so this project compiles the bytes under vendor/
  this answer describes the modules the manifest resolves, not those bytes; `kanonarion vendor` is what measures the vendored tree
```

No answer changes. `kanonarion vendor` compares the vendored bytes with the
published zips. An unvendored project prints nothing here.

## Reuse and re-derivation

The `go.mod` is **always re-resolved**, so working-tree edits are picked up.
Every run states on **stderr** where its walk and scan came from:

```
derivation:
  walk 01HZZZZZZZZZZZZZZZZZZZZZZB: re-resolved and found identical to the walk taken 2026-08-02T05:01:29Z; that record was reused
  vulnerability scan: reused run vscan-01HZZZZZZZZZZZZZZZZZZZZZZB-1700000000000000001 of 2026-08-02T05:01:35Z against snapshot vuln.go.dev@2026-07-27T20:14:16Z; nothing was re-scanned, and its 4 reachability answers came from the source that run read, which this run did not re-read (--force to re-measure)
```

or, when the run measured for itself:

```
derivation:
  walk 01HZZZZZZZZZZZZZZZZZZZZZZB: derived by this run
  vulnerability scan: derived by this run
```

| Line says | Meaning |
|---|---|
| walk: **"re-resolved and found identical"** | the `go.mod` resolved to the named walk's dependency set, so that walk and its records answer this run |
| walk: **"derived by this run"** | a new walk was recorded |
| scan: **"reused run … of &lt;date&gt;"** | the named scan run answers; `govulncheck` did not run |
| scan: **"failed — &lt;reason&gt;"** | the scan did not answer or analysed no module; exit `1` |
| scan: **"it analysed N of M modules"** | a partial run; exit `1` |

A vulnerability record failing its integrity check reads `(integrity check
failed)` in its row, and records that disagree `(conflicting records)`; both
exit `10`. The reachability clause states what source those answers rest on; it
does not claim your tree is unchanged.

Under `--json` these are the `walk`, `scan`, `vulnerability_scan` and
`reachability_basis` keys.

A new walk is recorded whenever the target, scope, depth, policy, build
environment, resolved graph (every module at every selected version, every edge,
every artefact hash) or per-node outcome differs. A stored scan is reused only
when **all** of these hold:

| condition | |
|---|---|
| same walk | findings belong to the dependency set they were derived over |
| same advisory snapshot (source, version, retrieval time and seal) | a newer advisory database re-scans |
| same scan pipeline version | a newer kanonarion re-scans |
| the stored run's coverage is **complete** | a partial or failed run is never served |
| the project directory still requires the versions the walk resolved | a moved `go.mod` re-derives |

To measure again:

- `--force` re-fetches the modules, records a new walk and re-scans.
- `--fresh` refreshes the advisory database. It re-scans only when an advisory
  listed for a module in this walk changed, and does not force a new walk.

## Refreshing the advisory database (`--fresh`)

`--fresh` refreshes the vulnerability advisory database and nothing else, in two
cheap checks before any large download:

1. The generation `vuln.go.dev` publishes is read from `index/db.json` (one small
   request). Unchanged: the stored snapshot is kept.
2. Otherwise `index/modules.json` (~60 KB compressed) is fetched and compared
   with the stored snapshot's copy, for the modules in this walk (`stdlib`
   included). Identical: no download, and the stored scan run still answers.

Only a change to an advisory listed for a module in the walk (a new advisory, a
changed fixed version, an upstream edit such as a withdrawal) downloads the
database body and re-scans.

The outcome is a line in the derivation block on **stderr**, printed only under
`--fresh`:

```
derivation:
  walk 01HZZZZZZZZZZZZZZZZZZZZZZB: re-resolved and found identical to the walk taken 2026-08-02T05:01:29Z; that record was reused
  advisory database: checked vuln.go.dev and found it unchanged at 2026-07-27T20:14:16Z; nothing was downloaded and the stored snapshot was kept
  vulnerability scan: reused run vscan-01HZZZZZZZZZZZZZZZZZZZZZZB-1700000000000000001 of 2026-08-02T05:01:35Z against snapshot vuln.go.dev@2026-07-27T20:14:16Z; nothing was re-scanned (--force to re-measure)
```

| line says | meaning |
|---|---|
| `checked … and found it unchanged at <generation>` | the published generation is the stored one; nothing was transferred |
| `advanced <old> -> <new>; the advisories listed for all N modules in this walk are identical between the two, so the run judged against <old> remains current for this walk` | the database moved, but not for anything this walk is judged on; nothing was transferred and the stored run still answers |
| `advanced <old> -> <new> and the advisories changed for a module in this walk` | the database body was downloaded and the walk re-scanned against it |
| `advanced … but the advisories could not be compared (<error>)` | the comparison failed, so the full download and a re-scan ran instead |
| `published generation unreadable (<error>)` | the first check failed, so the full download ran instead |
| `no snapshot was stored; downloaded …` | first refresh on this store |
| `refresh failed (<error>)` | the database could not be brought up to date at all; the run continues against the stored database |

A reused run always names the snapshot it was **actually judged against**, even
when the second check keeps it current across a newer generation.

## The toolchain axis

Every run states on **stderr** what the advisory database says about the Go
toolchain the walk was built by:

```
toolchain:
  go1.26.5: none of the 30 toolchain advisories in vuln.go.dev@2026-07-27T20:14:16Z covers it
```

```
toolchain:
  go1.26.2 is covered by 3 advisories in vuln.go.dev@2026-07-27T20:14:16Z: GO-2026-4978 (fixed in 1.26.3), GO-2026-4979 (fixed in 1.26.3), GO-2026-4984 (fixed in 1.26.3)
  this is the build toolchain, not a dependency of the artefact: it is reported as its own axis and is counted in no module roll-up
```

Under `--json` this is the `toolchain` key, with these lines verbatim in
`statement`.

The database keys the toolchain (`cmd/go`, the compiler, the linker) separately
from `stdlib`, and no project imports `cmd/*`, so no module scan or
reachability analysis reaches a toolchain advisory. This line is the only place
they appear.

| the line says | it means |
|---|---|
| `<version>: none of the N toolchain advisories in <snapshot> covers it` | the snapshot's toolchain advisories were read and none covers this toolchain |
| `<version> is covered by … : <ids>` | those advisories cover it; the fix named is the one on **this toolchain's own release branch** |
| `… covered only by N advisories … that have since been withdrawn` | advisories cover it, but every one has been retracted by the database that published it |
| `<version> was not judged …: <reason>` | no judgment was made, and the reason names the missing input |

| reason | remedy |
|---|---|
| `the snapshot's module index carries no toolchain key` | `--fresh` to refresh the advisory database |
| `the walk recorded no build toolchain version` | re-walk with `--force` |
| `the recorded toolchain version is not comparable to the database's version ranges` | a release-candidate or development toolchain; nothing to judge by version |
| `no advisory database snapshot is stored` | run once with network access |

The judgment is made at report time from the stored snapshot and the walk's
recorded toolchain version (`go env GOVERSION`): nothing is fetched or recorded.
`--stdlib-from-gomod` does **not** change it. The axis never changes the exit
code and never appears in the table, the `--json` rows, or the roll-ups.

On a walk taken with `--tinygo`, a second line states TinyGo beside Go, as
`vuln-scan` does (see [Scanning under a TinyGo frame](vuln.md#scanning-under-a-tinygo-frame)),
and the native-code coverage lines are followed by the `tinygo code:` block.
TinyGo is not a module row.

## Local `go.sum` verification

On the normal network path, when `go.sum` sits beside the walked `go.mod`,
`audit` also checks each fetched module against it. This is offline and costs
no extra hashing or network. For each module:

- **Matches `go.sum`** (zip and `/go.mod`): if the checksum database also
  verified it, `Verified` / `VerifiedBySumDBOnly` stands. If the database was
  **unavailable** (offline, `GOSUMDB=off`, or no entry), the module reports
  **`VerifiedByGoSum`** instead of `UnverifiedNoSumDB`.
- **Disagrees with `go.sum`**: `audit` exits `10`, naming the module.
- **Absent from `go.sum`**: not a failure for an unreplaced module; it falls
  through to the checksum database. For a **replaced** module it is a hard stop
  naming both coordinates, because `go.sum` records a replacement under the
  replace target.

A replaced module is looked up under the replace target and reported under both
names: `verified against local go.sum under <fork> (required as <upstream>)`. A
module replaced by a filesystem path has no checksum and records `local
directory <path as go.mod writes it> (local source, nothing to verify)`.

Under `--from-modcache` (below), `go.sum` is the only anchor and an absent entry
is a hard failure.

A private module (matching `GONOPROXY`, or `GOPRIVATE` when `GONOPROXY` is not
set) is read from the module cache and checked against this `go.sum` alone: its
row reads `VerifiedByGoSum`, and a module missing from `go.sum` stops the audit.
Nothing about it is sent to the proxy, and its staleness column reads
`unmeasured (private module)` when the go command cannot resolve its latest
version. See [`fetch`: private modules](fetch.md#private-modules-goprivate-gonoproxy)
and [`latest`: private modules](latest.md#private-modules).

## Sourcing from an existing module cache (`--from-modcache`)

`--from-modcache` reads modules from the Go module cache that `go build` already
filled, instead of downloading them from the proxy. In this mode `audit`:

- **Reads module bytes from the cache** (`go env GOMODCACHE`, or the directory
  given as `--from-modcache=/path`). A module missing from the cache is fetched
  into it with `go mod download`. Nothing is written to kanonarion's blob store.
- **Verifies each module's `h1` hash against the local `go.sum`**, with no
  `sum.golang.org`. A mismatch, or a module with no `go.sum` entry, exits `10`
  naming the modules. Verified modules report `VerifiedByGoSum`. VCS
  cross-verification is skipped.
- **Asks nothing upstream about staleness.** No calls go to
  `proxy.golang.org`/`sum.golang.org`, so rows carry `major_probed: false`. A
  module with a ledger recording **inside `staleness.ttl`** is served it, with
  its age (`latest: v0.57.0 (3 days ago) [from ledger, 20m0s old]`); every
  other module reads `unmeasured (offline)` (`is_latest: null`,
  `staleness_unmeasured: offline_no_ledger_entry`). The stderr coverage line
  counts both. Nothing is written to the ledger.

The vulnerability scan still reads the stored OSV database (`--fresh` to refresh
it).

```bash
# After `go build ./...` has populated the module cache:
kanonarion audit --from-modcache

# Or point at a specific cache directory:
kanonarion audit --from-modcache=/path/to/gomodcache
```

## Modules resolved under pre-modules semantics

A `+incompatible` coordinate resolves no requirement edges, so nothing under it
is in the audited set. A caveat on **stderr** (so `--json` is unchanged) names
the coordinates responsible; see
[pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).

## See also

- [`latest`](latest.md) - dedicated version staleness lookup
- `inspect` - full pipeline including interface, call-graph, and AI context
- `vuln-scan` - run vulnerability scanning independently for a walk
- `license-list` - list all stored license records
- `context` - query and display full stored context for a single module
