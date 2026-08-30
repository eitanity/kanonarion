# `kanonarion audit` - Dependency audit from a go.mod file

## Synopsis

```
kanonarion audit [--gomod <path>] [flags]
```

## Description

`audit` resolves a `go.mod`'s dependency **scope** and runs the full check suite
- fetch, license extraction, and vulnerability scanning - across every module in
one invocation. The scope is consistent with every other go.mod command:

| Scope | Flag | Set |
|-------|------|-----|
| **code** | _(default)_ | the project's own code dependencies (`go list -deps -test ./...`, incl. tests) |
| **tool** | `--tool` | the tooling supply chain (the `go.mod` `tool` directives' closure, Go 1.24+) |
| **complete** | `--project` | code **and** tooling (the full Go build list, `go list -m all`) |

`--tool` and `--project` are mutually exclusive; absent both, the scope is
`code`. See [`walk` Scopes](walk.md#scopes-code-tool-complete) for the shared
definition.

`audit` states the scope and its test axis on stderr, beside the derivation and
frame lines, with the count it resolved:

```
notice: code scope resolved 20 module(s); test-scope dependencies included
```

Every `--json` row carries the same fact as `dependency_scope`. `--exclude-tests`
is **refused by name** here: `audit` drives a project walk, and a walk record
names its scope but not its test axis, so a narrowed walk would be stored as
indistinguishable from a full one. Read a narrowed set with
`context --gomod --exclude-tests` or `latest --gomod --exclude-tests`. See
[Test scope](walk.md#test-scope---exclude-tests).

For each module in the scope, `audit` emits a single line containing:

- **Coordinate** - `module@version`
- **Verification** - outcome of sumdb/VCS cross-verification (`Verified`,
  `VerifiedBySumDBOnly`, `VerifiedByGoSum`, `UnverifiedNoSumDB`, etc.). See
  [Local `go.sum` verification](#local-gosum-verification) for `VerifiedByGoSum`.
- **License** - primary SPDX identifier; annotated with status when ambiguous
  (e.g. `Apache-2.0 [Multiple]`)
- **Staleness** - `current` when the pinned version is the latest published,
  `latest: vX.Y.Z (N days ago)` when a newer version exists, or
  `ahead of latest tag: vX.Y.Z` when the pin sorts *above* what the proxy
  answers `@latest` with. The last is ordinary: a pseudo-version taken after
  the last tag, or a pre-modules `+incompatible` major published above the
  newest version the unsuffixed path serves. No upgrade target and no age are
  offered there — there is nothing at that path to move to. A newer major line,
  if one exists, is still reported (see below): a separate fact, at a different
  path. In `--json` the same three positions are `is_latest` plus
  `pin_ahead_of_latest`, both emitted on every measured row and
  both `null` together where nothing was measured. `latest_release_age_days` is
  emitted on every row and **zero is a value**: a release that shipped today is
  `0` days old. Null means there is no age — the pin is ahead, or the proxy
  supplied no publication date, told apart by `pin_ahead_of_latest`. The text
  column matches: `latest: vX (today)` for a zero age, and a bare `latest: vX`
  where the date is unknown rather than an invented "today".
- **Deprecation** - the module author's own `// Deprecated:` notice from their
  `go.mod`, reproduced verbatim on the row's continuation line as `deprecated by
  its author: <notice>`. It is stated beside the staleness answer, never merged
  into it: a deprecated module is frequently `current` on its own path, and the
  successor a notice names is often somewhere the `/vN` probe cannot reach.
  kanonarion never infers a successor from name similarity. In `--json` the key
  is `deprecated`, always emitted, in three states: `null` where the question was
  not established (an offline row, or one resolved a path at a time), `""` where
  it was asked and the module declares none, or the notice text. `null` is not
  "not deprecated".
- **Vuln status** - `Clean`, `Affected (N findings)`, `Withdrawn (N retracted)`,
  `ScanFailed`, `(not scanned)` when no record exists at any pipeline version, or
  `(superseded)` when the store holds records for the module only at pipeline
  versions this build no longer reads — the module has been scanned, and the row's
  reason names the generations held and says to re-scan. A module whose every
  matched advisory was retracted upstream reads `Withdrawn`, and its count is
  reported as *retracted* rather than as findings: only one of the two is
  something to act on. A module carrying both reads
  `Affected (N findings, M retracted)`. The verdict is **project-rooted**: it
  comes from a single scan of the project's resolved, pruned build graph, not
  from scanning each dependency in isolation. A module the project builds
  cleanly reads `Clean`, `Affected` or `Withdrawn` within that graph; only a genuine fault of the whole scan (no `go.mod`, an OOM
  kill, a build that does not compile) reads `Unscannable`/`ScanFailed`.

The scope always includes the **Go standard library** as a first-class row
(`stdlib@vX.Y.Z`), so standard-library advisories are audited alongside module
dependencies. Its **Verification** column reports the toolchain-specific chain of
custody — `VerifiedGoDevChecksum` when the canonical `go{VERSION}.src.tar.gz`
acquired from `go.dev/dl` matched Go's published checksum — a status distinct
from the module sumdb ones (it is a published checksum plus a
`go.googlesource.com/go` tag/commit, never a `go.sum` entry). Its **License** is
`BSD-3-Clause` extracted from the tarball's `LICENSE` file (licence source
`stdlib-tarball`). On a fully offline run (`--from-modcache`) the custody chain
cannot be established and the Verification column reads `(custody
unavailable)`; the licence column then reads `BSD-3-Clause` with source
`stdlib-known` / status `Known` — the licence is reported from published
knowledge rather than extracted evidence, and `sbom` and `license-compat`
answer the same for the same node. See [SBOM standard-library chain of
custody](sbom.md#standard-library-chain-of-custody) for the full evidence set.

Its **Vulnerability** column answers in the frame of the walk this audit ran,
and reads only records that walk's scans covered. A store holding scans of a
second project therefore cannot put that project's verdict for a shared
dependency into this report.

Its **Vulnerability** column is **call-graph-analysed against the build
toolchain**, not resolved from advisory metadata by coordinate: the same
project-rooted `govulncheck` run that analyses the dependency graph also reasons
over standard-library symbols, so a surfaced stdlib finding carries a populated
`Reachable` verdict and `AffectedSymbols` exactly as a module finding does. A
standard-library advisory that affects the pinned toolchain version but whose
vulnerable symbols are **not reached** from the project therefore reads `Clean`,
as an unreachable advisory in a fetched module does. Query a specific verdict
with `kanonarion reachability stdlib@vX.Y.Z --vuln <id>`.

The scope is an **import closure**, not a `require`-line listing: the `code`
scope is every module the project's packages (and their tests) actually import,
so indirect modules that are genuinely used are included and `require` entries
nothing imports are excluded. The set is computed by delegating to the Go
toolchain (`go list`) in the project directory.

`audit` replaces this manual workflow:

```bash
# Old: for each direct dep
kanonarion walk github.com/foo/bar@v1.2.3
WALK_ID=$(kanonarion walk-list --json | jq -r '.records[0].id')
kanonarion vuln-scan "$WALK_ID"
kanonarion license-list          # global - needs manual filtering
kanonarion context github.com/foo/bar@v1.2.3
```

## Prerequisites

The vuln-scan step invokes `govulncheck` as a subprocess. It must be present
in `$PATH`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
```

If the binary is missing, the scan step fails with a descriptive error naming
the install command.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--gomod` | `./go.mod` | Path to the `go.mod` file to audit |
| `--tool` | `false` | Scope to the tooling supply chain (the `go.mod` `tool` directives' closure); tags walks `scope=tool`. Mutually exclusive with `--project` |
| `--project` | `false` | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--force` | `false` | Re-fetch and re-scan even if cached records exist |
| `--fresh` | `false` | Refresh the vulnerability advisory database. The published generation and, if it has moved on, the standalone module index are read first; the database body is downloaded only when an advisory listed for a module in this walk has changed. See [Refreshing the advisory database](#refreshing-the-advisory-database---fresh). Does not affect the staleness/latest column |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` node from the `go.mod` directive, not the live toolchain. See [Standard-library version](walk.md#standard-library-version---stdlib-from-gomod). |
| `--skip-vcs-verify` | `false` | Skip git cross-verification; the checksum-database check still runs. A sumdb-attested module then reports `VerifiedBySumDBOnly`, never the strongest `Verified` (the git leg never ran). Useful when auditing a large closure where git operations are rate-limited or unavailable |
| `--allow-verification-downgrade` | `false` | Permit a weaker re-measurement of a module to be recorded alongside a stronger stored one. Without it the weaker measurement is refused, the stronger record is kept and answers, and the run warns. See [Re-measuring with a weaker anchor](fetch.md#re-measuring-with-a-weaker-anchor---allow-verification-downgrade) |
| `--policy` | _(auto-discover `.kanonarion/policy.yaml`)_ | Depth policy file; its fetch stage governs traversal and the `allowed_vcs_hosts` forge allowlist |
| `--from-modcache[=dir]` | _(off)_ | Source modules from an existing Go module cache instead of the network proxy, verifying each against the local `go.sum`. Passed bare it uses `go env GOMODCACHE`; an optional value names the cache directory. See [Sourcing from an existing module cache](#sourcing-from-an-existing-module-cache---from-modcache) |
| `--goproxy` | `$GOPROXY` | Override the Go module proxy (ignored under `--from-modcache`), honoured not rewritten. Under `off` the run proceeds, the staleness column answered from the ledger alone — a walk still needs its module bytes. `direct` refuses, exit `20`. See [`fetch`: `GOPROXY=off` and `direct`](fetch.md#goproxyoff-and-direct) |
| `--json` | `false` | Emit output as one JSON object: the rows in `modules`, the run's own facts beside them |
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |
| `--no-progress` | `false` | Suppress stderr progress output (the throttled heartbeat and any per-module progress lines); results and warnings are unaffected |

## Example - code dependencies (default)

```
kanonarion audit
```

or explicitly:

```
kanonarion audit --gomod ./go.mod
```

```
github.com/CycloneDX/cyclonedx-go@v0.9.2                 Verified             Apache-2.0             latest: v0.11.0 (today)       Clean
github.com/google/licensecheck@v0.3.1                    Verified             BSD-3-Clause           current                       Clean
github.com/spf13/cobra@v1.10.2                           Verified             Apache-2.0             current                       Clean
gopkg.in/yaml.v3@v3.0.1                                  VerifiedBySumDBOnly  Apache-2.0 [Multiple]  current                       Clean
golang.org/x/mod@v0.35.0                                 Verified             BSD-3-Clause           latest: v0.36.0 (6 days ago)  Clean
golang.org/x/vuln@v1.3.0                                 Verified             BSD-3-Clause           current                       Clean
modernc.org/libc@v1.73.5                                 Verified             BSD-3-Clause           latest: v1.75.3 (5 days ago)  Clean
                                                                                                     newer major: modernc.org/libc/v2@v2.1.30
github.com/golang/protobuf@v1.5.4                        Verified             BSD-3-Clause           current                       Clean
                                                                                                     deprecated by its author: Use the "google.golang.org/protobuf" module instead.
modernc.org/sqlite@v1.50.0                               Verified             BSD-3-Clause           latest: v1.50.1 (3 days ago)  Clean
```

Every column is sized from the widest value the run produced, so the columns
line up on every row. The major-line and deprecation facts are the values
routinely wider than the rest of the row put together — a whole module path and
version, or a sentence — so they are stated in full on a continuation line under
the staleness column they belong to, rather than setting that column's width for the run.
`--json` is unaffected: it carries those paths and versions as fields.

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
golang.org/x/tools/cmd/stringer@v0.30.0            Verified   BSD-3-Clause   current   Clean
github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.0   Verified   MIT   current   Clean
```

## Example - JSON output

```
kanonarion audit --gomod ./go.mod --json
```

```json
{
  "dependency_scope": { "scope": "code", "test_scope": "included" },
  "module_count": 4,
  "walk": {
    "resolved": true,
    "id": "01M0ADKD8WXT7JA8219Z7XRGEC",
    "reused": true,
    "completed_at": "2026-08-18T12:30:07Z"
  },
  "scan": {
    "answered": true,
    "run_id": "vscan-01M0ADKD8WXT7JA8219Z7XRGEC-1787056207",
    "reused": true,
    "snapshot": { "source": "vuln.go.dev", "version": "2026-08-14T16:22:54Z" }
  },
  "reachability_basis": { "verdicts": 4, "source_read_by_this_run": false },
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
      "coordinate": "golang.org/x/vuln@v1.3.0",
      "verification": "Verified",
      "license": "BSD-3-Clause",
      "license_status": "Detected",
      "vuln_status": "Clean",
      "vuln_findings": 0,
      "is_latest": true,
      "staleness_source": "proxy",
      "major_probed": true
    },
    {
      "coordinate": "go.etcd.io/bbolt@v1.4.3",
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

`--json` emits **one JSON object** at every count, never a bare array. The
per-module rows are its `modules` member and are unchanged; beside them the
object states the facts about the run, which a bare array had nowhere to put:

| Key | Meaning |
| --- | --- |
| `dependency_scope` | The go.mod dependency scope that resolved the rows (`code`, `tool` or `complete`) and the test axis it applied (`included`, `excluded` or `unavailable`). Never null on `audit`, which always resolves a scope. |
| `module_count` | How many modules that scope resolved. It is the number the `notice:` line on stderr states. A module that failed to render is missing from `modules`, named on stderr, and the run exits non-zero. |
| `walk` | Which walk fixed the dependency set: `id`, `completed_at` (the record's date, RFC 3339), and `reused` - true when this run re-resolved the go.mod, found the resolution identical to a stored walk, and served that record. `resolved` is false when no walk was taken at all. |
| `scan` | Which vulnerability scan run filled the `vuln_status` column: `run_id`, `reused`, and the advisory `snapshot` it was judged against. `answered` is false when no run answered - an empty scope, or a scan leg that failed and said so on stderr. The run id is stated on both arms, which the stderr sentence is not: a scan derived by this run names no id there. |
| `reachability_basis` | How much of the answer depends on the project's own source: `verdicts` counts the findings carrying a reachability answer, and `source_read_by_this_run` is false on a served run, whose verdicts came from source this invocation did not re-read. The same object `vuln-scan --json` publishes under the same key. |
| `toolchain` | The toolchain axis, in the shape [`vuln-scan --json`](vuln-scan.md) publishes: `judged`, `status`, the `version` judged, the `snapshot` it was judged against, `reason` when nothing was judged, the `covering` advisory ids, and `statement`, the sentence stderr shows, verbatim. The toolchain is not a dependency of the artefact: it is no row and is counted in no roll-up. |
| `staleness` | Dates the staleness column for the run as a whole - the machine-readable half of the table's `latest as of ...` footer, which the text form prints on stdout. `as_of` is the OLDEST lookup behind the column, `age` is how old it was when this run read it, `ttl` is the `staleness.ttl` in force in the same units, and `refresh_with` names the command that re-queries. `measured` is false when no row carries a lookup. |
| `modules` | The per-module rows. `[]` when the scope resolved nothing - the empty answer is the same object, not a different shape. |

Every one of those keys is emitted on every run. An axis that was not measured
says so in a value - `"resolved": false`, `"judged": false`, `"measured": false`,
with a `reason` where there is one - because a missing key and a `null` both read
as "nothing to report", which is the one thing an unmeasured axis does not mean.

`audit` refuses `--exclude-tests` (it records a walk, and a walk record names its
scope but not its test axis), so it offers no `narrow_with` remedy on either
channel.

The rows above are abridged. Keys whose value is zero, `false` or `null` are
still emitted - `vuln_findings: 0`, `vuln_withdrawn: 0`, `policy_blocking:
false`, `policy_unevaluated: false`, `pin_ahead_of_latest: false`,
`latest_release_age_days: null`, `deprecated: null`. A key is absent only where
it names something that does not apply to the row at all: the string and list keys
(`latest_version`, `newer_major_module`, `republished_module`, `vuln_reason`,
`staleness_unmeasured`,
`license_uncertainty`, `license_electable_arms`, `license_governing_arms`,
`scope`).

`vuln_findings` counts **every** advisory on the record, retracted ones
included. `vuln_withdrawn` is the retracted subset and live advisories are the
difference between the two. Both are emitted on every row, `0` included: `0`
means no advisory covering this module was retracted, and it is a measurement,
not a gap. A row with no scan at all reports `0` for both and says which absence
it is in `vuln_status` (`(not scanned)`, `(superseded)`, `(scan record
unreadable)`) and `vuln_reason`.

`latest_release_age_days` is **how long ago the latest release shipped**, not how
far behind the pin is. There is no `days_behind` field. See
[`latest`](latest.md#latest_release_age_days) for the worked example.

## Pipeline

`audit` runs a single project walk rooted at the local module and derives its
per-module rows from that one walk's graph, rather than one shallow walk per
dependency:

1. `walk` - one project walk rooted at the local module (`modulePath@local`), equivalent to `walk --gomod` for the selected scope. It resolves the whole scoped closure into a single graph holding the local root, every scoped node, and the edges between them.
2. `extract --stages license` - extract license records once over the project walk
3. `vuln-scan` - one **project-rooted** scan of the live working tree: `govulncheck` runs once over the project's real import graph from its real entry points, and each finding is attributed to the module that owns the vulnerable symbol. Every other in-build module is analysed-and-clean. This is not a per-module isolated scan, so it never re-selects a dependency version the project's build does not use.
4. Staleness check - query the proxy for the latest version of each module (offline under `--from-modcache`: the ledger alone, see [When the column was not measured](#when-the-column-was-not-measured))
5. Query and report - iterate the walk's dependency nodes (every graph node bar the local root) and join fetch, license, vuln, and staleness into one line each

Walk, licence, staleness and the vuln scan all use stored results on subsequent
runs unless `--force` is passed; see
[Reuse and re-derivation](#reuse-and-re-derivation).

The staleness column reads a **store-side ledger** keyed on module path. Every
successful `@latest` resolution any command makes is recorded there, and a
recording younger than `staleness.ttl` (default `1h`, a config key) is served
instead of re-querying - so `latest --gomod` followed by `audit` pays the proxy
sweep once between them rather than once each. The table states the lookup time
it used (`latest as of ...`, dated by its oldest row) so a served answer is
never mistaken for a live one, and a **failed** lookup is never recorded. Under
`--json` that footer is the `staleness` key, dated by the same lookup.

A lookup that fails transiently (a loaded proxy answering an empty body, a
timeout, a 5xx) is retried, and each retry is narrated on stderr:

```text
staleness progress: retrying example.com/mod/v2 (attempt 2 of 4)
```

One line per retry, naming the module, the attempt and the budget - so a probe
that spends most of a minute waiting is distinguishable from a hang. A run where
nothing retries prints none of these lines. `--no-progress` silences them, as
does `preferences.progress: false` in the config; at `--log-level info` or
`debug` they are omitted because the log already streams each retry. A
definitive answer, including the 404 that says a major does not exist, is never
retried and never narrated.

The column reports separate facts per module, never merged. `is_latest` is about
the module **path**. `newer_major_module` names the newest major-suffixed path
above the pinned major - a dependency pinned a whole major line behind is at the
latest version of its own path and is still behind. `major_probed` separates
"probed, nothing newer" from "not probed" (a `--from-modcache` run, or a probe
whose request failed); an answered row whose probe was not is noted as `newer
major: not probed`.

`republished_module` is a third fact and only a `+incompatible` pin can have one:
the pinned major's own `/vN` publication. The major **number** is unchanged
there, so it renders as `same major republished:` rather than `newer major:` -
a path migration, not a major upgrade, and usually the cheaper move.
`republished_probed` separates "asked, this major is not republished" from "not
asked". Where a module has both, both are printed, the republication first.

### When the column was not measured

The staleness column is not always answerable, and it says so rather than
falling back on the affirmative answer:

| Table cell | `is_latest` | `staleness_source` | `staleness_unmeasured` |
|---|---|---|---|
| `current` / `latest: ...` | `true` / `false` | `proxy` or `ledger` | absent |
| `unmeasured (offline)` | `null` | `unmeasured` | `offline_no_ledger_entry` |
| `unmeasured (lookup failed)` | `null` | `unmeasured` | `lookup_failed` |
| `unmeasured (toolchain-pinned)` | `null` | `unmeasured` | `toolchain_pinned` |

`is_latest` is **null**, never `false`, on an unmeasured row: `false` claims
"your pin is behind", which nobody established. `staleness_source` names which
side answered a measured row - `proxy` (asked upstream) or `ledger` (recorded
inside `staleness.ttl`, dated by `staleness_looked_up_at`). `toolchain_pinned`
is the standard-library row, pinned to the build toolchain, with no proxy
`@latest` to compare against.

Beside the table, on stderr, `audit` states the column's **coverage** as it
already does for verification - measured, split into asked-upstream and
served-from-ledger, then a count per unmeasured reason:

```text
staleness coverage over 127 module(s):
  measured                               0    0.0%
  unmeasured (offline)                 127  100.0%
```

The measured line prints even at zero: a line that disappeared at zero could
not report the collapse, which is the whole point on an offline run.

### The unknown-licence gate

`audit` is where the licence policy is enforced. A default or `--project` run
evaluates every licence under the policy's `production` rule; `--tool` evaluates
under `tool`. Finding no rule for the scope in force (possible with a hand-edited
policy), the gate reports itself **unevaluated** — naming that scope and the
scopes that do carry rules — and exits `5`, never falling through to an allow.

Under `--json` the two facts are `policy_blocking` and `policy_unevaluated`,
both emitted on **every** row, `false` included, so a consumer can separate the
two states above:

| `policy_blocking` | `policy_unevaluated` | The row |
|---|---|---|
| `false` | `false` | The policy was evaluated and nothing blocks |
| `true` | `false` | Evaluated, and this row is a hard compliance failure (an undetermined licence under `unknown_license: block`) |
| `true` | `true` | The scope in force matched no rule, so the gate decided nothing - reported and blocking, never an implicit allow |

`false` on both is a measurement, not a missing field: it says the gate ran.
Neither key is ever `null` or omitted.

A dependency whose licence could not be resolved to any SPDX identifier is
**undetermined**, and undetermined is governed by
`license_policy.rules[].unknown_license`, not by the rule's `default`. When that
key resolves to `block` for the module's scope, `audit` prints the full table
and then exits `5`, naming every blocked module.

A `Multiple` licence status - detection found more than one licence identity -
splits four ways.

When the module offers a **choice** (a pure `A OR B` expression of identified
SPDX identifiers, e.g. a dual-licensed module), the row takes the most
favourable arm's outcome: one allowed arm among stricter ones reads `allow`, and
with no allowed arm a `warn` licence is still a `warn`, never a block. The
policy column names the arms carrying the outcome — `allow [permissive]
[electable: Apache-2.0 or MIT]` —
and `--json` repeats them in `license_electable_arms`. Such a row is not an open
item; recording the elected arm as a `license_overrides` entry still settles it
wholesale, and the row is then evaluated under that licence.

When the module carries **every** arm (a pure `A AND B` expression) the row
takes the **least** favourable arm's outcome: no choice exists, so the strictest
obligation binds. `Apache-2.0 AND MIT` reads `allow [permissive]`; a row worse
than allow names the arm responsible - `warn [strong_copyleft] [governing:
GPL-3.0-only]` - and `--json` repeats it in `license_governing_arms`. An arm in
no policy category is not folded: the strictest arm is then unknown, and the row
is carried as below.

When the expression names a **single** licence, that licence is the row's
resolution, evaluated as any determined licence is. A module whose one licence
file bundles third-party texts (an omnibus attribution file) reads `Multiple`
while its expression names its own licence alone: the status describes how
detection got there, not that it failed.

When the expression names none of those - candidates that could not be
identified - nothing was determined: the row is carried as unresolved
(uncertainty `multiple`) under every scope, governed by the same unknown-licence
key, until an operator records a `license_overrides` entry. The SPDX in the
licence column is then display information, not a resolution.

Left unset the key resolves to `block` for `scope: production` and `warn` for
every other scope, so an undetermined dependency fails a production audit
closed rather than passing as a clean allow. Run `kanonarion config show` to see
the value in force for each scope, and see
[`config`](config.md#license_policyrulesunknown_license---the-unknown-licence-gate)
for the four values.

### Precursor to `sbom --package`

Because `audit` leaves behind exactly the project walk, license records, and
vuln records that `sbom --package` auto-discovers, a completed `audit` is a
valid precursor to it - no extra `walk` or `extract` command is needed:

```bash
kanonarion audit --gomod ./go.mod
kanonarion sbom --package ./cmd/kanonarion   # reuses audit's project walk
```

## Vendored builds

A project carrying `vendor/modules.txt` beside its `go.mod` compiles the bytes
under `vendor/`, which need not be the bytes the proxy would serve for the same
coordinates. This command resolves the manifest, so its answer describes the
modules `go.mod` **resolves**, not what ships. Where the two can differ, the run
says so on its basis channel (stderr, with the other basis lines, on both the
text and `--json` paths):

```
vendored build:
  …/vendor/modules.txt is present beside go.mod, so this project compiles the bytes under vendor/
  this answer describes the modules the manifest resolves, not those bytes; `kanonarion vendor` is what measures the vendored tree
```

It states a fact and changes no verdict: a vendored project answers exactly as
before, with one more line of basis. `kanonarion vendor` is the command that
compares the shipped bytes against the published module zips.

An unvendored project states nothing - its answer was never ambiguous.

## Caching

`audit` is safe to re-run, but a warm re-run is **not** fully offline. The walk,
licence, and vulnerability-database stages are cached and do no network I/O on a
warm store.

- **Staleness** - `audit` queries the module proxy for each module's latest
  version (`@latest`). Answers are served from the staleness ledger inside
  `staleness.ttl` (default `1h`). `audit --fresh` does not change this: to
  re-query a latest answer on demand, run `latest --fresh`.
- **Walk** - the project's `go.mod` is **always re-resolved**, so an edit to the
  working tree is always picked up. When the resolution matches a walk already
  stored, that walk's record is reused rather than a new one recorded. See
  [Reuse and re-derivation](#reuse-and-re-derivation).
- **Project-rooted vuln scan** - served from the stored run unless one of the
  [reuse conditions](#reuse-and-re-derivation) fails; `govulncheck` then runs
  over the live working tree.

## Reuse and re-derivation

Every run reports, on **stderr**, where its two expensive answers came from:

```
derivation:
  walk 01KZ0DJEV5XKAV1PSN1JM47D37: re-resolved and found identical to the walk taken 2026-08-02T05:01:29Z; that record was reused
  vulnerability scan: reused run vscan-01KZ0DJEV5XKAV1PSN1JM47D37-1785646889 of 2026-08-02T05:01:35Z against snapshot vuln.go.dev@2026-07-27T20:14:16Z; nothing was re-scanned, and its 4 reachability verdicts came from the source that run read, which this run did not re-read (--force to re-measure)
```

or, when the run measured for itself:

```
derivation:
  walk 01KZ0DJEV5XKAV1PSN1JM47D37: derived by this run
  vulnerability scan: derived by this run
```

Reading the walk line: **"re-resolved and found identical"** means the `go.mod`
was resolved again this run and produced the same dependency set as the named
walk, so that walk's record — and every licence, vulnerability and SBOM record
keyed to it — answers this run too. **"derived by this run"** means a new walk
was recorded.

Reading the scan line: **"reused run … of &lt;date&gt;"** names the scan run whose
verdicts you are reading and when it was made; `govulncheck` did not run. The
findings, roll-ups and exit code are the ones that run produced.

Which advisories apply is fixed by the resolved module versions, so reuse is
sound there. Reachability is not: `govulncheck` reads source, and source is not
a reuse condition below. The reachability clause therefore appears whenever the
run answered any, and it states what those verdicts rest on rather than claiming
your tree is unchanged — nothing re-read it.

Under `--json` the same three facts are the `walk`, `scan` and
`reachability_basis` keys of the object. The scan's run id is there on both arms,
including the derived one the sentence names only in prose.

A new walk is recorded whenever the target, scope, depth, policy, build
environment, resolved graph (every module at every selected version, every edge,
every artefact hash) or per-node outcome differs.

A stored scan is reused only when **all** of these hold:

| condition | |
|---|---|
| same walk | verdicts belong to the dependency set they were derived over |
| same advisory snapshot (source, version, retrieval time and seal) | a newer advisory database re-scans |
| same scan pipeline version | a newer kanonarion re-scans |
| the stored run's coverage is **complete** | a partial or failed run is never served |
| the project directory still requires the versions the walk resolved | a moved `go.mod` re-derives |

To force a fresh measurement:

- `--force` — re-fetches the modules, records a new walk and re-scans.
- `--fresh` — refreshes the advisory database. It re-scans only when the refresh
  changes an advisory listed for a module in this walk; a database that moved for
  anything else leaves the stored run serving.

`--fresh` does not force a new walk: an unchanged `go.mod` still resolves to the
same walk.

## Refreshing the advisory database (`--fresh`)

`--fresh` refreshes the vulnerability advisory database and nothing else. Two
cheap checks stand between the flag and the multi-megabyte database body:

1. **Has the database changed at all?** The generation `vuln.go.dev` publishes is
   read from the standalone `index/db.json` — one small request. Unchanged: the
   stored snapshot is kept and nothing else is asked.
2. **Has it changed anything this walk is judged on?** A new generation is
   published whenever any advisory in the ecosystem moves. The standalone
   `index/modules.json` (~60 KB compressed) is fetched and compared against the
   stored snapshot's own copy, restricted to the modules this walk holds —
   `stdlib` among them. Identical for every one of them: no download, and the
   stored scan run still answers.

Only a change to an advisory listed for a module in the walk — a new advisory, a
changed fixed version, an upstream edit such as a withdrawal — reaches the
download, and a re-scan with it.

The refresh states its outcome in the derivation block on **stderr**:

```
derivation:
  walk 01KZ0DJEV5XKAV1PSN1JM47D37: re-resolved and found identical to the walk taken 2026-08-02T05:01:29Z; that record was reused
  advisory database: checked vuln.go.dev and found it unchanged at 2026-07-27T20:14:16Z; nothing was downloaded and the stored snapshot was kept
  vulnerability scan: reused run vscan-01KZ0DJEV5XKAV1PSN1JM47D37-1785646889 of 2026-08-02T05:01:35Z against snapshot vuln.go.dev@2026-07-27T20:14:16Z; nothing was re-scanned (--force to re-measure)
```

The outcomes the line distinguishes:

| line says | meaning |
|---|---|
| `checked … and found it unchanged at <generation>` | the published generation is the stored one; nothing was transferred |
| `advanced <old> -> <new>; the advisories listed for all N modules in this walk are identical between the two, so the run judged against <old> remains current for this walk` | the database moved, but not for anything this walk is judged on; nothing was transferred and the stored run still answers |
| `advanced <old> -> <new> and the advisories changed for a module in this walk` | the database body was downloaded and the walk re-scanned against it |
| `advanced … but the advisories could not be compared (<error>)` | the comparison failed, so the full download and a re-scan ran instead |
| `published generation unreadable (<error>)` | the first check failed, so the full download ran instead |
| `no snapshot was stored; downloaded …` | first refresh on this store |
| `refresh failed (<error>)` | the database could not be brought up to date at all; the run continues against the stored database |

A reused run always names the snapshot it was **actually judged against**. When
the second check keeps a stored run alive across an advanced generation, that the
run remains current is a separate statement with its own basis — the module
count the comparison covered — not a restamping of the run.

The line appears only under `--fresh`. Without the flag the run reads the stored
database and makes no claim about its currency.

## The toolchain axis

Every run states, on **stderr**, what the advisory database says about the Go
toolchain the walk was built by:

```
toolchain:
  go1.26.5: none of the 30 toolchain advisories in vuln.go.dev@2026-07-27T20:14:16Z covers it
```

and when an advisory covers it:

```
toolchain:
  go1.26.2 is covered by 3 advisories in vuln.go.dev@2026-07-27T20:14:16Z: GO-2026-4978 (fixed in 1.26.3), GO-2026-4979 (fixed in 1.26.3), GO-2026-4984 (fixed in 1.26.3)
  this is the build toolchain, not a dependency of the artefact: it is reported as its own axis and is counted in no module roll-up
```

Under `--json` the same judgment is the `toolchain` key, in the shape
[`vuln-scan --json`](vuln-scan.md) publishes, carrying the lines above verbatim
in its `statement`.

The advisory database keys the toolchain — `cmd/go`, the compiler, the linker —
**separately from `stdlib`**, and the two sets are disjoint. No project imports
`cmd/*`, so no module scan and no reachability analysis of project code can ever
reach a toolchain advisory. The line is the only place they appear.

Reading it:

| the line says | it means |
|---|---|
| `<version>: none of the N toolchain advisories in <snapshot> covers it` | the snapshot's toolchain advisories were read and none covers this toolchain |
| `<version> is covered by … : <ids>` | those advisories cover it; the fix named is the one on **this toolchain's own release branch** |
| `… covered only by N advisories … that have since been withdrawn` | advisories cover it, but every one has been retracted by the database that published it |
| `<version> was not judged …: <reason>` | no judgment was made, and the reason names the missing input |

The judgment is **derived at report time** from the stored advisory snapshot and
the toolchain version the walk recorded — nothing is fetched and nothing is
recorded, so it costs one local read (single-digit milliseconds) and it
classifies every walk ever taken.

The version judged is the walk's build environment (`go env GOVERSION`) — the
toolchain that actually compiled the project. `--stdlib-from-gomod` pins the
synthetic stdlib node to the `go.mod` directive instead; it does **not** change
this line, which always reports the toolchain that ran.

`unjudged` is stated rather than omitted, because a missing line reads as a
clear. Its reasons:

| reason | remedy |
|---|---|
| `the snapshot's module index carries no toolchain key` | `--fresh` to refresh the advisory database |
| `the walk recorded no build toolchain version` | re-walk with `--force` |
| `the recorded toolchain version is not comparable to the database's version ranges` | a release-candidate or development toolchain; nothing to judge by version |
| `no advisory database snapshot is stored` | run once with network access |

The axis never changes the exit code and never appears in the module table, the
`--json` rows, or the affected/clean roll-ups.

## Local `go.sum` verification

On the **normal** (network) path, whenever the project's `go.sum` is present next
to the walked `go.mod`, `audit` layers it on as an always-on, offline integrity
check that **complements** the network checksum database. It costs nothing extra:
the module `h1` hashes are already computed during download, so the check is just
a lookup and compare - no extra hashing, no network round-trip. For each fetched
module `audit`:

- **Matches `go.sum` (zip and `/go.mod`)** - a positive signal. If the network
  checksum database also verified the module, the stronger `Verified` /
  `VerifiedBySumDBOnly` stands. If the checksum database was **unavailable**
  (offline, `GOSUMDB=off`, or no entry), the module reports **`VerifiedByGoSum`**
  instead of `UnverifiedNoSumDB` - `go.sum` is itself populated under a prior
  `sum.golang.org` check, so this is a genuine offline anchor.
- **Disagrees with `go.sum`** - tamper-evidence. `audit` **fails hard**, exiting
  non-zero (code `10`) and naming the offending module. A `go.sum` mismatch is
  never silently downgraded.
- **Absent from `go.sum`** - not a failure for an unreplaced module (a `go.sum`
  legitimately omits some transitively-cached entries); it falls through to the
  network checksum database as before. For a **replaced** module the absence is
  a hard stop naming both coordinates: `go.sum` records a replacement under the
  replace target, so when it describes the build at all it has an entry for the
  fork.

A replaced module is looked up under the replace target and reported under
both spellings — the verification detail reads `verified against local go.sum
under <fork> (required as <upstream>)`. A module replaced by a filesystem path
has no checksum and records `no checksum is available for a filesystem source,
so none was checked`.

Because the check reads only the local `go.sum`, it still fires when
`sum.golang.org` is unreachable - a working offline integrity signal. This is
distinct from `--from-modcache` below, where `go.sum` is the *sole* anchor and an
absent entry *is* a hard failure.

## Sourcing from an existing module cache (`--from-modcache`)

In a build pipeline the modules are already on disk: `go build` populates
`$GOMODCACHE` with each dependency's `.mod`/`.zip` (the module-proxy protocol on
disk) and verifies them against `go.sum`. `--from-modcache` makes `audit` treat
that cache as the source of truth instead of re-downloading everything from the
proxy.

In this mode `audit`:

- **Reads module bytes from the module cache** (`go env GOMODCACHE`, or the
  directory you name with `--from-modcache=/path`). A module missing from the
  cache is fetched into it with `go mod download`; nothing is written to
  kanonarion's blob store.
- **Verifies each module's `h1` hash against the local `go.sum`**, fully offline
  - no `sum.golang.org`. A hash that does not match, or a module with no `go.sum`
  entry, is a **hard failure**: `audit` exits non-zero (code `10`) naming the
  offending modules. Verified modules report `VerifiedBySumDBOnly` (VCS
  cross-verification is skipped in this mode).
- **Asks nothing upstream about staleness.** The run makes **zero** network
  calls to `proxy.golang.org`/`sum.golang.org`, so no module's latest version is
  probed and rows carry `major_probed: false`. The column reports what that
  leaves it: a module with a lookup recorded in the staleness ledger **inside
  `staleness.ttl`** is served that recording, and the row states its age
  (`latest: v0.57.0 (3 days ago) [from ledger, 20m0s old]`); every other module
  reads `unmeasured (offline)`, with `is_latest: null` and
  `staleness_unmeasured: offline_no_ledger_entry` in `--json`. The stderr
  coverage line counts both. Nothing is written to the ledger. The
  vulnerability scan still reads the stored OSV database (`--fresh` to refresh
  it).

```bash
# After `go build ./...` has populated the module cache:
kanonarion audit --from-modcache

# Or point at a specific cache directory:
kanonarion audit --from-modcache=/path/to/gomodcache
```

This is the mode the release pipeline uses: the build step populates the
cache, then `audit` and `sbom --package` consume it without a second trip to the
network. Default (no-flag) behaviour is unchanged - the network proxy, the
checksum database, and VCS cross-verification all run as before.

## See also

- [`latest`](latest.md) - dedicated version staleness lookup, single module or all direct deps
- `inspect` - full pipeline including interface, call-graph, and AI context
- `vuln-scan` - run vulnerability scanning independently for a walk
- `license-list` - list all stored license records
- `context` - query and display full stored context for a single module

## Modules resolved under pre-modules semantics

A `+incompatible` coordinate resolves no requirement edges at all, so what this command can show is bounded: a row for such a module is honest about that module, but nothing UNDER it was resolved, so the audited set is narrower than the build. The caveat is written to **stderr**, beside the other run-level axis lines, so `--json` on stdout is unchanged. The answer states that and names the coordinates responsible; see [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
