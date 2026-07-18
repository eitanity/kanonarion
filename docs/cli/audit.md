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

For each module in the scope, `audit` emits a single line containing:

- **Coordinate** - `module@version`
- **Verification** - outcome of sumdb/VCS cross-verification (`Verified`,
  `VerifiedBySumDBOnly`, `VerifiedByGoSum`, `UnverifiedNoSumDB`, etc.). See
  [Local `go.sum` verification](#local-gosum-verification) for `VerifiedByGoSum`.
- **License** - primary SPDX identifier; annotated with status when ambiguous
  (e.g. `Apache-2.0 [Multiple]`)
- **Staleness** - `current` when the pinned version is the latest published, or
  `latest: vX.Y.Z (N days ago)` when a newer version exists
- **Vuln status** - `Clean`, `Affected (N findings)`, `ScanFailed`, or
  `(not scanned)` when no record exists yet. The verdict is **project-rooted**:
  it comes from a single scan of the project's resolved, pruned build graph - the
  build the project actually produces - not from scanning each dependency in
  isolation. A module the project builds cleanly reads `Clean` or `Affected`
  within that graph; only a genuine fault of the whole scan (no `go.mod`, an OOM
  kill, a build that does not compile) reads `Unscannable`/`ScanFailed`. Because
  no dependency is re-resolved on its own, a module can never be reported
  un-analysable merely because its isolated build would select a version the
  project never uses.

The scope always includes the **Go standard library** as a first-class row
(`stdlib@vX.Y.Z`), so standard-library advisories are audited alongside module
dependencies. Its **Verification** column reports the toolchain-specific chain of
custody — `VerifiedGoDevChecksum` when the canonical `go{VERSION}.src.tar.gz`
acquired from `go.dev/dl` matched Go's published checksum — which is deliberately
distinct from the module sumdb statuses (it is a published checksum plus a
`go.googlesource.com/go` tag/commit, never a `go.sum` entry). Its **License** is
`BSD-3-Clause` extracted from the tarball's `LICENSE` file. On a fully offline
run (`--from-modcache`) the chain cannot be established and the row reads
`(custody unavailable)`. See [SBOM standard-library chain of
custody](sbom.md#standard-library-chain-of-custody) for the full evidence set.

Its **Vulnerability** column is **call-graph-analysed against the build
toolchain**, not resolved from advisory metadata by coordinate: the same
project-rooted `govulncheck` run that analyses the dependency graph also reasons
over standard-library symbols, so a surfaced stdlib finding carries a populated
`Reachable` verdict and `AffectedSymbols` exactly as a module finding does. A
standard-library advisory that affects the pinned toolchain version but whose
vulnerable symbols are **not reached** from the project therefore reads `Clean`,
consistent with how an unreachable advisory in a fetched module is reported —
reachability is decided by the call graph, not by whether the enclosing symbol is
linked into the binary. Query a specific verdict with `kanonarion reachability
stdlib@vX.Y.Z --vuln <id>`.

The scope is an **import closure**, not a `require`-line listing: the `code`
scope is every module the project's packages (and their tests) actually import,
so indirect modules that are genuinely used are included and `require` entries
nothing imports are excluded. The set is computed by delegating to the Go
toolchain (`go list`) in the project directory.

`audit` replaces this manual workflow:

```bash
# Old: for each direct dep
kanonarion walk github.com/foo/bar@v1.2.3
WALK_ID=$(kanonarion walk-list --json | jq -r '.[0].id')
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
| `--fresh` | `false` | Fetch a fresh vulnerability database snapshot from the network |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` node from the `go.mod` directive, not the live toolchain. See [Standard-library version](walk.md#standard-library-version---stdlib-from-gomod). |
| `--skip-vcs-verify` | `false` | Skip git cross-verification; the checksum-database check still runs. A sumdb-attested module then reports `VerifiedBySumDBOnly`, never the strongest `Verified` (the git leg never ran). Useful when auditing a large closure where git operations are rate-limited or unavailable |
| `--from-modcache[=dir]` | _(off)_ | Source modules from an existing Go module cache instead of the network proxy, verifying each against the local `go.sum`. Passed bare it uses `go env GOMODCACHE`; an optional value names the cache directory. See [Sourcing from an existing module cache](#sourcing-from-an-existing-module-cache-from-modcache) |
| `--goproxy` | `$GOPROXY` | Override the Go module proxy (ignored under `--from-modcache`) |
| `--json` | `false` | Emit output as a JSON array |
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

## Example - code dependencies (default)

```
kanonarion audit
```

or explicitly:

```
kanonarion audit --gomod ./go.mod
```

```
github.com/CycloneDX/cyclonedx-go@v0.9.2    Verified              Apache-2.0              latest: v0.11.0 (today)       Clean
github.com/google/licensecheck@v0.3.1        Verified              BSD-3-Clause            current                       Clean
github.com/spf13/cobra@v1.10.2               Verified              Apache-2.0              current                       Clean
gopkg.in/yaml.v3@v3.0.1                      VerifiedBySumDBOnly   Apache-2.0 [Multiple]   current                       Clean
golang.org/x/mod@v0.35.0                     Verified              BSD-3-Clause            latest: v0.36.0 (6 days ago)  Clean
golang.org/x/vuln@v1.3.0                     Verified              BSD-3-Clause            current                       Clean
modernc.org/sqlite@v1.50.0                   Verified              BSD-3-Clause            latest: v1.50.1 (3 days ago)  Clean
```

## Example - complete set (code + tooling)

```
kanonarion audit --gomod ./go.mod --project
```

```
github.com/spf13/cobra@v1.10.2               Verified   Apache-2.0     current   Clean
golang.org/x/mod@v0.35.0                     Verified   BSD-3-Clause   current   Clean
github.com/golangci/golangci-lint/v2@v2.12.2 Verified   MIT            current   Clean
golang.org/x/vuln@v1.3.0                     Verified   BSD-3-Clause   current   Clean
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
[
  {
    "coordinate": "github.com/spf13/cobra@v1.10.2",
    "verification": "Verified",
    "license": "Apache-2.0",
    "license_status": "Detected",
    "vuln_status": "Clean",
    "vuln_findings": 0,
    "is_latest": true
  },
  {
    "coordinate": "golang.org/x/mod@v0.35.0",
    "verification": "Verified",
    "license": "BSD-3-Clause",
    "license_status": "Detected",
    "vuln_status": "Clean",
    "vuln_findings": 0,
    "is_latest": false,
    "latest_version": "v0.36.0",
    "days_behind": 6
  },
  {
    "coordinate": "golang.org/x/vuln@v1.3.0",
    "verification": "Verified",
    "license": "BSD-3-Clause",
    "license_status": "Detected",
    "vuln_status": "Clean",
    "vuln_findings": 0,
    "is_latest": true
  }
]
```

## Pipeline

`audit` runs a single project walk rooted at the local module and derives its
per-module rows from that one walk's graph, rather than one shallow walk per
dependency:

1. `walk` - one project walk rooted at the local module (`modulePath@local`), equivalent to `walk --gomod` for the selected scope. It resolves the whole scoped closure into a single graph holding the local root, every scoped node, and the edges between them.
2. `extract --stages license` - extract license records once over the project walk
3. `vuln-scan` - one **project-rooted** scan of the live working tree: `govulncheck` runs once over the project's real import graph from its real entry points, and each finding is attributed to the module that owns the vulnerable symbol. Every other in-build module is analysed-and-clean. This is not a per-module isolated scan, so it never re-selects a dependency version the project's build does not use.
4. Staleness check - query the proxy for the latest version of each module
5. Query and report - iterate the walk's dependency nodes (every graph node bar the local root) and join fetch, license, vuln, and staleness into one line each

Walk and licence extraction use cached results on subsequent runs unless
`--force` is passed. Two stages always do work on every run, warm store or not:
the project-rooted vuln scan is **always recomputed fresh** (the working tree
mutates between runs, so its verdict is live and never served from a coordinate
cache), and the **staleness check queries the module proxy** for each module's
latest version on every run - a live `@latest` request per module, never cached.

### Precursor to `sbom --package`

Because `audit` leaves behind exactly the project walk, license records, and
vuln records that `sbom --package` auto-discovers, a completed `audit` is a
valid precursor to it - no extra `walk` or `extract` command is needed:

```bash
kanonarion audit --gomod ./go.mod
kanonarion sbom --package ./cmd/kanonarion   # reuses audit's project walk
```

## Caching

`audit` is safe to re-run, but a warm re-run is **not** fully offline. The walk,
licence, and vulnerability-database stages are cached and do no network I/O on a
warm store (`--force` re-fetches the modules and re-runs the scan; `--fresh`
re-downloads the vulnerability database). Two stages always do work on every run:

- **Staleness** - `audit` queries the module proxy for each module's latest
  version (`@latest`) on every run. This is a live network call per module and
  is never cached.
- **Project-rooted vuln scan** - `govulncheck` re-runs over the live working
  tree every time (never served from a coordinate cache - see Pipeline above).
  This is local CPU work, not a network fetch, and reuses the cached
  vulnerability database unless `--fresh` is passed.

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
- **Absent from `go.sum`** - not a failure (a `go.sum` legitimately omits some
  transitively-cached entries); the module falls through to the network checksum
  database as before.

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
- **Skips the staleness check** (the per-module `@latest` proxy query), so the
  run makes **zero** network calls to `proxy.golang.org`/`sum.golang.org`. The
  vulnerability scan still reads the OSV database (`--fresh` to refresh it).

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
