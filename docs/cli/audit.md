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
  `VerifiedBySumDBOnly`, `UnverifiedNoSumDB`, etc.)
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
| `--skip-vcs-verify` | `false` | Skip git cross-verification; the checksum-database check still runs. A sumdb-attested module then reports `VerifiedBySumDBOnly`, never the strongest `Verified` (the git leg never ran). Useful when auditing a large closure where git operations are rate-limited or unavailable |
| `--goproxy` | `$GOPROXY` | Override the Go module proxy |
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

## See also

- [`latest`](latest.md) - dedicated version staleness lookup, single module or all direct deps
- `inspect` - full pipeline including interface, call-graph, and AI context
- `vuln-scan` - run vulnerability scanning independently for a walk
- `license-list` - list all stored license records
- `context` - query and display full stored context for a single module
