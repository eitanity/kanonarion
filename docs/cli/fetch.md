# `kanonarion fetch` - Module fetch & verification

## Synopsis

```
kanonarion fetch <module>[@<version>] [flags]
kanonarion fetch <module> --list-versions [flags]
kanonarion fetch <module>@<version> --gomod ./go.mod [flags]
kanonarion fetch --gomod ./go.mod [flags]
kanonarion fetch --tool [--gomod ./go.mod] [flags]
kanonarion fetch --project [--gomod ./go.mod] [flags]
```

## Description

`fetch` downloads a Go module from the proxy, cross-verifies it, stores the zip
in the content-addressed blob store, and writes a `FactRecord` with the module
coordinate, content hash and verification status.

`@<version>` is an explicit version or `@latest`. You may omit it only with
`--list-versions` or a scope flag (`--gomod`/`--tool`/`--project`).

The `VerificationStatus` is `Verified`, `Unverified` (for example when
`--insecure` forces a plain-HTTP proxy), or a failure status. `--strict` makes a
verification failure exit non-zero.

The record's `version_time` is the version's own time from the proxy's or module
cache's `.info`. It is `null` in `--json` when the source gave none or an earlier
version wrote the record.

### Checksum database

The module hash is checked against the Go checksum database (`sum.golang.org`
or a configured mirror), which holds one hash for the zip and one for the
`go.mod`. A full fetch checks both; either disagreeing records
`UnverifiedHashMismatch` naming the two hashes. A go.mod-only fetch (taken when
only a module's requirements are needed) is checked against the `go.mod` hash: a
match records `VerifiedBySumDBOnly`, a mismatch `UnverifiedHashMismatch`.

### VCS cross-verification

The proxy zip is compared against the upstream source repository. This needs a
`git` binary on `PATH`. `Verified` means the zip was reproduced from the git
commit, so a module whose git leg did not run reaches `VerifiedBySumDBOnly` at
best.

- `--skip-vcs-verify` skips the git leg; the checksum check still runs.
- **`git` absent:** the fetch does not fail. The VCS sub-check reports
  `UnverifiedVCSToolMissing` (the check never ran), not `UnverifiedNoVCS` (it
  ran and could not confirm). The detail names `--skip-vcs-verify`.
- **Time bound:** each git command that talks to the repository (`git
  ls-remote` for the tag, each `git fetch`) is limited to 2 minutes. On timeout
  the VCS leg is recorded as not run and the detail names the bound.

A record whose VCS leg could not run is never served from cache: the next
ordinary run checks again, with no `--force`. This includes a record written by
an earlier version whose detail says a git command exceeded the bound; the old
record stays in the store beside the new one.

A module in a repository subdirectory (`service/s3`, or `client/v3` for a `/v3`
module whose code lives in `client/`) is compared as the go command builds it:
against the prefixed tag (`refs/tags/service/s3/v1.2.3`), hashing only that
directory. The directory comes from the proxy's `Origin` metadata, else from the
module path. `git_subdir` names it relative to the repository root (`"."` for the
root; `null` when nothing was hashed or an earlier version wrote the record). If
the directory is missing at that tag, or its `go.mod` names another module, the
detail says so and nothing is hashed. A record from an earlier version keeps its
detail (often "proxy hash … does not match git checkout hash …") until the next
full fetch or `fetch --force`.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--force` | `false` | Re-fetch even if a cached record exists |
| `--strict` | `false` | Exit non-zero on verification failure |
| `--insecure` | `false` | Allow plain HTTP proxy URLs (forces unverified status) |
| `--skip-vcs-verify` | `false` | Skip git cross-verification (requires `git` on `PATH`); checksum verification still runs |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the module proxy. `off` and `direct` mean the same here as in `$GOPROXY` - see [`GOPROXY=off` and `direct`](#goproxyoff-and-direct) |
| `--list-versions` | `false` | List available versions from the proxy and exit without fetching |
| `--gomod` | `./go.mod` | Path to a `go.mod` file; fetch its dependency scope instead of a positional module. With a positional module, fetch only that module, verifying a private module against the `go.sum` beside this `go.mod` - see [Private modules](#private-modules-goprivate-gonoproxy) |
| `--tool` | `false` | Fetch the tooling supply chain (the `go.mod` tool directives' closure) instead of a positional module. Mutually exclusive with `--project`; refused by name alongside a positional module |
| `--project` | `false` | Fetch the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool`; refused by name alongside a positional module |
| `--allow-verification-downgrade` | `false` | Permit a weaker re-measurement of a coordinate to be recorded alongside a stronger stored one. Without it the weaker measurement is refused, the stronger record is kept and answers, and the run warns. See [Re-measuring with a weaker anchor](#re-measuring-with-a-weaker-anchor---allow-verification-downgrade) |
| `--policy` | _(auto-discover `.kanonarion/policy.yaml`)_ | Depth policy file; its fetch stage's `allowed_vcs_hosts` selects which forges may be cross-verified |
| `--no-progress` | `false` | Suppress the stderr lines that say the staleness lookup is being asked again; results and warnings are unaffected |
| `--json` | `false` | Emit the fact record as JSON |

A scope fetch is triggered by `--gomod`, `--tool`, or `--project`: default
`code` (`go list -deps -test ./...`), `--tool` the tooling supply chain,
`--project` the complete set, as in [`walk` Scopes](walk.md#scopes-code-tool-complete).
`--tool` and `--project` cannot be combined with a positional module, and no
scope flag with `--list-versions`. Every module in the scope is fetched,
continuing on per-module errors, except a local-path `replace`: it is compiled
from a directory, so it is not fetched and its path is never sent to the proxy.

The run states on stderr, before the first fetch, the scope and test axis it
resolved and how many modules it fetches. `--exclude-tests` is **refused by
name**: a walk record names no test axis. See
[Test scope](walk.md#test-scope---exclude-tests).

### Trusted VCS forges

Cross-verification clones the repository named by the proxy's `Origin`
metadata, or inferred from the module path when there is none. Only hosts on an
allowlist are handed to `git`. The built-in set is:

```
bitbucket.org  codeberg.org  github.com  gitlab.com  go.googlesource.com  gopkg.in
```

A module hosted elsewhere is not cloned; it falls back to checksum-database
verification and says so in `verification_detail`. Set the list with the fetch
stage's `allowed_vcs_hosts` - see
[`policy`](policy.md#trusted-vcs-forges-allowed_vcs_hosts). `fetch` reads the
same auto-discovered `.kanonarion/policy.yaml` as `walk`, or the file named by
`--policy`. The allowlist chooses **which** forges are trusted, not **whether**
cross-verification runs; use `--skip-vcs-verify` to skip it.

### `GOPROXY=off` and `direct`

kanonarion honours `GOPROXY=off`: no command fetches a module over the network.
`--goproxy off` on `fetch`, `walk`, `latest`, `audit` and `inspect` declares the
same air gap for the whole run. What each command does next:

| Command | Under `GOPROXY=off` |
|---|---|
| `fetch` | Refuses before it opens a socket, exit `20` |
| `walk <module>@latest`, `inspect <module>@latest` | Refuse before they open a socket, exit `20` |
| `latest` | Serves a lookup the store recorded inside `staleness.ttl`; with none, refuses, exit `20` |
| `walk --gomod` | Runs. Each module it cannot fetch is recorded as failed, and the walk ends partial, exit `1` |
| `walk <module>@<version>`, `inspect <module>@<version>` | Run. The target cannot be fetched, so the walk fails, exit `2` |
| `audit` | Warns and runs to completion. Modules it cannot fetch show `(not fetched)`, and the staleness column answers from the ledger |

Each refusal names the offline way to proceed, using only flags that command
accepts. `fetch` has no `--from-modcache`, so it names another command:

```
$ GOPROXY=off kanonarion fetch github.com/spf13/cobra@v1.8.1
error: execute root command: GOPROXY=off: the environment declares no module fetching
  kanonarion fetch reaches the network on every invocation and has no flag that withdraws it; to do this offline, run:
    kanonarion walk --gomod ./go.mod --from-modcache
$ echo $?
20
```

`walk`, `audit` and `sbom` have the flag and are told to pass it. `audit` logs
the remedy as a warning and carries on:

```
$ GOPROXY=off kanonarion audit --gomod ./go.mod
notice: code scope resolved 1 module(s); test-scope dependencies included
time=2026-10-12T19:30:33.638040142Z level=WARN msg="module fetching refused by the environment; reads continue, fetches will fail" reason="GOPROXY=off: the environment declares no module fetching\n  run it offline instead: kanonarion audit accepts --from-modcache, which answers without the network"
```

Reads of the store keep working (`callgraph`, `interface`, `license`,
`capability`, `vendor`, `extract`, `vuln show`, `walk show` and the rest), and
so do the offline acquisition modes: `--from-modcache` reads `$GOMODCACHE`, and
`kanonarion use --recursive` rebuilds a module and its closure from the store
into a module cache `go build` can use.

`GOPROXY=direct` asks for VCS-origin fetching, which this build does not
implement. It is refused, naming the mode; it is not an air gap, so nothing else
is withdrawn. `--goproxy direct` is refused the same way. Neither `off` nor
`direct` falls back to `proxy.golang.org`.

A list is resolved as Go does: entries separated by `,` or `|` are tried in
order, so `GOPROXY=https://proxy.example.com,direct` uses the first entry, and
an `off` reached first ends the chain.

`GOPROXY` is read from the environment, then from the file `go env -w` writes
to, so `go env -w GOPROXY=off` declares the air gap with nothing set in the
shell. A `--goproxy` flag comes before both, and the `go` commands kanonarion
starts get the same value. The exception is `--goproxy direct`: it declares
nothing, so the environment's value stays in force, an air gap included.

### What else `GOPROXY=off` withdraws

Under `GOPROXY=off`, or `--goproxy off`, every network path kanonarion owns
refuses before it opens a socket or starts a subprocess, and every `go` child is
given `GOPROXY=off`:

| Path | Under `GOPROXY=off` | What still answers |
|---|---|---|
| Module fetch | `fetch` refuses, exit `20`; a walk records the module as failed (exit `1`, or `2` when it is the walk's own target); `audit` carries on | `--from-modcache`, [`use --recursive`](use.md) |
| Advisory snapshot download (`vuln-scan`, `audit`, `inspect`) | Refuses the download | A snapshot the store already holds - see [`vuln`](vuln.md#air-gapped-scanning) |
| Checksum database (`sum.golang.org`) | Treated as `GOSUMDB=off`: modules record `UnverifiedNoSumDB`, or `VerifiedByGoSum` where a project `go.sum` anchors them | The local `go.sum` anchor |
| Standard-library `go.dev/dl` acquisition | Not used; the local-toolchain anchor is selected instead, as under `--from-modcache` | `$GOROOT/src` + `$GOROOT/LICENSE`, recorded `VerifiedLocalToolchain` |
| `git` cross-verification (`ls-remote`, shallow fetch) | Refuses to spawn; the record marks the VCS leg as one that could not run | Checksum-database or `go.sum` verification, landing on `VerifiedBySumDBOnly` |

`GOSUMDB=off`, `--from-modcache` and `--skip-vcs-verify` withdraw these paths
one at a time. `GONOSUMCHECK=1` turns the checksum database off for every
module; a `GONOSUMCHECK` naming module prefixes keeps its pattern meaning.

### Private modules (`GOPRIVATE`, `GONOPROXY`)

kanonarion follows the go command's rule. A module whose path matches
`GONOPROXY`, or `GOPRIVATE` when `GONOPROXY` is not set, is never named to a
module proxy. A pattern is a module path prefix: `corp.example.com` matches
`corp.example.com/a` and `corp.example.com/a/v2`. Separate patterns with commas.
Both variables are read from the environment, then from the file `go env -w`
writes to.

A private module is read from the module cache (`$GOMODCACHE`), as
`--from-modcache` reads every module:

- If it is not in the cache, kanonarion runs `go mod download
  <module>@<version>` in the project directory. The go command fetches it from
  its origin with your own credentials (`GOAUTH`, `.netrc`, git credential
  helpers, ssh keys). kanonarion holds no credentials.
- The bytes are hashed and checked against the project's `go.sum`. A hash that
  disagrees, or a module missing from `go.sum`, stops the run.
- The record reads `VerifiedByGoSum`. Its detail names the variable that made it
  private, for example `private module (GOPRIVATE): read from the module cache,
  ...`. Its VCS leg reads `private_module`: no `git` process starts and no URL is
  guessed from the path. The checksum database is not consulted.

Every other module uses the configured proxy. `GONOPROXY=none` with `GOPRIVATE`
set sends every module through the proxy, as the go command does.

The checksum database is skipped for a module that matches `GOPRIVATE`,
`GONOSUMDB` or a `GONOSUMCHECK` pattern, and the detail names the variable in
force: `module matches GONOSUMCHECK/GOPRIVATE pattern; the setting in force is
GOPRIVATE`.

A private module named on its own has no project `go.sum`, so it is refused,
exit `20`, before any request:

```
$ GOPRIVATE=corp.example.com kanonarion fetch corp.example.com/a@v1.0.0
error: execute root command: corp.example.com/a matches GOPRIVATE/GONOPROXY: kanonarion reads a private module only from the module cache against a project go.sum; run from the project with --gomod
```

`walk <module>@<version>` and `inspect <module>@<version>` refuse in the same
words. `fetch --gomod ./go.mod` fetches the project's private modules against
its `go.sum`; `fetch <module>@<version> --gomod ./go.mod` fetches one of them.
`@latest` is refused for a private module, since only a proxy resolves it.

A read that finds no fetch record for a private module (`license`, `callgraph`,
`interface`, `examples`, `native` and the rest) names that route as its remedy:

```
run 'kanonarion fetch corp.example.com/a@v1.0.0 --gomod <path to the project's go.mod>' from the project that requires it (a private module is verified against its go.sum)
```

The staleness note for a private module comes from the go command, never from
a proxy - see [`latest`: private modules](latest.md#private-modules).

### Re-measuring with a weaker anchor (`--allow-verification-downgrade`)

A connected run reaches the checksum-database transparency log. An offline run
(`--from-modcache`, or anything under `GOPROXY=off`) reaches only the local
`go.sum`. Re-measuring a coordinate offline therefore gives a weaker record than
the one a connected run stored.

By default the weaker measurement is **not recorded**. The run answers from the
stronger stored record, warns with both verification statuses and both
acquisition modes, and appends an event to the assurance log. These always
land: a re-measurement of equal or greater strength, and a full record after a
`go.mod`-only one.

With `--allow-verification-downgrade` the weaker measurement is recorded too.
The stronger record is still held and still answers, because a read composes a
coordinate's records by anchor strength. The run logs the permitted downgrade
in the assurance log as an operator decision. `--force` does not do this: it
re-measures, it does not accept a weaker anchor.

If the kept record's artefacts cannot be read on this run, the store still keeps
the stronger record and the run returns the bytes it just measured, unpersisted.

Accepted by `fetch`, `walk`, `sbom` and `audit`; it applies to every fetch the
invocation makes.

### Staleness annotation

A fetch of a pinned version asks the proxy whether the pin is the newest
version. Text output adds a trailing clause; `--json` adds a `staleness` block:

```json
{
  "record": { "...": "..." },
  "staleness": {
    "is_latest": false,
    "pin_ahead_of_latest": false,
    "latest_version": "v1.2.0",
    "days_since_latest": 3
  }
}
```

| Situation | Text clause | `is_latest` | `pin_ahead_of_latest` | `days_since_latest` | `staleness_unmeasured` |
|---|---|---|---|---|---|
| Pin is the newest version | _(none)_ | `true` | `false` | `null` | absent |
| Pin is behind | `[latest: v1.2.0, 3 days ago]` | `false` | `false` | `3` | absent |
| Pin is behind, released today | `[latest: v1.2.0, released today]` | `false` | `false` | `0` | absent |
| Pin is behind, no publication date | `[latest: v1.2.0]` | `false` | `false` | `null` | absent |
| Pin sorts above `@latest` | `[ahead of latest tag: v1.0.0]` | `false` | `true` | `null` | absent |
| Proxy lookup failed | `[staleness unmeasured (lookup failed)]` | `null` | `null` | `null` | `lookup_failed` |
| Private module the go command could not resolve | `[staleness unmeasured (private module)]` | `null` | `null` | `null` | `private_module` |
| `@latest` was requested | `[staleness unmeasured (not asked)]` | `null` | `null` | `null` | `not_asked` |

All three fields are emitted on every block. `days_since_latest` of `0` means
released today; `null` means there is no age, and the two fields to its left say
why. `@latest` fetches the newest version, so no comparison is made. A failed
lookup is also named on stderr and does not fail the fetch.

A lookup the proxy has not finished (an empty body, a timeout, a 5xx) is asked
again every 20 seconds for up to 4 minutes, and each retry says so on stderr
(`staleness progress: retrying example.com/mod (attempt 2, 10s of 4m0s)`). A
lookup still unanswered after that is `lookup_failed`.

The `staleness` block is **output only**: it is not part of the stored fact
record and is not hashed.

## Storage

Fetched zips are stored content-addressed under `<store-root>/blobs/`. Fact
records are stored in `<store-root>/mirror.db` (SQLite), keyed by
`(module, version, pipeline_version)`. Every fetch is also appended to
`<store-root>/audit.jsonl`.

### A stored record this build cannot reproduce

A fact record written by another build may spell a value differently, for
example a timestamp at another precision. Its values hash to its own seal, so
nothing was altered, but this build cannot re-derive the seal. Such a record is
**set aside**: left out of the answer and named once on stderr:

```
set aside fetch record example.com/mod@v1.0.0 (pipeline 0.4.0) content_hash sha256:3f1c…: written in a canonical shape this build cannot reproduce; its bytes hash to their own seal, so nothing was altered — read it with the build that wrote it, or upgrade
```

Readers answer from the module's other records. `context` names the record in
its `verification` section (`set_aside` under `--json`), and
`verification-coverage --json` in its `set_aside`. Each entry has
`kind: "fetch record"`.

When **every** record of a module was set aside:

- `fetch`, a walk's local-replace ingest, and the pre-fetch that `vuln-scan` and
  `callgraph` run for missing modules measure the module again and append a
  record this build can serve. The set-aside records stay as written.
- `callgraph`, `license`, `interface` and `examples` with a coordinate exit `4`
  and name each record.
- `context` reports `verification.status: set_aside`, `audit` shows
  `(set aside)` in the verification column, and `verification-coverage` puts the
  module in `unrecorded` with the statement as its reason.

A record whose values do **not** hash to its seal was altered after it was
written (`fetch record integrity check failed`): the commands above exit `10`,
`audit` shows `(integrity check failed)` and exits `10` after its table,
`verification-coverage` refuses at exit `10`, and `context` reports
`verification.status: read_error` with the failure.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Fetch or (with `--strict`) verification failed |
| `3` | Cancelled |
| `4` | A read needing a module's fetch record found only records this build cannot reproduce (see above) |
| `10` | Integrity check failed |
| `20` | Configuration or precondition error: an invalid flag combination, an environment that forbids fetching (`GOPROXY=off`, `GOPROXY=direct`), or a private module named without a project (see [Private modules](#private-modules-goprivate-gonoproxy)) |

## Examples

```
kanonarion fetch github.com/spf13/cobra@v1.8.1
kanonarion fetch github.com/spf13/cobra@latest --json
kanonarion fetch github.com/spf13/cobra --list-versions
kanonarion fetch github.com/spf13/cobra@v1.8.1 --force --strict --store-root /var/mirror
kanonarion fetch --tool --gomod ./go.mod
GOPROXY=off kanonarion fetch github.com/spf13/cobra@v1.8.1   # refuses, exit 20
```

## Relation to other stages

- **Produces:** the module zip in the blob store and a `FactRecord`.
- **Required by:** every extraction stage (`walk`, `interface`, `callgraph`,
  `examples`, `license`, `vuln-scan`) - they read the fetched zip from the
  blob store.

## See also

- [`kanonarion walk`](walk.md) - resolve a module's dependency graph
- [`kanonarion interface`](interface.md) - extract a module's public API
