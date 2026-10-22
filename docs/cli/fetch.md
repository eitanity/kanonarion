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

`fetch` downloads a Go module from the proxy, cross-verifies it, persists the
zip to the content-addressed blob store, and writes a `FactRecord` capturing
the module coordinate, content hash, and verification status.

Verification has two independent checks:

- **Checksum database** - the module hash is checked against the Go checksum
  database (`sum.golang.org` or a configured mirror). The database records two
  hashes per version, one for the zip and one for the `go.mod`. A full fetch
  checks both; either disagreeing records `UnverifiedHashMismatch` naming the
  two hashes. A go.mod-only fetch (the `go.mod` alone, taken when only a
  module's requirements are needed) is checked against the database's `go.mod`
  hash: a match records `VerifiedBySumDBOnly`, a mismatch
  `UnverifiedHashMismatch`.
- **VCS cross-verification** - the proxy zip is compared against the upstream
  source repository. Skippable with `--skip-vcs-verify`; the checksum check
  still runs. **Requires a `git` binary on `PATH`.** If `git` is absent the
  fetch does not fail: the checksum check still runs and the record is written
  with an unverified VCS status whose detail names `--skip-vcs-verify`. The
  record also marks the VCS leg as one that could not run, which is a fact about
  the host rather than about the module, so it is never served from cache -
  install `git` and the next ordinary run re-establishes the answer with no
  `--force`.

  Each git command that talks to the source repository - the `git ls-remote`
  that resolves the tag, and each `git fetch` - is bounded at 2 minutes. A
  command that exceeds the bound is recorded the same way: the VCS leg could not
  run, the detail names the bound, a module the checksum database attests lands
  on `VerifiedBySumDBOnly`, and the record is never served from cache, so the
  next ordinary run checks again. A record from an earlier version whose detail
  says a git command exceeded the fetch bound is also re-checked by the next
  ordinary run; the old record stays in the store beside the new one.

  Because `--skip-vcs-verify` means the git leg never ran, a module the
  checksum database attests resolves to `VerifiedBySumDBOnly`, **never** the
  strongest `Verified` - that status is reserved for a zip actually reproduced
  from the git commit, so the label can never claim a check that was skipped.

  A module in a subdirectory of its repository (`service/s3`, or `client/v3`
  for a `/v3` module whose code lives in `client/`) is compared as the go
  command builds it: the tag is the directory-prefixed one
  (`refs/tags/service/s3/v1.2.3`), and only that directory is hashed. The
  directory comes from the proxy's `Origin` metadata, or from the module path
  when the proxy gives none. The record's `git_subdir` names the directory
  hashed, relative to the repository root: `"."` for the root, and `null` in
  `--json` when the record names no directory (nothing was hashed, or the record
  was written by an earlier version). If the directory is missing at that tag,
  or its `go.mod` names another module, the detail says so and nothing is
  hashed. A record written by an
  earlier version keeps its detail (often "proxy hash … does not match git
  checkout hash …" for such a module) until the coordinate is fetched again:
  `fetch --force`, or the next full fetch of it.

`@<version>` may be an explicit version or `@latest`. Omitting it is only
valid with `--list-versions` or a scope flag (`--gomod`/`--tool`/`--project`).

The resulting `VerificationStatus` is `Verified`, `Unverified` (e.g. when
`--insecure` forces a plain-HTTP proxy), or a failure status. Use `--strict`
to make a verification failure exit non-zero.

When `git` is absent the VCS sub-check reports `UnverifiedVCSToolMissing` -
a distinct *"the check never ran because the tool is missing"* outcome, kept
separate from `UnverifiedNoVCS` (*"the check ran and could not confirm"*) so
the gap reads as fixable (install git) rather than as a verification failure.

## Commands

### `fetch`

Fetch, verify, and persist a single module fact record.

```
kanonarion fetch <module>@<version> [flags]
```

**Flags:**

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

A scope fetch is triggered by `--gomod`, `--tool`, or `--project`; the scope is
consistent with every other go.mod command - default `code` (the project's own
code dependencies, `go list -deps -test ./...`), `--tool` the tooling supply
chain, `--project` the complete set. See
[`walk` Scopes](walk.md#scopes-code-tool-complete). `--tool` and `--project`
cannot be combined with a positional module, and no scope flag with
`--list-versions`; every module in the
scope is fetched, continuing on per-module errors.

The run states which scope and test axis it resolved over on stderr before the
first fetch. `--exclude-tests` is **refused by name**: a scope fetch populates the
store for a walk of that scope, and a walk record names no test axis. See
[Test scope](walk.md#test-scope---exclude-tests).

### Trusted VCS forges

Cross-verification clones the repository the module's proxy `Origin` metadata
names - or, when there is no `Origin`, the repository inferred from the module
path itself. Either way a URL from outside kanonarion reaches a `git`
subprocess, so the set of hosts that may be handed to it is an allowlist, not a
free-for-all. By default it is the
built-in set:

```
bitbucket.org  codeberg.org  github.com  gitlab.com  go.googlesource.com  gopkg.in
```

A module whose repository lives elsewhere is not cloned; it degrades to
checksum-database verification and says so in `verification_detail`. The set is
policy-configurable via the fetch stage's `allowed_vcs_hosts` - see
[`policy`](policy.md#trusted-vcs-forges-allowed_vcs_hosts). `kanonarion fetch`
reads the same auto-discovered `.kanonarion/policy.yaml` that `walk` does, or
the file named by `--policy`.

The allowlist governs **which** forges are trusted, never **whether**
cross-verification runs; to skip the git leg entirely use `--skip-vcs-verify`.

### `GOPROXY=off` and `direct`

`GOPROXY=off` is Go's declaration that this environment does no module
fetching. kanonarion honours it. `--goproxy off` on `fetch`, `walk`, `latest`,
`audit` and `inspect` declares the same air gap: when the flag is given, its
value is used in place of the environment's for the whole run, and the run
prints what it prints under `GOPROXY=off`. No command fetches a module over
the network. What each one does next differs:

| Command | Under `GOPROXY=off` |
|---|---|
| `fetch` | Refuses before it opens a socket, exit `20` |
| `walk <module>@latest`, `inspect <module>@latest` | Refuse before they open a socket, exit `20` |
| `latest` | Serves a lookup the store recorded inside `staleness.ttl`; with none, refuses, exit `20` |
| `walk --gomod` | Runs. Each module it cannot fetch is recorded as failed, and the walk ends partial, exit `1` |
| `walk <module>@<version>`, `inspect <module>@<version>` | Run. The target cannot be fetched, so the walk fails, exit `2` |
| `audit` | Warns and runs to completion. Modules it cannot fetch show `(not fetched)`, and the staleness column answers from the ledger |

Each refusal names the offline way to proceed. The remedy is rendered **per
command**, and names only what that command accepts. `fetch` defines no
`--from-modcache`, so it is told what to run instead:

```
$ GOPROXY=off kanonarion fetch github.com/spf13/cobra@v1.8.1
error: execute root command: GOPROXY=off: the environment declares no module fetching
  kanonarion fetch reaches the network on every invocation and has no flag that withdraws it; to do this offline, run:
    kanonarion walk --gomod ./go.mod --from-modcache
$ echo $?
20
```

`walk`, `audit` and `sbom` do define the flag, and are told to pass it. `audit`
is not stopped: it logs the remedy as a warning and carries on:

```
$ GOPROXY=off kanonarion audit --gomod ./go.mod
notice: code scope resolved 1 module(s); test-scope dependencies included
time=2026-10-12T19:30:33.638040142Z level=WARN msg="module fetching refused by the environment; reads continue, fetches will fail" reason="GOPROXY=off: the environment declares no module fetching\n  run it offline instead: kanonarion audit accepts --from-modcache, which answers without the network"
```

The refusal withdraws **fetching**, not the store. Reading what has already
been measured keeps working under `GOPROXY=off` - `callgraph`, `interface`,
`license`, `capability`, `vendor`, `extract`, `vuln show`, `walk show` and the
rest - and so do the offline acquisition modes: `--from-modcache` reads
`$GOMODCACHE` and never the network, and `kanonarion use --recursive`
reconstitutes a module and its closure from the store into a module cache a
plain `go build` can consume.

`GOPROXY=direct` selects VCS-origin fetching, which this build does not
implement. The module proxy refuses it, naming the unsupported mode; it is not
an air gap, so nothing else is withdrawn. `--goproxy direct` is refused the same
way, and it does not lift an air gap the environment declares.
What neither value does is fall back to `proxy.golang.org`: `off` and `direct`
are the two values whose meaning is "not that proxy", and treating them as
"unset" would cross exactly the boundary the operator drew.

The list form follows Go's own resolution: entries are separated by `,` or
`|` and tried in order, so `GOPROXY=https://proxy.example.com,direct` uses the
first entry, while an `off` reached first terminates the chain and nothing
after it is tried.

`GOPROXY` is read from Go's own sources, not just the shell: the environment
variable first, then the env file `go env -w` writes to. `go env -w
GOPROXY=off` therefore declares the air gap for kanonarion exactly as it does
for `go build`, with nothing set in the environment. A `--goproxy` flag, when
given, comes before both, and the `go` commands kanonarion starts are given the
same value. `--goproxy direct` is the exception: it declares nothing, so the
environment's decision stays in force, an air gap included.

### What else `GOPROXY=off` withdraws

The declaration is not the module proxy's alone. Under `GOPROXY=off`, or
`--goproxy off`, every network path kanonarion owns refuses before it opens a
socket or starts a subprocess, and every `go` child it starts is given
`GOPROXY=off`:

| Path | Under `GOPROXY=off` | What still answers |
|---|---|---|
| Module fetch | `fetch` refuses, exit `20`; a walk records the module as failed (exit `1`, or `2` when it is the walk's own target); `audit` carries on | `--from-modcache`, [`use --recursive`](use.md) |
| Advisory snapshot download (`vuln-scan`, `audit`, `inspect`) | Refuses the download | A snapshot the store already holds - see [`vuln`](vuln.md#air-gapped-scanning) |
| Checksum database (`sum.golang.org`) | Treated as `GOSUMDB=off`: modules record `UnverifiedNoSumDB`, or `VerifiedByGoSum` where a project `go.sum` anchors them | The local `go.sum` anchor |
| Standard-library `go.dev/dl` acquisition | Not used; the local-toolchain anchor is selected instead, as under `--from-modcache` | `$GOROOT/src` + `$GOROOT/LICENSE`, recorded `VerifiedLocalToolchain` |
| `git` cross-verification (`ls-remote`, shallow fetch) | Refuses to spawn; the record marks the VCS leg as one that could not run | Checksum-database or `go.sum` verification, landing on `VerifiedBySumDBOnly` |

`GOSUMDB=off`, `--from-modcache` and `--skip-vcs-verify` remain the ways to
withdraw those paths individually. `GOPROXY=off` withdraws all of them at once,
which is what an air gap is. Reading the store is unaffected throughout.

`GONOSUMCHECK=1` is honoured as the boolean it is - the checksum database is
switched off for every module. A `GONOSUMCHECK` naming module prefixes keeps
its pattern meaning.

### Private modules (`GOPRIVATE`, `GONOPROXY`)

kanonarion follows the go command's rule for private modules. A module whose
path matches `GONOPROXY`, or `GOPRIVATE` when `GONOPROXY` is not set, is never
named to a module proxy. A pattern is a module path prefix: `corp.example.com`
matches `corp.example.com/a` and `corp.example.com/a/v2`. Several patterns are
separated by commas. Both variables are read from the environment, then from
the file `go env -w` writes to.

A private module is read from the module cache (`$GOMODCACHE`), the way
`--from-modcache` reads every module:

- When the module is not in the cache yet, kanonarion runs
  `go mod download <module>@<version>` in the project directory. The go command
  fetches it from its origin with your own credentials (`GOAUTH`, `.netrc`, git
  credential helpers, ssh keys). kanonarion holds no credentials of its own.
- The bytes are hashed and checked against the project's `go.sum`. A hash that
  disagrees, or a module missing from `go.sum`, stops the run, as it does under
  `--from-modcache`.
- The record reads `VerifiedByGoSum`. Its detail names the variable that made
  the module private, for example `private module (GOPRIVATE): read from the
  module cache, ...`. Its VCS leg reads `private_module`: no `git` process is
  started for it, and no URL is guessed from its path. The checksum database is
  not consulted.

Every other module takes the configured proxy exactly as before.
`GONOPROXY=none` with `GOPRIVATE` set sends every module through the proxy, as
the go command does.

The checksum database is skipped for a module that matches `GOPRIVATE`,
`GONOSUMDB` or a `GONOSUMCHECK` pattern, and the record's detail names the
variable in force: `module matches GONOSUMCHECK/GOPRIVATE pattern; the setting
in force is GOPRIVATE`.

A private module named on its own has no project `go.sum` to be verified
against, so it is refused, exit `20`, before any request:

```
$ GOPRIVATE=corp.example.com kanonarion fetch corp.example.com/a@v1.0.0
error: execute root command: corp.example.com/a matches GOPRIVATE/GONOPROXY: kanonarion reads a private module only from the module cache against a project go.sum; run from the project with --gomod
```

`walk <module>@<version>` and `inspect <module>@<version>` refuse in the same
words. `fetch --gomod ./go.mod` fetches the project's private modules against
its `go.sum`, and `fetch <module>@<version> --gomod ./go.mod` fetches one of
them. `@latest` is refused for a private module, since only a proxy resolves it.

A read that finds no fetch record for a private module - `license`,
`callgraph`, `interface`, `examples`, `native` and the rest - names that route
as its remedy:

```
run 'kanonarion fetch corp.example.com/a@v1.0.0 --gomod <path to the project's go.mod>' from the project that requires it (a private module is verified against its go.sum)
``` Its staleness note for a private module comes from the go command,
never from a proxy - see [`latest`: private modules](latest.md#private-modules).

### Re-measuring with a weaker anchor (`--allow-verification-downgrade`)

A stored record carries the strongest verification anchor the run that produced
it could reach. A connected run reaches the checksum-database transparency log;
an offline run - `--from-modcache`, or anything under `GOPROXY=off` - tops out
at the local `go.sum`. Re-measuring a coordinate offline therefore produces a
weaker record than a connected run already stored for it.

By default that weaker measurement is **not recorded**. The run keeps the
stronger stored record, answers from it, logs a warning naming both verification
statuses and both acquisition modes, and appends an event to the assurance log.
Two cases are not downgrades and always land: a re-measurement of equal or
greater strength, and a full record following a `go.mod`-only one, which adds
artefact coverage rather than weakening an anchor.

`--allow-verification-downgrade` permits the weaker measurement to be recorded.
The record ledger is append-only, so the stronger measurement is still held and
a read composes a coordinate's records by anchor strength - the stronger anchor
goes on answering. The permitted downgrade is recorded in the assurance log as
an operator decision.

`--force` is not a substitute: it means "measure this coordinate again now", not
"accept a weaker anchor for it". An air-gapped or `--from-modcache` run produces
the weakest measurements available, and is the run that should not pass this
flag.

One further case: where the kept record's artefacts cannot be read on this run,
the store still keeps the stronger record and the run returns the bytes it just
measured, unpersisted.

Accepted by `fetch`, `walk`, `sbom` and `audit`, and it applies to every fetch
the invocation performs.

### Staleness annotation

A fetch of a pinned version asks the proxy whether that pin is the module's
newest version, and reports the answer beside the verification status - in text
as a trailing clause, in `--json` as the `staleness` block:

```json
{
  "record": { "...": "..." },
  "staleness": {
    "is_latest": false,
    "latest_version": "v1.2.0",
    "days_since_latest": 3
  }
}
```

A current pin emits `{"is_latest": true}` and no text clause.

A lookup the proxy has not finished (an empty body, a timeout, a 5xx) is asked
again every 20 seconds for up to 4 minutes, and each retry says so on stderr
(`staleness progress: retrying example.com/mod (attempt 2, 10s of 4m0s)`); a
lookup still unanswered after that is `lookup_failed` below.

The question is not always asked, and is not always answerable. `is_latest` is
then **null** with `staleness_unmeasured` naming why, and the text line says so
rather than staying silent - silence there means "measured, and current":

| Situation | Text clause | `is_latest` | `pin_ahead_of_latest` | `days_since_latest` | `staleness_unmeasured` |
|---|---|---|---|---|---|
| Pin is the newest version | _(none)_ | `true` | `false` | `null` | absent |
| Pin is behind | `[latest: v1.2.0, 3 days ago]` | `false` | `false` | `3` | absent |
| Pin is behind, released today | `[latest: v1.2.0, released today]` | `false` | `false` | `0` | absent |
| Pin is behind, no publication date | `[latest: v1.2.0]` | `false` | `false` | `null` | absent |
| Pin sorts above `@latest` | `[ahead of latest tag: v1.0.0]` | `false` | `true` | `null` | absent |
| Proxy lookup failed | `[staleness unmeasured (lookup failed)]` | `null` | `null` | `null` | `lookup_failed` |
| `@latest` was requested | `[staleness unmeasured (not asked)]` | `null` | `null` | `null` | `not_asked` |

`days_since_latest` is emitted on every block and **zero is a value** — a
release that shipped today is `0` days old, and it used to be erased, which made
it indistinguishable from a release whose publication date is unknown. Null
means there is no age, and the two fields to its left say why.

`is_latest` and `pin_ahead_of_latest` are the three-valued answer between them,
and both are emitted on every measured block — `false` included, so "measured,
and not in that state" is never confused with "this build does not derive the
field". Both are `null` together where no comparison was made.

`is_latest: false` on an ahead pin is literally true: the pin is not the version
`@latest` names. What made it read as "behind" was the age travelling beside it,
so no age is emitted there. On a *current* pin the age is kept — it sits beside
`is_latest: true`, where it is the age of a release you are already on rather
than a distance.

`@latest` resolves the newest version and fetches **that**, so there is no pin
to be behind and no comparison was made; a failed lookup measured nothing. Both
used to report `is_latest: true` with no note, which reads as "this module is
current" - an answer to a question that was never put or never came back. The
failed lookup is also named on stderr; it does not fail the fetch.

The `staleness` block is **output only**. It is not part of the fact record
written to the store, so nothing about it is persisted or hashed.

## Storage

Fetched zips are stored content-addressed under `<store-root>/blobs/`. Fact
records are stored in `<store-root>/mirror.db` (SQLite), keyed by
`(module, version, pipeline_version)`. Every fetch is also appended to
`<store-root>/audit.jsonl`.

### A stored record this build cannot reproduce

A fact record written by another build may spell a value differently from this
build — the time of measurement at another precision, for example. Its stored
values hash to its own seal, so nothing was altered, but this build cannot
re-derive that seal. Such a record is **set aside**: left out of the answer and
named on stderr, once:

```
set aside fetch record example.com/mod@v1.0.0 (pipeline 0.4.0) content_hash sha256:3f1c…: written in a canonical shape this build cannot reproduce; its bytes hash to their own seal, so nothing was altered — read it with the build that wrote it, or upgrade
```

Every reader composes over the module's other records. `context` names it in
its `verification` section (`set_aside` under `--json`), and
`verification-coverage --json` in its document's `set_aside`. Each entry has
`kind: "fetch record"`.

When **every** record of a module was set aside:

- `fetch`, a walk's local-replace ingest, and the pre-fetch `vuln-scan` and
  `callgraph` make for missing modules treat the module as not yet held: they
  measure it again and append a record this build can serve. The set-aside
  records stay as written.
- `callgraph`, `license`, `interface` and `examples` with a coordinate exit `4`
  and name each record.
- `context` reports `verification.status: set_aside`, `audit` reports
  `(set aside)` in the verification column, and `verification-coverage` puts the
  module in `unrecorded` with the statement as its reason.

A record whose stored values do **not** hash to its seal was altered after it
was written. That is an integrity failure (`fetch record integrity check
failed`): the commands above exit `10`, `audit` shows `(integrity check failed)`
and exits `10` after its table, `verification-coverage` refuses at exit `10`,
and `context` reports `verification.status: read_error` with the failure.

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
