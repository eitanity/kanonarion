# `kanonarion fetch` - Module fetch & verification

## Synopsis

```
kanonarion fetch <module>[@<version>] [flags]
kanonarion fetch <module> --list-versions [flags]
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
  database (`sum.golang.org` or a configured mirror).
- **VCS cross-verification** - the proxy zip is compared against the upstream
  source repository. Skippable with `--skip-vcs-verify`; the checksum check
  still runs. **Requires a `git` binary on `PATH`.** If `git` is absent the
  fetch does not fail: the checksum check still runs and the record is written
  with an unverified VCS status whose detail names `--skip-vcs-verify`.

  Because `--skip-vcs-verify` means the git leg never ran, a module the
  checksum database attests resolves to `VerifiedBySumDBOnly`, **never** the
  strongest `Verified` - that status is reserved for a zip actually reproduced
  from the git commit, so the label can never claim a check that was skipped.

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
| `--gomod` | _(search upward from cwd)_ | Path to a `go.mod` file; fetch its dependency scope instead of a positional module |
| `--tool` | `false` | Fetch the tooling supply chain (the `go.mod` tool directives' closure) instead of a positional module. Mutually exclusive with `--project`; refused by name alongside a positional module |
| `--project` | `false` | Fetch the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool`; refused by name alongside a positional module |
| `--allow-verification-downgrade` | `false` | Permit a weaker re-measurement of a coordinate to be recorded alongside a stronger stored one. Without it the weaker measurement is refused, the stronger record is kept and answers, and the run warns. See [Re-measuring with a weaker anchor](#re-measuring-with-a-weaker-anchor---allow-verification-downgrade) |
| `--policy` | _(auto-discover `.kanonarion/policy.yaml`)_ | Depth policy file; its fetch stage's `allowed_vcs_hosts` selects which forges may be cross-verified |
| `--json` | `false` | Emit the fact record as JSON |

A scope fetch is triggered by `--gomod`, `--tool`, or `--project`; the scope is
consistent with every other go.mod command - default `code` (the project's own
code dependencies, `go list -deps -test ./...`), `--tool` the tooling supply
chain, `--project` the complete set. See
[`walk` Scopes](walk.md#scopes-code-tool-complete). A scope fetch cannot be
combined with a positional module or with `--list-versions`; every module in the
scope is fetched, continuing on per-module errors.

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
fetching. kanonarion honours it: every fetch-capable command - `fetch`,
`walk`, `latest`, `audit`, `inspect` against `@latest` - refuses before it
opens a socket and exits `20`, naming the offline ways to proceed:

```
$ GOPROXY=off kanonarion fetch github.com/spf13/cobra@v1.8.1
GOPROXY=off: the environment declares no module fetching; run offline instead:
--from-modcache reads the bytes already in $GOMODCACHE, and `kanonarion use
--recursive` reconstitutes a module from the store
$ echo $?
20
```

The refusal withdraws **fetching**, not the store. Reading what has already
been measured keeps working under `GOPROXY=off` - `callgraph`, `interface`,
`license`, `capability`, `vendor`, `extract`, `vuln show`, `walk show` and the
rest - and so do the offline acquisition modes: `--from-modcache` reads
`$GOMODCACHE` and never the network, and `kanonarion use --recursive`
reconstitutes a module and its closure from the store into a module cache a
plain `go build` can consume.

`GOPROXY=direct` selects VCS-origin fetching, which this build does not
implement. It refuses the same way, naming the unsupported mode. What neither
value does is fall back to `proxy.golang.org`: `off` and `direct` are the two
values whose meaning is "not that proxy", and treating them as "unset" would
cross exactly the boundary the operator drew.

The list form follows Go's own resolution: entries are separated by `,` or
`|` and tried in order, so `GOPROXY=https://proxy.example.com,direct` uses the
first entry, while an `off` reached first terminates the chain and nothing
after it is tried.

`GOPROXY` is read from Go's own sources, not just the shell: the environment
variable first, then the env file `go env -w` writes to. `go env -w
GOPROXY=off` therefore declares the air gap for kanonarion exactly as it does
for `go build`, with nothing set in the environment.

### What else `GOPROXY=off` withdraws

The declaration is not the module proxy's alone. Under `GOPROXY=off` every
network path kanonarion owns refuses before it opens a socket or starts a
subprocess:

| Path | Under `GOPROXY=off` | What still answers |
|---|---|---|
| Module fetch | Refuses, exit `20` | `--from-modcache`, [`use --recursive`](use.md) |
| Advisory snapshot download (`vuln-scan`, `audit`, `inspect`) | Refuses the download | A snapshot the store already holds - see [`vuln`](vuln.md#air-gapped-scanning) |
| Checksum database (`sum.golang.org`) | Treated as `GOSUMDB=off`: modules record `UnverifiedNoSumDB`, or `VerifiedByGoSum` where a project `go.sum` anchors them | The local `go.sum` anchor |
| Standard-library `go.dev/dl` acquisition | Not used; the local-toolchain anchor is selected instead, as under `--from-modcache` | `$GOROOT/src` + `$GOROOT/LICENSE`, recorded `VerifiedLocalToolchain` |
| `git` cross-verification (`ls-remote`, shallow fetch) | Refuses to spawn; counted as a missing VCS leg, exactly as `--skip-vcs-verify` is | Checksum-database or `go.sum` verification, landing on `VerifiedBySumDBOnly` |

`GOSUMDB=off`, `--from-modcache` and `--skip-vcs-verify` remain the ways to
withdraw those paths individually. `GOPROXY=off` withdraws all of them at once,
which is what an air gap is. Reading the store is unaffected throughout.

`GONOSUMCHECK=1` is honoured as the boolean it is - the checksum database is
switched off for every module. A `GONOSUMCHECK` naming module prefixes keeps
its pattern meaning.

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

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `2` | Fetch or (with `--strict`) verification failed |
| `3` | Cancelled |
| `10` | Integrity check failed |
| `20` | Configuration or precondition error: an invalid flag combination, or an environment that forbids fetching (`GOPROXY=off`, `GOPROXY=direct`) |

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
