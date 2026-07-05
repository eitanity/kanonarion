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
| `--pipeline-version` | _(compiled-in)_ | Override the pipeline version |
| `--force` | `false` | Re-fetch even if a cached record exists |
| `--strict` | `false` | Exit non-zero on verification failure |
| `--insecure` | `false` | Allow plain HTTP proxy URLs (forces unverified status) |
| `--skip-vcs-verify` | `false` | Skip git cross-verification (requires `git` on `PATH`); checksum verification still runs |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the module proxy |
| `--list-versions` | `false` | List available versions from the proxy and exit without fetching |
| `--gomod` | _(search upward from cwd)_ | Path to a `go.mod` file; fetch its dependency scope instead of a positional module |
| `--tool` | `false` | Fetch the tooling supply chain (the `go.mod` tool directives' closure) instead of a positional module. Mutually exclusive with `--project` |
| `--project` | `false` | Fetch the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--json` | `false` | Emit the fact record as JSON |

A scope fetch is triggered by `--gomod`, `--tool`, or `--project`; the scope is
consistent with every other go.mod command - default `code` (the project's own
code dependencies, `go list -deps -test ./...`), `--tool` the tooling supply
chain, `--project` the complete set. See
[`walk` Scopes](walk.md#scopes-code-tool-complete). A scope fetch cannot be
combined with a positional module or with `--list-versions`; every module in the
scope is fetched, continuing on per-module errors.

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
| `20` | Configuration error (e.g. invalid flag combination) |

## Examples

```
kanonarion fetch github.com/spf13/cobra@v1.8.1
kanonarion fetch github.com/spf13/cobra@latest --json
kanonarion fetch github.com/spf13/cobra --list-versions
kanonarion fetch github.com/spf13/cobra@v1.8.1 --force --strict --store-root /var/mirror
kanonarion fetch --tool --gomod ./go.mod
```

## Relation to other stages

- **Produces:** the module zip in the blob store and a `FactRecord`.
- **Required by:** every extraction stage (`walk`, `interface`, `callgraph`,
  `examples`, `license`, `vuln-scan`) - they read the fetched zip from the
  blob store.

## See also

- [`kanonarion walk`](walk.md) - resolve a module's dependency graph
- [`kanonarion interface`](interface.md) - extract a module's public API
