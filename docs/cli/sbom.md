# SBOM Commands

Generate and inspect Software Bills of Materials (SBOMs) for walks.
SBOMs are produced in CycloneDX 1.6 JSON format and are deterministic:
the same walk and scan inputs always produce byte-identical output.

> **Go-only scope.** kanonarion analyses Go modules exclusively. Every
> component in an emitted SBOM uses a `pkg:golang/…` Package URL, and
> each component's `properties` block includes `kanonarion:ecosystem = go`
> so that consumers do not have to infer the ecosystem from the module path.

### Document structure

The emitted document validates against the CycloneDX **1.6** JSON schema and,
in addition to the flat component list, carries:

- **A `dependencies` graph.** Every component (plus the root `metadata.component`)
  gets an entry, with `dependsOn` populated from the resolved module graph and
  ordered deterministically. Leaf components carry an empty relationship.
- **Per-component artefact hashes.** Each fetched library component carries
  `SHA-256`, `SHA-384` and `SHA-512` `hashes`, computed from the module zip bytes
  at download time (the same bytes the `h1` dirhash is taken over — the SBOM never
  recomputes them). The superseded MD5 and SHA-1 algorithms are never emitted.
  The **`stdlib` component** carries the same three hashes, taken over the Go
  source tarball rather than a module zip (see below). Only the local main
  component (the SBOM subject) carries no hashes; a missing hash block is never an
  error.

### Standard-library chain of custody

The synthetic `stdlib` component is toolchain-provided, not a proxy module, so it
can never carry a module's `h1`/sumdb custody. kanonarion establishes an
equivalent, necessarily different-anchored chain and emits it on the component:

- **`hashes`** — `SHA-256`/`SHA-384`/`SHA-512` over the canonical
  `go{VERSION}.src.tar.gz` acquired from `https://go.dev/dl/`. The `SHA-256`
  equals the checksum Go publishes for that tarball.
- **`externalReferences`** — the `go.dev/dl` source tarball (`distribution`), the
  `go.googlesource.com/go` repository (`vcs`), and a second `vcs` reference whose
  comment records the release tag → commit.
- **`licenses`** — `BSD-3-Clause`, **extracted from the tarball's `LICENSE`
  file**, not asserted from a constant.
- **`properties`** — `kanonarion:stdlib:verification`
  (`VerifiedGoDevChecksum` when the tarball SHA-256 matched the published
  checksum), `kanonarion:stdlib:verification_detail`,
  `kanonarion:stdlib:published_sha256`, and `kanonarion:stdlib:anchor_limitation`.

The `anchor_limitation` property states the honest ceiling: this anchor is a
**published checksum plus a source-repo tag/commit**, weaker than a module's
sumdb transparency-log entry, and it never appears in the project's `go.sum`. The
verification status is deliberately distinct from the module sumdb statuses so
the two are never read as equivalent.

The tarball is acquired once per Go version and cached; `--force` re-acquires and
re-verifies it. On a fully offline run (`--from-modcache`) the acquirer is not
wired and the `stdlib` component is emitted without the custody chain (a
best-effort coverage gap, never a failure). Skipping VCS cross-verification
(`--skip-vcs-verify`) omits the commit anchor but keeps the checksum verification.

---

## `sbom`

Generate an SBOM for a walk.

```
kanonarion sbom [<walk-id>] [flags]
```

The walk ID is required unless `--package` is used. With `--package` and no
walk ID, kanonarion reuses the latest succeeded project walk for the current
module when one exists. On a cold store (no such walk), it builds the
prerequisites itself, unattended: a project walk over the current `go.mod`
(equivalent to `kanonarion walk --gomod ./go.mod`), then a licence-extraction
stage over it (equivalent to `kanonarion extract <walk-id> --stages license`).
So a bare `sbom --package` on a clean store produces a fully-licenced SBOM with
no preceding `walk` or `extract` commands. Reuse is skipped and both steps
re-run when `--force` is passed.

### Flags

| Flag | Default | Description |
|---|---|---|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--scan <id>` | _(none)_ | Include vulnerabilities from this scan run ID |
| `--format` | `cyclonedx-1.6` | SBOM format |
| `--output <path>` | _(stdout)_ | Write SBOM content to a file |
| `--force` | `false` | Re-generate even if a cached SBOM exists |
| `--operator` | _(empty)_ | Identity of the operator requesting generation |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` component from the `go.mod` directive, not the live toolchain (applies when `sbom` builds a project walk, e.g. `--package`). See [Standard-library version](walk.md#standard-library-version---stdlib-from-gomod). |
| `--package <pattern>` | _(none)_ | Go package pattern (e.g. `./cmd/foo`); scopes `components` to modules in that binary's import closure |
| `--from-modcache[=dir]` | _(off)_ | When `sbom` builds a project walk (e.g. `--package` on a cold store), source modules from an existing Go module cache instead of the network proxy and verify each against the local `go.sum`. Passed bare it uses `go env GOMODCACHE`; an optional value names the cache directory. A `go.sum` mismatch or missing entry fails the command (exit code `10`). See [`audit --from-modcache`](audit.md#sourcing-from-an-existing-module-cache-from-modcache) for the full semantics. |
| `--log-level` | `warn` | Log level (`debug`, `info`, `warn`, `error`) |
| `--log-json` | `false` | Emit logs as JSON |

### Examples

```bash
# Generate an SBOM and print to stdout
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

# Generate with vulnerability data from a scan run
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD \
  --scan vscan-01KQDBVW092ER1HNXZ60X27CMD-1234 \
  --store-root ~/.kanonarion

# Write to a file
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD \
  --output sbom.json \
  --store-root ~/.kanonarion

# Force re-generation (bypass cache)
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --force --store-root ~/.kanonarion

# Scope components to a single binary's import closure. On a cold store this
# builds the project walk and extracts licences automatically.
kanonarion sbom --package ./cmd/kanonarion

# Scope components using an explicit project walk
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --package ./cmd/kanonarion
```

### Binary-scoped SBOMs (`--package`)

Pass `--package ./cmd/foo` to limit `components` to the modules that binary
actually imports. kanonarion runs `go list -deps` on the named package to
compute the import closure and intersects it with the walk's module graph.

This mirrors `notice --package` and is intended for projects where the
published artefact is a binary rather than a library, and where test-only or
tool dependencies in `go.mod` should be excluded from the SBOM.

- Requires the Go toolchain to be on `PATH`. Use `--package` from the module
  root directory so `go list` resolves correctly.
- On a cold store the project walk and its licence records are built for you,
  so no `walk` or `extract` command has to run first. An existing succeeded
  project walk is reused as-is (no redundant re-walk or re-extract) unless
  `--force` is passed.
- Multiple binaries require multiple `sbom` invocations, one per executable.
  The shared project walk is built once and reused across them.
- Scoped SBOMs are **ephemeral**: they are not cached or persisted to the store.
- When the project walk is built here, each fetched module's `h1` is
  cross-checked against the project's local `go.sum` (a cheap, offline complement
  to the network checksum database). A module whose hash **disagrees** with its
  `go.sum` entry is tamper-evidence: `sbom --package` **fails hard** rather than
  emitting an SBOM that silently omits it. See
  [`audit` › Local `go.sum` verification](audit.md#local-gosum-verification).

### Caching

Generation is cached by `(walkID, scanRunID, format, pipelineVersion)`.
A second call with the same inputs returns the cached record instantly.
Use `--force` to bypass the cache. Scoped (`--package`) results are never
cached.

### Licence completeness

If licence data is missing for one or more modules, the SBOM is still
generated — and still written when `--output` is given — but the command
**exits non-zero** and reports `sbom generated with incomplete licence data`
on stderr, and `LicensesIncomplete` is set in the stored record. The failure
signal never goes to stdout, so it cannot corrupt a piped SBOM. An incomplete
SBOM never exits zero, letting CI gate on it instead of publishing a
licence-less artefact.

---

## `sbom-show`

Print a stored SBOM record.

```
kanonarion sbom-show <sbom-id> [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Output record metadata as JSON instead of SBOM content |

### Examples

```bash
# Print the SBOM document
kanonarion sbom-show sbom-abc123def456 --store-root ~/.kanonarion

# Print record metadata as JSON
kanonarion sbom-show sbom-abc123def456 --json --store-root ~/.kanonarion
```

---

## `sbom-list`

List SBOM records in the store.

```
kanonarion sbom-list [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--walk <id>` | _(all)_ | Filter by walk ID |
| `--json` | `false` | Output as JSON array |

### Examples

```bash
# List all SBOMs
kanonarion sbom-list --store-root ~/.kanonarion

# List SBOMs for a specific walk
kanonarion sbom-list --walk 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

# JSON output
kanonarion sbom-list --json --store-root ~/.kanonarion
```

---

## Typical workflow

```bash
# 1. Walk the target module
kanonarion walk github.com/gin-gonic/gin@v1.9.1 --store-root ~/.kanonarion

# 2. Extract licence data
kanonarion extract --store-root ~/.kanonarion

# 3. (Optional) Scan for vulnerabilities
kanonarion vuln-scan <walk-id> --store-root ~/.kanonarion

# 4. Generate SBOM (without vulnerabilities)
kanonarion sbom <walk-id> --output sbom.json --store-root ~/.kanonarion

# 5. Generate SBOM (with vulnerabilities)
kanonarion sbom <walk-id> \
  --scan <scan-run-id> \
  --output sbom-with-vulns.json \
  --store-root ~/.kanonarion
```

## Binary-scoped workflow

On a cold store, a single `sbom --package` builds the project walk and extracts
licences for you, so this is all you need:

```bash
# Build the walk + licences on first run, then reuse them for every binary.
# components = what ./cmd/myapp ships
kanonarion sbom --package ./cmd/myapp --output sbom-myapp.json

# Multiple binaries: one invocation per executable, reusing the same walk
kanonarion sbom --package ./cmd/server --output sbom-server.json
kanonarion sbom --package ./cmd/worker --output sbom-worker.json
```

To build the prerequisites explicitly (for example to control the walk scope or
inspect the intermediate records), run them by hand first:

```bash
# 1. Walk the current project (creates a walk rooted at the local module)
kanonarion walk --gomod ./go.mod

# 2. Extract licence data for all walked modules
WALK_ID=$(kanonarion walk-list --latest-success --json | jq -r '.id')
kanonarion extract "$WALK_ID"

# 3. Generate the binary-scoped SBOM from that walk
kanonarion sbom --package ./cmd/myapp --output sbom-myapp.json
```
