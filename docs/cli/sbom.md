# SBOM Commands

Generate and inspect Software Bills of Materials (SBOMs) for walks.
SBOMs are produced in CycloneDX 1.6 JSON format and are deterministic:
the same walk, licence and `--generated-at` inputs always produce byte-identical
output.

> **The document is an inventory.** It describes components, their identity,
> hashes, licences and dependency graph. It carries **no `vulnerabilities` list**
> and no VEX `analysis`, under any flag. Vulnerability and reachability answers
> come from [`vuln-show`](vuln.md) and [`reachability`](reachability.md), which
> state the advisory snapshot and the analysis frame the answer was measured
> against.

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
- **External references, only where a fetch record supports them.** A library
  component carries one `vcs` reference — the repository its module zip was
  cross-verified against — when the fetch ledger holds a positively
  cross-verified record for that coordinate, and its comment names the ref and
  commit the cross-verification read. A component with no such record carries
  no `externalReferences` block at all: a local main module, a module fetched
  offline or with `--skip-vcs-verify`, and a module whose VCS check could not
  reach the repository are all in that state. **No library component carries a
  `distribution` reference**; the ledger records the route the bytes arrived by
  and the blob handle they were filed under, not a public download address. The
  `stdlib` component is the exception and carries both (see below), because it
  has a recorded source URL.
- **A licence-completeness statement**, whenever any component carries no licence
  identity. See below.
- **A vendor scope statement**, whenever the walk was rooted at a project that
  carries a `vendor/` tree. See below.
- **Metadata properties stating what `metadata.timestamp` means** and, separately,
  the newest licence extraction time among the document's inputs. See
  [Document timestamp](#document-timestamp).

### Document timestamp

`metadata.timestamp` is what CycloneDX defines it to be: when the document was
created. Pass `--generated-at <RFC3339>` to supply that moment. Two generations
with the same `--generated-at` and the same store inputs are byte-identical; two
with different values differ only in that field.

The generator reads no clock of its own — one that did could not re-emit a
document byte for byte from the same recorded inputs. With no `--generated-at`,
the document falls back to the newest licence extraction time among its inputs
and says so, rather than presenting a derived value as a creation time:

```json
"metadata": {
  "timestamp": "2026-07-29T04:44:15Z",
  "properties": [
    { "name": "kanonarion:document:timestamp_basis",
      "value": "derived: newest licence extraction time among this document's inputs; no creation time was supplied, and this generator reads no clock" },
    { "name": "kanonarion:licence:newest_extraction", "value": "2026-07-29T04:44:15Z" }
  ]
}
```

With `--generated-at`, `kanonarion:document:timestamp_basis` reads
`caller-supplied document creation time`. `kanonarion:licence:newest_extraction`
is emitted either way, so a reader never has to work out whether the timestamp is
the extraction time.

A supplied `--generated-at` bypasses the SBOM cache: the value is not part of the
cache key, so a cached document would answer with another generation's timestamp.

### Licence completeness in the document

A component carrying no `licenses` block is one whose licence kanonarion could
not determine — no licence file was found for it, or the files found match no
known SPDX licence text. Whenever a document carries any such component, it says
so where a reader meets the component list, as a CycloneDX `annotation` whose
`subjects` name each of them:

```json
{
  "annotations": [{
    "bom-ref": "kanonarion:licence-completeness",
    "subjects": ["pkg:golang/github.com/example/mod@v1.0.0"],
    "annotator": { "component": { "type": "application", "name": "kanonarion" } },
    "text": "Licence completeness of this document: 1 of the 19 component(s) inventoried here carry no licence identity ... It is not a statement that the component is unlicensed, and it must not be read as permission to use it: ..."
  }]
}
```

The document's subject (`metadata.component`) is counted with everything it
links. A subject with no licence — a binary built from a module with no
`--main-license` and no fetched licence record — is the one component in a
distributed document whose licensing would otherwise go uncounted.

The same condition sets the command's non-zero exit; see
[Licence completeness](#licence-completeness).

### What the document covers of a vendored tree

When the walk records a project root holding a `vendor/` tree, the document
carries a vendor scope annotation:

```json
{
  "annotations": [{
    "bom-ref": "kanonarion:vendor-scope",
    "annotator": { "component": { "type": "application", "name": "kanonarion" } },
    "text": "Scope of this document against the project's vendored tree: vendor/modules.txt lists 133 module(s); this document describes 126 of them. The 7 it does not describe, and why: example.com/mod v1.35.0 — contributes no package to the build; ... A package line is a package `go mod vendor` wrote under the module heading across all build constraints; it is not a count of what this build compiles."
  }]
}
```

The annotation is emitted whenever a tree was read, full coverage included; a
fully covered tree reads `Every module in the vendored tree is described here.`
It is absent when the walk records no project root, the project carries no
`vendor/` tree, or the tree could not be read.

A module `vendor/modules.txt` names with no package line under it is listed as
contributing no package to the build. A module that does carry package lines is
listed with the number of lines counted, and the statement says what a line is:
`go mod vendor` writes one for every package reachable under **any** build
constraint, so a non-zero count does not assert the module is compiled here.

A module replaced by a fork counts as described under either coordinate — the
original path `go mod vendor` files it under, or the replacement the build list
names.

With `--package`, the statement records that the component list is scoped to one
binary's import closure, so a reader can tell a deliberately narrower subject
from a gap.

The same statement is reported by [`kanonarion vendor`](vendor.md#scope-statement).

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

`anchor_limitation` states what this component's integrity actually rests on. It
is **derived from the verification status the measurement reached**, not a fixed
sentence: it names the anchor that was established, says separately whether the
`go.googlesource.com/go` tag/commit anchor was established, and ends with the
ceiling that holds on every route — weaker than a module's sumdb
transparency-log entry, and never present in the project's `go.sum`. So a
document generated offline says integrity rests on the locally-held toolchain
source with the published checksum not consulted, and a connected one names the
published checksum it matched. A status this build does not recognise names no
anchor at all. The verification status is deliberately distinct from the module
sumdb statuses so the two are never read as equivalent.

The tarball is acquired once per Go version and cached; `--force` re-acquires and
re-verifies it. On a fully offline run (`--from-modcache`) the offline acquirer
runs instead: it anchors to the installed toolchain's `$GOROOT/src` and
`$GOROOT/LICENSE`, records `VerifiedLocalToolchain`, and consults neither
go.dev/dl nor googlesource. Skipping VCS cross-verification (`--skip-vcs-verify`)
omits the commit anchor but keeps the checksum verification, and the limitation
property says so.

Both anchors are recorded per measurement, and a read composes them by strength
rather than recency: once a connected run has recorded `VerifiedGoDevChecksum`
for a toolchain version, a later offline run does not downgrade what a
connected-side document serves.

---

## `sbom`

Generate an SBOM for a walk.

```
kanonarion sbom [<walk-id>] [flags]
```

The walk ID is required unless `--package` is used. With `--package` and no
walk ID, kanonarion reuses the latest succeeded project walk for the current
module **resolved for this platform** (`go env GOOS`/`GOARCH`) when one exists —
a walk of the same project for another platform is not reused, because its
closure is a different one. On a cold store (or when only another platform's
walk is stored), it builds the
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
| `--format` | `cyclonedx-1.6` | SBOM format |
| `--output <path>` | _(stdout)_ | Write SBOM content to a file |
| `--force` | `false` | Re-generate even if a cached SBOM exists |
| `--generated-at <time>` | _(derived)_ | RFC3339 time the document is being created; becomes `metadata.timestamp`. Omitted, the document is stamped with the newest licence extraction time among its inputs and says so. Supplying it bypasses the cache |
| `--operator` | _(empty)_ | Identity of the operator requesting generation |
| `--stdlib-from-gomod` | `false` | Version the `stdlib` component from the `go.mod` directive, not the live toolchain. Applies when `sbom` builds a project walk (`--package` with no walk id); refused by name when a walk id is given, because that walk's `stdlib` node is already pinned. See [Standard-library version](walk.md#standard-library-version---stdlib-from-gomod). |
| `--package <pattern>` | _(none)_ | Go package pattern (e.g. `./cmd/foo`); scopes `components` to modules in that binary's import closure |
| `--from-modcache[=dir]` | _(off)_ | When `sbom` builds a project walk (e.g. `--package` on a cold store), source modules from an existing Go module cache instead of the network proxy and verify each against the local `go.sum`. Passed bare it uses `go env GOMODCACHE`; an optional value names the cache directory. A `go.sum` mismatch or missing entry fails the command (exit code `10`). See [`audit --from-modcache`](audit.md#sourcing-from-an-existing-module-cache---from-modcache) for the full semantics. |
| `--allow-verification-downgrade` | `false` | Permit a weaker re-measurement of a module to be recorded alongside a stronger stored one. Without it the weaker measurement is refused, the stronger record is kept and answers, and the run warns. See [Re-measuring with a weaker anchor](fetch.md#re-measuring-with-a-weaker-anchor---allow-verification-downgrade) |
| `--main-version <version>` | _(none)_ | Version to stamp on the SBOM subject (`metadata.component`) in place of the synthetic `local`. Supplying it bypasses the cache, and the document is not stored. See [Naming the subject](#naming-the-subject---main-version-and---main-license) |
| `--main-license <spdx>` | _(none)_ | SPDX id or expression to attach to the SBOM subject, which as a local main module has no fetched licence record of its own. Supplying it bypasses the cache, and the document is not stored. See [Naming the subject](#naming-the-subject---main-version-and---main-license) |
| `--policy` | _(auto-discover `.kanonarion/policy.yaml`)_ | Depth policy file; its fetch stage governs traversal and the `allowed_vcs_hosts` forge allowlist |
| `--log-level` | `warn` | Log level (`debug`, `info`, `warn`, `error`) |
| `--no-progress` | `false` | Suppress stderr progress output (the throttled heartbeat and any per-module progress lines); results and warnings are unaffected |

### Naming the subject (`--main-version` and `--main-license`)

The document's subject (`metadata.component`) is the thing being described, and
on a project walk it is the local main module. It has no proxy artefact, so it
is stamped with the synthetic version `local` and carries no fetched licence
record. Both flags supply what the store cannot.

- `--main-version v0.1.1` replaces `local` on the subject's version, `purl` and
  `bom-ref`, so the subject is a resolvable coordinate. A release document
  should carry it; without it the release SBOM describes the right bytes under
  a placeholder name.
- `--main-license Apache-2.0` attaches an SPDX id or expression to the subject.
  Without it the subject counts as a component with no licence identity, which
  is what sets the command's exit `1`.

Either stamp reaches **both** places the document describes the subject:
`metadata.component` and the subject's own entry in the `components` list, which
is also the entry the `dependencies` graph names. The stamped module therefore
appears under one `purl` throughout, and `--main-license` is what stops the
exit `1` naming your own module.

Both apply **only** when the subject is the local main module. A walk rooted at
a published module carries that module's own version and licence record, and
neither flag changes it.

Neither flag is part of the SBOM cache key, so a run that passes either is
never answered from the cache and never writes to it. The document is generated
on the spot — no `--force` needed over a warm store — and is not stored. The
stored SBOM for the walk keeps the subject the walk itself resolved, so a later
run that passes neither flag is never handed a release stamp somebody else's run
put there.

Because nothing is stored, the `ID:` and `Content-Hash:` lines printed under
`--output` name a document the store does not hold, and `sbom-show` of that id
answers with the stored one instead. The run says so on stderr:

```
note: --main-version/--main-license name this document's subject, so it was
generated now and not stored; the stored SBOM for walk <walk-id> is unchanged
```

Keep the release document from `--output`; it is the artefact.

### Examples

```bash
# Generate an SBOM and print to stdout
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

# Date the document to now rather than to the licence extraction time
kanonarion sbom 01KQDBVW092ER1HNXZ60X27CMD \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output sbom.json

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

Generation is cached by `(walkID, format, pipelineVersion)`.
A second call with the same inputs is served from the store — a record read,
measured at **48 ms** for a 128-module walk, rather than a regeneration.
Use `--force` to bypass the cache. `--generated-at`, `--main-version` and
`--main-license` also bypass it: none of the three is part of the key, so a
stored document would answer under a timestamp or a subject the caller did not
ask for. Scoped (`--package`) results, and results with a `--main-version` or
`--main-license` subject stamp, are never cached — they are generated on the
spot and not written back.

### Assurance log

The SBOM is the artefact that leaves the building, so both making one and
handing a stored one back are appended to the append-only assurance log
(`{store-root}/audit.jsonl`).

| Event | When | Payload |
|---|---|---|
| `sbom_generated` | a document was produced and its record persisted | record id, walk id, format, pipeline version, the document's content hash, and whether the creation timestamp was caller-supplied (`--generated-at`) |
| `sbom_served` | a stored document was handed back from the cache | the record served (id, walk id, format, pipeline version, content hash) and `requested_by`, the `--operator` of *this* request |

The two are separate types on purpose: a reader must be able to tell a document
that was produced from one that was handed over again, and "when did we last
produce this artefact, and how often has it gone out" needs both. `requested_by`
is the requester of the serving, not the record's stored `operator` — that named
whoever asked for the original generation, possibly another person on another
day. It is omitted when no `--operator` was given.

Neither event restates the document. Its component list, its licences and its
completeness statements are the document's own claims; the content hash is what
reaches them, and repeating them in the log would leave an unsealed second copy
of the artefact.

A `--package` run appends nothing: the result is ephemeral (no cache lookup, no
record persisted), and the events state that a record exists. A run with
`--main-version` or `--main-license` is ephemeral for the same reason and
likewise appends nothing. `--force` and `--generated-at` skip the cache but
still persist, so they append `sbom_generated` rather than `sbom_served`.
`sbom-show` and `sbom-list` read stored records and append nothing.

### Licence completeness

A component carries no licence identity when no licence record was found for it,
**or** when the record that was found identified no SPDX licence — no licence
file at the module root, or files matching no known SPDX text. Both produce a
component with no `licenses` block, and both count here; so does the document's
subject (`metadata.component`), which `--main-license` supplies for a local main
module.

When any component is in that state the SBOM is still generated — and still
written when `--output` is given — but the command **exits 1** and reports on
stderr:

```
sbom generated with undetermined licences: 2 component(s) with no licence
identity: github.com/dgryski/dgoogauth@v0.0.0-20190221195224-5a805980a5f3, ... —
run 'kanonarion license github.com/dgryski/dgoogauth@v0.0.0-20190221195224-5a805980a5f3',
and the same for the other 1 component(s) named
```

The message ends with the command that produces each missing record, and the
command depends on the component. A **dependency** is analysed by coordinate,
as above. The document's **subject** — the walk root's own licence — is not
fetchable, so it is analysed by re-walking the project:

```
sbom generated with undetermined licences: 1 component(s) with no licence
identity: github.com/eitanity/kanonarion@local (the document's subject) — run
'kanonarion walk --gomod ./go.mod --analyse-root' then
'kanonarion extract <walk-id>' to analyse the project's own licence
```

Both are the same sentence `license-compat` prints for the same missing record.
When a document is missing both kinds, both remedies are stated.

The components are named from the document that was written, so the message is
the same whether the document was generated now or served from the cache.
`LicensesIncomplete` is set in the stored record, and the document itself carries
the `kanonarion:licence-completeness` annotation naming them.

The failure signal never goes to stdout, so it cannot corrupt a piped SBOM. An
incomplete SBOM never exits zero, letting CI gate on it instead of publishing a
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
| `--walk <id>` | _(all)_ | Filter by walk ID, matched for exact equality |
| `--json` | `false` | Output as JSON array |

A zero result distinguishes "no SBOM for that walk" from "no SBOM has been
generated", per [Zero-result listings](conventions.md#zero-result-listings).

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

# 3. Generate the SBOM, dated to now
kanonarion sbom <walk-id> \
  --generated-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --output sbom.json \
  --store-root ~/.kanonarion

# 4. Vulnerabilities are a separate question, asked of the store
kanonarion vuln-scan <walk-id> --store-root ~/.kanonarion
kanonarion vuln-show <walk-id> --store-root ~/.kanonarion
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

## Modules resolved under pre-modules semantics

A `+incompatible` coordinate resolves no requirement edges at all, so what this command can show is bounded: such a component contributed no requirements to the walk the inventory was built from, so its own dependencies are absent from the component list. The caveat is written to **stderr**, never into the document — an SBOM has no field for it. The answer states that and names the coordinates responsible; see [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
