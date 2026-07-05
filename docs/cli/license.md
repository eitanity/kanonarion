# `kanonarion licence` - Licence Extraction

Extracts and persists licence information for a Go module that has already been
fetched. Extraction reads the module zip from the blob store, scans it for
licence-named files, classifies each against the SPDX licence corpus, extracts
copyright notices, and records a `LicenceRecord` in the store. An optional
second pass (`--per-file`) also scans root-level `.go` source files for
`SPDX-License-Identifier` headers when no dedicated licence file is found.

> **Note**: A confident SPDX identification is informational, not legal advice.
> Consult a lawyer for compliance decisions.

## Prerequisites

The module must have been fetched first:

```
kanonarion fetch github.com/spf13/cobra@v1.8.1
```

## Commands

### `kanonarion licence <module>@<version>`

Extract and display the licence record for a module.

```
kanonarion licence github.com/spf13/cobra@v1.8.1
kanonarion licence github.com/spf13/cobra@v1.8.1 --json
kanonarion licence github.com/spf13/cobra@v1.8.1 --force
kanonarion licence github.com/spf13/cobra@v1.8.1 --per-file
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--force` | false | Re-extract even if a cached record exists |
| `--per-file` | false | Scan root-level `.go` files for SPDX headers when no licence file is found |
| `--json` | false | Emit the full `LicenceRecord` as JSON |
| `--log-level` | `warn` | Log verbosity: `debug`, `info`, `warn`, `error` |

**Output (default):**

```
github.com/spf13/cobra@v1.8.1: Detected - Apache-2.0
  LICENSE: Apache-2.0 (100%)
```

**Overall statuses:**

| Status | Meaning |
|--------|---------|
| `Detected` | One clear primary licence at the module root |
| `Ambiguous` | The primary file matched multiple candidates with similar confidence |
| `Multiple` | Multiple root-level files with different SPDX identifiers, or one file containing multiple full licence texts at near-equal coverage |
| `Unclassified` | A root-level licence file **was** found but could not be matched to a known SPDX identifier - custom/commercial text, an "All rights reserved" notice, or a non-canonical/truncated licence. Distinct from `None` (no files at all): absence of classification is never reported as absence of a licence |
| `None` | No licence files found at the module root |
| `PerFile` | No dedicated licence file found; licence identified from `SPDX-License-Identifier` headers or copyright blocks in source files (only possible with `--per-file`) |
| `ExtractionFailed` | The module zip could not be read |

When a root file is `Unclassified` but a known licence was *partially*
recognised - coverage below the substantive floor, e.g. a truncated AGPL-3.0
whose only matching span is the "how to apply" appendix - the `context` /
`inspect` summary surfaces that fragment as a low-confidence caveat
(`Unclassified - license file present; low-confidence AGPL-3.0-or-later match
(~3% coverage)`). It is a caveated inference about a malformed file, never a
confident SPDX classification.

### `kanonarion licence-list`

List extracted licence records.

```
kanonarion licence-list
kanonarion licence-list --spdx MIT
kanonarion licence-list --limit 100
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--spdx` | | Filter by SPDX identifier (e.g. `MIT`, `Apache-2.0`) |
| `--limit` | 50 | Maximum records to show (0 = unlimited) |

## Caching

Each licence record is keyed by `(module_path, module_version, pipeline_version)`.
Re-running `kanonarion licence` without `--force` returns the cached record
immediately. A new pipeline version invalidates all existing records for that
stage (but not fetch records or walk records).

The database schema is versioned via the shared `schema_migrations` table
(migration version 4 for the `license` module - added the `spdx_expression`
column). The current pipeline version is `1.0.0`.

## Assurance log

Each fresh extraction appends a `license_extracted` event to the append-only
audit log (`{store-root}/audit.jsonl`): module, version, resolved
`primary_spdx`, `overall_status` (`Detected` / `Unclassified` / `None` / …), and
the identity `source` (`scanner`). Licence extraction is half of `audit`'s
compliance verdict, so this anchors *what licence was resolved, and when* in the
append-only assurance log - independent of the mutable licence record. A cache hit
(no `--force`) re-serves the stored record without re-extracting, so it appends
nothing.

## Vendored licences

Licence files under `vendor/` are recorded in `LicenseFiles` with
`IsVendored = true` and are included in `EffectiveSet.Components` (see above).
They do not contribute to `PrimarySPDX` or `Expression` - those fields reflect
the module author's own licence only. Each vendored dependency is also a
separate module in the walk graph with its own `LicenseRecord`.

## Per-package licences

Some modules contain first-party sub-packages governed by a **different licence
than the module root**. A sub-package may ship its own `LICENSE` file - for
example, a module that is Apache-2.0 overall but includes an MIT-licensed
utility package or a BSD-3-Clause reference implementation under a subdirectory.

These are surfaced in the `PackageLicenses` field on `LicenseRecord`:

```json
"PackageLicenses": [
  {
    "PackagePath": "gzhttp",
    "SPDX": "Apache-2.0",
    "Confidence": 1,
    "SourceFile": "gzhttp/LICENSE"
  },
  {
    "PackagePath": "internal/lz4ref",
    "SPDX": "BSD-3-Clause",
    "Confidence": 1,
    "SourceFile": "internal/lz4ref/LICENSE"
  }
]
```

**Key distinctions:**

- **`PackageLicenses`** - first-party sub-packages of the module itself; not
  vendored. Lets a consumer ask "what licence applies to the package I actually
  import?" when they import a sub-package rather than the module root.
- **`EffectiveSet.Components`** - all non-root, non-vendored subdirectory
  groups, including embedded third-party code. Used by the compatibility and
  notice pipelines to compute the full obligation set.

A module with a single, uniform root licence reports `PackageLicenses: null`
(no per-package divergence).

**Derivation rule:** `PackageLicenses` is computed from `LicenseFiles` on every
extraction and on every deserialisation - the same derived-field contract as
`EffectiveSet`. It is never stored separately. Vendored entries
(`IsVendored = true`) and NOTICE files are excluded. When a directory contains
multiple licence files, the highest-confidence match wins.

### Text output

```
$ kanonarion --json=false licence github.com/klauspost/compress@v1.18.2
github.com/klauspost/compress@v1.18.2: Multiple - Apache-2.0 (cached)
  LICENSE: Apache-2.0 (99%)
  gzhttp/LICENSE: Apache-2.0 (100%)
  ...
  per-package licenses (9 sub-packages):
    gzhttp                                   Apache-2.0 (100%)
    internal/lz4ref                          BSD-3-Clause (100%)
    internal/snapref                         BSD-3-Clause (100%)
    s2                                       BSD-3-Clause (100%)
    s2/cmd/internal/filepathx                MIT (100%)
    s2/cmd/internal/readahead                MIT (98%)
    snappy                                   BSD-3-Clause (100%)
    snappy/xerial                            MIT (98%)
    zstd/internal/xxhash                     MIT (100%)
```

### JSON query

```
$ kanonarion licence github.com/klauspost/compress@v1.18.2 --json \
    | jq '[.PackageLicenses[] | {pkg: .PackagePath, spdx: .SPDX}]'
[
  { "pkg": "gzhttp",                        "spdx": "Apache-2.0" },
  { "pkg": "internal/lz4ref",               "spdx": "BSD-3-Clause" },
  { "pkg": "internal/snapref",              "spdx": "BSD-3-Clause" },
  { "pkg": "s2",                            "spdx": "BSD-3-Clause" },
  { "pkg": "s2/cmd/internal/filepathx",     "spdx": "MIT" },
  { "pkg": "s2/cmd/internal/readahead",     "spdx": "MIT" },
  { "pkg": "snappy",                        "spdx": "BSD-3-Clause" },
  { "pkg": "snappy/xerial",                 "spdx": "MIT" },
  { "pkg": "zstd/internal/xxhash",          "spdx": "MIT" }
]
```
