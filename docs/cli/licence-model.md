# Licence model - shared explainers

Reference material for the licence pipeline: how SPDX expressions are
stored and propagated, how copyright statements are extracted, and
how the per-file mode works. Linked from [`licence`](license.md),
[`license-compat`](license-compat.md), [`license-diff`](license-diff.md),
and [`notice`](notice.md).

## SPDX expression model

Beyond the `PrimarySPDX` identifier, every record includes an `Expression` field
that models the module's licence as a proper SPDX expression (`OR`, `AND`, `WITH`).

**Why expressions matter:** the `Multiple` status covers two distinct situations
that a flat SPDX identifier cannot represent:

- **Dual-licensed, consumer chooses** - e.g. `MIT OR Apache-2.0` (the consumer
  picks the licence they distribute under). This is the common pattern for
  `gopkg.in/yaml.v3`, `github.com/klauspost/compress`, and the `gioui.org` family.
- **Genuinely mixed** - different root-level files carry different licences that
  all apply simultaneously, e.g. `CC-BY-4.0 AND CC-BY-SA-3.0`.

**Derivation rules (in precedence order):**

| Situation | Expression |
|-----------|------------|
| Single root file, single SPDX id, no close alternatives | bare identifier (e.g. `MIT`) |
| Single root file, multiple full texts at ≤ 0.5% confidence gap ("compound file") | `OR` of all identified ids, sorted |
| Multiple root files, all with the same SPDX id | bare identifier |
| Multiple root files, distinct ids, any file has a dual-license name (`LICENSE-MIT`, `LICENSE-APACHE`, `COPYING-BSD`) | `OR` of distinct ids, sorted |
| Multiple root files, distinct ids, no dual-license naming | `AND` of distinct ids, sorted |

**JSON output includes both fields:**

```json
{
  "PrimarySPDX": "MIT",
  "Expression": "Apache-2.0 OR MIT",
  ...
}
```

`PrimarySPDX` is kept for backward compatibility; downstream consumers should
prefer `Expression` when present.

**NOTICE files are excluded** from expression derivation - they satisfy Apache
§4(d) attribution but do not define the module's licence identity.

**Examples from kanonarion's own closure:**

| Module | Expression | Pattern |
|--------|------------|---------|
| `gopkg.in/yaml.v3@v3.0.1` | `Apache-2.0 OR MIT` | Compound LICENSE file |
| `github.com/klauspost/compress@v1.18.2` | `Apache-2.0 OR BSD-3-Clause OR MIT` | Compound LICENSE file |
| `gioui.org@v0.2.0` | `MIT OR Unlicense` | Compound LICENSE file |
| `github.com/ajstarks/deck/generate@...` | `CC-BY-4.0 AND CC-BY-SA-3.0` | Two separate root files, mixed |
| `github.com/spf13/cobra@v1.8.1` | `Apache-2.0` | Single licence, no change |

## Copyright extraction

Copyright notices are extracted from every licence-named file and from
`NOTICE`-style files at the module root. The extractor identifies lines that
start with a copyright declaration - `Copyright`, `©`, or `(c)` (the keyword
is matched case-sensitively to exclude prose references such as "copyright
notice, this list of conditions…").

**Normalisation applied before storage:**

- Leading comment markers (`//`, `*`, `#`, `!`) are stripped so Go source
  headers like `// Copyright 2013-2023 The Cobra Authors` are stored as
  `Copyright 2013-2023 The Cobra Authors`.
- Trailing prose conjunctions (` or`, ` and`) are stripped - these appear in
  multi-attribution blocks such as musl libc's math copyright notice, where
  consecutive lines are joined by prose conjunctions.
- Trailing punctuation (`.`, `,`, `;`, `:`) is stripped from holder names.
- Unicode en-dash year ranges (`-`) are normalised to ASCII hyphen.

Statements are deduplicated and sorted lexically. Each statement records the
normalised verbatim text, best-effort year range, best-effort holder name(s),
and the source file path within the zip.

**Pass 3 - source file backfill:** some modules (e.g. cobra) carry copyright
notices only in `.go` source file headers, not in the `LICENSE` file. When
licence files are present but yield no copyright, up to 20 root-level `.go`
files are scanned (first 4 KB each). Statements found this way are attached to
the primary licence entry with `Source: <source-headers>`.

## Per-file licence extraction (`--per-file`)

Some modules carry no standalone `LICENSE` file but declare their licence
through per-file headers (the [REUSE](https://reuse.software) specification):

```go
// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2024 The Authors
package foo
```

Pass 1 (the standard scan) finds no files to classify, so the record would
normally return `OverallStatus: None`. With `--per-file`, a second pass samples
up to 20 root-level `.go` files (capped at 64 KB each, 1 MB total):

1. **Fast path** - scans the first 4 KB of each file for an
   `SPDX-License-Identifier:` comment. If found, the identifier is recorded
   directly at `Confidence = 1.0`.
2. **Slow path** - if no SPDX header is present, runs the full licence
   detector. Files where the detector returns `Confidence ≥ 0.85` are recorded.

Entries produced by this pass have `IsPerFile = true` in `LicenseFiles`.
`OverallStatus` is set to `PerFile` when all root-level evidence came from
source files rather than a dedicated licence file.

Pass 1 always takes precedence: if any licence-named file exists, Pass 2 is
skipped entirely.

