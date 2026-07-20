# `kanonarion notice` - Attribution Document Generation

Generates a deterministic `THIRD-PARTY-LICENSES` attribution document from
stored licence records. The document lists, for each module: its coordinate,
SPDX identifier, verbatim copyright notices, and verbatim licence text.

Modules with an ambiguous or multiple licence status, or with no copyright
notice, are reported on stderr and cause a non-zero exit - they require human
review before the document can be published.

The document also covers third-party code **copied into first-party source**,
which has no `go.mod` entry and so is invisible to module licence extraction.
See [Copied-source attribution](#copied-source-attribution).

## Prerequisites

All modules in scope must have been fetched and have a stored licence record.
Run `kanonarion licence <module@version>` for any module that is missing.

## Command

```
kanonarion notice [--package <pattern>] [--gomod <path>] [--walk-id <id>]
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--package <pattern>` | | Go package pattern (e.g. `./cmd/kanonarion`); scopes the document to modules linked into that binary |
| `--gomod <path>` | auto-discovered | Path to a `go.mod` file; covers the project's code dependencies (`go list -deps -test ./...`). Prefer `--package` to scope to a distributed binary |
| `--walk-id <id>` | | Generate from a previously stored walk record |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--log-level <level>` | `warn` | Log verbosity: `debug` \| `info` \| `warn` \| `error` |

`--package`, `--gomod`, and `--walk-id` are mutually exclusive. When none is
given, kanonarion auto-discovers a `go.mod` by walking upward from the current
directory.

The global `--json` flag is a no-op here: `notice` always emits the
`THIRD-PARTY-LICENSES` text document, which is the deliverable artifact and has
no separate machine-readable projection.

## Scoping strategies

### `--package` (recommended for binary attribution)

Uses `go list -deps` to enumerate exactly the modules linked into a specific
binary. This excludes dev tools, linters, and test-only dependencies that
appear in `go.mod` but are never distributed in the binary.

```sh
# Generate notice for the kanonarion binary only
kanonarion notice --package ./cmd/kanonarion > THIRD-PARTY-LICENSES
```

This is the right scope for any artefact you ship: users receive the binary,
not the full module graph.

### `--gomod`

Covers the project's **code** scope - the modules the project's own packages
and their tests import (`go list -deps -test ./...`), the same default set every
go.mod command uses. This is broader than `--package` (it includes test-only
dependencies) but narrower than the full build list. Appropriate when you want
attribution across everything your code builds against, including tests, rather
than only what a single shipped binary links.

```sh
kanonarion notice --gomod ./go.mod > THIRD-PARTY-LICENSES
```

### `--walk-id`

Generates from a stored walk record (from `kanonarion walk`).

```sh
WALK_ID=$(kanonarion walk-list --latest-success --json | jq -r '.id')
kanonarion notice --walk-id "$WALK_ID" > THIRD-PARTY-LICENSES
```

## Output format

The document is written to stdout in a fixed format:

```
THIRD-PARTY-LICENSES

This project uses the following third-party software.

================================================================================
Module:  github.com/spf13/cobra@v1.10.2
License: Apache-2.0

Copyright notices:
  Copyright 2013-2023 The Cobra Authors

Apache-2.0 (LICENSE.txt):

                                Apache License
                          Version 2.0, January 2004
   ...
================================================================================
```

Copyright notices are deduplicated and sorted lexically. Each licence text is
reproduced verbatim from the file in the module zip.

## Embedded component attribution

Modules that bundle third-party source code under a different licence - either
under `vendor/` or in embedded subdirectories like `snappy/` or
`zstd/internal/xxhash/` - have those component licence texts reproduced in an
**"Embedded component"** section immediately after the module's root licence
text:

```
================================================================================
Module:  github.com/klauspost/compress@v1.18.2
License: Apache-2.0

Copyright notices:
  Copyright 2011-2016 Dmitry Chestnykh
  Copyright 2011 The Snappy-Go Authors
  ...

Apache-2.0 (LICENSE):

   ...Apache-2.0 text...

Embedded component: internal/lz4ref
  License: BSD-3-Clause

  internal/lz4ref (internal/lz4ref/LICENSE):

   Copyright (c) 2011 The LZ4 Authors. All rights reserved.
   ...BSD-3-Clause text...

Embedded component: snappy
  License: BSD-3-Clause

  snappy (snappy/LICENSE):

   Copyright 2011, Google Inc.
   ...

Embedded component: zstd/internal/xxhash
  License: MIT

  zstd/internal/xxhash (zstd/internal/xxhash/LICENSE.txt):

   ...MIT text...
================================================================================
```

The embedded component list is derived from `EffectiveSet.Components` on the
stored `LicenseRecord` (see [`licence`](license-compat.md#effective-licence-set)).
Only components with a classified SPDX identifier and a readable licence file
are included. Components whose licence is unclassified appear in the extraction
record but are not reproduced in the NOTICE document - add a licence override in
`config.yaml` if manual classification is needed.

**No new extraction step is required.** `EffectiveSet` is derived from the
existing `LicenseFiles` on every record load, so modules extracted before the
field existed benefit automatically once their licence record is loaded.

## Copied-source attribution

Third-party code is sometimes transcribed into first-party source rather than
imported as a module - a table of constants, a classification map, a small
algorithm. It carries its licence in a comment header, never appears in
`go.mod`, and is therefore invisible to module licence extraction. Omitting it
from `THIRD-PARTY-LICENSES` is an attribution gap.

`notice` scans the project's first-party Go source for SPDX snippet tags
(REUSE 3.0 / SPDX `SnippetBegin`..`SnippetEnd`) and renders each block as a
first-class attribution entry. Detection is **exactly** these tags - there are
no free-text heuristics, so annotating a block is a deliberate act by the
author, who is responsible for the identifier being correct.

### Annotating a block

```go
// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright 2023 Google LLC
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: Capslock stdlib capability classification data
// SPDX-SnippetComment: Transcribed from github.com/google/capslock@v0.3.2, interesting/interesting.cm

var funcSinks = map[string]Capability{ /* ... */ }

// SPDX-SnippetEnd
```

| Tag | Required | Meaning |
|-----|----------|---------|
| `SPDX-SnippetBegin` / `SPDX-SnippetEnd` | yes | Block delimiters. One block is one attribution record |
| `SPDX-License-Identifier:` | yes | A **single** SPDX identifier. Compound expressions (`MIT OR Apache-2.0`) are rejected |
| `SPDX-SnippetCopyrightText:` | yes | The verbatim copyright notice, reproduced as-is |
| `SPDX-SnippetComment:` | yes | Free text that must contain the origin coordinate in `module@version` form |
| `SPDX-SnippetName:` | no | Display name; defaults to the origin coordinate |

### Scope of the scan

Scanned: every `.go` file under the module root, resolved from `--gomod` or the
auto-discovered `go.mod`. Reads are confined to that root.

Not scanned: `_test.go` files (not distributed in the binary), files carrying a
`// Code generated` marker, and the `vendor/`, `testdata/`, `node_modules/` and
dot-directories. With `--walk-id` outside a project checkout there is no
first-party tree, and the scan is skipped.

### Output

Copied-source entries interleave with module entries in the same coordinate
sort, and are labelled so a reader can tell transcribed code from a dependency:

```
================================================================================
Copied source: Capslock stdlib capability classification data
Origin:  github.com/google/capslock@v0.3.2
Used in: internal/capability/domain/sinks.go
License: BSD-3-Clause

Copyright notices:
  Copyright 2023 Google LLC

BSD-3-Clause:

Redistribution and use in source and binary forms, with or without
   ...BSD-3-Clause text...
================================================================================
```

Several blocks citing the same origin **and** the same licence collapse into one
entry listing every contributing path under `Used in:`.

### Licence text resolution

A copied snippet has no module zip to read a `LICENSE` file from, so its
verbatim text comes from a table of licence texts embedded in the binary,
keyed by SPDX identifier. Covered identifiers:

`Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `BSL-1.0`, `CC0-1.0`, `GPL-2.0`,
`GPL-3.0`, `ISC`, `LGPL-2.1`, `LGPL-3.0`, `MIT`, `MPL-2.0`, `Unlicense`, `Zlib`

Identifiers are matched exactly and case-sensitively. For templated licences
(the BSD family, ISC, MIT, Zlib) the table stores the licence **body** with the
generic placeholder wording - the per-snippet copyright comes from
`SPDX-SnippetCopyrightText` and is rendered separately.

An identifier outside this set is a hard error naming the known set, not a
partial record: a NOTICE entry without its licence text looks complete while
understating what the project redistributes. To cover a further identifier, add
`internal/license/domain/spdxtexts/spdx-<identifier>.txt`; it is a data asset,
not a code change. A test re-classifies every stored text through the same
detector the licence pipeline uses for module `LICENSE` files, so a wrong,
truncated or misnamed text fails the build.

### Failure modes

A block that opts in must be complete. Each of these is a hard error naming the
offending `file:line`, on the same gate as a module with a missing copyright:

- a missing required tag;
- an unterminated block, or a nested `SPDX-SnippetBegin`;
- a compound licence expression;
- a `SPDX-SnippetComment:` with no `module@version` coordinate, or an invalid one;
- an SPDX identifier with no embedded licence text;
- two blocks citing the same origin under **conflicting** licences - one
  attribution would have to be dropped and there is no safe way to choose.

## Review failures

When a module cannot be included without human review, `notice` writes a
diagnostic to stderr and exits non-zero:

```
notice: 2 module(s) require human review before publishing:

  example.com/foo@v1.0.0: ambiguous licence (Apache-2.0 / MIT)
  example.com/bar@v2.0.0: no copyright notice found
```

Resolve by checking the module manually and either:
- Adding a licence override in `config.yaml` (for ambiguous identifications), or
- Filing an issue with the upstream project to add a copyright notice.

## Copyright extraction

Copyright notices are extracted from the module zip during `licence`
extraction. The extractor recognises three source types:

1. **Licence-named files** (`LICENSE`, `NOTICE`, `COPYING`, etc.) at the
   module root. Lines starting with `Copyright`, `©`, or `(c)` (case-sensitive
   for the keyword, to exclude prose references) are captured as statements.

2. **`NOTICE`-style files** that list attribution in plain-text blocks.

3. **Root-level `.go` source files** (Pass 3): when licence files are present
   but yield no copyright - a pattern found in projects like cobra that keep
   copyright headers only in source files - up to 20 root-level `.go` files are
   scanned (first 4 KB of each). Copyright statements found this way are marked
   with `Source: <source-headers>`.

Statements are normalised before storage:
- Leading comment markers (`//`, `*`, `#`) are stripped.
- Trailing prose conjunctions (` or`, ` and`) are stripped - these appear in
  multi-attribution blocks such as musl libc's math copyright notice.
- Trailing punctuation (`.`, `,`, `;`, `:`) is stripped from holder names.
- Unicode en-dash year ranges (`-`) are normalised to ASCII hyphen.

BSD boilerplate clauses ("copyright notice, this list of conditions…") and
lowercase `copyright` in prose are not captured as declarations. Two further
false-positive classes found in real licence text are also filtered:

- **Template scaffold** - the GPL/AGPL/LGPL "How to Apply These Terms" appendix
  ships literal placeholders such as `Copyright (C) <year>  <name of author>`.
  A line carrying an unfilled angle-bracket placeholder token (bare words, no
  URL/email punctuation) is not a real holder and is dropped. A URL or email in
  angle brackets - `Copyright 2020 Acme Corp <https://acme.example/>` - is a
  genuine declaration and is kept.
- **Licence-document self-copyright** - the GPL/AGPL/LGPL text carries the Free
  Software Foundation's copyright on the *licence document itself*
  (`Copyright (C) 2007 Free Software Foundation, Inc.`). That is a fact about
  the licence, not about the licensed work, so it is dropped.

## Examples

```sh
# Binary-scoped notice (recommended for shipping)
kanonarion notice --package ./cmd/kanonarion > THIRD-PARTY-LICENSES

# Full module graph notice
kanonarion notice --gomod ./go.mod > THIRD-PARTY-LICENSES

# Notice from a stored walk
kanonarion notice --walk-id abc123 > THIRD-PARTY-LICENSES

# Preview what modules will be included (without generating the document)
go list -deps -f '{{if not .Standard}}{{.Module.Path}}@{{.Module.Version}}{{end}}' ./cmd/kanonarion | sort -u
```
