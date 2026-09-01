# `kanonarion licence` - Licence Extraction

Every command in this family accepts both spellings: `licence` and `license`
(likewise `licence-list`/`license-list`, `licence-compat`/`license-compat`,
`licence-diff`/`license-diff`).

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

The one exception is the Go standard library, which is never fetched — see
[Standard library](#standard-library-stdlibvtoolchain).

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
| `--recursive` | false | Also report licences for the module's dependency closure |
| `--all` | false | With `--recursive`, list every dependency instead of a summary |
| `--walk-id` | (chosen) | With `--recursive`, read the closure from this walk |
| `--json` | false | Emit the licence record as a JSON object. Every key, at every depth, is snake_case; the keys are the command's own and are not the record type's Go field names |
| `--log-level` | `warn` | Log verbosity: `debug`, `info`, `warn`, `error` |

`--recursive` and `--all` read the closure from one walk of the module and print
which walk answered before the listing:

```
Answered from walk 01KQDBVW092ER1HNXZ60X27CMD (frame linux/amd64)
```

`--walk-id <id>` names the walk. Without it the walk is chosen by the shared
default-frame rule (see [conventions](conventions.md#the-default-walk)), and the
choice is stated on the line below whenever the store held more than one walk of
the module.

The frame reads `not-platform-scoped` for a module-rooted walk, which has
none. It matters because `GOOS` gates which files build, and so which modules
the closure contains.

**Output (default):**

```
github.com/spf13/cobra@v1.8.1: Detected - Apache-2.0
  LICENSE.txt: Apache-2.0 (100%) — covers this module's code
```

Every licence file line ends with what that licence covers. See
[what each licence covers](#what-each-licence-covers).

For a dual-licensed module (a disjunctive expression such as
`Apache-2.0 OR GPL-3.0`), the output prints one obligation set per arm and
names the election as the operator's to record:

```
github.com/gorhill/cronexpr@v0.0.0-…: Multiple — Apache-2.0 OR GPL-3.0
  APLv2: Apache-2.0 (100%) — covers this module's code
  GPLv3: GPL-3.0 (95%) — covers this module's code
  dual licence: obligations depend on the elected arm — the election is an
  operator decision, recorded as a license_overrides entry for this module
  obligations if Apache-2.0 is elected (catalogue v1.2.0):
    …
  obligations if GPL-3.0 is elected (catalogue v1.2.0):
    …
```

For a module under several licences at once (a conjunctive expression such as
`Apache-2.0 AND MIT`), there is no election. What the output can say depends on
what the record read, which is printed as the basis, and there are two cases.

**One licence file granting several licences.** Nothing attributes a licence to
any part of the module, so every grant governs its code and all of them bind.
The output prints the union of the arms' obligations — a duty any arm requires
is a duty owed, and the copyleft strength is the strictest arm's — then each
arm's own set, so a reader can see which licence imposed which duty:

```
gopkg.in/yaml.v3@v3.0.1: Multiple — Apache-2.0 AND MIT
  basis: split: covered by two different licenses
  LICENSE: MIT (85%) — covers this module's code
  NOTICE: Apache-2.0 (100%) — grants nothing: an attribution document
  conjunction: every arm binds at once, so the obligations below are the union
  of all arms — there is no election to make
  obligations (Apache-2.0 AND MIT, catalogue v1.2.0):
    …
  obligations required by Apache-2.0 (catalogue v1.2.0):
    …
  obligations required by MIT (catalogue v1.2.0):
    …
```

Where an arm is not in the obligations catalogue the union reports
`incomplete`: the merge saw part of what binds, and the arms it did recognise
are still listed beneath.

**One licence file per licence.** Here every arm covers code, and each file
names which code — `LICENSE.libyaml` is vendored C, `LICENSE.Golang` is
vendored Go — so each arm is printed with the file that grants it. Whether you
owe an arm depends on whether the artefact that file covers reaches your binary,
which kanonarion cannot determine, so the merged set is printed last and
labelled as an upper bound rather than as what you owe:

```
example.com/mod@v1.0.0: Multiple — Apache-2.0 AND Artistic-2.0
  basis: split: one file per licence, none naming a choice
  LICENSE: Apache-2.0 (100%) — covers this module's code
  LICENSE.perl: Artistic-2.0 (100%) — covers this module's code
  separate grants: each arm is granted by its own licence file, named below, and
  that file states what the arm covers
  obligations required by Apache-2.0, granted by LICENSE (catalogue v1.2.0):
    …
  obligations required by Artistic-2.0, granted by LICENSE.perl: unknown (…)
  maximal obligations across every arm (…) — an upper bound,
  not what you owe: which arms bind depends on which covered artefacts you ship
    …
```

An arm the catalogue does not know is reported on its own row and does not
degrade the rest: here the Apache-2.0 grant is identified at full confidence,
and an arm with no catalogue entry says nothing about it.

An arm that does not cover the module's code at all — a documentation licence,
an embedded font's licence — is a different case and never reaches this one: it
leaves the expression rather than joining the upper bound. See
[what each licence covers](#what-each-licence-covers).

With `--json` the merged set is the `obligations` object and the per-arm sets
are `binding_obligations`, keyed by SPDX identifier — the shape
`elective_obligations` uses for a disjunction. For separately granted arms two
more keys appear: `arm_grants`, mapping each identifier to the licence files
granting it, and `obligations_reading`, which states that `obligations` is a
maximal upper bound and not the set you owe. Both are absent when the arms came
from one file, where `obligations` is the owed set.

A module is reported as dual-licensed only when its licence file says so — an
`SPDX-License-Identifier` line naming a choice, or wording such as "under the
terms of either licence". Where one file carries several licence texts, the
output states what the file was read to say and, where a grant covers
third-party code the module carries rather than the module's own code, names
that grant separately. It is deliberately absent from the expression: it is
neither an arm anyone may elect nor an obligation the module imposes.

```
go.opentelemetry.io/otel@v1.44.0: Multiple — Apache-2.0
  basis: bundled-grant: copyright 2009 the go authors. — bundled: BSD-3-Clause
  bundled in the licence file, not a licence of this module: BSD-3-Clause
  LICENSE: Apache-2.0 (100%) — covers this module's code
```

Where the file carries several grants and says nothing about how they relate,
every grant is reported as applying (`A AND B`) and the `basis` line reads
`conservative:`. The same is true when the licence text could not be read.

`--json` carries the same two facts as `expression_basis` and `bundled_spdxs`.

To settle the election, record the chosen arm as a `license_overrides` entry
(see [`config`](config.md)); `audit` and `license-compat` treat the module as
an open item until one exists.

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

Under `--json` these names are the values of `overall_status` verbatim.
`copyright_status` (`not_analysed` / `found` / `none_found` /
`extraction_failed`), `provenance.confidence` (`not_analysed` / `high` /
`medium` / `low`) and each entry of `provenance.signals` (`inbound_outbound`,
`cla_required`, `dco_required`, `authors_file`, `contributors_file`,
`patents_file`) carry names on the same terms. Match on the name; the position
of a value in the Go constant block is not part of the contract.

When a root file is `Unclassified` but a known licence was *partially*
recognised - coverage below the substantive floor, e.g. a truncated AGPL-3.0
whose only matching span is the "how to apply" appendix - the `context` /
`inspect` summary surfaces that fragment as a low-confidence caveat
(`Unclassified - license file present; low-confidence AGPL-3.0-or-later match
(~3% coverage)`). It is a caveated inference about a malformed file, never a
confident SPDX classification.

## Standard library (`stdlib@v<toolchain>`)

`kanonarion licence stdlib@v1.26.5` answers from the **chain of custody** the
walk stage records for the toolchain, not from a licence record. The standard
library ships with the toolchain rather than through the module proxy, so
nothing fetches or extracts it and it holds no `LicenceRecord` — `kanonarion
fetch` rejects the coordinate outright (`malformed module path "stdlib"`) and is
never named as a remedy for it.

```
kanonarion licence stdlib@v1.26.5

stdlib@v1.26.5: Detected — BSD-3-Clause
  basis: extracted from the acquired source tree's LICENSE file (VerifiedGoDevChecksum)
  acquired via: godev
  source:       https://go.dev/dl/go1.26.5.src.tar.gz
  sha256:       495be4bc…
  vcs:          https://go.googlesource.com/go go1.26.5
  commit:       c19862e5f8415b4f24b189d065ed739517c548ba
```

The status word is the one `audit` prints in its Licence column for the same
node, and `context`, `sbom` and `licence-compat` resolve the same identity:

| Status | Basis | Meaning |
|---|---|---|
| `Detected` | `stdlib-tarball` | The SPDX identifier was extracted from the acquired source tree's `LICENSE` file |
| `Known` | `stdlib-known` | No measurement carried an identifier, so the answer is the `BSD-3-Clause` the Go project publishes |

The basis and the **verification status** are separate axes. A `Known` answer
over a recorded measurement says the measurement identified no licence; a
`Known` answer with no verification status says nothing has been acquired for
that toolchain at all, and names the command that would acquire it:

```
kanonarion licence stdlib@v1.99.0

stdlib@v1.99.0: Known — BSD-3-Clause
  basis: published knowledge of the Go project's licence; no chain of custody is
         recorded for go1.99.0 — establish one with: kanonarion walk --gomod ./go.mod
```

The offline (`--from-modcache`) anchor records `VerifiedLocalToolchain` and is
never reported as `VerifiedGoDevChecksum`: it establishes custody from
`$GOROOT`, having deliberately not consulted the published checksum.

`--history` lists every custody measurement the ledger holds for that toolchain
version, oldest first — the standard library's answer to the question `--history`
asks of every other module:

```
kanonarion licence stdlib@v1.26.5 --history

2 custody measurement(s) for stdlib@v1.26.5 (go1.26.5):
  2026-08-13T04:12:57Z  BSD-3-Clause  VerifiedGoDevChecksum  via godev
    artefact: sha256:495be4bc…
```

`--force`, `--per-file` and `--recursive` do not apply to the standard library
itself: there is nothing to re-extract, no source files to scan and no
dependency closure below it. A **project's** `--recursive --all` listing does
carry the `stdlib` row, resolved the same way — it is a node of the walk like
any other.

Because no record exists, `licence-list` never lists the standard library,
`licence-diff` refuses it by name (pointing at `--history` instead), and
`notice` carries it as a review item — its licence identity is known but no
stage extracts the toolchain's licence text for verbatim attribution.

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
| `--spdx` | | Filter by SPDX identifier (e.g. `MIT`, `Apache-2.0`), matched for exact equality |
| `--copyright` | | Filter by copyright holder, as a case-insensitive substring of the licence files (loads full records) |
| `--limit` | 50 | Maximum records to show (0 = unlimited) |
| `--offset` | 0 | Skip this many records before listing. With `--copyright` the offset applies to the records that matched the holder, not to the records read from the store |

When the limit bites, the listing says so on both output paths and names the
invocation that lifts it, per [Truncated listings](conventions.md#truncated-listings).

Under `--json` the command answers with one object carrying `records` and the
paging state, not a bare array, and writes nothing to stderr — see [Listing
documents](conventions.md#listing-documents).

The command takes no positional argument; one is refused rather than ignored. A
zero result names the filter it applied and what it was compared against, per
[Zero-result listings](conventions.md#zero-result-listings).

## Caching

Each licence record is keyed by `(module_path, module_version, pipeline_version)`.
Re-running `kanonarion licence` without `--force` returns the cached record
immediately. A new pipeline version invalidates all existing records for that
stage (but not fetch records or walk records).

A `local` coordinate is never served from cache at all: the working tree
mutates, so it is re-read and re-extracted on every run. The run appends a
generation only when the extraction says something the ledger does not already
say; a re-extraction that comes back identical appends nothing and says so on
stderr. `--force` records the measurement either way.

The database schema is versioned via the shared `schema_migrations` table
(numbered per module). The current pipeline version is `1.3.0`.

## Assurance log

Each fresh extraction appends a `license_extracted` event to the append-only
audit log (`{store-root}/audit.jsonl`): module, version, resolved
`primary_spdx`, `overall_status` (`Detected` / `Unclassified` / `None` / …), and
the identity `source` (`scanner`). Licence extraction is half of `audit`'s
compliance verdict, so this anchors *what licence was resolved, and when* in the
append-only assurance log - independent of the mutable licence record. A cache hit
(no `--force`) re-serves the stored record without re-extracting, so it appends
nothing. A re-extraction that appends no generation appends no event either: the log
records generations, not runs.

## What each licence covers

A module can carry more than one licence for more than one reason. Some of them
grant rights in its Go code; some grant rights in documentation it ships or in
an asset it embeds. Every entry of `license_files` therefore carries a
`coverage` field, and every licence file line in the text output ends with the
same statement:

| `coverage` | Text output | Meaning |
|---|---|---|
| `ModuleCode` | covers this module's code | The licence governs the module's own source |
| `Documentation` | covers documentation | The licence governs documentation the module ships |
| `BundledComponent` | covers a bundled component | The licence governs third-party material carried inside the module — a vendored library, an embedded font |
| `AttributionOnly` | grants nothing: an attribution document | The file is a `NOTICE`; it grants nothing, so there is nothing for it to cover |
| `NotDetermined` | covers something this artefact does not establish | The artefact does not settle it. A real answer, not an absence |

The field is emitted **always**, including for the ordinary code licence: an
absent field would make "governs the code" indistinguishable from "this build
does not derive coverage".

**A licence that does not cover the code does not enter the expression.**
`github.com/alecthomas/chroma/v2` is a Go syntax-highlighting library that
embeds a Liberation font; its root `COPYING` carries the library's MIT grant and
the font's SIL Open Font Licence, and the font licence covers more of the file:

```
github.com/alecthomas/chroma/v2@v2.27.0: Multiple — MIT
  basis: coverage: OFL-1.1 covers a bundled component, not this module's code; set aside from the recorded reading: split: is licensed under
  COPYING: OFL-1.1 (98%) — covers a bundled component
```

`github.com/opencontainers/go-digest` is the other shape — a root `LICENSE` for
the code beside a root `LICENSE.docs` for the documentation:

```
github.com/opencontainers/go-digest@v1.0.0: Multiple — Apache-2.0
  basis: coverage: CC-BY-SA-4.0 covers documentation, not this module's code; set aside from the recorded reading: split: one file per licence, none naming a choice
  LICENSE: Apache-2.0 (100%) — covers this module's code
  LICENSE.docs: CC-BY-SA-4.0 (82%) — covers documentation
```

In both cases `primary_spdx`, `expression` and the obligations are the code
licence's, `expression_basis` states that coverage took part and keeps the
reading it displaced, and the grant that was set aside is still reported against
what it covers. The licences are not lost — they are attributed.

**How coverage is decided.** By the licence instrument, never by the file's name
or where it sits. `COPYING` carries a font licence in chroma and a legitimate
code licence in `github.com/dchest/uniuri`, so no rule about names could tell
them apart. What tells them apart is what the instrument itself licenses:
OFL-1.1 defines *"Font Software"* and grants rights in nothing else, and the
Creative Commons attribution family grants rights in *"Licensed Material"*.
Those are clauses of the text the detector matched.

Three consequences follow, and each is deliberate:

- **A Creative Commons instrument is not automatically a documentation
  licence.** `CC0-1.0` is a public-domain dedication with no subject-matter
  restriction, published for software and widely used for Go source. It stays a
  code licence and stays the primary.
- **A module whose ONLY grant is a font or content instrument is left alone.** A
  font package licensed `OFL-1.1`, or a module its author genuinely published
  under `CC-BY-4.0`, has no code grant beside it to prefer; nothing in the
  artefact settles the question, so the coverage reads `NotDetermined` and the
  expression does not move.
- **A declared election is the module's own answer.** Where a module offers a
  choice — `codeberg.org/go-fonts/liberation` elects between `BSD-3-Clause` and
  `OFL-1.1` — every arm covers the whole work by the module's own statement, and
  none is set aside.

An SPDX identifier the instrument tables do not name reads `NotDetermined` and
is never set aside, so a licence new to the corpus cannot be silently demoted
out of a module's expression.

**Every surface answers this the same way.** `license` (text and `--json`),
`license-list`, `license-diff`, `context --json` / `inspect`, `audit`, `sbom`,
`notice` and `license-compat` all name the licence covering the module's code.
Where a surface has a second job, the correction is to the identity only:
`notice` names the code licence and still reproduces every licence text the
archive carries, and `license-compat` names the code licence and still evaluates
every identifier in the archive, so a documentation licence is raised for review
rather than hidden.

**Derivation rule:** `coverage` is computed from `license_files` on every
extraction and on every deserialisation — the same derived-field contract as
`effective_set` and `package_licenses`. It is never stored separately and is
outside the record's content hash, so records written before the field existed
still verify and still answer the question.

`effective_set` is deliberately unaffected: it is a faithful account of the
identifiers the module zip contains, so a set-aside grant is still listed there.
Coverage says what each of them governs.

## Vendored licences

Licence files under `vendor/` are recorded in `license_files` with
`is_vendored: true` and `coverage: BundledComponent`, and are included in
`effective_set.components` (see above).
They do not contribute to `primary_spdx` or `expression` - those fields reflect
the module author's own licence only. Each vendored dependency is also a
separate module in the walk graph with its own `LicenseRecord`.

## Per-package licences

Some modules contain first-party sub-packages governed by a **different licence
than the module root**. A sub-package may ship its own `LICENSE` file - for
example, a module that is Apache-2.0 overall but includes an MIT-licensed
utility package or a BSD-3-Clause reference implementation under a subdirectory.

These are surfaced in the `package_licenses` key of the document:

```json
"package_licenses": [
  {
    "package_path": "gzhttp",
    "spdx": "Apache-2.0",
    "confidence": 1,
    "source_file": "gzhttp/LICENSE"
  },
  {
    "package_path": "internal/lz4ref",
    "spdx": "BSD-3-Clause",
    "confidence": 1,
    "source_file": "internal/lz4ref/LICENSE"
  }
]
```

**Key distinctions:**

- **`package_licenses`** - first-party sub-packages of the module itself; not
  vendored. Lets a consumer ask "what licence applies to the package I actually
  import?" when they import a sub-package rather than the module root.
- **`effective_set.components`** - all non-root, non-vendored subdirectory
  groups, including embedded third-party code. Used by the compatibility and
  notice pipelines to compute the full obligation set.

A module with a single, uniform root licence reports `package_licenses: null`
(no per-package divergence).

**Derivation rule:** `package_licenses` is computed from `license_files` on every
extraction and on every deserialisation - the same derived-field contract as
`effective_set` and `coverage`. It is never stored separately. Vendored entries
(`is_vendored: true`) and NOTICE files are excluded. When a directory contains
multiple licence files, the highest-confidence match wins.

### Text output

```
$ kanonarion --json=false licence github.com/klauspost/compress@v1.18.2
github.com/klauspost/compress@v1.18.2: Multiple - Apache-2.0 (cached)
  LICENSE: Apache-2.0 (99%) — covers this module's code
  gzhttp/LICENSE: Apache-2.0 (100%) — covers this module's code
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
    | jq '[.package_licenses[] | {pkg: .package_path, spdx: .spdx}]'
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
