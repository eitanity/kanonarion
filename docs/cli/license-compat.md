# `kanonarion license-compat` - Licence compatibility

Reports licence conflicts in a module's dependency closure against a
target SPDX expression. Backed by the obligations catalogue and the
effective licence set described below.

## Implicit target (analysed root licence)

`--target` may be omitted: the root's own analysed licence record then becomes
the target, so the closure is checked against the project's ACTUAL declared
licence with nothing hand-typed.

```
kanonarion walk --gomod ./go.mod --analyse-root
kanonarion extract <walk-id>
kanonarion license-compat example.com/project@local
```

The root record must exist and carry an SPDX identity (`Expression`, falling
back to `PrimarySPDX`). Two failure modes are distinguished (absence
of data is never presented as an answer):

| Condition | Outcome |
|-----------|---------|
| No licence record for the root | Exit 4 (not found) with a diagnostic naming the command that produces it (`walk --gomod ./go.mod --analyse-root` + `extract` for a local root, `license <mod@ver>` otherwise) |
| Record exists but no SPDX identity (proprietary / `Unclassified` root) | Exit 2: the record is a valid outcome but cannot serve as an implicit SPDX target - pass `--target` explicitly |

## The answering walk

The closure checked is the closure of one walk — the most recent succeeded walk
of the root, whatever platform it resolved for. Both output forms name it, so a
verdict is always attributable to a build rather than to the module in the
abstract:

```
example.com/myapp@local vs Apache-2.0 (data v1.1.0, walk 01KQDBVW092ER1HNXZ60X27CMD, frame linux/amd64):
```

JSON output carries the same two values as `walk_id` and `walk_frame`. The
frame reads `unrecorded` for a walk taken before it was recorded.

---

## Obligations catalogue

Every `licence` record includes an **obligations** section that describes what
the identified licence requires of users and distributors. The catalogue is a
curated static dataset (SPDX licence list + choosealicense.com conditions data)
versioned by `ObligationCatalogueVersion` (current: `1.2.0`).

**Default text output:**

```
  obligations (Apache-2.0, catalogue v1.2.0):
    include-notice:        true
    include-license-text:  true
    state-changes:         true
    disclose-source:       false
    same-license:          none
    network-use-trigger:   false
    no-trademark-use:      true
    explicit-patent-grant: true
```

**JSON output** includes an `obligations` object with the same fields:

```json
"obligations": {
  "status": "known",
  "include_notice": true,
  "include_license_text": true,
  "state_changes": true,
  "disclose_source": false,
  "same_license": "none",
  "network_use_trigger": false,
  "no_trademark_use": true,
  "explicit_patent_grant": true,
  "catalogue_version": "1.2.0"
}
```

**Obligation fields:**

| Field | Description |
|-------|-------------|
| `status` | `known` when the SPDX identifier is in the catalogue; `unknown` when it is not. `unknown` must never be treated as "no obligations" - human review is required. |
| `include_notice` | Retain and distribute the original copyright notice and attribution text. |
| `include_license_text` | Include the complete licence text in all distributions. |
| `state_changes` | Document modifications made to original source files. |
| `disclose_source` | Make corresponding source code available to recipients (copyleft obligation). |
| `same_license` | Copyleft propagation strength: `none`, `weak`, `strong`, or `network`. |
| `network_use_trigger` | Providing the software over a network counts as distribution and triggers copyleft obligations (AGPL §13). |
| `no_trademark_use` | Prohibits using the licensor's name or marks to endorse derived works. |
| `explicit_patent_grant` | Includes an express grant of patent rights from contributors. |

The obligations are also surfaced in `kanonarion context` output under `license.obligations`,
making the actionable licence terms available to AI agents without network access.

**Coverage:** the catalogue covers Apache-2.0, MIT, BSD variants, ISC, Zlib,
0BSD, Unlicense, CC0-1.0, BlueOak-1.0.0, CC-BY-4.0, CC-BY-SA-3.0, OFL-1.1,
MPL-2.0, LGPL variants, EPL variants, EUPL variants, CDDL-1.0, GPL variants,
AGPL variants, OSL-3.0, BUSL-1.1, SSPL-1.0, and Elastic-2.0. Any identifier not
in this set reports `status: unknown`, which must never be read as "no
obligations".

The obligations catalogue and the compatibility dataset are separate datasets
and their coverage is not identical. BSL-1.0, Python-2.0 and WTFPL have a
compatibility verdict but no obligations entry, so `license` reports
`status: unknown` for a module whose root licence is one of those while
`license-compat` settles it as permissive.

## Effective licence set

A module's root `LICENSE` file describes the module author's chosen licence,
but many modules **bundle third-party code** under different terms. Two common
patterns:

- **Traditional vendor directory** - `vendor/github.com/google/snappy/LICENSE`
  (marked `IsVendored = true` in `LicenseFiles`)
- **Embedded subdirectory** - `snappy/LICENSE`, `internal/lz4ref/LICENSE`,
  `zstd/internal/xxhash/LICENSE.txt` (not under `vendor/` but still non-root)

Both patterns now contribute to the `EffectiveSet` field on `LicenseRecord`:

```json
"EffectiveSet": {
  "RootSPDXs": ["Apache-2.0"],
  "Components": [
    { "PathPrefix": "internal/lz4ref",           "SPDXs": ["BSD-3-Clause"] },
    { "PathPrefix": "internal/snapref",          "SPDXs": ["BSD-3-Clause"] },
    { "PathPrefix": "s2",                        "SPDXs": ["BSD-3-Clause"] },
    { "PathPrefix": "s2/cmd/internal/filepathx", "SPDXs": ["MIT"] },
    { "PathPrefix": "snappy",                    "SPDXs": ["BSD-3-Clause"] },
    { "PathPrefix": "snappy/xerial",             "SPDXs": ["MIT"] },
    { "PathPrefix": "zstd/internal/xxhash",      "SPDXs": ["MIT"] }
  ],
  "AllSPDXs": ["Apache-2.0", "BSD-3-Clause", "MIT"]
}
```

`AllSPDXs` is the sorted, deduped union of root and embedded licences - the
full set of obligations a consumer must honour. In the example above
(`github.com/klauspost/compress@v1.18.2`), the root claims Apache-2.0 but the
effective obligation set is **Apache-2.0 + BSD-3-Clause + MIT** because the
module ships BSD-licensed snappy and MIT-licensed xxhash source code.

**`EffectiveSet` is derived from `LicenseFiles`** on every extraction and on
every deserialization. It is never stored separately and is always consistent
with the file list; no re-extraction is needed for records produced before
the field existed.

### Downstream impact

**Compatibility engine** (`license-compat`): each SPDX identifier in the
effective set is evaluated independently against the target licence. A bundled
GPL component inside an otherwise-permissive module will therefore surface as a
conflict even when the module root is Apache-2.0 or MIT.

Two things about that consumption are specific to `license-compat`:

- **`testdata` directories are excluded.** A component prefix with a `testdata`
  segment at any depth is a test corpus, never linked code, so a copyleft
  licence on a fixture raises no compatibility conflict. The exclusion applies
  only here — `notice` and `sbom` still see the component, because a
  redistributor of the module zip still ships those bytes. `vendor/testdataloader`
  is a vendored library, not a corpus: the match is on whole path segments.
- **Every conflict entry names the origin of its identifier.** An identifier
  drawn from the effective set is not necessarily the module's own licence. See
  below.

The one exception is a **dual-licensed root**: a record whose expression is a
pure disjunction (`Apache-2.0 OR GPL-3.0`) offers an election, and each arm is
evaluated as a candidate election rather than as an unconditional obligation.
The outcomes:

- **every arm compatible** — settled compatible whichever arm is elected; no
  open item;
- **some arm compatible** — verdict `electable` (kind `election_required`):
  the module is compatible *if* a compatible arm is elected. The election is
  an operator decision, never resolved silently: record the elected arm as a
  `license_overrides` entry for the module and re-run. Pending elections exit
  `2` (review), like unknown pairs;
- **no arm compatible** — incompatible (or unknown-pair review when an arm is
  unmodelled) whichever arm is elected.

Embedded component licences are not part of the election — they apply
regardless of which root arm is elected. A `license_overrides` entry (the
recorded election, or any operator correction) replaces the scanner's record
for that module wholesale.

**Notice generator** (`notice`): embedded component licence texts are reproduced
in a separate "Embedded component" section after the module's root licence text.
See [`notice`](notice.md) for the output format.

**NOTICE files are excluded** from the effective set - they satisfy Apache §4(d)
attribution but do not define licence obligations.

### Worked example

```
$ kanonarion licence github.com/klauspost/compress@v1.18.2 --json \
    | jq '.EffectiveSet.AllSPDXs'
[
  "Apache-2.0",
  "BSD-3-Clause",
  "MIT"
]
```

The root `LICENSE` file is a compound Apache-2.0 attribution document, but
`snappy/`, `internal/lz4ref/`, and other subdirectories each carry their own
BSD-3-Clause or MIT licence files. Without `EffectiveSet`, these would be
invisible to the compatibility and notice pipelines.


## Whose licence is this? — origin on every conflict entry

An identifier in a conflict entry may be the module's own root licence, or it
may belong to a component the module bundles. Both bind a redistributor, but
only the first is what `license`, `license-list`, `audit`, `sbom`, `context`
and `inspect` mean when they report "the licence of this module". Every entry
therefore says which it is, and carries the module's own licence alongside.

```
Requires review — unmodelled license pair (2):
  gonum.org/v1/gonum@v0.16.0                              BSL-1.0
      from bundled component THIRD_PARTY_LICENSES — the module's own licence is BSD-3-Clause
  github.com/opencontainers/go-digest@v1.0.0              CC-BY-SA-4.0
      from the module's own licence Apache-2.0 AND CC-BY-SA-4.0 — arm CC-BY-SA-4.0
```

A conjunctive expression is reported whole, the way `sbom` reports it, with the
arm that raised the entry named. It is never reduced to that arm.

In JSON:

| Field | Meaning |
|-------|---------|
| `dep_spdx` | the identifier that was EVALUATED. It is the module's own licence only when `spdx_origin` is `module_root`. |
| `spdx_origin` | `module_root` or `bundled_component`. |
| `spdx_origin_path` | the component's path prefix, comma-separated when one identifier was found under several. Omitted for `module_root`. |
| `module_spdx` | the module's own licence expression, whole. This is the field that answers "what is this module licensed under", and it agrees with `license`, `sbom` and `audit`. |

When the operator has recorded a `license_overrides` entry for a module, the
override is the module's licence for all of these fields: the reported answer is
the decision, not the scan it replaced.

## Dataset coverage — a gap reported once, not once per module

An identifier the compatibility dataset does not model produces a review item on
every module that carries it. That reads as N legal questions when it is one
gap, so the report also names each distinct unmodelled identifier once:

```
Dataset coverage — 1 licence identifier in this closure is not modelled (data v1.1.0):
  CC-BY-SA-4.0             1 module(s)
      unmodelled by decision: Creative Commons share-alike for content; ...
```

`deliberate` (JSON `coverage_holes[].deliberate`) separates the two cases:

- **unmodelled by decision** — the identifier has a recorded reason for having
  no verdict, and the reason is printed. The current set is the Creative Commons
  content licences (CC-BY-4.0, CC-BY-SA-3.0, CC-BY-SA-4.0) and OFL-1.1: their
  obligations attach to documentation, data, media or fonts rather than to linked
  Go code. These still require review and still exit `2`.
- **not yet researched** — a gap. Nobody has ruled on the identifier.

`target_modelled` reports the same question about the `--target` itself. When it
is `false` every row in the report follows from that one fact rather than from
the dependencies' own licences, and the text output says so before the rows.

A permissive identifier never appears here: BSL-1.0, Python-2.0, WTFPL and
BSD-2-Clause-Views are modelled as permissive (`CopyleftNone`), so a module
bundling Boost-licensed or public-domain-equivalent code raises nothing.

## Modules resolved under pre-modules semantics

A `+incompatible` coordinate resolves no requirement edges at all, so what this command can show is bounded: a pre-modules module contributes its own licence and none of its dependencies', because none were resolved, so a clean verdict is clean over a closure smaller than the build. The answer states that and names the coordinates responsible; see [pre-modules modules](conventions.md#modules-resolved-under-pre-modules-semantics).
