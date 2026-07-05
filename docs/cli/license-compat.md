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

## Obligations catalogue

Every `licence` record includes an **obligations** section that describes what
the identified licence requires of users and distributors. The catalogue is a
curated static dataset (SPDX licence list + choosealicense.com conditions data)
versioned by `ObligationCatalogueVersion` (current: `1.1.0`).

**Default text output:**

```
  obligations (Apache-2.0, catalogue v1.1.0):
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
  "catalogue_version": "1.1.0"
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

**Coverage:** The catalogue covers all identifiers modelled by the compatibility
engine - Apache-2.0, MIT, BSD variants, ISC, Zlib, 0BSD, Unlicense, CC0-1.0,
BlueOak-1.0.0, MPL-2.0, LGPL variants, EPL variants, EUPL variants, CDDL-1.0,
GPL variants, AGPL variants, OSL-3.0, BUSL-1.1, SSPL-1.0, and Elastic-2.0. Any
identifier not in this set reports `status: unknown`.

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

**Compatibility engine** (`license-compat`): each SPDX identifier in
`AllSPDXs` is evaluated independently against the target licence. A bundled
GPL component inside an otherwise-permissive module will therefore surface as a
conflict even when the module root is Apache-2.0 or MIT.

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

