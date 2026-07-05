# `kanonarion fips`

Assess a project's FIPS *eligibility*: whether its toolchain can produce
FIPS-validated crypto, and whether its dependency closure pulls in non-FIPS
algorithm packages or cgo crypto dependencies.

```
kanonarion fips [--gomod ./go.mod] [--json]
```

## Why this exists

FIPS 140-3 is a regulatory requirement in several target markets (DORA/EBA,
US federal, NIS2). Stock Go has no FIPS-validated crypto; a build that *looks*
compliant but uses a non-capable toolchain or a non-FIPS algorithm is a
compliance failure that no dependency graph reveals. `fips` makes the
toolchain posture and the closure's crypto surface first-class facts.

## Toolchain capability: two sources

A toolchain is FIPS-capable from **either**:

- an **out-of-tree distribution** - a marker in `buildinfo.txt` / go.mod that
  matches the versioned catalogue of FIPS-capable Go variants (BoringCrypto,
  Microsoft Go/CNG, Red Hat go-toolset, AWS Go FIPS); or
- the standard toolchain's **native Go Cryptographic Module** - go 1.24+ with
  the `fips140` directive enabled (`//go:debug fips140=on` or
  `GODEBUG=fips140=on`).

## Not-capable reasons are named, never flat

When the toolchain is not capable the assessment states *why*, so a consumer
can act rather than reading one undifferentiated negative (the same
absence-is-surfaced principle):

| Situation | Assessment |
|---|---|
| go 1.24+ ships native FIPS but `fips140` is unset or `off` | `not enabled: … set //go:debug fips140=on (or GODEBUG=fips140=on) to enable` |
| go version predates the native floor (1.24) | `not eligible: toolchain go… predates native FIPS 140-3 (requires go1.24.0 or newer)` |
| go version absent/unparseable and no distribution recognised | `not eligible: … no FIPS-capable distribution was recognised` |

"Not enabled" is distinct from "not eligible" on purpose: the first is a
one-line remediation, the second needs a toolchain change.

## Finding kinds

Each finding carries a `kind`, a `category`, source `file:line` where
applicable, and its policy outcome:

| Kind | Category | Meaning |
|---|---|---|
| `toolchain` | compliant when capable, else deviation | the headline toolchain fact (always present) |
| `algorithm` | deviation | a non-FIPS algorithm package import (`crypto/md5`, `crypto/rc4`, …) |
| `cgo_crypto` | unknown | a cgo crypto dependency - the known cgo gap means validation cannot be asserted from source, so it is never silently passed |
| `direct_crypto_rand` | compliant | direct `crypto/rand` use - under a capable toolchain the runtime routes it to a validated DRBG, so it is a surface fact, not a violation |

This is **eligibility** assessment, NOT formal CMVP / FIPS 140-3 validation -
the output carries that caveat explicitly on every emission.

## Policy & exit code

Findings are evaluated against the `fips_policy` governance block. The default
is **opt-in**: `required: false` surfaces findings but never gates. With
`required: true`, a non-FIPS-capable toolchain, a non-FIPS algorithm import,
or a cgo crypto dependency resolves to a blocking outcome and the command
exits **20** (`ExitConfig`) - suitable as a CI gate. The exit contract is
identical in text and `--json` mode, so a policy violation gates regardless of
output format.

## Output

Text mode prints a `Project / Toolchain / Assessment / Caveat` header followed
by a finding table (`KIND PACKAGE MODULE SOURCE:LINE CATEGORY POLICY`).

`--json` emits the deterministic top-level `fips` section: `schema_version`,
`ecosystem` (always `"go"` - it declares the schema's scope, not a polyglot
mode), `pipeline_version`, `catalogue_version`, `project`,
`toolchain_fips_capable`, `toolchain_variant`, `toolchain_raw`,
`fips_mode_statically_enabled`, `compliance_assessment`, `caveat`,
`content_hash`, the per-kind buckets `non_fips_algorithm_usage[]`,
`cgo_crypto_dependencies[]`, `direct_crypto_rand_usage[]`, and the full
ordered `findings[]`. Findings are domain-sorted and no wall-clock field is
emitted, so identical inputs yield identical bytes. The same section appears in
`kanonarion inspect --gomod … --json` as the aggregate surface.

## Scope notes

- OSS scope is **source + buildinfo** assessment. Per-org policy
  overrides/waivers, DORA-register integration, and SIEM events are Enterprise.
