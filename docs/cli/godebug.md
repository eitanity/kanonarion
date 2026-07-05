# `kanonarion godebug`

Detect, classify and policy-check every `//go:debug` setting baked into a
project's main package - and any vendored dependency main packages.

```
kanonarion godebug [--gomod ./go.mod] [--json]
```

## Why this exists

`//go:debug` directives (Go 1.21+) and the `GODEBUG` environment variable
change **runtime security behaviour**, and the `//go:debug` form is compiled
into the binary as a build default - invisible to anyone reading import
statements or the dependency graph. Several settings actively weaken security:

- `tlsrsakex`, `tls10server`, `tls3des`, `tlssha1` - re-enable removed/weak
  TLS primitives;
- `x509ignoreCN`, `x509negativeserial` - relax certificate validation;
- `tarinsecurepath`, `zipinsecurepath` - restore path-traversal-prone archive
  extraction.

`godebug` makes each setting a first-class fact: enumerated with file/line,
risk-classified, policy-evaluated, and recorded as an audit event.

## Versioned risk taxonomy

Classification is driven by a **versioned data file**
(`internal/godebug/domain/taxonomy.json`), not hardcoded logic, so it stays
maintainable as Go adds settings - adding one is a one-line edit plus a
taxonomy-version bump.

| Tier    | Meaning                                              | Examples                                              |
|---------|------------------------------------------------------|-------------------------------------------------------|
| `red`   | Security-weakening                                   | `tlsrsakex`, `tls10server`, `x509ignoreCN`, `zipinsecurepath` |
| `amber` | Behaviour-modifying with security implications       | `http2client`, `multipartmaxparts`, `randautoseed`, `panicnil` |
| `green` | Benign (GC / debug logging toggles)                  | `asynctimerchan`, `gotypesalias`                      |
| `unknown` | Not in the taxonomy - **fails safe**                | a setting Go shipped after the taxonomy revision      |

An `unknown` setting is never silently treated as benign: the policy mapping
fails safe to the **red** posture until the taxonomy is updated.

The classifying taxonomy revision is recorded as `taxonomy_version` on every
record, and folded into the store key, so a taxonomy update transparently
re-classifies an unchanged project instead of returning a stale verdict.

## Applied vs not-applied

`//go:debug` only takes effect in the **main package of the main module**. A
directive carried by a vendored dependency is recorded with `"applied":
false` - surfaced as a fact, never silently dropped - but it does
**not** gate the build, since it has no effect on the produced binary.

## Policy & exit code

Each setting is evaluated against the `godebug_policy` governance block
(config schema v2). The default policy flags **red** settings
(`warn`), notifies on **amber**, allows **green**. When any *applied* setting
resolves to `warn`, the command exits **20** (`ExitConfig`) - suitable as a
CI gate. Per-org overrides/waivers are Enterprise.

## Output

`--json` emits the deterministic top-level `godebug` section
(`schema_version`, `ecosystem`, `pipeline_version`, `taxonomy_version`,
`project`, `content_hash`, `settings[]`). `ecosystem` is always `"go"` - it
declares the schema's scope (kanonarion is fitted for Go), not a polyglot mode.
Each entry carries `classification`,
`applied`, `module` and `policy_outcome`. The same section appears in
`kanonarion inspect --gomod … --json` as the aggregate surface.

## Audit

Every detected setting is appended to `audit.jsonl` as a
`godebug_setting_observed` event with its classification
and policy verdict. Because one event is emitted per setting per scan,
add/remove/modify between scans is observable directly from the append-only
log without a bespoke diff schema.

## Scope notes

- OSS scope is **source-directive** audit. Build-time `GODEBUG` *env* capture
  and extraction of settings embedded in a prebuilt binary are split to the
  linked Enterprise ticket, as are SIEM events.
