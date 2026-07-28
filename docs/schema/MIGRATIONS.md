# Output & Config Schema Migrations

Kanonarion versions schemas **per registered unit** (per-module fact records,
per-stage pipeline versions, the config schema), not via a single global
envelope. This file is the human-readable migration log; it complements the
output-schema stability contract and the store-migration policy.

## Compatibility contract

- Adding a field or a new optional top-level output **section** is a
  non-breaking, additive change. Consumers MUST ignore unknown fields.
- Removing/renaming a field, changing a type, or changing an exit-code meaning
  is breaking and requires a version bump + an entry here.

## Config schema

### v1 → v2

**Additive, backward-compatible.** v2 adds four unified supply-chain
governance blocks to `config.yaml`:

- `directive_policy` - replace/exclude classification outcomes
- `godebug_policy` - red/amber/green tier outcomes
- `vendor_policy` - drift/inconsistency outcomes + `vendor_only`
- `fips_policy` - `required` + `on_deviation`

Migration for existing configs: **none required.** A `version: "1"` file with
no governance blocks continues to load; absent blocks resolve to the default
governance posture (`DefaultConfig`), and an unset outcome resolves to an
implicit allow. To adopt v2 explicitly, set `version: "2"` and add any blocks
you wish to override.

## JSON output sections

The following top-level `--json` sections are introduced **additively** by the
supply-chain governance work on top of the shared corpus groundwork. Consumers
pinned to the prior shape are unaffected (unknown-section rule above):

| Section      | Status                |
|--------------|-----------------------|
| `directives` | reserved              |
| `godebug`    | reserved              |
| `vendor`     | reserved              |
| `fips`       | reserved              |

## Vulnerability record: pipeline `v14` → `v15`

**Additive.** Two changes to `VulnerabilityRecord`'s stored shape, both of which
alter the canonical bytes it hashes over, hence the pipeline bump:

- `coverage_status` (`Analysed` / `Unscannable` / `Failed`) and
  `findings_status` (`Affected` / `Clean`) join the collapsed `overall_status`,
  whose four values answered two different questions. `overall_status` keeps its
  existing values, so a consumer that reads only the summary word is unaffected;
  a consumer that wants a findings fact must read `findings_status`. See
  [`docs/cli/vuln.md`](../cli/vuln.md) for the mapping.
- `database_snapshot.content_hash` is now populated. It was already part of the
  record's shape and empty on every record ever written.

Migration for existing stores: **none required by the consumer.** Store
migration 11 back-fills the axis columns from `overall_status`; the projection is exact, so no verdict changes.
Records at `v14` and earlier are kept and still answer queries — their blobs
carry no axes, and readers derive them from `overall_status` on read. New scans
write `v15`.

## Vulnerability record: pipeline `v15` → `v16`

**Additive, and hash-transparent.** `VulnerabilityFinding` gains `withdrawn_at`,
the OSV top-level `withdrawn` timestamp, so a retracted advisory stops being
reported as a finding against the module it names.

The field carries `omitzero`, so it is absent from the encoding exactly when it is
zero, and a `v15` record's hash recomputes identically under this generation. The
bump records that the *verdict* changed, not the bytes: `overall_status` and
`findings_status` gain a fifth/third value, `Withdrawn`, for a module whose every
matched advisory has been retracted. A mixture stays `Affected` — one live advisory
decides the axis, and the retracted ones remain visible per finding.

Migration for existing stores: **none.** No store migration and no purge; existing
records verify unchanged. Their `withdrawn_at` is absent, which reads as "the
generation that wrote this never asked", not as "confirmed live" — re-scan to get a
retraction verdict for a coordinate scanned before `v16`. New scans write `v16`.

Consumer impact: `audit --json` gains `vuln_withdrawn` (`vuln_findings` keeps its
existing meaning, retracted advisories included), `context` gains
`findings[].withdrawn_at`, `reachability` gains a `withdrawn` verdict with
`withdrawn_at`, `vuln-scan-diff` gains a `WithdrawnFindings` bucket, and a
CycloneDX SBOM marks a retracted advisory `analysis.state: false_positive` with no
`ratings` block.

## Audit log (`audit.jsonl`)

Append-only JSONL; **no schema migration** is ever required to add an event
type. Every line carries an `event_type` discriminator. The
fact-record line keeps its historical flat layout with `event_type:
"fact_record_written"` added additively; all other events use the generic
`{event_type, timestamp, payload}` envelope. Recognised event types are the
closed set in `internal/audit`.
