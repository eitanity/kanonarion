# `kanonarion store` - Store inspection & maintenance

`store` inspects and maintains the kanonarion store (the `mirror.db` SQLite
database, the content-addressed blob directory, and the audit log) rooted at
`--store-root` (default `~/.kanonarion`). It is a CLI-only utility, not a
bounded context.

## Commands

### `kanonarion store info`

Report the store schema version and migration status (the per-module
migration versions recorded in the shared `schema_migrations` table).

```
kanonarion store info [--store-root <dir>] [--json]
```

Status is one of:

| Status | Meaning |
|---|---|
| `ok` | Every migration this binary knows is applied |
| `pending (N of M migrations applied)` | The store is behind this binary; the next command that writes will migrate it |
| `newer` | The store carries migrations this binary does not know, listed under `unknown` |

`newer` means the store was last written by a newer build of kanonarion. Every
command that writes refuses to run against it (exit 20 — see
[`conventions.md`](conventions.md#store-schema-newer-than-the-binary)); upgrade
kanonarion. This command is the exception, because it opens the store without
applying migrations and never writes — so it still answers for a store the rest
of the CLI will not touch.

### `kanonarion store clean`

Remove orphaned temporary files left behind by interrupted operations (e.g. a
fetch or extraction killed mid-write). Persisted records and blobs are not
touched.

```
kanonarion store clean [--store-root <dir>]
```

### `kanonarion store ledger`

List the events in the store's append-only assurance log (`audit.jsonl`), in
chronological order.

```
kanonarion store ledger [--since <RFC3339>] [--until <RFC3339>]
                        [--module <path>] [--event-type <type>]
                        [--limit <n>] [--offset <n>] [--store-root <dir>] [--json]
```

Every reading states three things besides the events themselves:

| Statement | Why it is there |
|---|---|
| **coverage** — the ledger's first and last event | Distinguishes "no event in this window" from "the ledger never spanned this window". Only the first supports a claim that nothing happened. An empty ledger reports `coverage: none` |
| **unreadable** — the count and line numbers of lines that could not be read | A torn line is reported and skipped, never dropped silently and never fatal. When one falls inside the window queried, the matched count is additionally flagged as a lower bound for that window |
| **not witnessed** — the persisted record kinds that append no event at all | Silence in the log is not proof that nothing happened; see below |
| **why this reading is empty** — stated only when nothing matched | Names the filter that emptied it: a module path no event names, a version no event carries for a path several events do, a window outside the ledger's coverage, an event type the log holds none of, or filters that each match events but never the same one |

The command is read-only: it opens no database, applies no migration, and never
writes to the ledger.

#### Which question a query answers

The log carries two kinds of event and they answer different questions:

- **when did we first learn X** — the *derivation* events (`fact_record_written`,
  `vuln_finding_observed`, `license_extracted`, `walk_completed`, …). Each dates
  a measurement.
- **when did we last check X** — the *served* events (`vuln_scan_served`,
  `sbom_served`). Each dates an asking that was answered from the store without
  re-measuring. A scan that reuses a stored run measures nothing, so without
  these the last check is invisible.

#### What the ledger does not witness

These are persisted and append no event, so their absence from a query is not
evidence they did not happen:

- individual vulnerability record generations — a walk scan *counts* them
  (`vuln_scan_completed`) and names each finding (`vuln_finding_observed`), but
  no event names a per-module verdict, and a Clean generation is only an
  increment. A single-module scan names no generation either, and appends only
  the advisory snapshot it acquired, if it acquired one. Enumerating
  generations is a store query (`vuln-scan-show`), not a ledger query.
- attestations — additive provenance recorded beside a fact record.
- latest-version (staleness) ledger entries.
- blob content writes — `fact_record_written` names the blob identity; the write
  of the bytes appends nothing.
- directive, GODEBUG and FIPS scans that found nothing — those events are
  emitted per finding, so a clean scan writes a record and appends no event.

#### Filters

| Flag | Effect |
|---|---|
| `--since` / `--until` | Restrict to a time window (RFC3339, inclusive). An unparseable or inverted bound is refused |
| `--module` | Restrict to events naming this module. Takes a path (`example.com/mod`) or a coordinate (`example.com/mod@v1.2.3`). The path is matched against the `module`, `module_path` (the flat fact-record layout) and `project` (directive/GODEBUG/FIPS/vendor) fields; a coordinate additionally requires the version, matched against `module_version` and `version` for the events that carry one. An event that names the module and no version still matches. A value that is neither form (`@v1.2.3`, `example.com/mod@`) is refused |
| `--event-type` | Restrict to one event type, e.g. `vuln_finding_observed`. A name that is neither an event type this build emits nor one the ledger in hand holds is refused, and the accepted set is named; `--help` lists it |
| `--limit` | List at most N events (0 = unlimited). The matched count is still the full total, and the output says it was truncated |
| `--offset` | Skip this many **matched** events before listing, so paging composes with the filters rather than re-scoping them. The output states how many were stepped over |

Because events come back in chronological order, `--limit 1` is the
first-awareness query:

```
kanonarion store ledger --event-type vuln_finding_observed \
  --module github.com/golang-jwt/jwt/v4 --limit 1
```

### `kanonarion store config show`

Show the effective configuration for this store (the resolved settings the
CLI will use for the given `--store-root`).

```
kanonarion store config show [--store-root <dir>] [--json]
```

## Flags

Only `ledger` takes command-specific flags (listed above). The global flags
apply to every subcommand:

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit output as JSON (`info`, `config show`, `ledger`) |
| `--log-level` | `warn` | Log level: `debug`/`info`/`warn`/`error` |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `20` | Any error (e.g. store root unreadable, migration check failed) |

## Examples

```
kanonarion store info --store-root ~/kanonarion/.mirror
kanonarion store config show
kanonarion store clean
kanonarion store ledger --since 2026-07-23T00:00:00Z --until 2026-07-24T00:00:00Z
kanonarion store ledger --event-type vuln_scan_served --json
```

## See also

- [`kanonarion policy`](policy.md) - inspect and validate depth policy files
- [`kanonarion walk`](walk.md) - populate the store with walk records
