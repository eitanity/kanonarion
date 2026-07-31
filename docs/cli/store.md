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

### `kanonarion store config show`

Show the effective configuration for this store (the resolved settings the
CLI will use for the given `--store-root`).

```
kanonarion store config show [--store-root <dir>] [--json]
```

## Flags

These commands take no command-specific flags; only the global flags apply:

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit output as JSON (`info`, `config show`) |
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
```

## See also

- [`kanonarion policy`](policy.md) - inspect and validate depth policy files
- [`kanonarion walk`](walk.md) - populate the store with walk records
