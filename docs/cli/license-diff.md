# `kanonarion license-diff` - Licence Relicensing Detection

Compares two stored licence records and reports what changed between them:
SPDX identifier, overall status, licence files added or removed, and
copyright-holder changes. A permissive → copyleft escalation (the Redis,
Terraform, HashiCorp, Sentry pattern) is flagged prominently in both text
and JSON output.

> **Note**: A confident SPDX identification is informational, not legal advice.
> Consult a lawyer for compliance decisions.

## Prerequisites

Both records must be extracted before diffing:

```
kanonarion license github.com/example/lib@v1.0.0
kanonarion license github.com/example/lib@v2.0.0
```

## Usage

```
kanonarion license-diff <module>@<versionA> <module>@<versionB> [--json]
```

The two coordinates can be the same module at different versions (the normal
relicensing case) or different module paths entirely (e.g. comparing an
upstream project with a fork).

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | false | Emit structured JSON diff |
| `--log-level` | `warn` | Log verbosity: `debug`, `info`, `warn`, `error` |

## Examples

```sh
# Spot a relicensing between two minor versions
kanonarion license-diff github.com/hashicorp/terraform@v1.4.0 github.com/hashicorp/terraform@v1.5.0

# Machine-readable output for CI or an agent
kanonarion license-diff github.com/redis/go-redis@v8.11.5 github.com/redis/go-redis@v9.0.0 --json
```

## Text output

When licences differ, `license-diff` prints a change summary. An escalation
line appears at the top when the primary licence moved from permissive to any
stronger copyleft:

```
Diff:  github.com/example/lib@v1.0.0 → github.com/example/lib@v2.0.0

[ESCALATION] MIT → GPL-3.0-only (permissive to strong copyleft)

SPDX:  MIT → GPL-3.0-only

Copyright added (1):
  + Copyright 2023 New Owner Corp

Copyright removed (1):
  - Copyright 2020 Original Author
```

When nothing changed:

```
Diff:  github.com/example/lib@v1.0.0 → github.com/example/lib@v1.0.1
No license changes.
```

## JSON output

`--json` emits a single object with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `module_a` | string | First coordinate (`path@version`) |
| `module_b` | string | Second coordinate (`path@version`) |
| `spdx_changed` | object or null | `{from, to}` when primary SPDX differs |
| `status_changed` | object or null | `{from, to}` when `OverallStatus` differs |
| `files_added` | array | Licence files present in B but not in A - each `{path, spdx}` |
| `files_removed` | array | Licence files present in A but not in B - each `{path, spdx}` |
| `copyright_added` | array of strings | Copyright statements present in B but not in A |
| `copyright_removed` | array of strings | Copyright statements present in A but not in B |
| `escalation` | object or null | `{from, to}` copyleft-strength strings when a permissive → copyleft change is detected |

```json
{
  "module_a": "github.com/example/lib@v1.0.0",
  "module_b": "github.com/example/lib@v2.0.0",
  "spdx_changed": { "from": "MIT", "to": "GPL-3.0-only" },
  "status_changed": null,
  "files_added": [],
  "files_removed": [],
  "copyright_added": ["Copyright 2023 New Owner Corp"],
  "copyright_removed": ["Copyright 2020 Original Author"],
  "escalation": { "from": "none", "to": "strong" }
}
```

## Copyleft escalation

The escalation field is set whenever the primary SPDX transitions from a
**permissive** licence (copyleft strength `none`) to any stronger copyleft:

| Strength | Examples |
|----------|---------|
| `weak` | MPL-2.0, LGPL-2.1-only, LGPL-3.0-only |
| `strong` | GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only |
| `network` | AGPL-3.0-only |

Copyleft → copyleft transitions (e.g. GPL-2.0-only → AGPL-3.0-only) are
reported as an SPDX change but not as an escalation - the dependency was
already copyleft-encumbered. Permissive → permissive transitions (e.g.
MIT → Apache-2.0) produce no escalation flag.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (diff computed, including the no-change case) |
| 5 | One or both licence records not found in the store |
| 1 | Unexpected error |

## Scope notes

- `license-diff` compares two **individual module** records. Walk-level
  diffing (detecting relicensing across an entire dependency closure between
  two walks) is a separate, unimplemented command.
- Both records are loaded at the current pipeline version. A record extracted
  with an older pipeline version will not be found; re-run `kanonarion license`
  to refresh it.

See also: [`licence`](license.md), [`license-compat`](license-compat.md),
[`notice`](notice.md).
