# Vulnerability Re-Scanning

Re-scanning re-runs the vulnerability scanner for an existing walk against a
fresh (or explicitly pinned) database snapshot. It answers the question: *"A
new CVE dropped - what in this walk is now at risk?"*

Re-scanning never modifies prior scan runs. Each re-scan appends a new
`WalkScanRun` record, preserving the full audit trail.

---

## Commands

### `vuln-scan-rescan`

Re-scan an existing walk against a fresh vulnerability database snapshot.

```
kanonarion vuln-scan-rescan <walk-id> [flags]
```

**Flags**

| Flag | Default | Description |
|---|---|---|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--reachability` | `false` | Enable call-graph reachability analysis |
| `--operator` | `$USER` | Operator name recorded in the scan run |
| `--snapshot-source` | _(fresh)_ | Pin to a specific snapshot source (requires `--snapshot-version`) |
| `--snapshot-version` | _(fresh)_ | Pin to a specific snapshot version (requires `--snapshot-source`) |
| `--log-level` | `warn` | Log level: `debug\|info\|warn\|error` |
| `--log-json` | `false` | Emit logs as JSON |

**Examples**

```bash
# Re-scan against the latest vulnerability database snapshot
kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

# Re-scan with reachability analysis
kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD --reachability --store-root ~/.kanonarion

# Re-scan against a previously stored snapshot (for reproducibility)
kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD \
  --snapshot-source osv.dev/go \
  --snapshot-version v2024-03-01T00-00-00 \
  --store-root ~/.kanonarion
```

**Output**

```
Re-scanning walk 01KQDBVW092ER1HNXZ60X27CMD...
Re-scan completed with status: Affected
Run ID: vscan-01KQDBVW092ER1HNXZ60X27CMD-1711929600
Snapshot: osv.dev/go@v2024-04-01T00-00-00
```

---

### `vuln-scan-history`

List every scan run for a walk in chronological order, with finding counts and
snapshot identities.

```
kanonarion vuln-scan-history <walk-id> [flags]
```

**Flags**

| Flag | Default | Description |
|---|---|---|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit records as JSON |

**Examples**

```bash
kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD --json --store-root ~/.kanonarion
```

**Output**

```
RUN ID                      STATUS        SNAPSHOT                        COMPLETED
vscan-01KQ...-1709251200    AllClean      osv.dev/go@v2024-03-01T00...    2024-03-01T00:01:00Z
vscan-01KQ...-1711929600    Affected      osv.dev/go@v2024-04-01T00...    2024-04-01T00:01:00Z
```

---

### `vuln-scan-diff`

Compare two scan runs of the same walk and report:

- **NEW** - findings present in run B but not in run A (newly known vulnerabilities).
- **RESOLVED** - findings present in run A but not in run B (no longer known, typically because the database revised them).
- **REACHABILITY changes** - findings present in both runs whose reachability determination changed.

```
kanonarion vuln-scan-diff <run-id-a> <run-id-b> [flags]
```

**Flags**

| Flag | Default | Description |
|---|---|---|
| `--store-root` | `~/.kanonarion` | Path to fact store root |
| `--json` | `false` | Emit diff as JSON |

**Examples**

```bash
kanonarion vuln-scan-diff vscan-01KQ...-1709251200 vscan-01KQ...-1711929600 \
  --store-root ~/.kanonarion

kanonarion vuln-scan-diff vscan-01KQ...-1709251200 vscan-01KQ...-1711929600 \
  --json --store-root ~/.kanonarion
```

**Output**

```
Diff: vscan-01KQ...-1709251200 → vscan-01KQ...-1711929600
Walk: 01KQDBVW092ER1HNXZ60X27CMD

NEW findings (2):
  + GO-2024-1234  github.com/some/lib@v1.2.3  Use of unsafe pointer arithmetic
  + GO-2024-1235  github.com/other/pkg@v0.9.0  Integer overflow in parser

RESOLVED findings (1):
  - GO-2023-9999  github.com/old/dep@v2.0.0  Path traversal in file handler
```

---

## Typical workflow

```bash
# 1. Initial scan after ingesting a target
kanonarion walk github.com/myorg/myapp@v1.0.0 --store-root ~/.kanonarion
kanonarion extract --store-root ~/.kanonarion
kanonarion vuln-scan 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

# 2. A new CVE drops - re-scan against the latest database
kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion

# 3. See what changed
kanonarion vuln-scan-history 01KQDBVW092ER1HNXZ60X27CMD --store-root ~/.kanonarion
kanonarion vuln-scan-diff <run-id-a> <run-id-b> --store-root ~/.kanonarion

# 4. Inspect a specific new finding (walk-id optional; defaults to most recent scan)
kanonarion vuln-show github.com/some/lib@v1.2.3 --store-root ~/.kanonarion

# 4a. See whether the finding existed in older scans
kanonarion vuln-show github.com/some/lib@v1.2.3 --history --store-root ~/.kanonarion
```

---

## Notes

- `vuln-scan-rescan` always bypasses the per-module cache so the new snapshot is
  actually consulted. It is equivalent to `vuln-scan --force` but with an
  explicit fresh snapshot fetch.
- Prior scan runs are never modified. Storage grows with each re-scan; a
  retention policy is outside Phase 3 scope.
- `vuln-scan-diff` requires both run IDs to belong to the same walk; diffing runs
  from different walks is an error.
- Snapshot pinning (`--snapshot-source` / `--snapshot-version`) is useful for
  reproducing a prior scan exactly. Use `vuln-snapshot-list` to enumerate stored
  snapshots.
