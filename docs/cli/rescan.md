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
| `--go-binary` | _(from `PATH`)_ | Path to the `go` binary if not on `PATH` (used by on-demand callgraph extraction) |
| `--operator` | `$USER` | Operator name recorded in the scan run |
| `--snapshot-source` | _(fresh)_ | Pin to a specific snapshot source (requires `--snapshot-version`) |
| `--snapshot-version` | _(fresh)_ | Pin to a specific snapshot version (requires `--snapshot-source`) |
| `--policy` | _(search upward for `.kanonarion/policy.yaml`)_ | Path to depth policy YAML |
| `--no-progress` | `false` | Suppress stderr progress output (the throttled heartbeat and any per-module progress lines); results and warnings are unaffected |
| `--log-level` | `warn` | Log level: `debug\|info\|warn\|error` |

**The build a re-scan re-evaluates**

Before the run starts, `vuln-scan-rescan` states on **stderr** the build the
named walk was resolved in, and that the run is re-evaluating that recorded
build:

```
build:
  linux/amd64 under go1.26.6
  a re-scan re-evaluates that recorded build against fresh advisories; it does not re-resolve the toolchain, so this run answers for the build above and not for the one a walk taken now would record
```

Where the project the walk was taken from is still present and `go env
GOVERSION` there no longer resolves the recorded toolchain, a line names both
versions. A re-scan is what an operator reaches for when they want a *dated*
statement, and the date is the only thing it refreshes — the standard library
the answer is about is the walk's, not the host's. To answer for the toolchain
standing here now, take a fresh walk (`kanonarion walk --gomod ./go.mod`) and
scan that instead.

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

A re-scan forces every module in the walk through the scanner, so it narrates as
it goes. The narration — the opening line and one line per module, in the same
format `vuln-scan` uses — goes to **stderr**; the result goes to **stdout**.
Redirecting stdout gives the result alone.

```
$ kanonarion vuln-scan-rescan 01KQDBVW092ER1HNXZ60X27CMD
Re-scanning walk 01KQDBVW092ER1HNXZ60X27CMD...          # stderr
  [1/3] github.com/gin-gonic/gin@v1.6.2 — Affected      # stderr
  [2/3] github.com/spf13/cobra@v1.8.1 — Clean           # stderr
  [3/3] golang.org/x/net@v0.0.0-20210405180319 — Clean  # stderr
Re-scan completed: Complete, Affected (2)               # stdout
Run ID: vscan-01KQDBVW092ER1HNXZ60X27CMD-1711929600     # stdout
Snapshot: osv.dev/go@v2024-04-01T00-00-00               # stdout
```

`--no-progress` silences the opening line and the per-module lines. Warnings,
diagnostics and the result are unaffected, so a silenced run still says what went
wrong.

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
- **WITHDRAWN** - findings that stopped standing for a stated reason: the advisory was
  retracted upstream. Reported with the retraction date, and never as a fix.
- **RESOLVED** - findings present in run A but not in run B, for which no reason is
  recorded. It is deliberately not called "fixed": within one coordinate the module
  version cannot have moved between the two runs, so a finding that simply stops
  being reported is an unattributed disappearance.
- **REACHABILITY changes** - findings present in both runs whose reachability determination changed.

WITHDRAWN is the attributed half of what used to fall wholesale into RESOLVED, and it
is the reason that bucket could not be trusted: "upstream fixed it", "we upgraded" and
"the report was withdrawn" all read the same there. Two shapes reach it — a finding both
runs report where only B's copy carries the retraction timestamp (the withdrawal landed
between the runs), and a finding absent from B whose A-side copy already recorded it.

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

WITHDRAWN advisories (1) — retracted upstream, not fixed:
  ! GO-2024-8888  github.com/some/lib@v1.2.3  withdrawn 2024-04-08T13:33:56Z  WITHDRAWN: out-of-range-index

RESOLVED findings (1) — no longer reported, no reason recorded:
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
- **A re-scan reproduces the analysis frame or refuses.** A re-scan is asked for
  the same evidence against a newer advisory database; answering in a different
  frame is not a narrower answer, it is an answer to another question. If the run
  being re-scanned was rooted at a project's working tree and this machine cannot
  reach that tree, `vuln-scan-rescan` exits with a configuration error naming the
  project-rooted form to run instead — it does not silently re-derive every
  module in isolation, where an isolated *not reachable* would then outrank the
  consumer's route. The frame is read from the run's own records, not only from
  the walk's provenance: a walk that records no directory may still have been
  scanned project-rooted, because the scan can be pointed at a tree directly
  (`--gomod`, `--project`, `kanonarion local`).
- `vuln-scan-diff` requires both run IDs to belong to the same walk; diffing runs
  from different walks is an error.
- Snapshot pinning (`--snapshot-source` / `--snapshot-version`) is useful for
  reproducing a prior scan exactly. Use `vuln-snapshot-list` to enumerate stored
  snapshots.
