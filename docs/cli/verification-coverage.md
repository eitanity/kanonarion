# `kanonarion verification-coverage` - Aggregate verification coverage for a walk

`verification-coverage` reports how the modules in a stored walk were verified:
how many carry the strongest assurance available - a checksum-database match
cross-verified against the content of the module's VCS commit - how many
degraded to a weaker anchor, and how many carry none at all.

`walk` and `audit` already print this aggregate to **stderr** as a side report
at the end of a run. This command reports the same figures on their own, from a
stored walk, and emits them under stable field names with `--json` so a CI gate
can assert on them.

## Why the figures exist

A whole-graph collapse in cross-verification is invisible in a populated status
column: every row reads `VerifiedBySumDBOnly`, no warning is raised, and the
exit code is `0`. The condition is only discoverable by reading every row.

The causes are ordinary operational ones:

- `GOPROXY` pointing at a proxy that does not publish `Origin` metadata;
- an egress rule blocking a forge, so every VCS checkout fails;
- `--skip-vcs-verify` left set in a CI job;
- `GOPROXY=off`, which refuses the `git` subprocess for the same reason it
  refuses a fetch, and is counted the same way;
- a policy whose `allowed_vcs_hosts` is narrower than the forges the graph
  actually resolves to.

Each silently converts the strongest assurance the pipeline offers into a weaker
one, across an entire dependency graph.

**No host is named and no proxy is judged.** The signal is coverage, not the
identity or provenance of a proxy. A proxy allowlist would catch one of the four
causes above, would age badly, and would require maintaining a list with
geopolitical content; a coverage figure catches all four without naming
anything.

## Usage

```
kanonarion verification-coverage <walk-id> [--json]
```

The walk id is one `kanonarion walk-list` prints. An `audit` run leaves its
project walk behind, so the walk this command reports on is the same graph the
audit reported on.

## Coverage classes

The classes partition the graph - every module lands in exactly one.

| Class | Meaning |
|-------|---------|
| `cross_verified` | Checksum database **and** the content of the module's VCS commit both matched. The strongest assurance. |
| `checksum_db_only` | Authentic with respect to the transparency log, with no VCS anchor. **This is the class a collapse lands in.** |
| `go_sum_only` | Matched a local `go.sum` with no live checksum-database query - a positive offline signal, weaker than the log itself. |
| `unverified` | No anchor was established, for any reason. The reasons differ in what to do about them, not in how much assurance they carry. |
| `local_source` | Built from a local source tree (the main module, a local-path replace). There is no remote artefact to cross-verify, so this is neither assurance nor a gap. |
| `unrecorded` | In the graph, with no fetch record found. Absence of a measurement, not a failed one. |
| `unrecognised` | A verification status this mapping has never heard of. It lands here rather than being folded into a class it may not belong to. |

`cross_verifiable` is the honest denominator: the recorded modules that are not
local source. Measured against `total`, a project walk would report a shortfall
for its own main module, which has no remote artefact to anchor.

`collapsed` is `true` when a graph had something to cross-verify and none of it
was. It is derived in the output so every gate agrees on what a collapse is.

## VCS evidence

The `vcs` figures answer a different question from the classes above: not how
strong the assurance is but how fresh it is, and whether the fetch ledger can
speak to it at all.

| Field | Meaning |
|-------|---------|
| `rechecked` | This measurement performed the VCS check itself. |
| `inherited` | Carried forward from an earlier measurement of the same artefact, which the record names. The module **is** backed by cross-verification evidence; this run simply did not re-establish it. |
| `never` | The record was written under the ledger, could have recorded a VCS leg, and has none. The only class where no cross-verification evidence exists. |
| `not_measured` | The record predates the ledger and carries no legs at all. **Not** the same as `never`: the check may well have run, the record simply cannot say. A gate that treats the two alike calls an unmigrated store a collapse. |

## JSON output

The field names are a published contract.

```
kanonarion verification-coverage 01KQDBVW092ER1HNXZ60X27CMD --json
```

```json
{
  "walk_id": "01KQDBVW092ER1HNXZ60X27CMD",
  "total": 412,
  "recorded": 412,
  "cross_verifiable": 411,
  "cross_verified": 0,
  "checksum_db_only": 400,
  "go_sum_only": 0,
  "unverified": 11,
  "local_source": 1,
  "unrecorded": 0,
  "unrecognised": 0,
  "collapsed": true,
  "vcs": {
    "rechecked": 0,
    "inherited": 0,
    "never": 400,
    "not_measured": 0
  }
}
```

Every count is emitted even when zero: a gate asserting `cross_verified == 0`
must be able to distinguish a graph with no cross-verification from a document
where the field was omitted.

## Flags

Only global flags apply.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit the aggregate as a JSON document |
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--log-level` | `warn` | Log level: `debug`/`info`/`warn`/`error` |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success - including a collapsed graph. Coverage is reported, not enforced; the gate is the caller's to write. |
| `4` | No walk record with that id |
| `10` | The walk record failed its integrity check |
| `20` | The store could not be opened |

## Examples

Fail a CI job when cross-verification has collapsed across the graph:

```
kanonarion verification-coverage "$WALK_ID" --json | jq -e '.collapsed | not'
```

Require that at least 95% of the modules where cross-verification applies carry
a VCS anchor:

```
kanonarion verification-coverage "$WALK_ID" --json |
  jq -e '.cross_verified / .cross_verifiable >= 0.95'
```

## See also

- [`kanonarion walk`](walk.md) - produce the walk this reports on; prints the
  same aggregate to stderr at the end of a run
- [`kanonarion audit`](audit.md) - prints the same aggregate to stderr over the
  modules it audited
- [`kanonarion fetch`](fetch.md) - where a module's verification status and its
  validation legs are established
