# `kanonarion reachability` - CVE reachability

## Synopsis

```
kanonarion reachability <module>@<version> --vuln <id> [flags]   # stored-module query
kanonarion reachability --local <dir> [flags]                    # live local probe
```

## Two modes - and a third concept that shares the word

`reachability` has two modes, and it is easy to confuse them with a third
command that produces the data one of them reads. Keep them distinct:

| Concept | Command | Role |
|---|---|---|
| Producer | `vuln-scan --reachability <walk-id>` | **Computes and persists** a per-finding reachability verdict across a walk. Expensive; needs the call graph. |
| Stored-module query | `reachability <module>@<version> --vuln <id>` | **Reads back** the persisted verdict for one module and one CVE. Never scans or recomputes. |
| Live local probe | `reachability --local <dir>` | Analyses the **working tree** directly - a separate, live analysis, not a query of stored facts. |

> A "not reachable" answer from the **query** is a *read of a prior
> analysis*, not a fresh guarantee. To refresh it, re-run the producer:
> `kanonarion vuln-scan <module>@<version> --reachability`.

The project-scoped vuln views - `audit`, `inspect --gomod`, and
`vuln-scan --gomod/--tool/--project` - now derive their verdict from the **same
project-rooted analysis of the live working tree** that `--local` performs:
one `govulncheck` over the project's real import graph, with findings attributed
per module. So a project scan's `Clean`/`Affected` verdicts are already
project-rooted; `reachability --local` remains the way to inspect the per-CVE
symbol-level detail of that same live analysis.

### Reachability is method-plural

The persisted verdict carries a `method` field. Today the only method is
govulncheck source-mode **call-graph** analysis (a CHA over-approximation).
A future symbol-table probe method may produce verdicts for the same CVEs;
the query reports `method` so probe-derived answers are distinguishable
rather than silently mixed in. Do not read "reachability" as one fixed
algorithm.

## Stored-module query: `--vuln`

`reachability <module>@<version> --vuln <id>` answers, for a single CVE,
whether it is reachable in a module that has already been scanned with
`vuln-scan --reachability`. It is **read-only**: it loads the persisted
finding and reports its verdict and confidence. It never fetches, scans, or
recomputes.

It distinguishes *"not analysed / unknown"* from
*"analysed, genuinely not affected/reachable"*. Exit `0` answers are
confident; an unknown answer is a non-zero, actionable diagnostic that tells
you which command to run - it is never reported as a false "not reachable".

| Result | Exit | Meaning |
|---|---|---|
| `<id> is REACHABLE in <m>@<v>` | 0 | Affected symbol is reachable from an entry point. |
| `<id> affects <m>@<v> but is NOT reachable` | 0 | Affected symbol is present but unreachable. |
| `<m>@<v> is not affected by <id>` | 0 | Module was scanned; this CVE is not among its findings. |
| `… has not been vuln-scanned` | non-zero | No record. Run `vuln-scan <m>@<v> --reachability`. |
| `… ScanFailed` / `… is unscannable` | non-zero | Module could not be scanned; reachability is unknown. |
| `… scanned without --reachability` | non-zero | Findings exist but reachability was not computed. |
| `… reachability is undetermined` | non-zero | Reachability ran but the call graph was unavailable. |

```bash
kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113
kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113 --json
```

JSON shape:

```json
{
  "module": "golang.org/x/text",
  "version": "v0.3.7",
  "vuln_id": "GO-2021-0113",
  "aliases": ["CVE-2021-38561"],
  "summary": "...",
  "verdict": "reachable",
  "confidence": "High",
  "method": "call-graph",
  "example_paths": [["main.main", "golang.org/x/text/...Vuln"]],
  "scanned_at": "2026-06-14T00:00:00Z"
}
```

`--vuln` requires a `<module>@<version>` argument and is mutually exclusive
with `--local`.

## Live local probe: `--local`

`reachability --local <dir>` analyses a local Go workspace and reports, for
each dependency that has stored vulnerability findings, whether any
CVE-affected symbol is actually referenced from the workspace's own code.

It answers the question:

> *"This CVE is in a module I depend on - but does my binary actually call
> the affected function?"*

The command takes a snapshot of all `.go`, `go.mod`, and `go.sum` files
under `<dir>`, type-checks the workspace via `go/packages`, and cross-
references the imported symbols against the call graph and vulnerability
records already in the store. No fetch is performed; populate the store
beforehand with `kanonarion walk` and `kanonarion vuln-scan` for the
modules of interest.

## Workspace resolution

`--local <dir>` uses the `go.mod` at `<dir>` (or, if absent, the nearest
ancestor's). Nested `go.mod` files in subdirectories - for example test
fixtures or sub-modules - are ignored when picking the workspace module
identity; the root `go.mod` always wins. This makes the command safe to
run from the root of a repository that contains fixture modules under
`testdata/` or `test/fixtures/`.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--vuln` | *(empty)* | Vulnerability ID to query (stored-module mode); requires a `<module>@<version>` argument |
| `--local` | *(empty)* | Path to the local Go workspace to probe (live local mode) |
| `--json` | false | Emit output as JSON (global flag) |

Exactly one mode must be selected: either `<module>@<version> --vuln <id>`
or `--local <dir>`.

## Output

JSON shape (text rendering follows the same fields):

```json
{
  "root": "/abs/path/to/workspace",
  "module_path": "github.com/example/app",
  "version_id": "local-<sha256>",
  "probe_kind": "",
  "notice": "<optional diagnostic>",
  "modules": [
    {
      "path": "github.com/some/dep",
      "version": "v1.2.3",
      "findings": [
        {
          "cve_id": "GHSA-xxxx-yyyy-zzzz",
          "aliases": ["CVE-2024-12345"],
          "summary": "...",
          "verdict": "reachable",
          "verdict_source": "callgraph",
          "reason": "<why>",
          "matched_symbols": ["pkg.Symbol"]
        }
      ]
    }
  ]
}
```

`notice` is set when the store has no findings for the analysed dependency
modules - typically because they have not been scanned yet. Because absence is
never presented as an answer, an empty `modules` array with `notice` populated is
*not* the same as "no vulnerabilities reachable"; it means "uncertain".

## Examples

```bash
# Analyse the current workspace
kanonarion reachability --local . --json

# Analyse a project elsewhere on disk
kanonarion reachability --local /path/to/workspace --json | jq '.modules[]'
```

## See also

- [`vuln-scan`](vuln.md) - populate vulnerability findings for a walk
- [`local`](local.md) - ingest the workspace's call graph so
  `callers`/`callees` resolve internal symbols
