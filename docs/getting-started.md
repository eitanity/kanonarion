  # Getting started - understand an unfamiliar Go project

## Why this matters

A Go project's security and legal surface lives in the dependency graph behind
`go.mod` - the direct and transitive modules, most of which nobody on the team
has read. AI assistants and our own memories work from stale assumptions about
it: versions have moved on, APIs have changed, advisories have been published,
licences differ from what we guess. Code built on those assumptions is wrong in
ways that surface late - in review, in the pipeline, after release - and has to
be redone. Kanonarion turns the dependency graph into current, deterministic,
auditable facts - what you depend on, who published it, under which licence, with
which known vulnerabilities, and whether the vulnerable code is reachable from the
binary you ship - so the code is right before it reaches your pipeline. It is a
developer tool you run while you work, not a pipeline component.

For everyday Go work that is one repeatable analysis, as stable JSON you can
script and compare, in place of hand-rolled `go list` queries and module-cache
spelunking across the whole dependency graph. In a regulated setting (finance, healthcare,
public sector, defence) it is the evidence an auditor asks for - a licence and
policy result for every module, a content-addressed SBOM, an append-only audit
record, and a reproducible vulnerability history - with uncertainty stated as
*unknown*, never concealed. If you ship into the EU, it is the underlying
evidence a process like the Cyber Resilience Act relies on.

> Kanonarion reports facts and clearly qualified inferences, not compliance
> verdicts. It does not certify conformance, and this material is not legal advice.

This guide takes you from a fresh checkout of an unfamiliar Go project to
per-module answers (licences, API surface, vulnerabilities) using only the CLI.
Part 1 is a human walkthrough; Part 2 is a copy-pasteable prompt for an AI agent.
Durations below were measured against kanonarion's own `go.mod` on a developer
workstation; your numbers scale with dependency count and bandwidth, but the
*shape* - slow once, fast forever - is the point.

---

## Part 1 - Human walkthrough

### 0. Prerequisites

- **Go 1.26+** - required to install and run kanonarion; it drives the `go`
  toolchain (`go list`, `go mod download`, `go tool nm`, binary-mode analysis).
- **git** on `PATH` at runtime - fetches are cross-verified against the
  upstream source repository. Without git, fetches still verify against the
  Go checksum database but record an unverified VCS status.
- **govulncheck** on `PATH` - required by the vulnerability scan (used by
  `inspect` and `vuln-scan`); the scan fails fast with an actionable error if
  it is missing. Install with
  `go install golang.org/x/vuln/cmd/govulncheck@latest`.
- Network access for the *first* run only. Everything afterwards is served
  from the local store at `~/.kanonarion`.

### 1. Install kanonarion

```bash
go install github.com/eitanity/kanonarion@latest
```

This puts a `kanonarion` binary on your `PATH` (under `$(go env GOBIN)`, or
`$(go env GOPATH)/bin`). The store root defaults to `~/.kanonarion`, so no
flag is needed for normal use. To use an isolated store - for throwaway
experiments, or to keep several projects side by side - pass
`--store-root <dir>` to any command.

### 2. Populate the store: `inspect`

> **Try one module first.** `kanonarion inspect github.com/spf13/cobra@v1.8.1`
> runs the same pipeline against a single module, finishing in seconds with
> output you can read end to end. Do that once to see the shape of the results
> before pointing kanonarion at a whole project - where the closure can take
> anywhere from seconds to tens of minutes depending on dependency count.

`cd` into the project you want to understand (anywhere with a `go.mod`) and
run every analysis stage:

```bash
kanonarion inspect
```

With no arguments, `inspect` defaults to `--gomod ./go.mod`: it walks the
project's **code-scope build list** in a single project-rooted walk (the
modules your packages actually import, tests included - the same set as
`go list -deps -test ./...`), fetches and verifies each module zip (checksum
database + git cross-verification), extracts licence / public API / call
graph / examples, and scans for vulnerabilities. It finishes with a summary:

```
Status:   AllClean
Modules:  21 (0 failed)
Affected: 0
Snapshot: 2026-06-02T21:39:47Z
Walk ID:  01KTXYAHXB5S7JA9KFKC06NSPF

To get module context: kanonarion context --gomod ./go.mod
```

How to read it: `Status` is the vulnerability roll-up
(`AllClean` / `Affected`), `Affected` is how many modules have findings,
`Snapshot` dates the vulnerability database the scan used (pass `--fresh`
to pull a current snapshot), and the walk ID is the stored dependency
walk you can feed to `walk-show`, `sbom`, or `context --walk-id`. With
`--json` the summary also includes `directives` and `godebug` sections
flagging `replace`/`exclude` directives and `//go:debug` settings in the
project itself - empty lists mean the project was scanned and none were
found. (Every command accepts `--json`; to make it the default, run
`kanonarion config set preferences.json true`.)

**Duration & resources - this is the one slow step.** Measured on the
reference project:

| Run | Measured | What dominates |
|---|---|---|
| First run (empty store) | ~16 min | resolving the require graph (~470 module metadata fetches) and downloading + verifying the 21 build-list zips and extracting; fetching the vulnerability DB snapshot and scanning. Scales with dependency count and bandwidth. |
| Re-run (warm store) | walk ~3 s **+ vuln scan** | The walk/extract stages are cache checks only (every walk logs `cached successful walk exists`), but `inspect` is project-rooted, so the vulnerability scan re-runs `govulncheck` over the live working tree every time - it is never cached (see the `audit` section below for the same behaviour and its ~2 min reference cost). |

These are for the 21-module reference project. Cost scales with closure size,
and not gently. A **large project** measured end-to-end (velociraptor,
**594 modules**): the cold walk took **~7 min** - all 594 modules fetched and
verified concurrently under the default 16 workers (down from ~53 min when the
fetch phase ran sequentially) - and extract → vuln-scan → context another
~36 min, so roughly **45 min** for the first full run, now dominated by the
scan rather than the walk. Tune `walk --workers` for proxy throughput on very
large closures. Plan the first run against your *own* closure size, not the
reference figure.

**Memory.** The first run is memory-intensive: peak resident set was ~2.5 GB on
the reference project. The vulnerability scan dominates - `govulncheck` runs
in source mode and type-checks each module, the heaviest phase. On a
memory-constrained machine or container a scan can be OOM-killed; kanonarion
records that module as `Unscannable` and continues rather than failing the
whole run. Budget ~3-4 GB of RAM **for a small closure like the reference
project** - but RAM scales sharply with closure size and with the largest
single module `govulncheck` must type-check. The 594-module velociraptor run
peaked at **~13 GB**. Provision for *your* closure, not the 3-4 GB reference
figure; under-budgeting does not fail the run, it silently turns scans into
`Unscannable` results. Warm re-runs are cheap.

**Progress output.** During the (long) walk phase, `inspect` prints a
throttled **progress heartbeat** to stderr - about one line every 20 s, e.g.
`walk progress: 142 modules fetched (3m20s elapsed)` - so you can tell a
healthy run from a hang without drowning in per-module output. The heartbeat
goes to stderr only; stdout (and `--json`) is never touched. Suppress it with
`--no-progress` (or `kanonarion config set preferences.progress false`); a warm
re-run shorter than the interval prints nothing at all. For full per-module
detail (`fetch_start`, `fetch_end`, `cache_hit`, extraction lines, and the
vulnerability-snapshot byte-progress line) pass `--log-level info` instead.
Set a generous timeout (e.g. 30 min) and let it finish. Every subsequent
command in this guide is a local SQLite read.

### 3. Per-module context: `context`

```bash
kanonarion context            # all code-scope modules, one summary block per module
```

Bare `context` enumerates the same module set bare `inspect` populated, so
the pair composes: nothing you see here should be unanalysed. For one
module at a time:

```bash
kanonarion context golang.org/x/mod@v0.36.0
```

```
golang.org/x/mod@v0.36.0
  Verification:    Verified (git: https://go.googlesource.com/mod)
  Provenance:      no fork indicators (name-path heuristic, catalogue 1.0.0)
  Dependencies:    1 direct (succeeded)
  License:         BSD-3-Clause
  Interface:       9 package(s), 159 symbol(s) (Extracted)
  Call Graph:      649 nodes, 1844 edges (Extracted)
  Examples:        3 (Found)
  Vulnerabilities: Clean [walk: AllClean]

Context size: ~106 tokens  (use --full for complete docs, --json for machine-readable)
```

With `--json`, each module becomes one NDJSON line carrying the full
AI-ready record - verification, provenance, direct dependencies, licence +
obligations + copyright statements, public interface, call graph, examples,
vulnerabilities - plus a `commands` section listing the exact drill-down
invocation for each section.

**Duration:** ~2 s warm for all 21 modules. **Size warning:** the JSON
form is large (~9 MB for these 21 modules); prefer per-module queries
when feeding an LLM.

### 4. One line per dependency: `audit`

```bash
kanonarion audit
```

One line per module in the code-scope build list: coordinate, verification
status, SPDX licence, version staleness, vulnerability status, policy outcome:

```
github.com/spf13/cobra@v1.10.2     Verified               Apache-2.0    current                        Clean  allow [permissive]
golang.org/x/mod@v0.36.0           Verified               BSD-3-Clause  latest: v0.37.0 (9 days ago)   Clean  allow [permissive]
modernc.org/sqlite@v1.50.1         Verified               BSD-3-Clause  latest: v1.52.0 (11 days ago)  Clean  allow [permissive]
stdlib@v1.26.5                     VerifiedGoDevChecksum   BSD-3-Clause  current                        Clean  allow [permissive]
...
```

The default scope is the code-scope build list - the same set bare `inspect`
populated, direct and transitive together. To widen the scope, `--tool`
audits the tooling supply chain (the `go.mod` `tool` directives' closure) and
`--project` audits the complete set (code + tooling). Statuses like
`ScanFailed` are surfaced in the relevant line, never hidden behind a roll-up.

The report includes the Go standard library as a `stdlib` row, so a toolchain CVE
is triaged like any dependency's. It is verified like one too: its source tarball
is fetched from `go.dev/dl` and checked against Go's published checksum (the
`VerifiedGoDevChecksum` status), with `BSD-3-Clause` read from the tarball itself
- see [the SBOM standard-library chain of custody](cli/sbom.md#standard-library-chain-of-custody).
Its version defaults to the live toolchain (`go env GOVERSION`);
`--stdlib-from-gomod` pins it to the `go.mod` directive instead, making `audit`
and `sbom` reproducible in CI. The release pipeline sets it on both.

**Duration:** dominated by the vuln leg. The vulnerability verdict is
**project-rooted** - one `govulncheck` over the project's live working tree - and
is recomputed fresh every run (the working tree mutates, so it is never served
from a cache), which took ~2 min on the reference project. Walk and licence
columns are cached, but the staleness column is **not**: every run resolves each
module's latest version live from the module proxy (a `@latest` request per
module, ~35 s on the reference project), so a warm `audit` always makes those
outbound calls.

### 5. Drill-downs

All of these are warm-store reads and return in **tens of milliseconds**:

```bash
# Is this dependency's closure licence-compatible? Omitting --target adopts
# the module's own analysed licence. Exit codes: 0 clean, 1 conflicts,
# 2 unknown pairs (human review needed - unknown is never silently "compatible"),
# 4 no root licence record yet (the diagnostic names the command that produces it).
kanonarion license-compat github.com/spf13/cobra@v1.10.2

# Vulnerability record for one module
kanonarion vuln-show golang.org/x/tools@v0.45.0

# Full public API surface of a module
kanonarion interface-show golang.org/x/mod@v0.36.0

# Who calls / what does a symbol call, across every analysed module
kanonarion callers 'github.com/spf13/pflag.NewFlagSet'
kanonarion callees 'github.com/spf13/cobra.(*Command).Execute'
```

### 6. Bring your own code into the graph: `local`

`callers`/`callees` only see analysed modules. To resolve symbols in the
project's *own* packages, ingest the working tree:

```bash
kanonarion local .
kanonarion callers '<module-path>/internal/server.New'
```

**Duration:** ~27 s to analyse this codebase (2,744 functions / 19,022
call edges). Working-tree analysis is recomputed fresh on every run - it is
intentionally never cached, because the tree changes between runs and a stale
graph would be worse than a recomputed one.

Two related working-tree modes hang off `context <dir>`:

```bash
# Which dependency packages/symbols does the working tree actually use?
kanonarion context . --symbol        # symbol-level, go/packages type-check
                                     # (<1 s with a warm Go build cache; ~1 min
                                     #  fully cold - it type-checks the project)

# Are any stored CVE findings reachable from this tree?
kanonarion context . --reachability
```

`--reachability` is near-instant when the store holds no findings for the
analysed dependencies (measured 0.6 s here) - it then prints a notice
telling you which command would populate findings. When findings exist it
probes the binary for the affected symbols, which takes on the order of
30 s (the command's own estimate; this project had no findings to probe).

### 7. Reading `not_run` / `not_fetched`: unknown is not zero

kanonarion never presents *absence of analysis* as a confident negative.
Every `context` section always exists in the output and carries a status;
queries over unanalysed data exit non-zero with a diagnostic naming the
command that would analyse it, e.g.:

```
error: execute root command: symbol "github.com/pkg/errors.Wrap" is not in
the call-graph store: its module has not been analysed (consumer-mode code).
Analyse it first, e.g.:
  kanonarion callgraph <module>@<version>
```

| Status | Meaning | What to run next |
|---|---|---|
| `not_fetched` | Module has never been fetched into the store | `kanonarion fetch <mod>@<ver>` (or `inspect <mod>@<ver>` to run every analysis stage) |
| `not_run` | Module is fetched but this extraction stage hasn't run | `kanonarion extract <walk-id>`, or the stage command (`license`, `interface`, `callgraph`, `examples`) |
| `read_error` | The store returned an error reading the record | Check the `error` field; `kanonarion store` to inspect the store |
| Empty list + status `succeeded` | Analysed, genuinely zero results | Nothing - this is a real answer |

The distinction matters: an empty `vulnerabilities` list under
`"status": "not_run"` means *we haven't looked*, not *there are none*.

---

## Part 2 - Suggested agent prompt

Paste the block below into an agentic coding session (Claude Code, etc.)
working on a Go project. It is self-contained.

````text
When answering questions about this Go project's dependencies - licences,
vulnerabilities, API surfaces, call graphs, who-uses-what - use the
`kanonarion` CLI instead of `go list`, `go mod graph`, scraping the module
cache, or answering from memory. Always pass `--json` and parse the output.
Run commands from the project root (the directory containing go.mod).

One-time population (network-bound; measured ~16 minutes on a mid-sized
project (21 modules), and memory-intensive - budget ~3-4 GB of RAM for a
closure that size, but BOTH scale sharply with closure size: a 594-module
project measured ~1.5 h and ~13 GB peak. Set the timeout and memory limit
from YOUR closure size, generously, e.g. 30+ minutes, and do NOT kill it. It
prints a throttled
progress heartbeat to stderr during the walk phase (about one line every 20s,
e.g. `walk progress: 142 modules fetched (3m20s elapsed)`); read stdout for the
result. A gap between heartbeats is normal, not a hang. Use `--no-progress` to
silence the heartbeat, or `--log-level info` for full per-module detail).
Re-runs on a warm store take seconds:

    kanonarion inspect --json                      # heartbeat on stderr; --no-progress to silence, --log-level info for detail

Then answer questions from these (all local reads, warm timings for an
11-direct-dep project):

    kanonarion context --json                      # per-module full context, NDJSON, ~2s (large: ~9MB)
    kanonarion context <module>@<version> --json   # one module, ~20ms
    kanonarion audit --json                        # one line per build-list module: licence/vuln/staleness,
                                                   # ~6s warm (first run after inspect ~35s: network staleness lookups)
    kanonarion license-compat <module>@<version> --json   # exit 0 clean / 1 conflicts / 2 unknown pairs / 4 no root record
    kanonarion vuln-show <module>@<version> --json
    kanonarion interface-show <module>@<version> --json
    kanonarion callers '<pkg.Symbol>' --json
    kanonarion callees '<pkg.Symbol>' --json
    kanonarion local . --json                      # ingest working tree so callers/callees resolve
                                                   # internal symbols (~27s; recomputed fresh each run, never cached)
    kanonarion context . --symbol --json           # which dep symbols the working tree uses, seconds
    kanonarion context . --reachability --json     # are stored CVE findings reachable (~30s when probing;
                                                   # instant + notice when no findings are stored)

Interpretation rules - these are load-bearing:

1. Unknown is not zero. A context section with "status": "not_run" or
   "not_fetched" means the analysis has not happened, NOT that the result
   is empty. Never report "no vulnerabilities" / "no licence issues" from
   a not_run/not_fetched section. Run the command the status implies
   (not_fetched → fetch/inspect the module; not_run → extract) and re-query.
2. Queries over unanalysed data exit non-zero and print which command to
   run. Run that command, then re-run the query. An empty result with
   exit 0 over analysed data is a genuine zero - report it as such.
3. license-compat exit code 2 means licence pairs outside the modelled
   dataset: report "needs human review", never "compatible".
4. kanonarion reports facts and caveated inferences, not verdicts. Relay
   its statuses; don't upgrade them to judgments it didn't make.
````

---

## Where to go next

- [`docs/cli/reference.md`](cli/reference.md) - index of every command's
  reference page.
- [`docs/cli/conventions.md`](cli/conventions.md) - output conventions,
  exit codes, configuration layering, store discovery.
- [`docs/cli/context.md`](cli/context.md) - full schema of the context
  output used throughout this guide.
