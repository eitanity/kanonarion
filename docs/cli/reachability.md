# `kanonarion reachability` - CVE reachability

## Synopsis

```
kanonarion reachability <module>@<version> --vuln <id> [--walk-id <id> | --gomod [path]] [flags]   # stored-module query
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
> analysis*, not a fresh guarantee. To refresh it, re-run the producer. Note
> the grammar: `vuln-scan`'s positional argument is a **walk id**, never a
> coordinate. The coordinate form is the `--module` flag:
>
> ```bash
> kanonarion walk <module>@<version>
> kanonarion vuln-scan --module <module>@<version> --reachability
> ```

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

### Which build the answer is about

A stored verdict is a verdict about one build. Name the build:

- `--walk-id <id>` answers in the frame of that walk's scans, restricted to the
  records that walk covered.
- `--gomod [path]` does the same for the newest succeeded project walk of that
  `go.mod`; the valueless form means `./go.mod`. Mutually exclusive with
  `--walk-id`, and rejected alongside `--local`, which measures the tree it is
  given.

Either flag prints a `notice:` line naming the walk and its frame above the
answer, and the verdict names its rooting as it always has.

With neither flag, and the coordinate present in more than one consumer's build,
the query **refuses** (exit 20) and names the frames it found plus the flags
that select one:

```
$ kanonarion reachability github.com/golang-jwt/jwt/v4@v4.5.1 --vuln GO-2025-3553
error: the store holds github.com/golang-jwt/jwt/v4@v4.5.1 in 2 consumer frames, and this question names none:
  target-rooted:github.com/cortezaproject/corteza/server@local
  target-rooted:github.com/tmc/langchaingo@v0.1.14
name the build you mean: kanonarion reachability … --walk-id <walk of that build>, or … --gomod <path/to/go.mod>
```

One project's scans in the store leave nothing to disambiguate, and the query
answers as before. A pinned walk that covered the module but holds no record in
its own frame is refused (exit 4) naming that walk — never answered from another
build's record.

It distinguishes *"not analysed / unknown"* from
*"analysed, genuinely not affected/reachable"*. Exit `0` answers are
confident; an unknown answer is a non-zero, actionable diagnostic that tells
you which command to run - it is never reported as a false "not reachable".

| Result | Exit | Meaning |
|---|---|---|
| `<id> is REACHABLE in <m>@<v>` | 0 | Affected symbol is reachable from an entry point. |
| `<id> affects <m>@<v> but is NOT reachable` | 0 | Affected symbol is present but unreachable. |
| `<id> affects <m>@<v> at PACKAGE level; symbol-level reachability is not determined` | 0 | The advisory names no symbols for this module path, so there is no symbol for a route to reach. The module **is** affected. |
| `<id> was WITHDRAWN upstream <date>` | 0 | The advisory was retracted upstream; the module is not affected by it. |
| `<m>@<v> is not affected by <id>` | 0 | Module was scanned; this CVE is not among its findings. |

The `withdrawn` verdict is answered **before** reachability is consulted, and is its
own verdict rather than a flavour of "not reachable". Whether anything calls the
symbol does not matter for an advisory that no longer stands, and answering "not
reachable" would offer reachability as the mitigation — inviting the reader to
conclude the module would be at risk if only something called it, when there is
nothing to be at risk from. For the same reason the two "run this command" errors
below are never raised for a retracted advisory: it needs no call graph.

The `package_level_only` verdict is its own answer for the same kind of reason. An
OSV entry may name the affected symbols for one major-version path and none for
another; where the matched entry names none, govulncheck treats the whole package
as vulnerable and the only trace it can report is the package's own `init` running
— which follows from the package being linked into the build, not from anything
calling the vulnerable code. That is neither `reachable` nor `not_reachable`, and
it is not fixed by computing a call graph, so it is answered before the
"run this command" diagnostics rather than through them.
| `… has not been vuln-scanned` | non-zero | No record. Walk the module, then scan that walk. |
| `… ScanFailed` / `… is unscannable` | non-zero | Module could not be scanned; reachability is unknown. |
| `… scanned without --reachability` | non-zero | Findings exist and the scan was rooted elsewhere, so the flag was genuinely not passed. |
| `no reachability route … it was rooted at <coord>` | non-zero | The scan **did** run with reachability, but the module was its own root. See below. |
| `… reachability is undetermined` | non-zero | Reachability ran but the call graph was unavailable. |

Every one of these refusals prints the commands that carry out its remedy, and
each printed line is a whole invocation the CLI accepts as written.

### A module rooted at itself has no consumer route

A finding with no reachability answer has more than one cause, and they take
opposite remedies. The refusal reads the cause off the record's analysis frame
rather than assuming one.

When the newest scan of a coordinate was rooted at **that same coordinate** —
a `walk <module>@<version>` followed by `vuln-scan --module … --reachability`
produces exactly this — the module is the analysis's own main module. Version-
range advisory matching never fires on a main module, so the finding is
attributed by coordinate, and there is no consumer above it for a route to
start from. The tool declines to fabricate one.

Re-scanning the module cannot help however it is invoked. Only a scan rooted at
the consuming project can produce a consumer route:

```bash
kanonarion walk --gomod ./go.mod
kanonarion vuln-scan --gomod ./go.mod --reachability
kanonarion reachability --local .
```

### Root classification

A route says a path exists. It does not say what starts the path, and a route
rooted at an HTTP handler, at a test helper, and at an exported function nothing
in the project calls were all reported the same way. Every route now reports what
sits at its **root**, read from the stored call graph the answer was computed
over — the test axis, the exported-API flag, and the edges into the node.

| Kind | Means |
|---|---|
| `ingress` | The root is entered from outside the module's own call structure: an `http.Handler` implementation, the process entry point, a package initialiser, or a function a dependency calls back into. The `reason` says which. |
| `exported-api` | The root is exported by the analysed module and called by nothing in it. A consumer could drive it; this project does not. |
| `internal` | The root has in-project callers and is not itself an entry point — the route begins where the analyser stopped, not where execution starts. The `remedy` names the `kanonarion callers` query that walks the hops above it. |
| `test` | The root is a test-scope declaration. This is printed **on the same line as the verdict**, so a test-only reach is never read as a production one. |
| `unrooted` | The graph could not say, with the reason named — no call graph stored for the module, a graph analysed at a fidelity that holds no nodes, or an entry point that is not a node in it. |

Two rules keep this honest:

- **It is not an exploitability claim.** Naming the root kind is a measurement;
  "exploitable" is a judgement about data flow that kanonarion does not make and
  this classification does not introduce. Taint analysis is out of scope. The
  classification is reported **alongside** the verdict and never overrides it: a
  reachable finding whose root is `exported-api` is still reachable.
- **A closure-rooted route says so.** Where the analysis was not rooted at an
  application — an isolated scan, or a `--gomod` walk that roots at the dependency
  closure — the answer carries `closure_rooted` and the command that would root it
  at the application, instead of presenting a dependency's own entry point as the
  project's.

The classification is **derived at read time**, not stored: the facts it reads
live in the call-graph ledger, so an answer improves as the graph does and no
re-scan is owed for it.

```bash
kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113
kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113 --json
```

JSON shape:

```json
{
  "module": "example.com/dep",
  "version": "v1.2.0",
  "vuln_id": "GO-2026-0001",
  "aliases": ["CVE-2026-00001"],
  "summary": "...",
  "verdict": "reachable",
  "confidence": "High",
  "method": "govulncheck",
  "fidelity": "source",
  "rooting": "target-rooted:example.com/app@local",
  "routes": [
    {
      "versioned": true,
      "frames": [
        {"module": "example.com/app", "package": "example.com/app/pkg/apigw", "receiver": "*apigw", "symbol": "ServeHTTP"},
        {"module": "example.com/dep", "version": "v1.2.0", "package": "example.com/dep", "receiver": "*handler", "symbol": "ServeHTTP"}
      ],
      "root": {
        "kind": "ingress",
        "reason": "an http.Handler implementation (method named ServeHTTP) — an HTTP server invokes it per request",
        "node_id": "example.com/app/pkg/apigw.(*apigw).ServeHTTP"
      }
    }
  ],
  "route_root": {
    "kind": "ingress",
    "reason": "an http.Handler implementation (method named ServeHTTP) — an HTTP server invokes it per request",
    "node_id": "example.com/app/pkg/apigw.(*apigw).ServeHTTP"
  },
  "scanned_at": "2026-06-14T00:00:00Z"
}
```

Every route carries its own `root`; `route_root` repeats the first route's, so a
consumer asking "is this a test-only reach" does not have to index into the list.
Both are absent when the answer records no route — an absent route on a
package-level finding is explained by the advisory naming no symbols, and
answering `unrooted` there would offer a missing root as the reason for a search
that was never possible.

A retracted advisory answers with `"verdict": "withdrawn"` and a `withdrawn_at`
timestamp instead of a reachability determination, so the answer states its reason
rather than asserting a bare negative the reader has to take on trust:

```json
{
  "module": "go.etcd.io/bbolt",
  "version": "v1.4.3",
  "vuln_id": "GO-2026-4923",
  "aliases": ["CVE-2026-33817", "GHSA-6jwv-w5xf-7j27"],
  "summary": "WITHDRAWN: out-of-range-index in go.etcd.io/bbolt",
  "verdict": "withdrawn",
  "method": "none",
  "withdrawn_at": "2026-04-08T13:33:56Z",
  "scanned_at": "2026-07-28T06:06:20Z"
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

The probe is scoped to the **whole build** — every non-main module
`go list -deps ./...` reports, transitive as well as direct — because the
binary whose symbol table it reads contains the whole build. A module reached
only through a dependency (a JWT library pulled in by a SAML library, say) is
queried like any other.

### Coverage: what the answer speaks about

The probe reports stored findings, so it can only speak about modules the store
holds a record for. Every module in the build it cannot speak about is **named**
in `coverage.uncovered_modules` with its reason, never omitted — a ten-module
reply that silently drops the eleventh is indistinguishable from one that
examined eleven and cleared one.

| `reason` | Means |
|---|---|
| `no stored vulnerability record for this coordinate; it has never been vuln-scanned` | Nothing is known about it either way. This is **not** "no known vulnerabilities" — a record with no findings is an answer and counts as covered. |
| `the local build resolves this module without a version (a directory replacement), so it names no coordinate to look up` | Nothing asked the store about it. |
| `the store holds a vulnerability record for this coordinate, but only from another build's frame; this build has not been vuln-scanned` | The module has been scanned — for a different project. Nothing measured this build, so nothing seeded the probe. Scan this build to cover it. |

### Which records seeded the probe

The probe is seeded from stored records, and a store shared by several projects
holds several answers per dependency. The seed is restricted to the records
measured in **this tree's own frame** — a walk rooted at the module path this
tree's `go.mod` declares, at any version — plus the **isolated** frame, which
answers "the module built alone" and belongs to no project. Another project's
records are never read. `seed_restriction` states this on every run:

```
seed restricted to stored records measured in this tree's own frame (rooted at
github.com/example/app) or in the isolated frame; records measured in another
consumer's build were not read
```

A dependency whose only records belong to another project therefore seeds
nothing, and appears in `coverage.uncovered_modules` — the probe still measures
the tree. To cover it, scan this build: `kanonarion walk` then
`kanonarion vuln-scan` from this working tree.

A finding whose verdict came from the seed rather than from this probe's symbol
table says so in `reason`, naming the frame the stored scan was rooted at:

```
carried from the stored scan (by govulncheck, fidelity source, rooted at
target-rooted:github.com/example/app@local)
```

### Which binaries the probe read

A workspace with more than one `main` package ships more than one artefact, and
a symbol linked into only one of them is still in the product. The probe builds
**every** main the workspace declares and unions the symbol tables: a finding is
`present` if any binary carries the symbol, and `matched_binaries` names the
ones that do. Building whichever main sorted first reported `absent` for every
symbol linked solely into another — a false negative on the exact question the
probe answers.

`coverage.probed_binaries` names every main package found, probed or not. A main
that fails to build does not fail the probe and is not dropped from the answer
either: it appears with a `build_error`, so a reader can see which artefact the
verdict does not rest on. A workspace with no main is probed through the
synthetic harness instead and names no binaries.

`coverage.uncovered_remedy` names the route to a wider answer. There is no
refresh flag on `reachability` and none is needed: `version_id` is a content
digest recomputed from the working tree on every run, so the probe is never
serving a cached snapshot. What limits the answer is the store's coverage, and
scanning the build is what widens it.

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
| `--walk-id` | *(empty)* | Answer the stored query in the frame of this walk's scans |
| `--gomod` | *(empty)* | Answer the stored query in the frame of the latest project walk for this go.mod (valueless form: `./go.mod`) |
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
  "seed_restriction": "seed restricted to stored records measured in this tree's own frame (rooted at github.com/example/app) or in the isolated frame; records measured in another consumer's build were not read",
  "notice": "<optional diagnostic>",
  "coverage": {
    "snapshot_taken_at": "2026-01-01T00:00:00Z",
    "build_modules": 2,
    "queried_modules": 2,
    "covered_modules": 1,
    "modules_with_findings": 0,
    "uncovered_modules": [
      {
        "path": "example.com/dep",
        "version": "v1.8.1",
        "reason": "no stored vulnerability record for this coordinate; it has never been vuln-scanned"
      }
    ],
    "uncovered_remedy": "<the commands that widen the next answer>",
    "probed_binaries": [
      { "import_path": "github.com/example/app/cmd/server" },
      {
        "import_path": "github.com/example/app/cmd/tool",
        "build_error": "building probe binary: exit status 1\n..."
      }
    ]
  },
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
          "matched_symbols": ["pkg.Symbol"],
          "matched_binaries": ["github.com/example/app/cmd/server"]
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
