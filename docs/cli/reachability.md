# `kanonarion reachability` - CVE reachability

## Synopsis

```
kanonarion reachability <module>@<version> --vuln <id> [--walk-id <id> | --gomod <path>] [flags]   # stored-module query
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
`vuln-scan --gomod/--tool/--project` - derive their verdict from the **same
project-rooted analysis of the live working tree** that `--local` performs, with
findings attributed per module. Their `Clean`/`Affected` verdicts are already
project-rooted; `reachability --local` inspects the per-CVE detail of that same
analysis.

### Reachability is method-plural

The persisted verdict carries a `method` field: govulncheck's own analysis, or
kanonarion's search over the stored call graph. The local probe adds a third,
reading a linker's symbol tables. The query reports `method` so answers from
different instruments are distinguishable rather than silently mixed. Do not read
"reachability" as one fixed algorithm.

## Stored-module query: `--vuln`

`reachability <module>@<version> --vuln <id>` answers, for a single CVE, whether
it is reachable in a module already scanned with `vuln-scan --reachability`. It
is **read-only**: it reports the persisted finding's verdict and confidence, and
never fetches or scans.

### Which build the answer is about

A stored verdict is a verdict about one build. Name the build:

- `--walk-id <id>` answers in the frame of that walk's scans, restricted to the
  records that walk covered.
- `--gomod <path>` does the same for the succeeded **code-scope** project walk of
  that `go.mod`, resolved for **this platform**, that the
  [default-frame rule](conventions.md#the-default-walk) picks — the most recent
  one whose recorded resolution still agrees with the manifest, else the most
  recent. The path is required and may be written either way round
  (`--gomod ./go.mod` or `--gomod=./go.mod`). Mutually exclusive with
  `--walk-id`, and rejected alongside `--local`, which measures the tree it is
  given.

  `reachability` has no scope flag, so it asks for the code scope. A project
  walked only in the `tool` or `complete` scope gets a refusal naming the scopes
  the store holds and the `walk` command that produces the missing one — never an
  answer read out of another build. The toolchain is not part of the selection;
  among the walks of one scope and platform, recency still decides.

Either flag prints a `notice:` line naming the walk, its scope and its frame
above the answer, and the verdict names its rooting as it always has.

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
| `<id> affects <m>@<v> but is NOT reachable` | 0 | Affected symbol is present but unreachable. The line also states the **soundness** of the search behind it — see below. |
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

## A negative states how sound the search behind it was

A positive carries a route: a hop-by-hop path that either exists or does not, and
you can check it against your own build. A negative is the *absence* of a route,
and an absence is worth exactly as much as the search that failed to find one. So
every not-reachable and package-level answer carries a `soundness` rung and the
reason for it, beside the confidence:

```
GO-2025-3487 affects golang.org/x/crypto@v0.31.0 but is NOT reachable
  [confidence: High, soundness: inferred, by: govulncheck, fidelity: source, rooted at: target-rooted:…]
  soundness: inferred — govulncheck analysed this build from source and reported no
  route to the vulnerable symbol; the negative reads that silence, not a search over
  a call graph that ran and came back empty
```

`confidence` says how sure the verdict is. `soundness` says what was actually
searched, which is the question you are asking if you are about to *not* upgrade.
The rungs, most to least sound:

| `soundness` | What was searched |
|---|---|
| `confirmed` | A call-graph search ran over a graph built with function bodies and found no path. The only rung a clean negative may rest on. |
| `inferred` | No search ran for this finding. An analysis loaded the whole build from source and never reported a route; the negative reads that silence. |
| `unconfirmed` | An analysis ran that could not have found a route at all — a symbol table inspected in binary mode, a call graph below `BUILT_WITH_BODIES`, or an answer that does not say what produced it. |
| `unsearchable` | The advisory names no symbols for this module path, so there was never a target to search for. Unlike the rungs above, no re-scan at any fidelity changes this. |
| `disputed` | The recorded negative is contradicted: a call-graph search over the module's own graph found a path to the symbol. Both answers stand; neither is discarded. Treat the finding as open. |

Two consequences worth knowing before you read a negative:

- **govulncheck never produces a `confirmed` negative, in either mode.** It emits
  findings for what it *reached*, so a module it examined and did not report
  produces no finding at all; the negative you are reading was manufactured
  afterwards by matching the advisory database against the module's coordinate.
  Source mode is that silence at its strongest and reports `inferred`; binary
  mode inspected a symbol table with no call graph behind it and reports
  `unconfirmed`. Where the store holds a call graph for the coordinate, that
  silence is put through kanonarion's own search when you read the finding, which
  is what can raise it to `confirmed` or `disputed` with no re-scan. A search over
  a dependency's own graph can confirm a negative in any frame, but contradicts
  one only in the frame it was measured in; a path found in another frame is
  reported in the reason and does not change the rung.
- **A reachable answer states no soundness.** A route is its own evidence, so the
  text prints no rung for a positive. The JSON still carries the `soundness` key,
  with the value `"not stated"`: the key present says this producer derived the
  rung and found no absence to qualify; the key absent says it states no rung at
  all. An omitted key rendered those identically.

The rung is derived at read time, so it appears on records scanned long before it
existed and improves whenever the analysis behind them does. The search costs one
call-graph decode per coordinate that has a negative to search — under a second
here — and nothing at all where none has.

The rung is appended to the per-finding label in `vuln-show` and `vuln-scan`,
where a bare `[not reachable]` read the same whether a call graph had been
searched or nothing had looked:

```
GO-2025-3487 (CVE-2025-22869) [not reachable — inferred]: Potential denial of service in golang.org/x/crypto
```

### Every surface that publishes a verdict carries the rung

Every surface publishing a reachability verdict states the rung, in text and in
JSON, under the same two keys:

| Surface | Where the rung appears |
|---|---|
| `reachability <mod> --vuln <id>` | verdict line and `soundness` / `soundness_reason`; the isolated-frame aside carries its own |
| `reachability --local <dir>` | on the verdict, and in each finding's `soundness` / `soundness_reason` |
| `vuln-show`, `vuln-show --history` | the `[not reachable — …]` label, and per finding in `--json` |
| `vuln-by-id --json` | per finding (this command's text form publishes no verdict) |
| `vuln-scan-show --json` | per finding (its text form lists finding ids only) |
| `vuln-scan-diff` | on the transition's later side, in text and per finding in `--json` |
| `vuln-scan` | the per-finding label in the run summary |
| `context`, `context --local --reachability` | `soundness` / `soundness_reason` in `--json`, and a `Soundness:` line under `--full` |

The record-shaped surfaces — `vuln-show`, `vuln-show --history`, `vuln-by-id
--json` and `vuln-scan-show --json` — also publish the route's
[root classification](#root-classification) per finding, under `route_root`,
built from the same two derivations this command uses. They emit `null` where the
finding records no route rather than dropping the key: "no route here" and "this
producer does not derive the root" must look different, and the second is what
`vuln-scan-diff --json` means by omitting it — a diff delta states no analysis
frame, and the frame decides `closure_rooted`.

`audit` and the SBOM commands publish no reachability verdict and carry no rung.
`audit` reports a module's vulnerability status and directs you to `vuln-show`;
an SBOM asserts what is in the build and never what is reachable in it.
| `… has not been vuln-scanned` | non-zero | No record at any pipeline version. Walk the module, then scan that walk. |
| `… that this build serves: it reads pipeline <v> and the store holds this coordinate at pipeline <v>` | non-zero | The module has been scanned, under scan logic this build supersedes. The message names each generation held and how many records and findings sit in it. Re-scan the coordinate. |
| `… ScanFailed` / `… is unscannable` | non-zero | Module could not be scanned; reachability is unknown. |
| `… scanned without --reachability` | non-zero | Findings exist and the scan was rooted elsewhere, so the flag was genuinely not passed. |
| `no reachability route … it was rooted at <coord>` | non-zero | The scan **did** run with reachability, but the module was its own root. See below. |
| `… reachability is undetermined` | non-zero | Reachability ran but the call graph was unavailable. |

Every one of these refusals prints the commands that carry out its remedy, and
each printed line is a whole invocation the CLI accepts as written.

### A module rooted at itself has no consumer route

A finding with no reachability answer has several causes taking opposite
remedies, so the refusal reads the cause off the record's analysis frame.

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
| `unrooted` | The graph could not say, with the reason named — no call graph stored for the module, a graph analysed at a fidelity that holds no nodes, or an entry point that is not a node in it. The `remedy` is the command that re-derives *that* module's graph: `kanonarion local <dir>` when the route starts in the project's own module (which carries the synthetic `@local` version and cannot be fetched), `kanonarion callgraph <module>@<version>` when it starts in a dependency. |

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
  project's. The flag is on every classification, `false` included: a route that
  does begin in the rooted module has been measured to, and the reader needs that
  stated rather than inferred from a missing key.

The classification is **derived at read time**, not stored: the facts it reads
live in the call-graph ledger, so an answer improves as the graph does and no
re-scan is owed for it.

#### Entry-point distance

The kind is read off the root node's own identity, and a handler that runs only
because it was *registered* with a router has nothing in its identity that says
so. It classifies `internal`, correctly — and on a 21,713-node application graph
70.7% of the owned nodes sit transitively under an entry point while classifying
that way. So every classified root also carries how far it sits below the
nearest entry point:

```
  root: internal — called from within the analysed module (1 caller), so the route begins where the analyser stopped, not where execution starts
    node: example.com/app/auth/external.(*externalSamlAuthHandler).CompleteUserAuth
    entry-point distance: 4 hops below example.com/app/pkg/apigw.(*apigw).ServeHTTP (an http.Handler implementation (method named ServeHTTP) — an HTTP server invokes it per request), weakest edge on that path CHA-overapprox
```

| Field (`entry_point_ancestry`) | Means |
|---|---|
| `found` | Whether an entry-point ancestor was reached. `false` is a **measurement**: nothing in the analysed graph enters this code. The whole object is absent when no search ran — an unresolved root, or no graph — so "not measured" and "measured, none" never look alike. |
| `hops` | Edges from the nearest entry-point ancestor down to the root. `0` with `found` means the root **is** the entry point. A method value costs one hop more than the source reads, because the path goes through the synthetic wrapper (see [callgraph](callgraph.md#the-wrapper-hop)). |
| `entry_point_id` / `entry_point_reason` | Which ancestor, and what made it one — the same reason string the `ingress` kind carries, so a package initialiser is never mistaken for a request handler. Several ancestors can sit the same distance away on paths of the same strength; the one named is then the lowest node id, so one stored answer reads back identically every time. The others are not listed. |
| `weakest_confidence` | The weakest edge on that path. It is what stops a distance being read as a certainty: four hops of CHA over-approximation are not four hops of resolved calls. |
| `via_reference` | At least one hop is a **registration rather than a call** (see [callgraph](callgraph.md#calls-and-references)). Carried apart from the confidence because a reference resolves exactly and would otherwise report `Direct`. Always present: `false` says every hop on this path is a call, which is the caveat's absence and not its non-derivation. |
| `search_bound` | The hop limit used. `0` is unbounded, which is what the search uses, so `found: false` means "nothing enters this code" and not "not within N hops". |

The kind is **not** made transitive, and the distance is not a kind. On the same
graph a majority of the edges into owned nodes are not `Direct`, so a transitive
`ingress` rule would inherit that over-approximation wholesale and label most of
a codebase `ingress` — as useless as labelling all of it `internal`, and
considerably more misleading. "internal, 4 hops below an ingress, weakest edge
CHA-overapprox" is a fact. "ingress" would be a claim.

A path where `weakest_confidence` is `Direct` and `via_reference` is false is a
chain of statically-resolved calls, and is the one case the transitive reading
is sound without caveat. It is a small set — 121 of 10,405 owned nodes on one
real graph, 345 of 21,713 on another — and it has no separate field, because
those two fields already say it.

None of this is an exploitability claim. It is a statement about graph shape.

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
        "node_id": "example.com/app/pkg/apigw.(*apigw).ServeHTTP",
        "entry_point_ancestry": {
          "found": true,
          "hops": 0,
          "entry_point_id": "example.com/app/pkg/apigw.(*apigw).ServeHTTP",
          "entry_point_reason": "an http.Handler implementation (method named ServeHTTP) — an HTTP server invokes it per request",
          "search_bound": 0
        }
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

The example above is a positive, so its `soundness` reads `"not stated"` and it
carries no `soundness_reason`. A negative names its rung and its basis, and drops
`routes`:

```json
{
  "verdict": "not_reachable",
  "confidence": "High",
  "method": "govulncheck",
  "fidelity": "source",
  "soundness": "inferred",
  "soundness_reason": "govulncheck analysed this build from source and reported no route to the vulnerable symbol; the negative reads that silence, not a search over a call graph that ran and came back empty"
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
| `the store holds vulnerability records for this coordinate only at superseded pipeline versions; it has been vuln-scanned and must be scanned again` | The module has been scanned for this build, under scan logic this build supersedes. Re-scan it to cover it. |

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

A dependency whose only records belong to another project seeds nothing and
appears in `coverage.uncovered_modules`. To cover it, run `kanonarion walk` then
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
`present` if any binary carries the symbol, and `matched_binaries` names the ones
that do. Building whichever main sorted first reported `absent` for every symbol
linked solely into another.

`coverage.probed_binaries` names every main package found, probed or not. A main
that fails to build does not fail the probe and is not dropped from the answer
either: it appears with a `build_error`, so a reader can see which artefact the
verdict does not rest on. A workspace with no main is probed through the
synthetic harness instead and names no binaries.

`coverage.uncovered_remedy` names the route to a wider answer. There is no
refresh flag and none is needed: `version_id` is a content digest recomputed from
the working tree every run, so the probe never serves a cached snapshot. What
limits the answer is the store's coverage, which scanning the build widens.

## Workspace resolution

`--local <dir>` uses the `go.mod` at `<dir>` (or, if absent, the nearest
ancestor's). Nested `go.mod` files - test fixtures, sub-modules - are ignored
when picking the workspace module identity; the root `go.mod` always wins, so the
command is safe to run from the root of a repository with fixture modules under
`testdata/`.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--vuln` | *(empty)* | Vulnerability ID to query (stored-module mode); requires a `<module>@<version>` argument |
| `--walk-id` | *(empty)* | Answer the stored query in the frame of this walk's scans |
| `--gomod <path>` | *(empty)* | Answer the stored query in the frame of the latest **code-scope** project walk for this go.mod on this platform. Takes a path, e.g. `--gomod ./go.mod`. Refuses, naming the scopes the store does hold, rather than answering from a walk of another scope or platform |
| `--local` | *(empty)* | Path to the local Go workspace to probe (live local mode) |
| `--json` | false | Emit output as JSON (global flag) |

Exactly one mode must be selected: either `<module>@<version> --vuln <id>`
or `--local <dir>`.

## Output

Without `--json` the probe prints prose: what the answer was drawn from, then
the coverage block, then one line per finding with its verdict, the rung behind
it and the instrument that produced it. `--json` emits the document below.

JSON shape:

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
          "matched_binaries": ["github.com/example/app/cmd/server"],
          "soundness": "not stated"
        }
      ]
    }
  ]
}
```

### What rung the probe's own negatives earn

The probe publishes two kinds of negative and they are not the same claim, so
they do not carry the same rung.

| Verdict | `verdict_source` | `soundness` |
|---|---|---|
| `absent` | `symbol-table` | `unconfirmed` - the affected symbols are not in the symbol table of the binaries this build links, so the linker did not keep them. Real evidence, and not a search: no call graph was built, so nothing could have found a route whether or not one exists. |
| `unreachable` | `govulncheck` | whatever the stored scan's own analyser and fidelity earn, usually `inferred`. This verdict was not measured here; it was carried from the store, and it states the rung of the search it actually came from. |
| `present`, `reachable`, `unknown` | - | `not stated`. There is no absence to qualify. |

An `absent` verdict never reads `confirmed`, whatever the probe built.
`confirmed` means a call-graph search ran over a graph built with function bodies;
this probe reads a linker's output. Where the probe could not read every main
package, or where the workspace declares no main and a synthetic harness was
compiled instead, `soundness_reason` says so - an absence from tables that do not
cover the product is a weaker claim than one from tables that do.

`notice` is set when the store has no findings for the analysed dependency
modules - typically because they have not been scanned. An empty `modules` array
with `notice` populated is *not* "no vulnerabilities reachable"; it means
"uncertain".

## Examples

```bash
# Analyse the current workspace, as prose
kanonarion reachability --local .

# The same answer as a document
kanonarion reachability --local . --json

# Analyse a project elsewhere on disk
kanonarion reachability --local /path/to/workspace --json | jq '.modules[]'

# Every negative in the tree, with the rung behind it
kanonarion reachability --local . --json | jq '.modules[].findings[]
  | select(.verdict=="absent" or .verdict=="unreachable")
  | {cve_id, verdict, soundness}'
```

## See also

- [`vuln-scan`](vuln.md) - populate vulnerability findings for a walk
- [`local`](local.md) - ingest the workspace's call graph so
  `callers`/`callees` resolve internal symbols
