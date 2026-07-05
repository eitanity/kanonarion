# Writing quality code with Kanonarion

Kanonarion does not lint your code or grade it. It supplies *verified facts*
about the code you and your tools are working against - the real public API of
a pinned dependency, the actual call graph of your own tree, which licences and
advisories apply - so the code you write is correct against reality instead of
against a guess. Quality here means *less rework*: fewer wrong assumptions
caught late in review, the build, or production.

This guide covers four ways it helps while you write.

## 1. Generate against the real API, not a remembered one

An AI assistant - and human memory - writes calls from what it learned in
training. For a dependency pinned at a specific version, that is often wrong:
signatures changed, a function moved, an option was renamed. Code built on a
stale signature compiles in the model's imagination and fails in yours.

Pull the actual surface of the version your `go.mod` resolves *today*:

```bash
kanonarion interface-show golang.org/x/mod@v0.36.0
kanonarion context golang.org/x/mod@v0.36.0          # API + licence + vulns + examples
```

Feeding the real interface to a coding agent (or reading it yourself) removes a
whole class of "that function doesn't take those arguments" rework before the
first compile.

## 2. Check your own architecture with the call graph

Ingest your working tree, then ask who calls what across the whole graph -
including your internal packages:

```bash
kanonarion local .
kanonarion callers '<your-module>/internal/app.Execute'
kanonarion callees '<your-module>/internal/app.Execute'
```

This makes structural rules *checkable* rather than aspirational. A layered or
DDD codebase says "dependencies point inward - `application` reaches `adapters`
only through `ports`." The call graph shows it: edges into an injected adapter
come back as `[DynamicDispatch]` (interface-mediated, fine), while a `[Direct]`
edge from `application` into a concrete `adapters` type is a coupling violation
you can see. Run it before you commit a refactor to confirm you did not
quietly wire a layer the wrong way.

It also gives you blast radius before you change a signature: `callers` of a
symbol is exactly the set of call sites that break if you change it - review
those, not the whole repo.

## 3. Catch licence and vulnerability problems while you choose, not at release

Quality is not only correctness; it is not shipping a dependency you will have
to rip out later. Before you commit to a module, get its facts and its
closure's:

```bash
kanonarion audit                                     # one line per direct dep: licence, staleness, vulns
kanonarion license-compat <module>@<version>         # exit 0 clean / 1 conflict / 2 needs review
kanonarion vuln-show <module>@<version>
```

Finding an incompatible licence or a known advisory while you are still deciding
*whether* to add the dependency is cheap. Finding it in a release audit is
rework - sometimes a rewrite.

## 4. Trust the output, including what it admits it doesn't know

Two properties make the facts safe to build on:

- **Deterministic.** Sorted keys, stable ordering. You can store a report,
  diff it against the next run, and review only what changed - the same
  discipline you apply to code.
- **Unknown is never dressed up as zero.** A module that has not been analysed
  is reported as `not_fetched` / `not_run`, and queries over un-analysed data
  exit non-zero with the exact command to run next - never a confident "no
  vulnerabilities" over data nobody looked at. You act on a real answer or a
  clear gap, never a false reassurance.

Kanonarion reports facts and clearly qualified inferences, not verdicts. The
judgement stays yours; the tool's job is to make sure it rests on what is
actually true now.

## How it compares to other Go tools

Kanonarion is not a competing detector. It builds on the same canonical
engines the ecosystem already trusts - `golang.org/x/vuln` (govulncheck) for
advisories, Google's `licensecheck` (the engine behind pkg.go.dev) for
licences, `cyclonedx-gomod`'s library for SBOMs, `golang.org/x/tools` for the
call graph - and adds what those single-purpose tools individually do not: a
persistent, deterministic, version-keyed store whose facts are linked across
concerns.

| You currently reach for… | …to get | Kanonarion's difference |
|---|---|---|
| `go list` / `go mod graph` | the dependency graph | walks the same graph, but *fetches and verifies* each module and persists the result as queryable facts, not a one-shot text dump |
| `go doc` / pkg.go.dev | a package's API | the public surface of the exact version your `go.mod` resolves, stored offline and machine-readable for an agent to consume |
| `govulncheck` | vulnerabilities | runs it for you across the whole transitive closure, records the exact DB snapshot for reproducibility, and keeps history so you can diff two points in time |
| `go-licenses` / `licensecheck` | a licence per module | a licence *and* a closure-wide compatibility result, with unknowns reported as unknown rather than skipped |
| `cyclonedx-gomod` / `syft` | an SBOM | the same SBOM, backed by content-addressed archives and an append-only audit record |
| `x/tools/cmd/callgraph`, `guru` | a call graph | a call graph you can query by symbol across *every* analysed module and your own tree at once (`callers` / `callees`) |

Two things follow from unifying these in one store:

- **Cross-concern questions become possible.** No single tool above can answer
  "is the vulnerable symbol in this advisory actually reachable from the binary
  I ship?" - that needs the vulnerability data and the call graph joined.
  Kanonarion holds both, so `reachability` (and `context . --reachability`)
  answers it.
- **The facts are stable and honest.** Output is deterministic (sorted,
  diff-reviewable across runs), and absence of analysis is reported as
  `not_fetched` / `not_run` with a non-zero exit, never as a confident zero -
  a guarantee a pipe through several ad-hoc tools does not give you.

What kanonarion deliberately does **not** do: it is not a linter, formatter,
type-checker, or test runner. `staticcheck`, `golangci-lint`, `go vet`, and
`gofmt` judge *your* code's style and correctness; kanonarion supplies *facts
about your dependencies and structure* that those tools cannot see. They are
complementary - keep running both.

### A note on gopls

`gopls` is the one tool with real overlap: its *find-references* and *call
hierarchy* do roughly what `callers` / `callees` do. But they sit on different
axes. gopls is a language server - live, interactive, in your editor - that
type-checks the *one workspace you have open* and answers navigation and
refactoring questions against it precisely and ephemerally. kanonarion extracts
those facts in batch and persists them.

| | gopls | kanonarion |
|---|---|---|
| When | Live, as you type | On demand; results persisted |
| Scope | The active workspace + its build | Many modules at pinned versions, plus your tree |
| Call graph | Exact, type-checked references | Whole-program CHA (over-approximate for interfaces) |
| Persistence | Recomputed each time | Deterministic records, diffable across runs |
| Beyond code | - | Licences, advisories, SBOM, provenance |

Use **gopls** for precise, rename-safe references inside your project and live
navigation while authoring - kanonarion does not replace it. Reach for
**kanonarion** when you need that structural view across the *whole dependency
closure at pinned versions*, offline and queryable without opening the project,
deterministic over time, or joined to other facts - the headline being
reachability (a CVE's symbols ∩ the call graph), which gopls has no notion of
because it does not know about vulnerabilities at all.

They share a foundation rather than compete: `context . --symbol` type-checks
via `golang.org/x/tools/go/packages` - the same library gopls is built on. It is
the same engine pointed at a different job: gopls makes one workspace navigable
interactively; kanonarion makes a verified, versioned dependency universe
queryable and auditable.

## A minimal loop

```bash
# Once, per project (slow; populates the local store)
kanonarion inspect

# While writing - all local, sub-second reads
kanonarion context <module>@<version>     # real API for the code you're about to write
kanonarion audit                          # licence / vuln / staleness sanity check
kanonarion local . && kanonarion callers '<symbol>'   # structure + blast radius before a refactor
```
