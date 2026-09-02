# Writing quality code with Kanonarion

Kanonarion does not lint your code or grade it. It supplies *verified facts*
about the code you and your tools are working against - the real public API of
a pinned dependency, the call graph of your own tree, which licences and
advisories apply - so the code you write is correct against reality instead of
against a guess. Quality here means *less rework*: fewer wrong assumptions
caught late in review, the build, or production.

Four ways it helps while you write.

## 1. Generate against the real API, not a remembered one

An AI assistant - and human memory - writes calls from what it learned in
training. For a dependency pinned at a specific version, that is often wrong:
signatures changed, a function moved, an option was renamed. Code built on a
stale signature compiles in the model's imagination and fails in yours.

Pull the actual surface of the version you depend on:

```bash
kanonarion interface-show github.com/spf13/cobra@v1.8.1
kanonarion context github.com/spf13/cobra@v1.8.1   # API, licence, vulns, call graph, examples
```

`context` is the orientation view: it aggregates all eight record types into one
document, deliberately reduced so an agent can read a whole dependency scope
without spending its budget on advisory prose. It is not the full record of any
one of them. When you are acting on a specific fact - remediating an advisory,
matching a signature - read the record's own command: `vuln-show` carries the
affected range, the affected symbols and the references that `context` leaves
out, and `interface-show` carries the complete API. Use `context` to decide
*which* module to look at, and the record command to act.

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
only through `ports`." Every edge carries how it was resolved:
`[CHA-overapprox]` is an unrefined interface dispatch, `[Direct]` names one
concrete callee. Read `[Direct]` with care - an interface site with exactly one
implementer is devirtualised and tagged `[Direct]` too, so the tag alone does
not separate a coupling violation from a sole-implementer port. The call site
does. Run it before you commit a refactor to confirm you did not quietly wire a
layer the wrong way.

One more edge kind is worth knowing before you rely on a negative: a function
*value* - a callback stored in a struct, a closure handed to `sync.Once.Do`, a
handler put in a map - is where static routing is weakest, because the analysis
cannot always tell which of several stored functions a call site reaches. A
codebase that routes behaviour dynamically has many of these, and a graph query
over it is correspondingly more over-approximate. `callgraph-show` reports the
count for a module as its *reference scope*, which is a useful measure of how
much of its structure is decided at runtime rather than by the type system.

For a change to an interface itself, `implementers` is the query that scopes it:
it lists the concrete types in the module whose method sets have to change
together, including the ones that satisfy the interface only by embedding -
which a grep for the method name reports as no match at all.

It also gives you blast radius before you change a signature: `callers` of a
symbol is the set of call sites that break if you change it, over-estimated
where the call goes through an interface - review those, not the whole repo.

## 3. Catch licence and vulnerability problems while you choose, not at release

Quality is not only correctness; it is not shipping a dependency you will have
to rip out later. Before you commit to a module, get its facts and its
closure's:

```bash
kanonarion audit                                     # one line per module in the go.mod's code scope
kanonarion license-compat <module>@<version>         # exit 0 clean / 1 conflict / 2 needs review
kanonarion vuln-show <module>@<version>
```

Finding an incompatible licence or a known advisory while you are still deciding
*whether* to add the dependency is cheap. Finding it in a release audit is
rework - sometimes a rewrite.

The default scope includes test-scope dependencies, because that is the set your
repository builds - so a dependency count from `audit` covers modules a user
never receives. `context` and `latest` take `--exclude-tests` to narrow to
production packages, and the difference between the two counts is the part of
your supply chain that ships to nobody. Say which scope you mean when you quote
a count; every command states the one it used, on stderr and in a
`dependency_scope` field.

## 4. Read the output, including what it says it could not determine

Two properties make the facts safe to build on. Both are enforced by the test
suite, not promised:

- **Deterministic.** Every sealed record orders its collections by a total
  order, so one unchanged thing seals the same twice. You can store a report,
  diff it against the next run, and review only what changed - the same
  discipline you apply to code.
- **Unknown is never dressed up as zero.** A module that has not been analysed
  is reported as `not_fetched` or `not_run`, and queries over un-analysed data
  exit non-zero with the exact command to run next - never a confident "no
  vulnerabilities" over data nobody looked at. You act on a real answer or a
  clear gap, never a false reassurance.

That principle has a sharp edge on reachability, and it is the one to internalise:
**a negative is not a proof of absence, and the record says which kind it is.**
Every not-reachable answer carries a `soundness` rung and the reason in the
tool's own words:

- `inferred` - *"govulncheck analysed this build from source and reported no
  route to the vulnerable symbol; the negative reads that silence, not a search
  over a call graph that ran and came back empty."*
- `unsearchable` - *"the advisory names no symbols for this module path, so
  there was never a symbol for a search to look for; no fidelity and no re-scan
  changes that."*

The second cannot be improved by re-running anything. The first can, by
analysing more of the closure. Treating them the same is how a gap becomes a
false reassurance.

For the same reason the answer is not a boolean. A finding is `reachable`,
`not_reachable`, `package_level_only` (the advisory matches the module but names
no symbol, so symbol-level reachability was never determinable),
`not_affected`, or `withdrawn`. And a `reachable` answer usually carries
*several* routes - dozens is normal - of which a rendering shows the first. Read
the set: one route can pass through a hop the analysis over-approximated and
suggest something the source does not support, while the rest of the set is
sound.

Kanonarion reports evidence and clearly qualified inferences. It does not
certify, clear, or grade anything, and no output of it should be read as a
decision that has been made for you - the judgement stays yours, and the tool's
job is to make sure it rests on what is actually true now.

## How it compares to other Go tools

Kanonarion is not a competing detector. It builds on the same canonical engines
the ecosystem already trusts - the `govulncheck` binary (`golang.org/x/vuln`)
for advisories, Google's `licensecheck` (the engine behind pkg.go.dev) for
licences, `github.com/CycloneDX/cyclonedx-go` for SBOM documents,
`golang.org/x/tools` for the call graph - and adds what those single-purpose
tools individually do not: a persistent, deterministic, version-keyed store
whose facts are linked across concerns.

| You currently reach for… | …to get | Kanonarion's difference |
|---|---|---|
| `go list` / `go mod graph` | the dependency graph | walks the same graph, but *fetches and verifies* each module and persists the result as queryable facts, not a one-shot text dump |
| `go doc` / pkg.go.dev | a package's API | the public surface of the exact version your `go.mod` resolves, stored offline and machine-readable for an agent to consume |
| `govulncheck` | vulnerabilities | runs it for you across the whole scope, records the exact advisory snapshot for reproducibility, and keeps history so you can diff two points in time |
| `go-licenses` / `licensecheck` | a licence per module | a licence *and* a closure-wide compatibility result, with unknowns reported as unknown rather than skipped |
| `cyclonedx-gomod` / `syft` | an SBOM | the same SBOM, backed by content-addressed archives and an append-only audit record |
| `x/tools/cmd/callgraph` | a call graph | a call graph you can query by symbol across *every* analysed module and your own tree at once (`callers` / `callees`) |

Unifying these in one store makes cross-concern questions possible. No single
tool above can relate an advisory to the code that actually runs - that needs
the vulnerability data and the call graph joined, and kanonarion holds both, so
`reachability` (and `context . --reachability`) reports on it.

Read that answer for what it is. A source-mode scan roots at `./...`, so
"reachable" means *reachable from something this module tree builds* - which
includes your examples, your tools and your tests, not only the binary you ship.
The route says which: each answer names its entry point and classifies the root
as `ingress` (the runtime enters here), `internal` (your own code calls it) or
`exported-api` (a consumer could drive it, nothing in the tree does). A finding
whose only routes start in `examples/` is a different fact from one that starts
in your request path, and only the entry point separates them.

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
| Call graph | Exact, type-checked references | Whole-program CHA; a sole-implementer dispatch is devirtualised, the rest stay over-approximate |
| Reachability | - | A separate instrument: `govulncheck` in source mode produces the answer, not the CHA graph above. `callers`/`callees` read the CHA graph; a reachability answer names its method and fidelity so you can tell which produced it |
| Persistence | Recomputed each time | Deterministic records, diffable across runs |
| Beyond code | - | Licences, advisories, SBOM, provenance |

Use **gopls** for precise, rename-safe references inside your project and live
navigation while authoring - kanonarion does not replace it. Reach for
**kanonarion** when you need that structural view across the *whole dependency
closure at pinned versions*, offline, deterministic over time, or joined to
other facts - the headline being reachability, which gopls has no notion of
because it does not know about advisories at all.

They share a foundation rather than compete: `context . --symbol` type-checks
via `golang.org/x/tools/go/packages`, from the same `x/tools` codebase gopls is
built on - one engine pointed at two jobs.

## A minimal loop

```bash
# Once, per project (slow; populates the local store)
kanonarion inspect

# While writing. Cost varies by what each one has to do: a record read is
# milliseconds, a graph computation is seconds, and the legs that re-analyse
# or go to the network are tens of seconds or more.
kanonarion context <module>@<version>     # real API for the code you're about to write
kanonarion audit                          # licence / vuln / currency check; under a second warm, up to ~75s when the staleness TTL has lapsed and it probes the network. It extracts what it finds missing, so it writes to the store as well as reading
kanonarion local . && kanonarion callers '<symbol>'   # structure + blast radius before a refactor
```
