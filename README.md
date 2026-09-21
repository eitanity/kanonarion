# Kanonarion
**Dependency assurance software for Go.**

Kanonarion is a deterministic, local source of truth about your dependencies -
what's in them, how they're licensed, how to call them, and which known
vulnerabilities your code actually reaches. Developers query it from the CLI
with human-readable output; AI coding agents get JSON. Both get the same answer,
computed from your real dependency tree - not a model's best guess. The questions
you would answer by hand, burn through tokens, or skip are answered quickly and
correctly.

It surfaces evidence, not verdicts. Where the answer is uncertain, it says so,
and in what way it is uncertain — never collapsing uncertainty into "safe."

A single binary. SQLite-backed local store. No SaaS, no account, no proprietary
scanner deciding for you. The facts are public; the judgment is local and yours.

---

## Why Kanonarion?

Modern AI coding agents (Claude, Copilot, Cursor, Junie) should be asking questions
about dependencies constantly - what's the API, is this CVE reachable, can I use
this license commercially, how do I call this function. Without a local fact store,
the agent usually doesn't ask at all - it guesses. That's what I found writing
Kanonarion. When you force the agent to find the answers you pay in tokens and latency.

Kanonarion solves this by running a **walk → extract → query** pipeline once per
dependency set, then serving all facts locally at query time. The agent asks Kanonarion
instead of guessing. The answers are deterministic and reproducible.

---

## How it works

```
walk  →  extract  →  query commands
```

1. **`walk <module@version>`** - resolves the full transitive dependency graph and persists a `WalkRecord` to the local SQLite store.
2. **`extract [walk-id]`** - runs the licence, interface and examples stages for every module in the walk. The call graph is opt-in (`--stages callgraph`) because it can exhaust RAM on a large walk; `inspect` runs it. Vulnerabilities are `vuln-scan`'s.
3. **Query commands** - fast, offline reads from the local store. No network required.

The store lives at `~/.kanonarion` by default. All metadata is in a single SQLite database; module ZIPs are content-addressed blobs. Every network fetch is verified against the Go checksum database and, where git is available, cross-checked against the upstream repository. A fetch from a carried-in module cache (`--from-modcache`, for an air-gapped host) is anchored on your `go.sum` instead, and the record says so.

---

## Uncertainty is a first-class state

Kanonarion never silently renders uncertainty as certainty.

A vulnerability finding carries one of five reachability states: **reachable**, **not reachable**, **package level only** (the advisory names no symbol, so symbol-level reachability was never determinable), **not affected**, or **withdrawn**. Beside the state it carries a **soundness** value that says how thorough the search behind a negative was - a "not reachable" that rests on the scanner's silence is labelled as that, not as a clean result. A module nobody could scan reads `Unscannable`, never `Clean`.

A licence record is **Detected**, **Multiple**, **Ambiguous**, **Unclassified**, **None**, **PerFile** or **ExtractionFailed**. Licence text that could not be classified is never reported as no licence, and neither is ever rendered as "allowed": an unknown licence blocks by default in the production scope. Where several licences apply, the record says whether they are a choice (`A OR B`) or separate grants (`A AND B`), and what that reading was based on.

If kanonarion can't determine something, it says so, and a command that refuses names the command that would produce the missing answer.

---

## Quick start

```bash
# Install (puts `kanonarion` on your PATH)
go install github.com/eitanity/kanonarion@latest

# Analyse a single module end to end (walk → extract → vuln-scan → context).
# One module = a result you can read and sanity-check on one screen.
kanonarion inspect github.com/spf13/cobra@v1.8.1

# --- Query the store (offline, no network) ---

# Show a module's public API
kanonarion interface-show github.com/spf13/cobra@v1.8.1

# Find usage examples for a symbol
kanonarion examples-find GenManTree

# List vulnerability scan runs
kanonarion vuln-scan-list

# Check licences
kanonarion license-list
```

**Analyse your own project.** Run kanonarion from your project root and it
defaults to your `go.mod`'s dependency set:

```bash
cd ~/my-project
kanonarion inspect          # same as --gomod ./go.mod (your code-scope deps)
kanonarion audit            # one-line-per-module fetch + licence + vuln report
```

This walks the full transitive closure, so it can take anywhere from seconds
to tens of minutes depending on how many dependencies you have - the
vulnerability scan dominates, as `govulncheck` analyses the project. Narrow
or widen the set with `--tool` / `--project`; see the CLI reference.

`audit`, `inspect` (no argument), and `vuln-scan --gomod` are **project-rooted**:
they derive each module's vulnerability status from a single scan of your
project's real build, so an in-build dependency reads `Clean`/`Affected`, never
un-analysable merely for a build your project never produces. A *single-module*
`inspect <module@version>` or `vuln-scan --module <module@version>` is the
coordinate-keyed view: it scans that module in isolation as its own main module,
which is the intended "look at it on its own" analysis and is unchanged.
(`vuln-scan --module` resolves the latest walk **rooted at** that coordinate — a
walk that merely contains it as a dependency is a different thing, and is scanned
by its walk id.)

A module whose every matched advisory was **retracted upstream** reads `Withdrawn`,
not `Clean`, and is reported in its own section with the retraction date. `Clean`
says no advisory ever applied; `Withdrawn` says one did and was withdrawn.

**Drive the pipeline stage by stage.** `walk`, `extract`, and `vuln-scan` all
key off a **walk id**. `walk` prints it, and you can always resolve the most
recent successful walk:

```bash
# Walk a module and its full transitive closure (prints a walk id)
kanonarion walk github.com/spf13/cobra@v1.8.1

# Resolve the latest successful walk id (needs jq)
WALK_ID=$(kanonarion walk-list --latest-success --json | jq -r '.id')

# Extract the facts for that walk (licences, interfaces, examples).
# Call graphs are opt-in: add --stages callgraph, or let `inspect` run them.
kanonarion extract "$WALK_ID"

# Scan that walk for vulnerabilities (add --reachability to triage by reachability)
kanonarion vuln-scan "$WALK_ID"
```

---

## Agentic coding workflow

Kanonarion is designed to be called directly from agent tool-use. The recommended pattern in agent guidelines:

| Situation                                  | Command |
|--------------------------------------------|---|
| User adds or upgrades a dependency         | `walk <module@version>` then `extract` |
| Onboard a new module end-to-end            | `inspect <module@version>` (walk + extract + vuln-scan + context) |
| Load everything known about a module into the agent's context | `context <module@version> --json` |
| "What's the API for X?"                    | `interface-show <module@version> --json` |
| Inspect a specific type or function        | `interface-show <module@version> --symbol <Name>` |
| Everything about a symbol (signature, docs, examples) | `symbol-context <Name> --json` |
| "How do I use X?"                          | `examples-find <symbol>` then `examples-show` |
| "Which library should I use for X?"        | `symbol-find <Name>` |
| "Should we adopt this library?"            | `inspect <module@version>`, then read `fetch` (authenticity), `provenance`, `license`, `latest`, `vuln-show` and `capability` for it |
| "Is this advisory reachable from my code?" | `reachability <module@version> --vuln <id> --gomod ./go.mod` |
| "What can this dependency actually do?"    | `capability <module@version>` |
| "Can I use this commercially?"             | `license <module@version>` |
| "Is my dependency closure licence-compatible?" | `license-compat <root-module@version> --target <SPDX>` (the coordinate a stored walk is rooted at; `@local` for your own project) |
| Generate a third-party attribution / NOTICE file | `notice --package ./cmd/<binary>` |
| "What does function F call?"               | `callees '<fully.qualified.Symbol>'` |
| "What calls function F?" / impact analysis | `callers '<fully.qualified.Symbol>'` |
| "Which types implement this interface?" / port-change scoping | `implementers '<pkg/path.Interface>'` |
| Scope an answer to production code only    | add `--exclude-tests` to any of the three, to `context <dir>`, or to a go.mod read (`context --gomod`, `latest --gomod`) - every go.mod answer states its test scope either way |
| Make those queries resolve my own project's symbols | `local <dir>` |
| Dependency upgraded - what changed in the graph? | `walk-diff <old-id> <new-id>` |
| "What changed in the API between two versions, and do we call any of it?" | `interface-diff <module@a> <module@b> --used-by ./go.mod` |
| "How does my own code use this dependency?" | `usage <module@version>` |
| "Did the licence change between two versions?" | `license-diff <module@a> <module@b>` |
| "Who in my build depends on X?"            | `dependents <module>` |
| "Does this dependency compile a C library into my binary?" | `native <module@version>`, `native-list` |
| "When did we first know about this advisory?" | `store ledger`, `vuln-scan-history <walk-id>`, `vuln-scan-diff <run-a> <run-b>` |
| "Was every module actually cross-verified?" | `verification-coverage <walk-id>` |
| Produce an SBOM for a build                | `sbom <walk-id>` |
| "Is there a newer version of X?"           | `latest <module>` |
| Audit this project's supply-chain hygiene  | `directives` / `godebug` / `vendor` / `fips` |

All query commands support `--json` for machine-readable output, making them easy to parse in agent tool implementations.

---

## Key features

- **Offline-first.** After the initial walk and extract, all queries are local SQLite reads. No network calls, no rate limits.
- **Deterministic.** Pinned versions, checksum-verified ZIPs, sorted JSON output. The same query returns the same result today and a year from now.
- **No SaaS, no phone home.** A single binary that runs where you run it. No account, no telemetry, no vendor in the loop.
- **Reachability-aware vulnerability scanning.** Integrates govulncheck with optional `--reachability` filtering. Every finding states whether a path from your entry points to the vulnerable symbol was found, was not found, or was never determinable because the advisory names no symbol for that module path - and says which, so the triage is yours to make on evidence rather than on a severity number.
- **Licence compliance with provenance.** Per-module SPDX licence detection with a full transitive summary. Each record states its status, what each licence file covers (the module's code, documentation, a bundled component), and whether several licences are a choice or separate grants. A licence or copyright a person determined by reading upstream is recorded in the config with who decided, when and on what basis, and the attribution document prints it as a human determination, not a detection.
- **Interface extraction.** Full public API surface - types, functions, methods, constants - in structured JSON the agent can consume directly, measured in one named build frame (`goos/goarch` plus cgo) rather than every platform at once.
- **Call graph with a three-valued answer.** A call graph across your project and its dependencies, for impact analysis and reachability queries. Every answer says whether an empty result is a *measurement* (`RESOLVED-ABSENT`) or an *undecided* one (`UNRESOLVED`, naming what blocked it) - so "nothing calls this" is never a guess dressed as a fact. `_test.go` declarations are in the graph and tagged, because test fakes are most of the edit surface of an interface change; `--exclude-tests` narrows any query to production code and says so on the answer, empty or not.
- **Interface implementers.** `implementers` lists the concrete types satisfying an interface, including ones that satisfy it only by embedding - the question a port-signature change actually raises, and one a grep for the method name answers wrongly.
- **Usage examples.** `Example*` functions harvested from each module's own test files, so the agent codes against patterns the module's authors wrote and test.
- **Upgrade evidence.** `interface-diff --used-by` compares two versions' public API and joins the result against your own call graph, so a bump is judged on the symbols you call rather than on the whole changelog. `usage` lists what your code uses from one dependency, with call-site counts. An empty signature diff is reported as exactly that - the behaviour may still have moved - and the output says what would answer it.
- **Native code in a Go binary.** A cgo module can compile a whole C library into your binary that no Go advisory database indexes. `native` records what a module ships or links and names the component where it can; `native-list` asks the whole store. A module with no native record was not examined, and the output says that rather than implying it is clean.
- **Append-only evidence.** Records are sealed with a content hash and never rewritten. A re-scan adds a generation; the earlier one stays readable as what was concluded then. Every record names the pipeline version that produced it; call-graph, interface and vulnerability records also name the Go toolchain, and a call-graph record names the analyser library. `store ledger`, `vuln-scan-history` and `vuln-scan-diff` answer "what did we know, and when".
- **The standard library and the toolchain are in scope.** The standard library is a node in the graph with its own chain of custody, and `audit` checks the Go toolchain itself against its advisories.
- **Air-gapped and vendored builds.** `walk --from-modcache` acquires from a carried-in module cache; `vendor` reconciles a `vendor/` tree against what the manifest resolves, because a vendored tree is the build.
- **Policy gates.** Walk-traversal rules in YAML - max depth, whether replace directives and indirect requirements are followed, and which VCS forges may be cross-verified against - validated with `policy validate`.
- **SBOM generation.** CycloneDX 1.6 software bill of materials from any walk, with a full dependency graph and per-component `SHA-256/384/512` artefact hashes computed at download. The Go standard library is a first-class component, verified against Go's published source-tarball checksum; `--stdlib-from-gomod` pins its version to the `go.mod` directive for reproducible release artifacts.
- **Auditable evidence chain.** Every fetch, verification and policy decision is recorded in an append-only `audit.jsonl`: reproducible, time-stamped evidence of what kanonarion did and when.

---

## Store layout

```
~/.kanonarion/
  mirror.db          # SQLite - all metadata (walks, interfaces, vulns, licences, …)
  blobs/             # Content-addressed module ZIPs
  sumdb/             # Checksum database client state
  audit.jsonl        # Append-only event log: walks, extractions, scans, SBOMs, custody
  config.yaml        # Optional - preferences, licence policy, recorded determinations
```

---

## Policy files

Place a `.kanonarion/policy.yaml` in your project root (Kanonarion searches upward from cwd). Policies control walk traversal - the maximum depth, whether replace directives are followed, and whether indirect requirements are traversed - and the fetch stage's `allowed_vcs_hosts`, the set of forges a module's repository may be cloned from during cross-verification. Omitting `allowed_vcs_hosts` keeps the built-in forge set; see [`policy`](docs/cli/policy.md).

```bash
# Validate a single policy file
kanonarion policy validate .kanonarion/policy.yaml

# Validate all policy files in a directory
kanonarion policy validate docs/examples/policies
```

Example policies are in [`docs/examples/policies/`](docs/examples/policies/).

---

## Exit codes

Every command uses the same codes, so a caller can tell "no record yet" from "the evidence is in doubt":

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Partial - an answer, with a statement of what it missed |
| 2 | The work could not complete |
| 4 | No record - the message names the command that produces it |
| 5 | A policy or publication gate fired on real findings |
| 10 | Recorded evidence is in doubt: a failed hash, or two records that disagree |
| 20 | Never reached an answer: bad argument, missing toolchain, no store |

The full contract, including output channels and listing shape, is in [`docs/cli/conventions.md`](docs/cli/conventions.md).

---

### Observability

Logging defaults to `--log-level warn`. Long runs narrate on stderr with a throttled progress heartbeat, silenced by `--no-progress`. `--log-level info` adds per-module detail; `debug` adds memory telemetry for troubleshooting large closures.

---

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md) - from fresh checkout to per-module dependency answers, zero prior knowledge (includes a copy-pasteable agent prompt)
- [`docs/cli/reference.md`](docs/cli/reference.md) - full CLI reference
- [`docs/cli/conventions.md`](docs/cli/conventions.md) - exit codes, output channels, listing and paging rules
- [`docs/cli/vuln.md`](docs/cli/vuln.md) - vulnerability commands
- [`docs/cli/extract.md`](docs/cli/extract.md) - extraction pipeline

---

## Requirements

Kanonarion is a single binary, but it shells out to a handful of external
tools. Have these on `PATH`:

| Tool | When it's needed | Install |
|---|---|---|
| **Go 1.26.6+** (an older Go with the default `GOTOOLCHAIN=auto` downloads it) | Install *and* runtime - kanonarion drives the `go` toolchain (`go list`, `go mod download`, `go test -c`, `go tool nm`) to resolve build lists and analyse binaries. | [go.dev/dl](https://go.dev/dl/) |
| **git** | Runtime - VCS cross-verification (the `fetch` stage compares the proxy zip against the upstream source repository). Optional: without git, fetches still verify against the Go checksum database but record an unverified VCS status; pass `--skip-vcs-verify` to skip explicitly. | system package manager |
| **govulncheck** | Runtime - required by `vuln-scan` / `inspect`. The scan fails fast with an actionable error if it's missing. It type-checks source in-process, so the Go release it was **built with** must be at least the one your project's `go` directive names; a scan that meets that gap names the tool and the command that rebuilds it. | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| **jq** | Optional - only the shell snippets in this README use it to pull a walk id out of `--json` output. | system package manager |

Network access is needed for the **first** run of a given module set only
(module downloads, checksum database, VCS cross-verification, vulnerability
database snapshot). Every query afterwards is served from the local store at
`~/.kanonarion` with no network calls. Project-rooted commands (`audit`,
`inspect`, `vuln-scan`) serve a stored scan run rather than re-scanning, and name
the run they reused; the conditions are in
[reuse and re-derivation](docs/cli/audit.md#reuse-and-re-derivation).
`audit`'s staleness column asks the module proxy for each module's latest
version, but serves a recorded lookup younger than `staleness.ttl` (default
`1h`), so a warm run costs nothing outbound. `--fresh` refreshes the advisory
database; `--force` re-fetches the module set and re-measures.

## Building from source

Contributors build from a checkout instead of `go install`:

```bash
make build     # compile binary to ./kanonarion
make test      # run all tests with race detector
make coverage  # generate coverage report
make lint      # go vet, staticcheck, govulncheck, gosec
go tool golangci-lint run ./...   # golangci-lint is separate from make lint
```

## Status

Kanonarion is open source under Apache-2.0 and is in active development. If your organisation is using AI coding tools against Go codebases under regulatory scrutiny - DORA, CRA, NIS2, EU AI Act, the Australian ISM - and you'd like to shape the roadmap, get in touch.
