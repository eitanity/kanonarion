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
2. **`extract [walk-id]`** - runs all extraction stages (licence, interface, call graph, examples, vulnerabilities) for every module in the walk.
3. **Query commands** - fast, offline reads from the local store. No network required.

The store lives at `~/.kanonarion` by default. All metadata is in a single SQLite database; module ZIPs are content-addressed blobs. Every fetch is verified against the Go checksum database.

---

## Uncertainty is a first-class state

Kanonarion never silently renders uncertainty as certainty.

Vulnerabilities are **reachable**, **not reachable**, or **unknown** - the last for advisories where symbol-level reachability data isn't available. Licences are **Detected**, **Unclassified**, or **None** - a resolved SPDX identity, licence text that could not be classified, or no licence evidence found - never silently rendered as "allowed". If kanonarion can't determine something, it says so. Policy can be configured to treat unknowns as hard failures so a CI gate fails loudly rather than passing on a blind spot.

---

## Quick start

```bash
# Install (puts `kanonarion` on your PATH)
go install github.com/eitanity/kanonarion/cmd/kanonarion@latest

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
they derive each module's vulnerability verdict from a single scan of your
project's real build, so an in-build dependency reads `Clean`/`Affected`, never
un-analysable merely for a build your project never produces. A *single-module*
`inspect <module@version>` or `vuln-scan --module <module@version>` is the
coordinate-keyed view: it scans that module in isolation as its own main module,
which is the intended "look at it on its own" analysis and is unchanged.

**Drive the pipeline stage by stage.** `walk`, `extract`, and `vuln-scan` all
key off a **walk id**. `walk` prints it, and you can always resolve the most
recent successful walk:

```bash
# Walk a module and its full transitive closure (prints a walk id)
kanonarion walk github.com/spf13/cobra@v1.8.1

# Resolve the latest successful walk id (needs jq)
WALK_ID=$(kanonarion walk-list --latest-success --json | jq -r '.id')

# Extract all facts for that walk (interfaces, licences, call graphs, examples)
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
| "Is this library safe?"                    | `vuln-scan --module <module@version> --reachability` |
| "Can I use this commercially?"             | `license <module@version>` |
| "Is my dependency closure licence-compatible?" | `license-compat <module@version>` |
| Generate a third-party attribution / NOTICE file | `notice --package ./cmd/<binary>` |
| "What does function F call?"               | `callees '<fully.qualified.Symbol>'` |
| "What calls function F?" / impact analysis | `callers '<fully.qualified.Symbol>'` |
| Make callers/callees resolve my own project's symbols | `local <dir>` |
| Dependency upgraded - what changed?        | `walk-diff <old-id> <new-id>` |
| "Is there a newer version of X?"           | `latest <module>` |
| Audit this project's supply-chain hygiene  | `directives` / `godebug` / `vendor` / `fips` |

All query commands support `--json` for machine-readable output, making them easy to parse in agent tool implementations.

---

## Key features

- **Offline-first.** After the initial walk and extract, all queries are local SQLite reads. No network calls, no rate limits, no flaky CI.
- **Deterministic.** Pinned versions, checksum-verified ZIPs, sorted JSON output. The same query returns the same result today and a year from now.
- **No SaaS, no phone home.** A single binary that runs where you run it. No account, no telemetry, no vendor in the loop after install.
- **Reachability-aware vulnerability scanning.** Integrates govulncheck with optional `--reachability` filtering. CVEs your code can't actually reach are triaged down, not paged on at 2am.
- **Licence compliance with provenance.** Per-module SPDX licence detection with a full transitive summary, classified as Detected, Unclassified, or None.
- **Interface extraction.** Full public API surface - types, functions, methods, constants - in structured JSON the agent can consume directly.
- **Call graph.** Intra-module call graph for impact analysis and reachability queries.
- **Usage examples.** Verified code snippets extracted from module test files, so the agent codes against patterns that actually work.
- **Policy gates.** Walk-traversal rules in YAML - max depth, and whether replace directives and indirect requirements are followed - validated with `policy validate`.
- **SBOM generation.** CycloneDX-compatible software bill of materials from any walk.
- **Auditable evidence chain.** Every fetch, every verification, every policy decision is recorded in an append-only `audit.jsonl`. Reproducible, time-stamped evidence of what kanonarion did and when - useful for CI investigation, compliance reporting, or understanding why a build failed.

---

## Store layout

```
~/.kanonarion/
  mirror.db          # SQLite - all metadata (walks, interfaces, vulns, licences, …)
  blobs/             # Content-addressed module ZIPs
  audit.jsonl        # Append-only fetch audit log
```

---

## Policy files

Place a `.kanonarion/policy.yaml` in your project root (Kanonarion searches upward from cwd). Policies control walk traversal - the maximum depth, whether replace directives are followed, and whether indirect requirements are traversed.

```bash
# Validate a single policy file
kanonarion policy validate .kanonarion/policy.yaml

# Validate all policy files in a directory
kanonarion policy validate docs/examples/policies
```

Example policies are in [`docs/examples/policies/`](docs/examples/policies/).

---

### Observability

By default, `kanonarion` emits progress information at the `INFO` level. For large-scale module analysis (e.g., Envoy), high-frequency memory telemetry can be enabled for troubleshooting via `--log-level debug`.

---

## Documentation

- [`docs/getting-started.md`](docs/getting-started.md) - from fresh checkout to per-module dependency answers, zero prior knowledge (includes a copy-pasteable agent prompt)
- [`docs/cli/reference.md`](docs/cli/reference.md) - full CLI reference
- [`docs/cli/vuln.md`](docs/cli/vuln.md) - vulnerability commands
- [`docs/cli/extract.md`](docs/cli/extract.md) - extraction pipeline

---

## Requirements

Kanonarion is a single binary, but it shells out to a handful of external
tools. Have these on `PATH`:

| Tool | When it's needed | Install |
|---|---|---|
| **Go 1.26+** | Install *and* runtime - kanonarion drives the `go` toolchain (`go list`, `go mod download`, `go test -c`, `go tool nm`) to resolve build lists and analyse binaries. | [go.dev/dl](https://go.dev/dl/) |
| **git** | Runtime - VCS cross-verification (the `fetch` stage compares the proxy zip against the upstream source repository). Optional: without git, fetches still verify against the Go checksum database but record an unverified VCS status; pass `--skip-vcs-verify` to skip explicitly. | system package manager |
| **govulncheck** | Runtime - required by `vuln-scan` / `inspect`. The scan fails fast with an actionable error if it's missing. | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| **jq** | Optional - only the shell snippets in this README use it to pull a walk id out of `--json` output. | system package manager |

Network access is needed for the **first** run of a given module set only
(module downloads, checksum database, VCS cross-verification, vulnerability
database snapshot). Every query afterwards is served from the local store at
`~/.kanonarion` with no network calls. Note that project rooted commands
(audit, inspect, vuln-scan --gomod) still re-run the vulnerability scan over
your live working tree using the cached modules and vulnerability database.
`audit` also resolves each module's latest version live from the module proxy on
every run (the staleness column), so it always makes those outbound calls even on
a warm store.
The flag --fresh re-downloads the vulnerability database snapshot and --force
forces a re-fetch of the module set. 

## Building from source

Contributors build from a checkout instead of `go install`:

```bash
make build     # compile binary to ./kanonarion
make test      # run all tests with race detector
make coverage  # generate coverage report
make lint      # run golangci-lint
```

## Status

Kanonarion is open source under Apache-2.0 and is in active development. If your organisation is using AI coding tools against Go codebases under regulatory scrutiny - DORA, CRA, NIS2, EU AI Act, the Australian ISM - and you'd like to shape the roadmap, get in touch.
