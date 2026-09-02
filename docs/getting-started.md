# Getting started: understand an unfamiliar Go project

## Why this matters

A Go project depends on many modules. Nobody on your team has read most of them.
Their versions move. Their APIs change. New advisories appear. Their licences are
often not what people guess.

You answer from memory, and so does your AI assistant. Memory goes stale. Code
built on a stale answer is wrong, and you find out late: in review, in the
pipeline, or after release.

kanonarion reads your dependency graph and turns it into facts. It tells you what
you depend on, who published it, under which licence, with which known
vulnerabilities, and whether the vulnerable code can be reached from the binary
you ship. It writes every fact to a local store, so the second question is fast.

kanonarion is a tool you run while you work. It is not a pipeline component.

If you work under audit, the same records are the evidence an auditor asks for: a
licence and policy result for every module, a content-addressed SBOM, an
append-only audit record, and a vulnerability history you can reproduce. Where
kanonarion does not know something, it says so. It never hides it.

> kanonarion reports facts and clearly labelled inferences. It does not decide
> whether you comply with anything, and this guide is not legal advice.

Part 1 is a walkthrough for you to read. Part 2 is a prompt you can paste into an
AI coding session.

The timings below come from one developer machine, running kanonarion against its
own project. Your numbers depend on how many dependencies you have. The shape is
the point: slow once, then fast.

## Four words you need

kanonarion uses these four words everywhere.

- **coordinate** - a module path and a version together, such as
  `github.com/spf13/cobra@v1.8.1`.
- **walk** - one recorded pass over a dependency graph. Every walk starts at one
  module or project, called its root, and gets an ID.
- **record** - one stored fact about one coordinate: its licence, its public API,
  its call graph, or its vulnerabilities.
- **scope** - which dependencies an answer covers. `code` means the modules your
  packages import. `tool` means the modules your `go.mod` `tool` directives pull
  in. `complete` means both.

---

## Part 1 - Walkthrough

### 0. Before you start

- **Go 1.26 or newer.** kanonarion never downloads a Go toolchain. It analyses
  with the one you already have. If a project needs a newer Go than that, it
  uses a newer Go that is already unpacked on this machine — in `~/sdk`, or one
  the go command downloaded earlier into the module cache. If there is none, it
  stops and tells you which version to install.
- **git on your `PATH`.** kanonarion checks each download against the upstream
  source repository. Without git it still checks the Go checksum database, and it
  records that the repository check did not run.
- **govulncheck on your `PATH`.** The vulnerability scan needs it, and stops with
  a clear error if it is missing. Install it with
  `go install golang.org/x/vuln/cmd/govulncheck@latest`.
- **Network access for the first run only.** After that kanonarion answers from
  the local store at `~/.kanonarion`.

### 1. Install kanonarion

```bash
go install github.com/eitanity/kanonarion@latest
```

This puts a `kanonarion` binary in `$(go env GOBIN)`, or in
`$(go env GOPATH)/bin`. The store is `~/.kanonarion` by default, so you do not
need a flag. To keep a separate store, pass `--store-root <dir>` to any command.

### 2. Fill the store: `inspect`

`inspect` runs every analysis stage. It walks the dependency graph, downloads and
verifies each module, extracts the licence, the public API, the call graph and the
examples, and scans for vulnerabilities.

#### Start with one module

One module finishes in seconds, and you can read the whole answer:

```bash
kanonarion inspect github.com/spf13/cobra@v1.8.1
```

```
github.com/spf13/cobra@v1.8.1
  Verification:    VerifiedBySumDBOnly (git: https://github.com/spf13/cobra)
  Provenance:      no fork indicators (name-path heuristic, catalogue 1.0.0)
  Dependencies:    4 direct (succeeded) [walk 01KZWK6GHN7CK9Y54YTHMTNRKJ, frame target-rooted:github.com/spf13/cobra@v1.8.1]
  License:         Apache-2.0
  Interface:       2 package(s), 194 symbol(s) (Extracted)
  Call Graph:      1362 nodes, 6330 edges (Extracted)
  Examples:        2 (Found)
  Vulnerabilities: Clean
  Walk basis:      01KZWK6GHN7CK9Y54YTHMTNRKJ (frame target-rooted:github.com/spf13/cobra@v1.8.1)
  Run context:     this record was measured in a walk outside the 10 most recent walks this report loaded, so there is no run context to show
  Snapshot:        2026-08-21T20:38:00Z (pipeline v24)

Context size: ~6062 tokens (24248 bytes) of JSON for this module  (use --full for complete docs, --json for machine-readable)
```

Read it line by line.

- `Verification` - how kanonarion checked the download.
- `Provenance` - whether the module looks like a fork or a republication.
- `Dependencies` - how many modules it requires directly, and which walk measured
  that.
- `License` - the SPDX licence kanonarion read from the files in the module.
- `Interface` - the size of the public API.
- `Call Graph` - the size of the call graph.
- `Examples` - how many `Example*` functions the module ships.
- `Vulnerabilities` - `Clean`, or the findings.
- `Walk basis` - which walk each fact came from.
- `Run context` - why kanonarion has no scan-run detail for a fact. Here the walk
  is not one of the 10 newest walks in the store. kanonarion shows this line only
  when it has something to say.
- `Snapshot` - the date of the advisory database the scan used.

Run this once. Now you know the shape of an answer.

#### Then your whole project

`cd` into any directory that has a `go.mod`, and run:

```bash
kanonarion inspect
```

With no arguments, `inspect` uses `--gomod ./go.mod` and walks your code scope:
the modules your packages import, tests included. That is the same set as
`go list -deps -test ./...`. It prints a summary:

```
Status:   AllClean
Scope:    code — test-scope dependencies included
Modules:  22 (0 failed)
Affected: 0
Snapshot: 2026-08-21T20:38:00Z
Walk ID:  01M0RGVEZH7BN09G63JX3B1X88
Frame:    linux/amd64

To get module context: kanonarion context --gomod ./go.mod
```

Read it line by line.

- `Status` - the roll-up for the whole run: `AllClean`, `Affected`, `Partial` or
  `ScanFailed`.
- `Scope` - which dependency set the run covered.
- `Modules` - how many modules the walk holds, and how many of them failed.
- `Affected` - how many modules have vulnerability findings. kanonarion counts
  this separately from `Status`, so a run that ends `Partial` still reports its
  real `Affected` count.
- `Extract fails` - how many extraction stages did not finish. kanonarion shows
  this line only when the number is above zero. It prints the reason for each one
  on stderr, and every reason names the command that fixes it.
- `Snapshot` - the date of the advisory database the scan used. Pass `--fresh` to
  pull a newer one.
- `Walk ID` - the ID of the walk. Pass it to `walk-show`, `sbom` or
  `context --walk-id`.
- `Frame` - the platform the walk resolved for.

A module can also read `Withdrawn`. That means an advisory matched it, and the
advisory was later retracted upstream. `Withdrawn` is not `Clean`. `Clean` means
no advisory ever applied. kanonarion lists withdrawn modules in their own section
with the retraction date, and keeps them out of the `Affected` count.

Every command takes `--json`. To make JSON the default, run
`kanonarion config set preferences.json true`. With `--json`, the `inspect`
summary also carries a `directives` and a `godebug` section. They report
`replace` and `exclude` directives, and `//go:debug` settings, in your own
project. Empty lists mean kanonarion looked and found none.

**How long it takes.** This is the one slow step.

| Run | Measured | What takes the time |
|---|---|---|
| First run, empty store | ~16 min | resolving the require graph, then downloading, verifying and extracting every module zip, then fetching the advisory database and scanning |
| Later run, warm store | ~17 s | kanonarion checks its records instead of measuring again |

Cost grows with the number of dependencies, and it grows fast. One large project
(velociraptor, 594 modules) took about 45 minutes for its first full run. Plan
for your own dependency count, not for the numbers above.

**Memory.** kanonarion needs a lot of memory. On this project, a warm re-run
peaked at 3,679 MB. A first run does more work than that, so treat 3,679 MB as a
floor and not as a budget. The vulnerability scan uses the most, because
`govulncheck` type-checks every module. The figure also depends on the machine:
kanonarion analyses one module per core at once, and this one has 32 cores.
Fewer cores means less memory. If the machine runs out of memory, kanonarion
marks that module `Unscannable` and carries on. It never reports it as clean.

**Progress.** During the walk and extract stages, `inspect` prints one progress
line to stderr about every 20 seconds, such as
`walk progress: 142 modules fetched (3m20s elapsed)`. A gap between lines is
normal. It is not a hang. Pass `--no-progress` to silence it, or
`--log-level info` to see every module. stdout and `--json` never change.
`--no-progress` works on `walk`, `inspect`, `extract`, `vuln-scan`,
`vuln-scan-rescan`, `audit` and `sbom`.

That was the slow step. Every command below reads the local store, or
analyses your own working tree. Only `audit` still uses the network, when it
asks upstream for the latest version of a module.

### 3. Read one module: `context`

```bash
kanonarion context
```

Bare `context` prints one block per module in your code scope. That is the same
set of modules bare `inspect` filled in, so the two commands fit together:
nothing you see here is unanalysed. On this project that is 20 modules, and it
takes about 13 seconds.

For one module at a time:

```bash
kanonarion context github.com/spf13/cobra@v1.8.1
```

This prints the same block you read in step 2, in about 40 milliseconds.

Add `--json` to get the whole record instead of the summary: verification,
provenance, direct dependencies, licence with its obligations and copyright
lines, public interface, call graph, examples and vulnerabilities. The JSON also
carries a `commands` section, which names the exact command for each part.

`context --json` always prints one JSON object. The per-module records are in
its `modules` list, whether you asked about the whole project or named one
module. Beside them the object says which dependency scope was read, how many
modules that was, and which build the vulnerability answers came from. The JSON
is large. For all 20 modules of this project it is 1.6 MB. When you feed an LLM,
ask for one module at a time.

### 4. One line per dependency: `audit`

```bash
kanonarion audit
```

`audit` prints one line per module in your code scope: the coordinate, how
kanonarion verified it, its SPDX licence, how far behind the latest version it
is, its vulnerability status, and the policy outcome.

```
github.com/CycloneDX/cyclonedx-go@v0.11.0                            Verified               Apache-2.0               latest: v0.12.0 (4 days ago)   Clean  allow [permissive]
github.com/dustin/go-humanize@v1.0.1                                 Verified               MIT                      current                        Clean  allow [permissive]
github.com/google/licensecheck@v0.3.1                                Verified               BSD-3-Clause             current                        Clean  allow [permissive]
github.com/google/uuid@v1.6.0                                        Verified               BSD-3-Clause             current                        Clean  allow [permissive]
github.com/klauspost/compress@v1.19.0                                Verified               BSD-3-Clause [Multiple]  latest: v1.19.2 (21 days ago)  Clean  allow [permissive]
github.com/oklog/ulid/v2@v2.1.1                                      Verified               Apache-2.0               latest: v2.1.2 (34 days ago)   Clean  allow [permissive]
github.com/remyoudompheng/bigfft@v0.0.0-20230129092748-24d4a6f8daec  Verified               BSD-3-Clause             current                        Clean  allow [permissive]
github.com/rogpeppe/go-internal@v1.15.0                              Verified               BSD-3-Clause             latest: v1.16.0 (56 days ago)  Clean  allow [permissive]
github.com/spf13/cobra@v1.10.2                                       Verified               Apache-2.0               current                        Clean  allow [permissive]
github.com/spf13/pflag@v1.0.10                                       Verified               BSD-3-Clause             current                        Clean  allow [permissive]
go.uber.org/goleak@v1.3.0                                            Verified               MIT                      current                        Clean  allow [permissive]
golang.org/x/mod@v0.40.0                                             Verified               BSD-3-Clause             current                        Clean  allow [permissive]
golang.org/x/sync@v0.22.0                                            Verified               BSD-3-Clause             current                        Clean  allow [permissive]
golang.org/x/sys@v0.47.0                                             Verified               BSD-3-Clause             current                        Clean  allow [permissive]
golang.org/x/tools@v0.49.0                                           Verified               BSD-3-Clause             current                        Clean  allow [permissive]
gopkg.in/yaml.v3@v3.0.1                                              Verified               MIT [Multiple]           current                        Clean  allow [permissive]
modernc.org/libc@v1.73.5                                             Verified               BSD-3-Clause             latest: v1.75.6 (today)        Clean  allow [permissive]
                                                                                                                     newer major: modernc.org/libc/v2@v2.1.30
modernc.org/mathutil@v1.7.1                                          Verified               BSD-3-Clause             current                        Clean  allow [permissive]
modernc.org/memory@v1.11.0                                           Verified               BSD-3-Clause             latest: v1.12.1 (7 days ago)   Clean  allow [permissive]
modernc.org/sqlite@v1.53.0                                           Verified               BSD-3-Clause             latest: v1.57.0 (7 days ago)   Clean  allow [permissive]
stdlib@v1.26.6                                                       VerifiedGoDevChecksum  BSD-3-Clause             unmeasured (toolchain-pinned)  Clean  allow [permissive]

latest as of 2026-08-27 01:12 UTC (staleness.ttl 1h0m0s; `latest --fresh` to re-query)
```

The default scope is `code`. Pass `--tool` for the tooling supply chain, or
`--project` for both. A status such as `ScanFailed` appears on its own line.
kanonarion never hides it behind the roll-up.

The report has a `stdlib` row for the Go standard library, so you triage a
toolchain CVE like any other dependency. kanonarion verifies it the same way: it
fetches the source tarball from `go.dev/dl` and checks it against Go's published
checksum. The version comes from your live toolchain (`go env GOVERSION`). Pass
`--stdlib-from-gomod` to use the `go.mod` directive instead. See
[the SBOM standard-library chain of custody](cli/sbom.md#standard-library-chain-of-custody).

**How long it takes.** A warm `audit` takes about 1 second. The first `audit`
after an `inspect` costs more, because it extracts any licence records that are
still missing and asks upstream for the latest version of each module.

The vulnerability answer is **project-rooted**: one `govulncheck` run over your
live working tree. kanonarion does not measure it every time. It reuses a stored
run when nothing that matters has changed, and it names the run it reused.
`--force` measures again. The exact conditions are in
[reuse and re-derivation](cli/audit.md#reuse-and-re-derivation).

The staleness column also reuses recent lookups. It always prints the time of the
lookup it used, so you cannot mistake a stored answer for a live one.
`latest --fresh` asks upstream again.

A Go module's next major version lives at a different module path. So the
staleness column reports up to three separate facts, and never merges them: the
latest version at this path, a republication of the same major version at its own
`/vN` path (`same major republished: .../v3@v3.3.5`), and the newest major path
above the one you pin (`newer major: .../v5@v5.3.1`). See
[`docs/cli/audit.md`](cli/audit.md).

### 5. Ask questions: drill-downs

Every command in this section reads records that are already in the store.
Nothing here analyses anything again. They all work once you have run steps 2
to 4.

They do not all cost the same.

- Reading one record (`license-compat`, `vuln-show`, `interface-show`,
  `dependents`) takes tens of milliseconds.
- Walking the call graph (`callers`, `callees`, `implementers`) takes well under
  a second on this store.
- Following the graph transitively (`--transitive`) is much slower. A depth-3
  caller traversal over 544 nodes took 67 seconds. Always pass `--depth`.

**Can I ship this module and everything it depends on?**

```bash
kanonarion license-compat github.com/spf13/cobra@v1.8.1
```

```
github.com/spf13/cobra@v1.8.1: closure is compatible with Apache-2.0 (data v1.1.0, walk 01KZWK6GHN7CK9Y54YTHMTNRKJ, frame not-platform-scoped)
```

Without `--target`, kanonarion compares the closure against the module's own
licence. Pass `--target <SPDX id>` to compare it against the licence you ship
under.

**What does the vulnerability record say?**

```bash
kanonarion vuln-show github.com/spf13/cobra@v1.8.1
```

```
github.com/spf13/cobra@v1.8.1 — Clean
  Walk:            01KZWK6GHN7CK9Y54YTHMTNRKJ
  Analysis frame:  target-rooted:github.com/spf13/cobra@v1.8.1
  Toolchain:       go1.26.5
  First validated: 2026-08-27T01:09:38Z
  Last validated:  2026-08-27T01:09:38Z
  Snapshot:        vuln.go.dev@2026-08-21T20:38:00Z
  Advisories:      4291 in the snapshot scanned against
  Snapshot age:    retrieved 2026-08-25T03:40:11Z (1 day(s) old at validation)
  No findings.
```

**What is the module's public API?**

```bash
kanonarion interface-show github.com/spf13/cobra@v1.8.1
```

**What in my build pulls this module in?**

Use any coordinate from the `audit` table in step 4.

```bash
kanonarion dependents github.com/spf13/pflag@v1.0.10
```

```
notice: ./go.mod names the build, so the answer below is walk 01M0RGVEZH7BN09G63JX3B1X88 (code scope, frame linux/amd64) rooted at github.com/eitanity/kanonarion@local; the require directives in ./go.mod agree with that walk, though the manifest was not re-resolved through the toolchain for this read; the store holds 2 walks of this target in the code scope on linux/amd64 under go1.26.6 and none was named, so this one was chosen — name one with --walk-id to choose it yourself
1 module(s) in walk 01M0RGVEZH7BN09G63JX3B1X88 (frame linux/amd64) depend on github.com/spf13/pflag@v1.0.10 (the walk root does; it is excluded by default — pass --include-root):
  github.com/spf13/cobra@v1.10.2  [direct]
```

**Who calls this symbol, and what does it call?**

```bash
kanonarion callers 'github.com/spf13/pflag.NewFlagSet'
kanonarion callees 'github.com/spf13/cobra.(*Command).Execute'
```

These search every module in the store, including other projects you have
analysed. Add `--gomod ./go.mod` to keep the answer inside this project's build.

Results from `_test.go` files carry a `[test]` tag. Pass `--exclude-tests` for
the production-only view. kanonarion then states what it narrowed, so you cannot
read a narrow answer as a wide one:

```bash
kanonarion callees 'github.com/spf13/cobra.(*Command).Execute' --exclude-tests
```

```
3 callees of github.com/spf13/cobra.(*Command).Execute:
  github.com/spf13/cobra.(*Command).ExecuteC  [Direct]  (github.com/spf13/cobra@v1.10.2)
  github.com/spf13/cobra.(*Command).ExecuteC  [Direct]  (github.com/spf13/cobra@v1.4.0)
  github.com/spf13/cobra.(*Command).ExecuteC  [Direct]  (github.com/spf13/cobra@v1.8.1)
scope: test callees omitted (--exclude-tests was given)
```

**Which concrete types satisfy this interface?**

```bash
kanonarion implementers 'github.com/spf13/pflag.Value'
```

A text search for the method name does not answer this. It cannot tell an
implementation from a call, and it misses types that satisfy the interface by
embedding.

**Read the answer line.** When `callers`, `callees` or `implementers` find
nothing, they say which kind of nothing it is:

```bash
kanonarion callers 'github.com/google/uuid.NewDCEGroup' --exclude-tests
```

```
No callers found for github.com/google/uuid.NewDCEGroup
answer: RESOLVED-ABSENT — no callers of github.com/google/uuid.NewDCEGroup across a fully-built path (production only; --exclude-tests was given)
```

`RESOLVED-ABSENT` is a measurement. You may report it as "nothing calls this".
`UNRESOLVED` means the graph could not decide, and the line names what stopped
it. Never read `UNRESOLVED` as "nothing calls this".

### 6. Add your own code: `local`

`callers`, `callees` and `implementers` only see modules kanonarion has analysed.
To ask about symbols in your project's own packages, ingest the working tree:

```bash
kanonarion local .
```

```
github.com/eitanity/kanonarion@local: Extracted — 14819 nodes, 198790 edges [CHA] (cached)
```

That is 14,819 nodes and 198,790 call edges for this codebase. 8,584 of the
nodes are declarations in `_test.go` files.

The first analysis takes about 11 seconds. After that kanonarion re-reads the
tree, and if nothing changed it serves the stored record in under a second. The
`(cached)` note above says that is what happened. Any edit to your source, to
`go.mod` or to `go.sum` starts a new analysis. `--force` always starts one.

Now you can ask about your own symbols:

```bash
kanonarion callers '<module-path>/internal/server.New'
kanonarion callers '<module-path>/internal/server.New' --exclude-tests
```

Test files are part of the graph. When you change a signature, most of the code
you have to fix is in tests.

Interfaces your own code declares work too. One query tells you every type you
have to change:

```bash
kanonarion implementers '<module-path>/internal/vuln/ports.VulnerabilityStore'
```

**Which dependency symbols does my code actually use?**

```bash
kanonarion context . --symbol
```

This type-checks your project with `go/packages`. It takes under a second with a
warm Go build cache, and about a minute when the cache is cold.

**Can a stored vulnerability finding be reached from my code?**

```bash
kanonarion reachability --local .
```

```
local reachability probe of /home/mb/dev/kanonarion
  module:    github.com/eitanity/kanonarion
  snapshot:  local-5f4438c9453f312e903b0c61eb5cbef18633b072bdbe9ef4f1586e0ecf00a384 taken 2026-08-27T01:33:16Z
  seed:      seed restricted to stored records measured in this tree's own frame (rooted at github.com/eitanity/kanonarion) or in the isolated frame; records measured in another consumer's build were not read
  notice:    no stored vulnerability findings for the 18 module(s) of this build the store holds a record for

coverage: 18 build module(s), 18 queried, 18 covered, 0 with findings

no affected modules in the analysed build
```

This probe reads only records measured in your own tree's frame, and says so.
When there are findings to probe, it walks the call graph from your code to the
affected symbols, which takes about 30 seconds.

### 7. `not_run` and `not_fetched`: unknown is not zero

kanonarion never presents a missing analysis as a confident negative. Every
`context` section is always present in the output, and always carries a status. A
query over data nobody has analysed exits non-zero and names the command that
would analyse it:

```
error: execute root command: symbol "github.com/hashicorp/go-multierror.Append" is not in the call-graph store: its module has not been analysed (consumer-mode code). Analyse it first, e.g.:
  kanonarion callgraph <module>@<version>
```

| Status | Meaning | What to run next |
|---|---|---|
| `not_fetched` | kanonarion has never fetched this module | `kanonarion fetch <mod>@<ver>`, or `inspect <mod>@<ver>` to run every stage |
| `not_run` | The module is fetched, but this extraction stage has not run | `kanonarion extract <walk-id>`, or the stage command (`license`, `interface`, `callgraph`, `examples`) |
| `read_error` | The store returned an error while reading the record | Read the `error` field; `kanonarion store` inspects the store |
| Empty list, status `succeeded` | kanonarion analysed it and found nothing | Nothing. This is a real answer |

The difference matters. An empty `vulnerabilities` list under
`"status": "not_run"` means *we have not looked*. It does not mean *there are
none*.

---

## Part 2 - Suggested agent prompt

Paste the block below into an agentic coding session (Claude Code, or similar)
that is working on a Go project. It is self-contained.

````text
When answering questions about this Go project's dependencies - licences,
vulnerabilities, API surfaces, call graphs, who-uses-what - use the
`kanonarion` CLI instead of `go list`, `go mod graph`, reading the module
cache, or answering from memory. Run commands from the project root, the
directory that contains go.mod.

Pass `--json` and parse the output, with one exception noted below.

One-time population. This is network-bound and memory-hungry. It measured
~16 minutes on a 20-module project, whose warm re-run peaked at 3,679 MB on a
32-core machine; a first run does more. Both numbers grow fast with dependency
count: a 594-module project measured ~45 minutes. Memory also grows with core
count, because kanonarion analyses one module per core at once. Set your timeout
and memory limit from THIS project's dependency count, generously, for example
30+ minutes, and do NOT kill the run. It prints a progress line to stderr about
every 20 seconds during the walk and extract stages, such as
`walk progress: 142 modules fetched (3m20s elapsed)`. A gap between those lines
is normal, not a hang. Read stdout for the result. Use
`--no-progress` to silence the heartbeat, or `--log-level info` for per-module
detail. A re-run on a warm store takes seconds.

    kanonarion inspect --json

Then answer questions from these. All of them read the local store.

    kanonarion context --json                      # every module, ~13s. One JSON object;
                                                   # the records are in .modules
                                                   # 1.6 MB for a 20-module project
    kanonarion context <module>@<version> --json   # one module, ~40ms. Same object,
                                                   # one record in .modules
    kanonarion audit --json                        # one line per module: licence, vuln,
                                                   # staleness. Records in .modules.
                                                   # ~1s warm
    kanonarion license-compat <module>@<version> --json
    kanonarion vuln-show <module>@<version> --json
    kanonarion interface-show <module>@<version> --json
    kanonarion dependents <module>@<version> --json   # what in this build requires it
    kanonarion callers '<pkg.Symbol>' --json       # --exclude-tests for production only;
                                                   # --gomod ./go.mod to stay in this build
    kanonarion callees '<pkg.Symbol>' --json
    kanonarion implementers '<pkg/path.Interface>' --json  # also accepts
                                                   # '<pkg/path.(Interface).Method>'
    kanonarion local .                             # ingest the working tree so the three
                                                   # queries above resolve internal
                                                   # symbols. ~11s; an unchanged tree is
                                                   # served from the stored record.
                                                   # Do NOT add --json here: it emits
                                                   # 77 MB for a one-line result
    kanonarion context . --symbol --json           # which dependency symbols this tree uses
    kanonarion reachability --local . --json       # can a stored finding be reached from
                                                   # this tree? ~30s when there is
                                                   # something to probe

Exit codes you must branch on:

    license-compat  0 clean
                    1 conflicts
                    2 unknown licence pairs, or a pending dual-licence election
                    4 either there is no walk rooted at that coordinate, or the
                      walk exists but the root has no licence record. These are
                      different problems. The diagnostic says which one it is and
                      names the command that fixes it: `kanonarion walk <coord>`
                      for the first, `--target <SPDX>` or an `--analyse-root`
                      walk plus `extract` for the second.
                   20 bad invocation

Interpretation rules. These are load-bearing.

1. Unknown is not zero. A context section with "status": "not_run" or
   "not_fetched" means the analysis has not happened. It does NOT mean the
   result is empty. Never report "no vulnerabilities" or "no licence issues"
   from a not_run or not_fetched section. Run the command the status implies
   (not_fetched: fetch or inspect the module; not_run: extract) and ask again.
2. Queries over unanalysed data exit non-zero and print the command to run.
   Run that command, then repeat the query. An empty result with exit 0 over
   analysed data is a real zero. Report it as one.
3. Read the answer line on callers, callees and implementers, not just the
   list. RESOLVED-ABSENT is a measurement and you may report it as "nothing
   calls this". UNRESOLVED is not an answer: the graph could not decide, and
   the line names what stopped it. Relay that. Never turn it into a confident
   negative. Results tagged [test] come from test files. Pass --exclude-tests
   when the question is about production code, and say that is what you
   measured.
4. license-compat exit code 2 means licence pairs outside the modelled data
   set. Report "needs human review". Never report "compatible".
5. kanonarion reports facts and labelled inferences, not verdicts. Relay its
   statuses. Do not upgrade them to judgements it did not make.
````

---

## Where to go next

- [`docs/cli/reference.md`](cli/reference.md) - one reference page per command.
- [`docs/cli/conventions.md`](cli/conventions.md) - output conventions, exit
  codes, configuration layering, store discovery.
- [`docs/cli/context.md`](cli/context.md) - the full schema of the `context`
  output used throughout this guide.
