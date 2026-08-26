# kanonarion CLI conventions

Shared semantics that apply across every `kanonarion` subcommand:
configuration layering, depth policy, on-disk layout, and exit codes.
Per-command pages link back here instead of restating these rules.

## Global conventions

- All commands write logs to **stderr** and data to **stdout**.
- Pass `--json` to get machine-readable output on stdout. Log lines remain on stderr.
- `--store-root` defaults to `~/.kanonarion`. It holds the SQLite database, blob store, sumdb cache, audit log, and `config.yaml`.
- The `<module@version>` argument follows standard Go module coordinate syntax, e.g. `github.com/spf13/cobra@v1.8.1`.

### Layered configuration

Flag values take precedence over store config, which in turn takes precedence over built-in defaults:

```
flag > <store-root>/config.yaml > built-in default
```

On first run kanonarion writes a fully commented `config.yaml` to your store root with all defaults populated. Edit it to set sticky preferences. When a new binary version adds sections, they are appended non-destructively on the next invocation - existing content and comments are preserved.

To inspect the effective configuration:

```
kanonarion store config show          # raw file with comments
kanonarion store config show --json   # parsed effective config as JSON
```

```yaml
version: "1"
preferences:
  json: false
  log_level: warn
license_policy:
  categories:
    permissive:      [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
    weak_copyleft:   [LGPL-2.1-only, LGPL-3.0-only, MPL-2.0]
    strong_copyleft: [GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only, AGPL-3.0-only]
    restricted:      [SSPL-1.0, BSL-1.1, AGPL-3.0-only]
  rules:
    - scope: production
      allow:   [permissive]
      notify:  [weak_copyleft]
      warn:    [strong_copyleft, restricted]
      default: allow
      unknown_license: block
    - scope: tool
      allow:   [permissive, weak_copyleft, strong_copyleft]
      notify:  [restricted]
      default: allow
      unknown_license: warn
license_overrides:
  # golang.org/x/mod: MIT
copyright_declarations:
  # example.com/mod:
  #   copyright: "Copyright 2019 Example Authors"
  #   declared_by: "you@example.com"
  #   declared_on: "2026-01-31"
  #   basis: "LICENSE header at example.com/mod v1.2.3, read 2026-01-31"
callgraph:
  exclude: []
```

Policy outcomes for a *resolved* licence are `allow`, `notify`, and `warn`. Categories not listed in any outcome list resolve to `default`; an absent `default` resolves to `allow`. The same implicit allow applies when no rule exists for a scope.

An *undetermined* licence - one the detector could not resolve to any SPDX identifier at all - does not fall through to `default`. It is governed by `unknown_license`, the per-scope unknown-licence gate, which is the one setting that can fail a build: `block` makes an undetermined dependency a hard compliance failure and `audit` exits `5`. Left unset it resolves to `block` for `scope: production` and `warn` for every other scope, so uncertainty fails closed rather than being reported as a clean allow. See [`config`](config.md#license_policyrulesunknown_license---the-unknown-licence-gate) for the four values and `kanonarion config show` for the value in force.

---

## Depth policy

Walk behaviour is governed by a depth policy file (YAML). kanonarion searches for `.kanonarion/policy.yaml` starting from the current directory and walking up to the filesystem root. If no file is found, built-in defaults are used.

**Policy file format**

```yaml
version: "1"
stages:
  fetch:
    max_depth: 0        # 0 = unlimited
    follow_replace: true
    follow_test: false
    follow_indirect: true
```

The `stages` map is keyed by stage name. Only `fetch` is used in Phase 1; additional stages (`licence`, `interface`) will be consumed in later phases and are preserved for forward compatibility.

Example policies are available in `docs/examples/policies/`.

---

## The build frame

A walk records the `GOOS`/`GOARCH` it resolved for **and the Go toolchain that
resolved it** (`go env GOVERSION` in the project's own directory, after any
`toolchain` directive or `GOTOOLCHAIN` switch). One store can hold walks of the
same project for several platforms — a cross-compiled release run produces one
per target — and for several toolchains, because which `go` leads `PATH` decides
which one a walk records. The two kinds of command behave differently:

**Commands that run analysis over a walk** select the walk resolved in the
current environment — both the platform and the toolchain — not the newest one.
This covers `vuln-scan --gomod` (and `--tool`/`--project`), `vuln-scan
<module@version>`, and `sbom --package` without `--force`.

The toolchain is part of the question because the walk names the standard
library the project links, and the standard library is what toolchain advisories
are judged against. Answering from a walk resolved by a different toolchain
reports the advisories of a Go release the project does not compile with — and
because a newer patch release clears advisories, the error runs towards a clean
answer.

`vuln-scan` refuses when no such walk exists, naming the build and the
command that produces one:

```
no succeeded code project walk for example.com/myapp on darwin/arm64 under go1.26.5 — run: kanonarion walk --gomod ./go.mod
```

When the `go env` probe cannot answer, the toolchain is not pinned at all rather
than pinned to "unrecorded": the read widens to any toolchain and names the one
the walk it selected was resolved by.

`sbom --package` builds the missing walk itself in the current frame rather
than refusing.

To scan or inventory another platform's walk deliberately, name it by ID:
`kanonarion vuln-scan <walk-id>`.

**Query commands** (`inspect`, `license`, `license-compat`, `context`,
`dependents`, `interface-diff --used-by`, `callers`/`callees`/`implementers`
with `--gomod`) answer from one walk of the target whatever its platform, and
state which frame answered:

```
Walk ID:  01KQDBVW092ER1HNXZ60X27CMD
Frame:    linux/amd64
```

A module-rooted walk resolves no platform and reads `not-platform-scoped`; an
unknown platform reads `unrecorded`. JSON carries the token in `frame` /
`walk_frame` and the basis (`platform`, `not_platform_scoped`, `unrecorded`)
in `frame_basis` / `walk_frame_basis`.

Where such a command chooses among walks that were **resolved by different
toolchains**, it names the one it chose, because that choice decides which
standard library the answer is about:

```
notice: no walk was named and the store holds 2 for this target, so one was chosen: walk "01M0RE94X8VJ8C0PT9Z3VJJQ0S" (frame linux/amd64), the most recent — ...; the candidates were resolved by go1.26.5 and go1.26.6 and this one by go1.26.6, which is the standard library the answer is about; pin one with --walk-id ...
```

Where every walk of the target was resolved by one toolchain there is nothing to
have chosen and nothing is said. `walk-list --json` carries the toolchain as
`go_version`, and `walk-list --latest` returns one walk per
`(target, scope, toolchain)` rather than one per `(target, scope)`.

---

## The default walk

Every query command that answers in a walk takes a selector — `--walk-id`, or
`--gomod` for the ones that start from a manifest. Where none is given the walk
is chosen, by this rule:

1. the most recent walk whose recorded resolution still agrees with the
   `go.mod` on disk — the path `--gomod` named, or the project directory the
   walk itself recorded;
2. failing that, the most recent walk.

Under `--gomod` the rule ranks **within one build**, never across builds. The
candidates are the succeeded walks of that project in the **scope** the command
asked for — the caller's `--tool` / `--project` where the command has them,
otherwise `code` — resolved for **this platform**. One project walked in three
scopes is three different module sets (measured on this repo: 22, 246 and 474
modules), so ranking them together by recency answers whichever was walked last.

Where no walk matches, the command **refuses and names the remedy**, and the
refusal distinguishes "no walk of that scope" from "no walk at all":

```
error: no succeeded code project walk for example.com/myapp on linux/amd64, though the store holds 2 succeeded walk(s) of it (complete on linux/amd64, tool on linux/amd64); a walk of another scope or platform is a different build, so it does not answer here — run: kanonarion walk --gomod ./go.mod
```

The **toolchain is not** part of this selection. Two walks under two toolchains
link different standard libraries, so this narrowing is not complete: among the
walks of one scope and platform, recency still decides which toolchain's walk
answers. The choice states the toolchain it landed on whenever the candidates
disagreed, which is the disclosure offered in place of a filter.

The choice is always stated when there was one to make: a store holding one walk
of the target says nothing, and a store holding several says which walk answered
and which of the two rules picked it. The statement names the scope and platform
the candidates were counted in, because a count of "1 walk of this target" would
otherwise be read as a count of every walk of it. Under `--json` the same facts
are a `walk_selection` object — `candidates` beside `candidate_set` — rather
than a line, and every `notice:` line that names a walk names its scope beside
its frame.

Rule 1 exists because recency alone answers from the wrong build after any
rehearsal. A walk taken while a manifest was temporarily edited stays the newest
walk of that project after the tree is restored: re-walking an unchanged
resolution reuses the existing record rather than writing a newer one, so the
walk that matches the tree is permanently the older row. Recency alone would
serve the rehearsal forever, and only `walk --force` could displace it.

The comparison parses the manifest's `require` directives and checks them
against the walk's recorded module versions. It is not a re-resolution through
the toolchain — the commands that MEASURE (`vuln-scan --gomod`) pay that, and
say so — so a read still states that the manifest was not re-resolved. A module
the manifest requires that the walk does not carry is not a disagreement: that
is the difference between a `code` walk and a `complete` one, and only a version
both name differently counts.

The eight most recent walks are compared. When none agrees, the answer says so
and names the disagreement.

---

## The default licence record

`provenance` answers from a licence record rather than a walk, and follows the
same discipline. With `<module>@<version>` the record is that coordinate's.
Without a version the record is the one for the **newest version** the store
holds — never the most recently extracted, which changes the stated basis
whenever an unrelated walk lands.

The choice is stated when there was one to make: a module the store holds one
version of says nothing, and a module it holds several of says which versions
were candidates, which one answered, and how to pin a different one. Where the
candidates disagree about the copyright signal, the disagreement is reported
instead of being resolved by picking. Under `--json` the same facts are a
`selection` object.

---

## Modules resolved under pre-modules semantics

A module that reached major version 2 or above without adopting Go modules is
resolved with the `+incompatible` suffix, and the go command **ignores its
`go.mod` entirely**. No requirement edge is ever resolved under such a
coordinate: a walk of one records its own node and no edges, and inside a
project walk its dependencies are either absent or attributed to whichever
consumer also requires them.

The record is honest — it holds exactly what the module system resolved — so
every answer surface that reads dependency structure or version identity states
the limitation rather than letting an empty list read as a measurement:

```
caveat: 1 module(s) in this walk resolved under pre-modules semantics
(github.com/Masterminds/sprig@v2.22.0+incompatible) — the Go module system
ignores a +incompatible module's own go.mod, so no requirement edges are
resolved under it: its dependencies are ABSENT from this answer, not measured to
be none. They can therefore neither show their own dependencies nor appear as
the dependent of anything. if the project later published a /vN major it is a
proper module and resolves normally.
```

It appears on `walk-show`, `dependents` (both directions), `context`'s
dependencies section, `interface-diff`, `license-compat` and `vuln-show`; on
`audit` and `sbom` it goes to **stderr**, beside the other run-level axis lines,
so `--json` and the SBOM document itself stay exactly what they were. `latest`
needs no caveat: it already probes for and reports a newer major line, which is
the remedy the caveat can only name conditionally.

Under `--json` the same statement is a `pre_modules_caveat` object
(`coordinates`, `limitation`, `remedy`), present only when the answer is
actually bounded by one. `walk-show --json` is the exception: its stdout is the
walk record's own sealed bytes, so the caveat goes to stderr there too.

No synthetic edges are ever produced to fill the gap. The `require` directives
kanonarion pins into a synthesised `go.mod` for a pre-modules module are **scan
inputs** — see [callgraph](callgraph.md#modules-published-before-go-modules) —
and are never presented as resolved dependency edges anywhere.

---

## Zero-result listings

A record listing that returns nothing says which of three things happened,
because the remedies differ:

- **The store holds no record of that kind at all.** The line says so and offers
  the invocation that produces one.
- **A filter matched nothing.** The line names the filter, the value given, what
  that value was compared against, and how many records it was compared with —
  plus one example in the shape the comparison uses. Every filter on these
  listings is an exact-equality match on one indexed column, not a substring or
  prefix test, so a module path shortened by one segment matches nothing; the
  line states that rather than leaving it to be inferred.
- **Paging skipped past the end.** The line names the `--offset` that did it.

Every remedy printed is an invocation this CLI's own parser accepts.

Under `--json` the data channel is unchanged — an empty array is still an empty
array, so a consumer never has to branch on the row count to know the output's
type. The same statement is emitted on **stderr** as a single JSON object:

```json
{"subject":"call graph record","filter":{"name":"module path","value":"no-such-module","compared_against":"module path, compared for exact equality"},"records_considered":312,"store_empty":false,"paged_past":false,"remedy":["kanonarion callgraph-list"]}
```

A listing that returned rows prints no such statement, on either channel, and
performs no extra store read to decide that: the survey that sizes the corpus is
reached only once the page has come back empty.

The same statement answers a **single-record selector** that matched nothing —
a command given one name that is not in the store. Those exit `4` and carry the
statement on the error rather than on stdout, on one line, so the data channel
stays the data channel; under `--json` the object is emitted on stderr as well.
The selectors are `walk-list --walk-id`, `walk-list --latest-success`,
`directives show`, `vuln-snapshot-show`, `walk-show`, `verification-coverage`,
`dependents --walk-id`, `context --walk-id`, `walk-diff`, `vuln-scan-show`,
`examples-show`, `examples-list <module>`, `interface-show`,
`interface-list <module>`, `use`, `license --recursive` and `license-compat`.

Every command that reads a walk by ID answers a missing one with the identical
sentence, whichever command it was.

`walk-diff` takes two IDs, so it names **which** of them is missing — or both
when both are. The corpus it counts is the store's, not the two IDs it was
given.

Where the older message already carried a remedy — `use`, `license-compat`,
`license --recursive`, `examples-show`, `examples-list <module>`,
`interface-show`, `interface-list <module>` — that remedy is kept and the corpus
statement is added beside it, so the answer offers both the invocation that
produces the record and the one that lists what is there.

The survey that sizes the corpus runs only on the miss. A lookup that found its
record performs no extra read and prints no statement, on either channel.

This applies to every record listing: `callgraph-list`, `vuln-scan-list`,
`licence-list`/`license-list`, `sbom-list`, `interface-list`, `examples-list`,
`walk-list`, `extract list`, `directives list` and `vuln-snapshot-list`.

`interface-list`, `examples-list` and `extract list` take no filter, so only the
empty-store and the paged-past causes can arise on them. Given a module
coordinate, `interface-list` and `examples-list` render that one module instead
of listing, and an absent record is refused with a non-zero exit carrying the
single-record statement above: the remedy that produces it, and the corpus the
coordinate was compared against.

`vuln-snapshot-list` takes neither a filter nor a `--limit`, so it has exactly
one cause it can have and states that one: the store holds no snapshot. It does
not offer a paging remedy, because it cannot page.

`directives list` reports one project, and which of the two remaining causes it
names follows from that project's own scan count. With scans for the project,
the project is the corpus and paging is the only remaining explanation, so the
notice names the project in the subject and counts its history. With none, the
project is what excluded them: it moves into the filter slot and the count
becomes the whole store's, so "the store holds no directive scan at all" is said
only when that is what was measured. There is no store-wide directive listing —
every read is keyed on a project — so the remedy names the `--project` slot.

`store ledger` is not a record listing and states its scope its own way: a
coverage line, the `matched` count over the whole window, and how many events
the offset stepped over.

---

## Measured zeros in JSON

A scalar field whose value was measured is always present in the JSON, zero and
false included. `0`, `0.0` and `false` are answers — no direct dependencies,
no entry points in the package named, a snapshot pulled today, a route with no
registration hop on it — and a key that vanishes at those values leaves a
consumer unable to tell them from a build that does not derive the field.

Where a row can genuinely carry no answer, and no sibling field already says so,
the field is a pointer and the key is still always present, carrying `null`:

- `null` means the value was not measured for this row.
- `0` / `false` means it was measured and this is the answer.

Both statements are readable without knowing which fields a given build emits,
which is what an agentic consumer needs and prose cannot give it.

This applies to numbers and booleans only. Strings and arrays keep `omitempty`:
an empty string there means "does not apply", and the field beside it names the
state the row is in.

---

## Truncated listings

Every listing that applies a `--limit` states when the limit bit. On the text
path it prints one trailing line:

```
showing first 50 license records — more exist (--limit 0 for all, --offset 50 for the next page)
```

The line appears **only when a further record exists**. A listing that happens to
hold exactly its limit and nothing more prints nothing, so silence means "these
are all of them".

Under `--json` the array on stdout is unchanged — a consumer's payload keeps its
shape — and the same statement is emitted on **stderr** as a single JSON object:

```json
{"truncated":true,"limit":50,"subject":"license records","remedy":"--limit 0","offset":0,"next_offset":50}
```

Unlike the text line, the JSON object is emitted whenever a limit was applied,
with `truncated` true or false, so a machine reader can tell "nothing was
withheld" from "this output does not say". `--limit 0` applies no limit and
prints nothing on either channel.

**No total is reported.** The listing asks the store for one row more than it
will print and reports on that row's presence; it never counts. Knowing *that*
records were withheld costs one extra row, knowing *how many* would cost a second
read every listing would then pay.

This applies to `licence-list`/`license-list`, `interface-list`, `examples-list`,
`callgraph-list`, `vuln-scan-list`, `walk-list`, `extract list` and
`directives list`. `sbom-list` applies no limit and returns its whole population.

---

## Paging

Every command that takes `--limit` also takes `--offset`: the number of records
to skip before listing. `--limit N --offset M` returns records M+1 to M+N of the
same ordering the unpaged listing produces, so a caller told "more exist" can
read the next page instead of re-fetching the whole population and slicing it.

```
$ kanonarion license-list --limit 50 --offset 50
...
showing license records 51-100 — more exist (--limit 0 for all, --offset 100 for the next page)
```

`--offset 0` is the default and is byte-identical to passing no offset at all.
An offset past the last record returns no rows — with the zero-result notice
saying that paging, not the filter, emptied the page — rather than an error. The
last partial page states no truncation, because it withheld nothing.

Under `--json` the stderr object carries `offset` and `next_offset`, so a
consumer pages by reading `next_offset` back into the next invocation.

Every paged listing is ordered on a timestamp with the row's primary key as
tiebreak, so the ordering is total: two calls order the population identically
and a page is exactly the rows the previous page did not show.

`store ledger` pages the same way, over the events its filter matched:
`matched` still reports the whole window and the output states how many events
the offset stepped over.

---

## Store layout

All state lives under `--store-root` (default `~/.kanonarion`):

```
~/.kanonarion/
  mirror.db       # SQLite - all records (fetch, walk, callgraph, license, …)
  audit.jsonl     # append-only audit log of every fetch
  sumdb/          # go.sum database tile cache
  blobs/          # fetched module ZIP content
```

---

## Exit codes

This is the authoritative table. Every command uses these codes and no others;
where a command gives one of them a command-specific meaning it is listed below
and repeated in that command's `--help`.

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | Success |
| 1 | Partial | The work completed but is known-incomplete: walk partial, an extraction run some of whose stages failed, a call graph that measured some packages and not others, or an SBOM generated with one or more components carrying no licence identity |
| 2 | Failed | The work could not complete: walk failed, a call-graph extraction produced no graph at all, or `license-compat` found unmodelled licence pairs needing review |
| 3 | Cancelled | The context was cancelled before the work completed |
| 4 | NotFound | A record requested by ID or coordinate does not exist. The message names the command that produces it |
| 5 | Policy | A governance or publication gate fired on real findings. The scan succeeded and the finding is genuine |
| 10 | Integrity | Recorded evidence is in doubt: a record failed its content-hash check, or two records for one coordinate diverge. Every domain that stores records raises it — walk, fetch, extraction run, call graph, interface, licence, example, vulnerability, advisory snapshot, stdlib facts — and the code does not depend on which one did |
| 20 | Config | The command never got as far as an answer: malformed argument, unparseable coordinate, missing toolchain, absent policy *file*, a `config.yaml` the loader rejected, or a store whose schema is newer than this binary |

The distinction that matters to an automation caller is **4 vs 5 vs 20**. A 4
means the request was well-formed and the named remedy command fixes it. A 5
means the command did its job and the answer is one a human must accept or
reject — it must not be routed to whoever fixes broken invocations. A 20 means
the invocation itself was wrong.

### Which commands use which codes

| Code | Commands |
|---|---|
| 1 | `walk`, `inspect` (partial closure); `extract` (the run is recorded partial — the stages that ran ARE stored, and the failed-stage breakdown names the rest); `callgraph`, `local` (a `Partial` graph — it IS still an answer, and the failed packages line scopes what it does not cover); `sbom` (a component with no licence identity — the document IS still written and names it); `license-compat` (confirmed incompatible pairs); `use` (some modules with a stored artefact did not reach the module cache) |
| 2 | `walk`, `inspect` (target unfetchable); `callgraph`, `local` (no graph at all: `LoadFailed`, or a `Partial` that measured no function); `extract` (the run itself failed and produced no usable stage); `license-compat` (unknown pairs, never silently "compatible"); `license-compat` (root has a licence record but no SPDX identity); `use` (no module reached the module cache) |
| 4 | `walk-show`, `walk-list --walk-id`, `walk-diff`, `dependents`, `context --walk-id`, `verification-coverage`, `vuln-show`, `vuln --history`, `scan-show`, `snapshot-show`, `vuln-scan --snapshot`, `reachability --vuln`, `callgraph-show`, `interface-show`, `interface-list`, `examples-show`, `examples-list`, `license`, `license-compat`, `license-diff`, `directives-show`, `directives-diff`, `use`; `vuln-scan-show` (a run the store holds, some of whose modules produced no record this build serves — the report is still printed) |
| 5 | `audit` (unknown licence blocked by policy), `directives`, `godebug`, `vendor`, `fips`, `notice` (modules require human review) |
| 10 | any command consuming a record whose content hash does not verify, or that meets two records for one coordinate which disagree — a walk node, a fetched artefact, an extraction run, a call graph, an interface, a licence, an example, a vulnerability record, an advisory snapshot or the stdlib facts. A store-inspection command reports the same condition and exits 0 (see [Store layout](#store-layout)); a consuming command fails closed |
| 20 | every command, for a malformed invocation, or for a `config.yaml` the loader rejected (except `config init`/`show`/`get`/`set` and `store config show`, which are how the file is seen and repaired — see [`config`](config.md#when-the-config-file-is-rejected)) |

A policy gate is only a 5 when it *fired on findings*. A policy **file** that
cannot be found or parsed is a 20 — that is a broken invocation, not a verdict.

### Store schema newer than the binary

Every command that writes to the store refuses to run when `mirror.db` carries
schema migrations the binary does not know — that is, when the store was last
written by a newer build of kanonarion. Exit code is **20**: the store is intact
and a current binary reads it fine, so this is a precondition failure, not a
record-integrity failure (10).

The refusal names the unrecognised migrations and the remedy, which is to upgrade
kanonarion. `kanonarion store info` is exempt: it opens the store without
applying migrations and never writes, so the command that diagnoses the refusal
stays available. This mirrors how a divergence is handled — a store-inspection
command reports and exits 0 while a consuming command fails closed.

Running an older binary against a newer store without this gate is not a
harmless no-op: writes fail per statement against tables shaped by a later
build, so a scan can complete, print a summary and have persisted nothing.
