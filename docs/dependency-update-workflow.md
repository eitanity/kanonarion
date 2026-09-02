# Dependency-update workflow (self-hosted, against `./go.mod`)

A repeatable recipe for deciding **whether and how far** to bump a dependency,
using kanonarion on its own `go.mod`. The ordering is deliberate: analyse
*before* you bump, so the diff between "what you have" and "what you'd adopt" is
still available as signal. Do **not** bump to latest first - that discards it.

All commands assume a built binary (`make build`) and the default store root
(`~/.kanonarion`). Default scope is the **code** dependency set (`go list
-deps -test ./...`); add `--tool` for the tooling supply chain or `--project`
for the complete build list.

> Road-tested end-to-end on 2026-07-05 as a pre-v0.1 release check. The
> "Observed" blocks below are real output from that run.

---

## 1. See how stale you are

```bash
./kanonarion latest --gomod ./go.mod
```

Reports each direct code dependency's pinned version against the latest
published, with age. This is read-only - nothing is fetched or changed.

**Observed (7 of 20 stale):**

```
github.com/klauspost/compress@v1.18.6   latest: v1.19.0 (4 days ago)
github.com/rogpeppe/go-internal@v1.14.1 latest: v1.15.0 (78 days ago)
golang.org/x/mod@v0.36.0                latest: v0.37.0 (26 days ago)
golang.org/x/sync@v0.20.0               latest: v0.21.0 (30 days ago)
golang.org/x/sys@v0.44.0                latest: v0.46.0 (38 days ago)
golang.org/x/tools@v0.45.0              latest: v0.47.0 (9 days ago)
modernc.org/libc@v1.72.3                latest: v1.73.5 (8 days ago)
modernc.org/sqlite@v1.50.1              latest: v1.53.0 (13 days ago)
```

Everything else printed `current`. Add `--tool` to include the linter/tooling
supply chain in the staleness report.

---

## 2. Build the dependency graph

Needed once per session so extraction, call-graph, and vuln stages have a graph
to work against. Rooted at the local module (`target: local`), the set equals
`go list -deps -test ./...`.

```bash
./kanonarion walk --gomod ./go.mod --json > walk.json
WALK_ID=$(./kanonarion walk-list --latest-success --json | jq -r '.id')
```

`--latest-success` filters to succeeded walks and emits a single object, so a
failed/empty walk can never leak into `$WALK_ID`.

**Observed:** `overall_status: 0`, 21 nodes, 50 edges, `partial: false`.

---

## 3. Signature diff - *how much* changed, and is it breaking?

`interface-diff` compares two stored interface records and reports what the
exported surface added, removed and changed. Both records must be extracted
first, and a version can only be extracted once it has been fetched - each
command names the one before it when its input is missing.

```bash
# Candidate not in the store yet? The error names the fix:
#   error: ... module not fetched: golang.org/x/mod@v0.37.0: run 'kanonarion fetch golang.org/x/mod@v0.37.0' first
./kanonarion fetch golang.org/x/mod@v0.37.0

# Extract + persist the interface record for each version.
for v in v0.36.0 v0.37.0; do
  ./kanonarion interface golang.org/x/mod@$v --json >/dev/null
done

./kanonarion interface-diff golang.org/x/mod@v0.36.0 golang.org/x/mod@v0.37.0
```

Read it as: `removed` and `changed` are **breaking** - the bump is a refactor,
not a one-liner - while `added` is new surface you can adopt at your own pace.
Two categories are deliberately outside the breaking count: a signature that
differs only in a spelling the language treats as identical (`interface{}`
rewritten as `any`, a result that stopped being named) is reported as
`spelling`; and across a major-version path pair (`example.com/lib` against
`example.com/lib/v2`) a declaration that only moved import path is reported as
`renamed-path`. `renamed-path` is not breaking but still obliges an import
rewrite, which the output states on its own line.

A zero-breaking result is not a safety judgement. The comparison reads exported
signatures, so a release that changes no signature at all can still change what
your calls return; where the delta is non-empty the output says so where the
zero is printed.

**Observed (`x/mod` v0.36.0 → v0.37.0):** one addition (`SetRequireAtMostTwo`),
nothing removed or changed. Purely additive: adopting v0.37.0 cannot break
existing call sites on signature grounds.

See [interface-diff](cli/interface-diff.md) for the category table, the JSON
shape and the exit codes.

---

## 4. Call tree - does the change *matter to us*?

Ingest the local working tree once, then ask whether our code reaches the
symbol(s) the bump touches. `callers` walks up (who reaches it), `callees`
walks down (what it reaches).

```bash
./kanonarion local .

# Which of the breaking deltas from §3 does our own code call?
./kanonarion interface-diff golang.org/x/mod@v0.36.0 golang.org/x/mod@v0.37.0 \
  --used-by ./go.mod

# Do we reach a particular dependency symbol at all, and from where?
./kanonarion callers 'golang.org/x/mod/modfile.Parse'
./kanonarion callees 'golang.org/x/mod/modfile.Parse'
```

`--used-by ./go.mod` resolves the module that `go.mod` declares to its latest
succeeded project walk and asks the **stored** call graph which of the breaking
deltas your own code calls, so its answer cannot disagree with `callers` on the
same symbol. Each breaking delta comes back reached (with the call sites and the
functions that hold them), not reached, or unmeasured - types, constants and
variables have no call-graph node, so the call graph cannot answer for them.
Edges owned by other dependencies are excluded.

Two nuances change how far that answer reaches. The join is measured over
recorded **call edges**, so a method referenced as a value rather than called is
not counted and a symbol shown as not reached may still be referenced that way.
And where the project has no stored call graph the run says the reach could not
be measured and names `kanonarion local .`, rather than reporting a count of
zero.

`interface-diff --used-by` exits `5` when a breaking change falls inside the
used set - the gate to run in CI, distinct from `20` for a bad invocation and
`4` for a record that is not in the store.

**Observed:** `local .` ingested 2808 nodes / 19401 edges (CHA). `modfile.Parse`
has **17 callers in our tree** across `internal/cli`, `walk`, `directive`,
`vuln`, `fips`, `vendortree`, `fetch` - this dependency is load-bearing, so its
changes warrant attention. Conversely the *new* symbol `SetRequireAtMostTwo`
has no callers here, so the additive change is inert for us today.

Combined read from §3 + §4: a large signature diff in code you never call is
cheap to adopt; a small one directly under live callers is not. Here the diff
is both small **and** additive, and the touched surface is heavily used but
unchanged - a low-risk bump.

---

## 5. Vulnerabilities and reachability

Scan the project; the project-scoped scan (`--gomod`, and the same leg inside
`audit`/`inspect --gomod`) is **project-rooted** - one `govulncheck` over the
project's live working tree, with each finding attributed to the module that
owns the vulnerable symbol and every other in-build module analysed-and-clean.

```bash
./kanonarion vuln-scan --gomod ./go.mod --json > vuln.json
./kanonarion vuln-scan-show "$(jq -r .id vuln.json)"
```

**Observed:** status **`AllClean`** over 21 modules against snapshot
`vuln.go.dev@2026-06-26` - every in-build module (yaml.v3, cobra, sqlite,
x/tools, oklog/ulid, ...) reads `Clean` within the project's resolved build. No
exploitable findings surfaced. There are no `version-not-in-project-build` rows
on this path: because the scan roots at the project, no dependency is
re-resolved in isolation, so a module can never be reported un-analysable merely
for a build the project never produces. (A bare `vuln-scan <walk-id>` or
`--module` scan is the coordinate-keyed path and still scans each module in
isolation - see [vuln.md](cli/vuln.md).)

When a CVE *does* land on a dependency, gate on reachability rather than mere
presence:

```bash
# Read a stored answer computed by 'vuln-scan --reachability':
./kanonarion reachability golang.org/x/text@v0.3.7 --vuln GO-2021-0113

# Or probe the live working tree directly:
./kanonarion reachability --local .
```

An advisory in code you never reach is low urgency; one on a live call path is
not.

### Before a release: rescan against a fresh snapshot

A clean `vuln-scan` is a **point-in-time** statement - "no known advisories as of
snapshot *S*", not a timeless guarantee. Before cutting a release, re-scan the
release walk against a freshly pulled vulnerability database so the clean result
reflects the database as of the release, not whenever the walk was first scanned:

```bash
# Always pulls a fresh DB and bypasses the per-module cache, so the new
# snapshot is actually consulted (a plain re-scan would reuse cached answers).
./kanonarion vuln-scan-rescan "$WALK_ID"
./kanonarion vuln-scan-show <run-id>   # confirm: 0 affected
```

`vuln-scan-rescan` operates on a stored walk and re-scans each module on the
coordinate-keyed (isolated) path, so a project's release gate is best read from
the **affected** count. On that path a `Partial` caused only by
`version-not-in-project-build` modules is expected and not a finding; the
project-rooted `audit`/`vuln-scan --gomod` view avoids the condition entirely by
scanning the project's real build. This is the security-relevant pre-release
action; version bumps for their own sake are not (see the note below).

> A stale-but-clean set of pins is safe to ship. Prefer a fresh-snapshot rescan
> over a pre-release dependency bump: the rescan answers "are we exposed?"
> directly, while a bump introduces behavioural risk right before a release. Do
> the staleness sweep (§1-4 per module) *after* the release, unless the rescan
> turns up an advisory that a bump resolves.

---

## Decision summary

| Signal | Command | Read it as |
|---|---|---|
| Staleness | `latest --gomod` | how far behind, and how old |
| Breaking-ness | `interface` + `interface-diff` | removed/changed signature = refactor; zero breaking is not safety |
| Blast radius | `local .` + `interface-diff --used-by`, `callers`/`callees` | a breaking delta your own code calls = it matters |
| Risk | `vuln-scan` + `reachability` | reachable advisory = act; `Partial` ≠ clean |

Run reachability/callgraph against the **specific candidate version** you intend
to adopt, not against "latest" as a default - the evidence is version-specific.
