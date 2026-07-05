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

There is **no `interface-diff` command**. Extract each version's public API
(deterministic JSON) and diff those. The candidate version must be fetched
first - the tool tells you so if it isn't.

```bash
# Candidate not in the store yet? The error names the fix:
#   error: ... module not fetched: run 'kanonarion fetch' first
./kanonarion fetch golang.org/x/mod@v0.37.0

# Extract + persist the interface record for each version, then dump both.
for v in v0.36.0 v0.37.0; do
  ./kanonarion interface     golang.org/x/mod@$v --json >/dev/null
  ./kanonarion interface-show golang.org/x/mod@$v --json > iface-$v.json
done

# Compare exported symbol signatures.
for v in v0.36.0 v0.37.0; do
  jq -r '.. | objects | select(has("name") and has("signature"))
         | "\(.name)\t\(.signature)"' iface-$v.json | sort -u > sig-$v.txt
done
diff sig-v0.36.0.txt sig-v0.37.0.txt
```

Read the diff as: lines added = new API (safe to adopt), lines removed or
changed = **breaking** (return/param changed) → the bump is a refactor, not a
one-liner.

**Observed (`x/mod` v0.36.0 → v0.37.0):** one addition, nothing removed -

```
> SetRequireAtMostTwo	func (f *File) SetRequireAtMostTwo(req []*Require)
```

Purely additive: adopting v0.37.0 cannot break existing call sites on
signature grounds.

---

## 4. Call tree - does the change *matter to us*?

Ingest the local working tree once, then ask whether our code reaches the
symbol(s) the bump touches. `callers` walks up (who reaches it), `callees`
walks down (what it reaches).

```bash
./kanonarion local .

# Do we reach this dependency symbol at all, and from where?
./kanonarion callers 'golang.org/x/mod/modfile.Parse'
./kanonarion callees 'golang.org/x/mod/modfile.Parse'
```

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
# Read a stored verdict computed by 'vuln-scan --reachability':
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
# snapshot is actually consulted (a plain re-scan would reuse cached verdicts).
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
| Breaking-ness | `interface` + `jq`/`diff` | removed/changed signature = refactor |
| Blast radius | `local .` + `callers`/`callees` | callers on the changed symbol = it matters |
| Risk | `vuln-scan` + `reachability` | reachable advisory = act; `Partial` ≠ clean |

Run reachability/callgraph against the **specific candidate version** you intend
to adopt, not against "latest" as a default - the verdict is version-specific.

---

## Road-test result (2026-07-05, pre-v0.1)

Every command above ran clean against the live `./go.mod`:

- `latest --gomod` - 20 code deps reported, 8 stale. ✅
- `walk --gomod` - status 0, 21 nodes / 50 edges, not partial. ✅
- `fetch` + `interface`/`interface-show` - v0.37.0 fetched (Verified) and
  extracted; signature diff surfaced one additive symbol. ✅
- `local .` - ~2.8k nodes / ~19.4k edges; `callers` found 17 real call sites. ✅
- `vuln-scan --gomod` / `vuln-scan-show` - **`AllClean`** over 21 modules: the
  project-rooted scan reads every in-build module `Clean` within the project's
  real build, with no `version-not-in-project-build` rows and no exploitable
  findings. ✅
- `vuln-scan-rescan` - fresh-snapshot pre-release rescan (`vuln.go.dev@2026-06-26`,
  pulled 2026-07-05): **0 affected**. ✅

Pre-v0.1 decision: **freeze the pins.** No advisories at the current snapshot and
no forcing function; the stale set is hygiene, deferred to a post-release sweep.

One documentation correction folded in: the signature comparison uses
`interface` + `jq`/`diff`; there is no `interface-diff` subcommand.
