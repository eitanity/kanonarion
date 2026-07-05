# `kanonarion vendor`

Analyse a vendored project and reconcile `vendor/` against
`vendor/modules.txt`, the `go.mod` require set and `go.sum`.

```
kanonarion vendor [--gomod ./go.mod] [--vendor-only] [--json]
```

## Why this exists

A vendored project (`vendor/` + `vendor/modules.txt`, `-mod=vendor` builds)
is the gold standard for reproducible / airgapped builds, and **the vendored
code is what compiles**. Kanonarion therefore treats the vendored tree as a
first-class input: it resolves the closure from `modules.txt` instead of
re-fetching from the proxy, and verifies what is actually on disk.

## Findings

| Kind                       | Meaning                                                            | Policy axis     |
|----------------------------|--------------------------------------------------------------------|-----------------|
| `drift`                    | recomputed vendored tree hash ≠ expected `go.sum` checksum          | `on_drift`      |
| `missing_from_vendor`      | `modules.txt` lists a module with no files under `vendor/`           | `on_inconsistency` |
| `extra_in_vendor`          | files under `vendor/` for a module `modules.txt` does not list       | `on_inconsistency` |
| `missing_from_modules_txt` | `go.mod` requires a module `vendor/modules.txt` omits                | `on_inconsistency` |
| `version_mismatch`         | `modules.txt` version disagrees with the `go.mod` require version    | `on_inconsistency` |
| `unverified`               | vendored module with **no `go.sum` entry** - integrity unconfirmed   | `on_inconsistency` |

`unverified` is deliberate: a vendored module with no checksum to verify
against is **surfaced as uncertainty, never assumed clean** (the
absence-as-answer defect class).

## Integrity check

Each present vendored module's tree is rehashed with the canonical
`dirhash` (`h1:`) algorithm under the `module@version` prefix and compared to
the `go.sum` entry. This is a kanonarion vendored-tree integrity check (the Go
toolchain does not itself hash `vendor/`); a mismatch means the vendored files
were altered after `go mod vendor`, with both the expected and actual hashes
reported.

## `--vendor-only` (airgapped)

`--vendor-only` (or `vendor_policy.vendor_only: true`) asserts the airgapped
contract: the scan completes with **no proxy contact**. OSS scope resolves
the entire closure from `modules.txt`, so this never requires the network -
the flag records and guarantees the offline posture for audit.

## Vendor mode vs cache mode

- **Vendor mode** (`kanonarion vendor`): use when the project has a
  `vendor/` tree - for reproducible/airgapped builds and CI gates that must
  reflect exactly what compiles. No proxy contact.
- **Cache mode** (`fetch` / `walk` / `inspect`): use when there is no
  `vendor/` tree - the closure is resolved and fetched from the module proxy
  into the content-addressed store.

A non-vendored project is reported informationally and exits 0 - `vendor` is
a no-op there, not a failure.

## Policy & exit code

Each finding is evaluated against the `vendor_policy` governance block
(config schema v2). The default policy flags both **drift** and
**inconsistency** (`warn`). When any finding resolves to `warn`, the command
exits **20** (`ExitConfig`) - suitable as a CI gate.

## Output

`--json` emits the deterministic top-level `vendor` section
(`schema_version`, `ecosystem`, `project`, `vendor_dir`, `vendor_only`,
`overall_status`, `content_hash`, `modules[]`, `findings[]`). `ecosystem` is
always `"go"` - it declares the schema's scope (kanonarion is fitted for Go),
not a polyglot mode. Each module carries its
reachability `dir` and both hashes. The same section appears in
`kanonarion inspect --gomod … --json`.

## Audit

Every scan appends a `vendor_tree_generated` event to
`audit.jsonl` with the reconciled posture and content hash, so a tree's
drift/inconsistency history is first-class in the append-only log.

## Scope notes

- Reachability: each module's `dir` is recorded as the analysis target
  (vendored code is what compiles). Re-pointing walk/callgraph reachability
  at it is a planned follow-up.
- `kanonarion vendor` (signed reproducible tree from an approved set),
  `vendor verify`, signed manifests, airgap bundles and `use` integration
  are **Enterprise**.
