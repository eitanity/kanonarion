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
| `drift`                    | a file under `vendor/` is not the file the published module holds   | `on_drift`      |
| `missing_from_vendor`      | `modules.txt` lists a module with no files under `vendor/`           | `on_inconsistency` |
| `extra_in_vendor`          | files under `vendor/` for a module `modules.txt` does not list       | `on_inconsistency` |
| `missing_from_modules_txt` | `go.mod` requires a module `vendor/modules.txt` omits                | `on_inconsistency` |
| `version_mismatch`         | `modules.txt` version disagrees with the `go.mod` require version    | `on_inconsistency` |
| `unverified`               | vendored module with **no `go.sum` entry**, or whose verified module zip is not held - integrity unconfirmed | `on_inconsistency` |

`unverified` is deliberate: a vendored module with no checksum to verify
against - or no held artefact to compare against - is **surfaced as
uncertainty, never assumed clean** (the absence-as-answer defect class).

## Integrity check

The oracle is the module zip kanonarion holds whose bytes hash to the `h1:`
checksum `go.sum` records for `module@version`. The blob store addresses an
artefact by the hash of its bytes, so a zip reachable at that address is by
construction the artefact `go.sum` verifies.

Every file present under `vendor/<module>` must be byte-identical to the
same-named file in that zip. A file `vendor/` holds that the zip does not
publish, or publishes with different bytes, is `drift`, reported **per file**
with the published and vendored digests. A vendored entry that is not a
regular file (a symlink, for instance) is drift regardless of what it resolves
to: the build would resolve it to bytes outside the tree the scan measured,
and a published module zip holds only regular files.

Files the zip publishes and `vendor/` omits are **not** a finding. `go mod
vendor` prunes each module to the packages the build imports and strips its
test files and `go.mod`, so a pruned tree is the normal shape of `vendor/`.

This is why the whole tree is not hashed and compared to `go.sum`: `go.sum`'s
`h1:` covers the complete published zip while `vendor/` holds a pruned subset,
so the two hash different things by construction and no intact pruned module
could ever match. The Go toolchain does not checksum-verify `vendor/` for the
same reason. Subtrees that are themselves separately vendored modules
(`example.com/dep/v2` inside `example.com/dep`) are attributed to the nested
module, not to its parent.

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
not a polyglot mode. Each module carries its reachability `dir` and the
`expected_hash` its oracle zip was verified against; a `drift` finding carries
the `file` it is about. There is deliberately no hash of the vendored tree:
a pruned tree's whole-directory hash can never equal `expected_hash`, so
reporting the pair asserted a mismatch that was an artefact of the
measurement. The same section appears in
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
