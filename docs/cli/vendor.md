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
| `missing_from_vendor`      | `modules.txt` lists a module that contributes packages and has no files under `vendor/` | `on_inconsistency` |
| `extra_in_vendor`          | files under `vendor/` for a module `modules.txt` does not list       | `on_inconsistency` |
| `missing_from_modules_txt` | `go.mod` requires a module `vendor/modules.txt` omits                | `on_inconsistency` |
| `version_mismatch`         | `modules.txt` version disagrees with the `go.mod` require version    | `on_inconsistency` |
| `unverified`               | vendored module with **no `go.sum` entry** for the coordinate its bytes are, or whose verified module zip is not held - integrity unconfirmed | `on_inconsistency` |

`unverified` is deliberate: a vendored module with no checksum to verify
against - or no held artefact to compare against - is **surfaced as
uncertainty, never assumed clean** (the absence-as-answer defect class).

## Replaced modules

`go mod vendor` writes a replaced module's source under the **original** module
path, recording the replacement only on the `modules.txt` heading:

```
# github.com/PaesslerAG/gval v1.2.1 => github.com/cortezaproject/gval v1.2.4
```

The directory is therefore named for a module whose bytes it does not hold. Each
module is resolved through that clause before the `go.sum` lookup, so a replaced
module is verified against the **replacement's** `h1` - the coordinate the build
resolves, and the only one `go.sum` attests. Three outcomes, kept apart because
they call for different actions:

| Outcome | What it means | Reported as |
|---|---|---|
| replaced by a module `go.sum` attests | the vendored bytes were compared, file by file, against the replacement's verified zip | no finding; the module row carries `replacement_path` / `replacement_version`, and the text report names both coordinates |
| replaced by a filesystem path (`=> ../fork`) | such a replacement publishes no module, so no checksum for it can exist anywhere | `unverified`, naming the path |
| a checksum exists and the bytes disagree | tampering or an edited tree | `drift`, per file, naming the replacement's zip |

A filesystem replacement never falls back to the original coordinate's `go.sum`
line. A project that once required upstream keeps that line, and holding a fork's
files to upstream's zip reports an intact tree as wholesale drift.

The clean case is stated rather than left silent, because a report naming only
`github.com/PaesslerAG/gval` would read as "upstream was verified":

```
replacements: 1 vendored module(s) hold another module's source
  github.com/PaesslerAG/gval v1.2.1 => github.com/cortezaproject/gval v1.2.4 — 12 file(s) checked against the replacement's go.sum-verified zip
```

## How much was compared

Every report states the number of files compared, in total and per module:

```
compared: 3355 file(s) across 133 of 133 module(s) against their published module zips
```

The count is the measurement's own size. "No drift across 133 modules" cannot be
argued with until it says whether that was twelve files or twelve thousand, and a
zero beside a clean status is a run that compared nothing. It is printed at zero
rather than suppressed, and `files_compared` carries no `omitempty` in the JSON
for the same reason.

A module `modules.txt` names with **no package line under it** is not a finding.
`go mod vendor` writes its heading and vendors no directory for it. It is
reported in the scope statement below, never as `missing_from_vendor`.

## Scope statement

Every report states what it covers of the vendored tree: how many modules
`vendor/modules.txt` lists, how many the report describes, and every module it
does not with the reason.

```json
"scope": {
  "tree_modules": 133,
  "covered": 126,
  "uncovered": [
    {
      "path": "example.com/mod",
      "version": "v1.35.0",
      "reason": "contributes no package to the build; vendor/modules.txt names the module but no package under it, so the tree holds no code for it",
      "package_lines": 0
    }
  ]
}
```

Reasons a module appears under `uncovered`:

| `reason` | Circumstance |
|---|---|
| `contributes no package to the build; ...` | `modules.txt` names the module with no package line under it |
| `vendor/modules.txt lists package lines under it that this document does not describe` | `modules.txt` lists packages under the module and the document omits it |

`package_lines` is the number of packages `go mod vendor` wrote under the module
heading, **across all build constraints**. It is not a count of what a build
compiles: a package reachable only under a tag such as `//go:build modhack` is
vendored and never built, so a non-zero `package_lines` does not establish that
the module contributes to any particular build. Zero does settle it downwards —
a module with no vendored package under any constraint has none under one.

When the report covers the whole tree, `uncovered` is an empty list and the
text output reads `the report covers the whole vendored tree`.

The same statement is emitted into a generated SBOM as a CycloneDX annotation.
A module replaced by a fork counts as covered under either coordinate — the
original path `go mod vendor` files it under, or the replacement the build list
names.

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
exits **5** (`ExitPolicy`) - suitable as a CI gate. A bad invocation, an
unreadable policy file or a project with no `vendor/` tree exits **20**.

## Output

`--json` emits the deterministic top-level `vendor` section
(`schema_version`, `ecosystem`, `project`, `vendor_dir`, `vendor_only`,
`overall_status`, `content_hash`, `files_compared`, `modules[]`, `findings[]`,
`scope`). `ecosystem` is
always `"go"` - it declares the schema's scope (kanonarion is fitted for Go),
not a polyglot mode. Each module carries its reachability `dir`, its `files_compared` count, the
`expected_hash` its oracle zip was verified against, and - when
`vendor/modules.txt` names one - `replacement_path` and `replacement_version`;
a `drift` finding carries the `file` it is about. `expected_hash` is the
replacement's checksum for a replaced module, because that is what the bytes
are, and it is absent for a filesystem replacement, which has no published
artefact. There is deliberately no hash of the vendored tree:
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
