# `kanonarion capability` - Capability analysis

## Synopsis

```
kanonarion capability <module>@<version> [flags]
kanonarion capability <module>@<version> --against <module>@<version> [flags]
```

## Description

`capability` reports which sensitive capabilities a module's reachable code can
exercise (NETWORK, FILES, EXEC, UNSAFE_POINTER, …), derived from the module's
stored call graph.

**Reaching something is not the same as doing it, so the report has two lists.**
cobra's man-page generator writes man pages to disk: that is a **capability**,
and it answers "can this library write to my filesystem" with a yes. cobra also
links `os/exec` without ever calling into it, and takes a `sync` mutex whose own
body does pointer arithmetic — neither makes cobra a program-launcher or a
pointer-arithmetic library, so both are **observations**. They are listed
separately, kept out of the capability set, and ignored by `--against`.

Roots are the module's exported API and its package `init` functions (init runs
unconditionally at package load). **Test declarations are not roots**: a
consumer compiles none of the module's `_test.go` files, so a sink only its test
suite reaches is not in the consuming build. `--include-tests` widens the roots
to them. When nothing qualifies, roots fall back to every node the module owns,
under the same test scope.

Every report states which root set produced it, in text and in JSON
(`test_roots`).

From those roots a widest-path search finds, for each reachable sink, the
witnessing path with the strongest minimum edge confidence. Each capability is
reported once, with its example path and that path's weakest edge.

The call graph must exist first: run `kanonarion callgraph <module>@<version>`.

## Sink detection

A node witnesses a capability in two ways:

- **Callee identity** - the callee's package or function is a known sink
  (e.g. `net/http` → NETWORK, `os/exec` → EXEC, `reflect` → REFLECT).
- **Body-level facts** - a per-node fact recorded at call-graph extraction time,
  for sinks that are a property of a function's body rather than its identity:
  - `UsesUnsafePointer` → **UNSAFE_POINTER** (the body performs an
    `unsafe.Pointer` conversion; the `unsafe` package exposes no callable
    function, so it is never a callee).
  - `IsAssemblyOrLinkname` → **ARBITRARY_EXECUTION** (the function has no Go
    body - assembly or `//go:linkname` - so nothing calls into it as a Go
    function).

A body fact classifies the function it is recorded on. On a node the analysed
module owns it is that module's capability; on an external callee it is a fact
about the callee, so calling `sync.(*RWMutex).Lock` or `time.Sleep` does not make
the caller's code unsafe or arbitrary-executing. Those paths are reported as
observations (below), not capabilities.

## What a path establishes: `basis`

Every finding carries a `basis` saying what its path proved. Only `use` is a
capability of this module. The other two are observations: reported separately,
under `observations` in JSON and under `not capabilities of this module` in
text.

| `basis` | Meaning |
|---------|---------|
| `use` | The module's code calls into a sink, or carries the body fact itself |
| `linkage_only` | The sink is another package's `init`: the package is linked and its initialiser ran, nothing in it was called |
| `callee_body_fact` | The body fact is recorded on an external callee, so it is true of that function and not of the code calling it |

An observation is emitted only for a capability that has no `use` witness — a
real witness answers the question outright. Observations never enter the
capability set, so they never enter `--against` either.

**Limit worth knowing.** A package's `init` node merges the imports of its test
files, and both endpoints of the edge carry `is_test=false`, so `--include-tests`
cannot separate them: `github.com/spf13/cobra.init` calls `testing.init` even
though production cobra does not import `testing`. Reaching those initialisers
is `linkage_only`, so the merged imports no longer produce capabilities.

## Capability taxonomy

| Capability | Meaning |
|------------|---------|
| `NETWORK` | Opens sockets or makes network connections |
| `FILES` | Reads or writes the filesystem |
| `EXEC` | Starts other programs (`os/exec`) |
| `ARBITRARY_EXECUTION` | Runs code chosen at runtime; plugins; assembly/linkname leaves |
| `REFLECT` | Uses the `reflect` package |
| `UNSAFE_POINTER` | Performs an `unsafe.Pointer` conversion |
| `CGO` | Calls into C via cgo |
| `SYSTEM_CALLS` | Direct system calls (`syscall`, `golang.org/x/sys`) |
| `RUNTIME` | Uses low-level runtime facilities |
| `READ_SYSTEM_STATE` | Reads process/host state (env, user) |
| `MODIFY_SYSTEM_STATE` | Changes process/host state (env, signals, logging) |
| `OPERATING_SYSTEM` | Other OS-level interaction (pid, hostname, exit) |

## Confidence

Every finding carries the weakest edge confidence along its witnessing path
(`Direct`, `CHA-overapprox`, `VTA`, `Framework`, `Unknown`), so a capability
reached by a resolved direct call is distinguishable from one reached only
through interface fanout. Reflect-dispatched edges carry `Unknown` plus a
separate reflect attribute. See [`callgraph`](callgraph.md) for edge confidence
semantics.

## Partial graphs

When the call graph did not fully resolve (`OverallStatus` other than
`Extracted`), the report is flagged `Partial` and carries a caveat: the
capability set is a lower bound, never presented as clean.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--against` | _(none)_ | Second `<module>@<version>`; diff the capability sets instead of reporting one |
| `--include-tests` | `false` | Also root the traversal at test functions, which a consumer of the module does not compile |
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit the report (or diff) as JSON |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

## Report

```
$ kanonarion capability github.com/spf13/cobra@v1.8.1
github.com/spf13/cobra@v1.8.1 capabilities:
  roots: exported API and package init; test functions excluded (widen with --include-tests)
  FILES                [Direct]  via os.Close
    path: github.com/spf13/cobra/doc.GenManTreeFromOpts → os.(*File).Close
  READ_SYSTEM_STATE    [Direct]  via os.Getenv
    path: github.com/spf13/cobra.GetActiveHelpConfig → os.Getenv
  SYSTEM_CALLS         [Unknown]  via syscall.Clearenv
    path: …(*Command).ExecuteC → …(*Command).execute → …(*Command).preRun → syscall.Clearenv
  …
  not capabilities of this module — what the path establishes instead:
    EXEC                 [Direct]  via os/exec.init
      linkage only: the package is linked and its initialiser ran; nothing in it was called
      path: github.com/spf13/cobra.init → os/exec.init
    UNSAFE_POINTER       [Direct]  via sync.Lock
      callee body fact: the fact is recorded on that external function, not on this module's code
      path: github.com/spf13/cobra.(*Command).RegisterFlagCompletionFunc → sync.(*RWMutex).Lock
```

Read the confidence as well as the name: `SYSTEM_CALLS` is `[Unknown]`, so it
rests on an unresolved edge rather than a call anyone can point at, where
`FILES` names a call anyone can look up. Everything below the line is an
observation, and each one says which of the two reasons put it there.

JSON (`--json`) emits `module`, `version`, `test_roots` (`excluded` or
`included`), `partial`, `caveat`, `capabilities` (the sorted set), `findings`
and `observations`. Each entry of both arrays carries `capability`,
`weakest_confidence`, `basis`, `basis_note` (absent for `use`), `sink_package`,
`sink_symbol` and `path`. `observations` is always present, empty when there is
nothing to report.

## Diff

`--against` compares two versions' capability sets to answer whether an update
expanded them. Where a capability was added the line reads `+ NETWORK`. When
neither set moved, it names the set held in common — a different finding from
neither version witnessing anything:

```
$ kanonarion capability github.com/spf13/cobra@v1.4.0 --against github.com/spf13/cobra@v1.8.1
capability diff github.com/spf13/cobra@v1.4.0 → github.com/spf13/cobra@v1.8.1:
  roots: exported API and package init; test functions excluded (widen with --include-tests)
  no capability change: both versions witness the same 9 capabilities (CGO, FILES,
  MODIFY_SYSTEM_STATE, NETWORK, OPERATING_SYSTEM, READ_SYSTEM_STATE, REFLECT, RUNTIME,
  SYSTEM_CALLS)
```

**The set is coarse.** A module that reaches most of the taxonomy holds it at
both versions, so the diff has nothing to report even where the code changed a
great deal. Read it as a coarse gate, not as a review.

The diff is only valid when neither side is `Partial`; otherwise it is flagged
with a caveat and the added/removed sets are provisional. JSON output adds
`parity_ok`, `added`, `removed`, `common`, and the full `from`/`to` reports.

## Relation to other stages

- **Requires:** `kanonarion callgraph <module>@<version>` - the stored call
  graph the analysis reads.

## If you also run capslock

The taxonomy is modelled on capslock (`github.com/google/capslock`) but the two
are not directly comparable without normalising: `CGO` is kanonarion's alone,
capslock reports an `UNANALYZED` marker in the same list as capabilities, and it
qualifies some names (`MODIFY_SYSTEM_STATE/ENV`). More importantly capslock
analyses the module **and its dependencies' bodies** as one program, so it sees a
capability reached only by passing through a dependency — where this command
analyses one module with its dependencies at type level and stops at that edge.

capslock's `CAPABILITY_TYPE_DIRECT` is not this command's `use`. It says the path
started in the package you asked about; it does not ask whose code performs the
sensitive operation. So capslock reports a package that only calls
`encoding/json.Unmarshal` as DIRECT `UNSAFE_POINTER`, because `internal/strconv`
does pointer arithmetic several hops down — the same shape this command records
as `callee_body_fact` and lists as an observation. Expect disagreement in both
directions: capslock attributes stdlib bodies to your code, and this command
stops at a dependency edge capslock reads through.

## See also

- [`callgraph`](callgraph.md) - extract the call graph and its per-node facts
- [`reachability`](reachability.md) - whether CVE-affected symbols are reachable
