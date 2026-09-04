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

Roots are the module's exported API, its package `init` functions (init runs
unconditionally at package load), **and its test functions**. When nothing
qualifies, roots fall back to every node the module owns. A capability whose only
witnessing path starts at a `Test…` root is reached by the module's test suite
and not by code a consumer compiles — read the path, not just the label.

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
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit the report (or diff) as JSON |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

## Report

```
$ kanonarion capability github.com/spf13/cobra@v1.8.1
github.com/spf13/cobra@v1.8.1 capabilities:
  ARBITRARY_EXECUTION  [Unknown]  via crypto/fips140.setBypass
    path: …(*Command).ExecuteC → …(*Command).execute → …(*Command).postRun → crypto/fips140.setBypass
  EXEC                 [Direct]  via os/exec.Run
    path: github.com/spf13/cobra.TestBashCompletions → os/exec.(*Cmd).Run
  FILES                [Direct]  via io/ioutil.TempDir
    path: github.com/spf13/cobra/doc.TestGenYamlTree → io/ioutil.TempDir
  …
```

Two things to read off that report. `ARBITRARY_EXECUTION` is `[Unknown]`, so it
rests on an unresolved edge rather than a call anyone can point at. `EXEC` and
`FILES` are `[Direct]` but both witnesses are test functions.

JSON (`--json`) emits `module`, `version`, `partial`, `caveat`, `capabilities`
(the sorted set) and `findings` (each with `capability`, `weakest_confidence`,
`sink_package`, `sink_symbol`, `path`).

## Diff

`--against` compares two versions' capability sets to answer whether an update
expanded them. Where a capability was added the line reads `+ NETWORK`. When
neither set moved, it names the set held in common — a different finding from
neither version witnessing anything:

```
$ kanonarion capability github.com/spf13/cobra@v1.4.0 --against github.com/spf13/cobra@v1.8.1
capability diff github.com/spf13/cobra@v1.4.0 → github.com/spf13/cobra@v1.8.1:
  no capability change: both versions witness the same 12 capabilities (ARBITRARY_EXECUTION,
  CGO, EXEC, FILES, MODIFY_SYSTEM_STATE, NETWORK, OPERATING_SYSTEM, READ_SYSTEM_STATE,
  REFLECT, RUNTIME, SYSTEM_CALLS, UNSAFE_POINTER)
```

**The set is coarse.** A module that reaches the whole taxonomy holds it at both
versions, so the diff has nothing to report even where the code changed a great
deal. Read it as a coarse gate, not as a review.

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

## See also

- [`callgraph`](callgraph.md) - extract the call graph and its per-node facts
- [`reachability`](reachability.md) - whether CVE-affected symbols are reachable
