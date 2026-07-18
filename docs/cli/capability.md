# `kanonarion capability` - Capability analysis

## Synopsis

```
kanonarion capability <module>@<version> [flags]
kanonarion capability <module>@<version> --against <module>@<version> [flags]
```

## Description

`capability` reports which sensitive capabilities a module's reachable code can
exercise (NETWORK, FILES, EXEC, UNSAFE_POINTER, …), derived from the module's
stored call graph. The taxonomy mirrors capslock (`github.com/google/capslock`)
so reports are directly comparable.

Roots are the module's exported API plus its package `init` functions (init runs
unconditionally at package load, so init-reachable code is reachable in any real
execution). When nothing qualifies, roots fall back to every node the module
owns. From those roots a widest-path search finds, for each reachable
sink, the witnessing path with the strongest minimum edge confidence. Each
capability is reported once, with its example path and that path's weakest edge.

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
(`Direct`, `DynamicDispatch`, `Reflection`, `Unknown`), so a capability reached
by a resolved direct call is distinguishable from one reached only through
interface fanout. See [`callgraph`](callgraph.md) for edge confidence semantics.

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
$ kanonarion capability example.com/mod@v1.4.0
example.com/mod@v1.4.0 capabilities:
  ARBITRARY_EXECUTION  [Direct]  via time.Sleep
    path: …/pkg/engine.(*Batch).AddInstance → …tryLock → time.Sleep
  UNSAFE_POINTER       [Direct]  via google.golang.org/protobuf/internal/impl.LoadMessageInfo
    path: …/pkg/proto.(*Request).ProtoReflect → …impl.LoadMessageInfo
  …
```

JSON (`--json`) emits `module`, `version`, `partial`, `caveat`, `capabilities`
(the sorted set) and `findings` (each with `capability`, `weakest_confidence`,
`sink_package`, `sink_symbol`, `path`).

## Diff

`--against` compares two versions' capability sets to answer whether an update
expanded them:

```
$ kanonarion capability github.com/spf13/cobra@v1.8.0 --against github.com/spf13/cobra@v1.8.1
capability diff github.com/spf13/cobra@v1.8.0 → github.com/spf13/cobra@v1.8.1:
  + NETWORK
```

The diff is only valid when neither side is `Partial`; otherwise it is flagged
with a caveat and the added/removed sets are provisional. JSON output adds
`parity_ok`, `added`, `removed`, `common`, and the full `from`/`to` reports.

## Relation to other stages

- **Requires:** `kanonarion callgraph <module>@<version>` - the stored call
  graph the analysis reads.

## See also

- [`callgraph`](callgraph.md) - extract the call graph and its per-node facts
- [`reachability`](reachability.md) - whether CVE-affected symbols are reachable
