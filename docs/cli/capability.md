# `kanonarion capability` - Capability analysis

## Synopsis

```
kanonarion capability <module>@<version> [flags]
kanonarion capability <module>@<version> --against <module>@<version> [flags]
```

## Description

`capability` reports what a module's reachable code can do, derived from the
module's stored call graph. Every callee it finds is labelled on three axes —
**capability** (what the callee does), **reach** (how deliberately it is
reached) and **caller kind** (what kind of function makes the call) — and the
report is built from those labels.

**Reaching something is not the same as doing it, so the report has two lists.**
cobra's completion generator creates files: that is a **capability**, and it
answers "can this library write to my filesystem" with a yes. cobra also links
`os/exec` without ever calling into it, and takes a `sync` mutex whose own body
does pointer arithmetic — neither makes cobra a program-launcher or a
pointer-arithmetic library, so both are **observations**. They are listed
separately, kept out of the capability set, and ignored by `--against`.

**Roots are every function the module owns**, exported or not. A module's code
is entered through more than its exported API — registered handlers, cgo
callback trampolines, closures, goroutine entries — and none of those entries
can be enumerated statically, so rooting only the exported API leaves their code
dark. Rooting everything owned reaches it with no framework knowledge.

**Test declarations are not roots**, and the search does not pass through them
either: a consumer compiles none of the module's `_test.go` files, so a sink only
its test suite reaches is not in the consuming build, even where an
over-approximated edge leads from production code into a test function.
`--include-tests` widens the roots to them and lets the search enter them. That is the only axis that
narrows the root set, and every report states which of the two produced it, in
text and in JSON (`test_roots`).

From those roots a widest-path search finds, for each reachable sink, the
witnessing path with the strongest minimum edge confidence. Each capability is
reported once, with its example path and that path's weakest edge.

The call graph must exist first: run
`kanonarion fetch <module>@<version> && kanonarion callgraph <module>@<version>`.

## Sink detection

A callee is labelled by its **identity** — package, receiver and symbol — using
the rules below. One label comes from a **body fact** instead: `UsesUnsafePointer`,
recorded at extraction time on a function whose own body performs an
`unsafe.Pointer` conversion, is the only source of `UNSAFE_POINTER`. The
`unsafe` package exposes no callable function, so it is never a callee.

A body fact classifies the function it is recorded on. On a node the analysed
module owns it is that module's capability; on an external callee it is a fact
about the callee, so calling `sync.(*RWMutex).Lock` does not make the caller's
code unsafe. That path is reported as an observation (below), not a capability.

A function with an **assembly or `//go:linkname` body** (`IsAssemblyOrLinkname`)
carries no label of its own: the graph cannot see what it does. When the module
owns it, it is listed under **unanalysed bodies**, by name. When it is an
external callee with an identity label (`syscall.RawSyscall`) it keeps that
label with reach `UNANALYZED`; one with no identity label (`time.Sleep`,
`sync/atomic.AddUint64`) is counted in `unanalyzed_callees` and is not a row.

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
capability set, the rows, the sensitive calls or `--against`.

**Limit worth knowing.** A package's `init` node merges the imports of its test
files, and both endpoints of the edge carry `is_test=false`, so `--include-tests`
cannot separate them: `github.com/spf13/cobra.init` calls `testing.init` even
though production cobra does not import `testing`. Reaching those initialisers
is `linkage_only`, so the merged imports do not produce capabilities.

## Capability taxonomy

Twenty-one values in three tiers. The tier is a property of the value: text
prints Act findings first, then Context, and hides the Suppressed tier unless
`--show-suppressed` is given.

| Tier | Capability | Meaning |
|------|------------|---------|
| Act | `EXEC_PROCESS` | Starts another program |
| Act | `EXEC_DYNAMIC` | Loads code chosen at runtime (`plugin`) |
| Act | `NET_DIAL` | Opens an outbound connection or resolves a name |
| Act | `NET_LISTEN` | Accepts inbound connections |
| Act | `NET_TRANSFER` | Reads or writes an established connection or HTTP body |
| Act | `FS_READ` | Names a path and reads it |
| Act | `FS_WRITE` | Creates, changes or removes a filesystem entry |
| Act | `ENV_READ` | Reads the process environment |
| Act | `ENV_WRITE` | Changes the environment or working directory |
| Act | `SYSCALL_DIRECT` | Makes a system call through `syscall` or `golang.org/x/sys` |
| Act | `CGO_CALL` | Calls into C through cgo |
| Act | `UNSAFE_POINTER` | The module's own `unsafe.Pointer` conversion |
| Act | `REFLECT_DYNAMIC` | Dispatches or mutates through reflection |
| Context | `NET_INSPECT` | Parses, formats or reads metadata; no socket I/O |
| Context | `FS_STREAM` | Reads or writes a handle that is already open |
| Context | `PATH_PURE` | Manipulates a path string without touching the disk |
| Context | `REFLECT_INSPECT` | Inspects types and values through reflection |
| Context | `HOST_IDENTITY` | Reads who and where the process is |
| Context | `PROC_CONTROL` | Exits, signals or inspects processes |
| Context | `LOG_WRITE` | Writes through `log` or `log/syslog` |
| Suppressed | `RUNTIME_INTERNAL` | The runtime's own machinery |

The rules, in order; the first that matches wins. `bare` is the receiver with
any pointer star and package qualifier removed.

1. `ENV_READ`: the free functions `Getenv`, `LookupEnv`, `Environ`, `ExpandEnv`
   in `os`, `syscall` and any `golang.org/x/sys` package; `os/exec.(*Cmd).Environ`.
2. `ENV_WRITE`: the free functions `Setenv`, `Unsetenv`, `Clearenv`, `Chdir` in
   the same packages; `os.(*File).Chdir`.
3. `HOST_IDENTITY`: the `os` free functions `Hostname`, `Getpid`, `Getppid`,
   `Getuid`, `Getgid`, `Geteuid`, `Getegid`, `Getgroups`, `Getpagesize`,
   `Executable`, `Getwd`, `TempDir`, `UserHomeDir`, `UserConfigDir`,
   `UserCacheDir`; all of `os/user`; `runtime.GOROOT`;
   `runtime/debug.ReadBuildInfo`; `net.Interface*` (the free functions and the
   methods on `Interface`).
4. `net`, `net/http`, `net/textproto`, `net/rpc`, `net/smtp`:
   - `NET_DIAL`: `Dial`, `DialTCP`, `DialUDP`, `DialIP`, `DialUnix`,
     `DialTimeout`, `DialContext`, `FileConn`, `FilePacketConn`, `SendMail`,
     `NewClient`, `NewClientWithCodec`, `NewClientConn`, `RoundTrip`, `Do`,
     `Get`, `Head`, `Post`, `PostForm`, **only when `bare` is empty or one of
     `Client`, `Transport`, `ClientConn`, `Dialer`, `Resolver`, `Conn`** — so
     `(Header).Get` is not a dial; and any symbol starting `Lookup` or
     `Resolve` where `bare` is not `Header`.
   - `NET_LISTEN`: `Listen`, `ListenTCP`, `ListenUDP`, `ListenIP`,
     `ListenUnix`, `ListenPacket`, `ListenAndServe`, `ListenAndServeTLS`,
     `Serve`, `ServeTLS`, `ServeCodec`, `Accept`, `AcceptTCP`, `AcceptUnix`,
     `HandleHTTP`, `NewServer`, `Register`.
   - `NET_TRANSFER`: any symbol starting `Read` or `Write`, and `Cmd`, `Call`,
     `Push`, `Flush`, `Hijack`, `Pipe`, `ServeContent`, `ServeFile`,
     `ServeHTTP`, `FileServer`, `FileServerFS`, `ReadRequest`, `ReadResponse`,
     `CloseWrite`, `SyscallConn`.
   - `NET_INSPECT`: `ParseIP`, `ParseCIDR`, `ParseMAC`, `SplitHostPort`,
     `JoinHostPort`, `CanonicalMIMEHeaderKey`, `StatusText`, `NewRequest`,
     `LocalAddr`, `RemoteAddr`, `SetDeadline`; `Get`, `Set`, `Add`, `Del`,
     `Values` on `Header`; any method on `IP`, `IPNet`, `IPMask`. Package
     default.
5. `path/filepath`: `PATH_PURE` for `Join`, `Clean`, `Base`, `Dir`, `Ext`,
   `Split`, `SplitList`, `ToSlash`, `FromSlash`, `IsAbs`, `IsLocal`, `Match`,
   `Rel`, `VolumeName`, `HasPrefix`, `Localize`; `FS_READ` for `Abs`,
   `EvalSymlinks`, `Glob`, `Walk`, `WalkDir`. Package default `PATH_PURE`.
6. `os`: `PROC_CONTROL` for every method on `Process` and `ProcessState`
   (inspecting or signalling a process, as with the `os/exec` exit-status types
   below), checked before the symbol lists; `EXEC_PROCESS` for `StartProcess`; `PROC_CONTROL` for `Exit`,
   `FindProcess`, `Kill`, `Signal`, `Wait`, `ExitCode`; `FS_WRITE` for `Create`,
   `CreateTemp`, `OpenFile`, `Mkdir`, `MkdirAll`, `MkdirTemp`, `Remove`,
   `RemoveAll`, `Rename`, `Link`, `Symlink`, `Truncate`, `Chmod`, `Chown`,
   `Chtimes`, `WriteFile`, `TempFile`, `Write`, `WriteAt`, `WriteString`,
   `WriteTo`, `ReadFrom`, `Sync`; `FS_READ` for the operations that name a path,
   `Open`, `OpenRoot`, `ReadFile`, `ReadDir`, `Readdir`, `Readdirnames`,
   `Readlink`, `Lstat`, `Stat`, `DirFS`, `SameFile`; `FS_STREAM` for `Read`,
   `ReadAt`, `Seek`, `Close`, `Fd`, `Name`, `NewFile`, `FS`, `ReadAll`. Package
   default `FS_STREAM`. `io/ioutil` follows by symbol: `ReadFile` and `ReadDir`
   are `FS_READ`, `WriteFile`, `TempFile` and `TempDir` are `FS_WRITE`,
   `ReadAll`, `NopCloser` and `Discard` are `FS_STREAM`, and the package default
   is `FS_STREAM`. A read on an open handle is often an `io.Reader` dispatch
   target rather than a deliberate file read, which is why it is not `FS_READ`.
7. `os/exec`: `LookPath` is `FS_READ` (it only searches `PATH`); methods on
   `ExitError` and `Error` are `PROC_CONTROL` (formatting an exit status runs
   nothing); `Command`, `CommandContext` and every `(*Cmd)` method are
   `EXEC_PROCESS`. Package default `EXEC_PROCESS`.
8. `plugin`: `EXEC_DYNAMIC`.
9. `reflect`: `REFLECT_DYNAMIC` for `Call`, `CallSlice`, `Method`,
   `MethodByName`, `Methods`, `MakeFunc`, `NewAt`, `Select`, `Send`, `Recv`,
   `UnsafeAddr`, `Pointer` and any symbol starting `Set`. Package default
   `REFLECT_INSPECT`.
10. `syscall`, `golang.org/x/sys/unix`, `golang.org/x/sys/windows`:
    `SYSCALL_DIRECT`.
11. `runtime/debug.WriteHeapDump`: `FS_WRITE`.
12. `log`, `log/syslog`: `LOG_WRITE`. `os/signal`: `PROC_CONTROL`.
    `runtime/cgo`: `CGO_CALL`. `runtime`, `runtime/debug`: `RUNTIME_INTERNAL`.
13. `UNSAFE_POINTER` comes only from the `UsesUnsafePointer` body fact.

A promoted method has a wrapper node whose ID names the embedding type, such
as `(*os/exec.ExitError).String`, while the node records the embedded method's
package (`os`) and the embedding type's receiver. When the package in the ID is
a sink package and differs from the node's, the ID's package decides, receiver
kept: `(*os/exec.ExitError).String` is `PROC_CONTROL`, not an `os` file stream.
A wrapper whose ID names a package outside the rules (the module's own type,
say) is labelled by the node's package as usual.

### `classified_by` and package defaults

A callee in a package that rules 4–7 or 9 split by symbol, and that no rule
names, takes the package default. That is an approximation, so every finding and
row records `classified_by`: `rule` or `package_default`. The report counts, per
package, the distinct callees labelled by a default — `package_defaults` in
JSON, one `package defaults:` line in text. The packages labelled whole by rules
8, 10 and 12 are `rule`.

## Reach

How deliberately a capability is reached, decided from the callee alone. The
first match wins:

| `reach` | Rule |
|---------|------|
| `UNANALYZED` | The callee has an assembly or `//go:linkname` body |
| `PKG_LINKAGE` | The callee is an initialiser: `init` or `init#N` |
| `RUNTIME_PLUMBING` | The callee's symbol is unexported: its first rune is not upper-case. The symbol is tested, not the receiver, so `net.(*conn).Read` is a direct call; `_Cgo_use` is plumbing |
| `DIRECT_CALL` | Otherwise |

An owned function's own `UsesUnsafePointer` fact is a `DIRECT_CALL`: its own
code does it. A finding's witness prefers `DIRECT_CALL`, then
`RUNTIME_PLUMBING`, then `UNANALYZED`, then the strongest confidence — except
that an `UNANALYZED` callee with an exported symbol outranks any plumbing.

**Plumbing** is one rule for findings and rows alike: reach `RUNTIME_PLUMBING`,
or reach `UNANALYZED` with an unexported symbol (a `syscall.runtime_*` linkname,
`runtime/cgo.set_crosscall2`). So a finding's witness is plumbing only when the
capability has no other witness, and that is exactly when it is marked
`plumbing-only`.

## Caller kind

The kind of the function whose own code makes the call, or carries the body
fact. On a finding it is the last function on the path that the module owns.
JSON field `caller_kind`; text shows it as a `[KIND]` tag. The first match wins:

| `caller_kind` | Rule |
|---------------|------|
| `TEST_INIT` | An initialiser declared in test code |
| `INIT` | An initialiser |
| `TEST` | Declared in a `_test.go` file or an external test package |
| `MAIN` | A function `main` with no receiver, other than the one the go command synthesises for a test binary |
| `EXPORTED_API` | Part of the public API, or handed to a caller outside Go by an export directive (`//export`, `//go:wasmexport`) |
| `INTERNAL` | Everything else |

It says what the caller is, not what reaches it: an `INTERNAL` function may be
called from anywhere.

## Sensitive calls

`sensitive_calls` is the short, high-signal list: each exported sensitive
function this module calls. A callee is a member when

- its capability is `EXEC_PROCESS`, `EXEC_DYNAMIC`, `NET_DIAL`, `NET_LISTEN`,
  `NET_TRANSFER`, `FS_READ`, `FS_WRITE`, `ENV_READ`, `CGO_CALL` or
  `REFLECT_DYNAMIC`;
- its reach is `DIRECT_CALL`;
- and at least one of the module's calls to it is a `Direct` edge. Only a Direct
  edge names a unique callee; a callee reached only through interface
  over-approximation stays a row, labelled with its confidence, and is not a
  member.

The deprecated `io/ioutil` functions are counted as the `os` function they
forward to — `ReadFile`, `ReadDir`, `WriteFile` as themselves, `TempFile` as
`os.CreateTemp`, `TempDir` as `os.MkdirTemp` — so moving off `io/ioutil` is not
a change. Each member lists the kinds of caller that reach it and how many
callers there are; the list is not filtered by caller kind.

### Co-location

Two facts, each reported as the functions it names, never as a score:

- **`collects_and_egresses`**: one function the module owns calls, over Direct
  edges, both a collection member (`ENV_READ`, `FS_READ`) and an egress member
  (`NET_DIAL`, `NET_TRANSFER`) of the sensitive calls.
- **`init_reaches_both`**: from an initialiser the module owns, following
  **Direct edges only**, both a collection and an egress member are reachable.
  It names the initialiser, the nearest member of each with its hop count, and
  the depth at which the second first appears. No depth bound is set.

## Suppression

Text hides two things unless `--show-suppressed` is given, and always prints a
count of what it hid with the flag that shows it:

- findings and rows whose capability is `RUNTIME_INTERNAL`;
- rows whose callee is plumbing (see [Reach](#reach)).

A capability whose only witnesses are plumbing is not hidden: its finding is
shown and marked `plumbing-only`, and in a diff its first-ranked row is shown,
marked the same way. `runtime/cgo`'s witnesses are all unexported, so without
this rule `CGO_CALL` would disappear. JSON carries everything, each entry with
`suppressed: true|false` and `plumbing_only`.

## Confidence

Every finding carries the weakest edge confidence along its witnessing path
(`Direct`, `CHA-overapprox`, `VTA`, `Framework`, `Unknown`), so a capability
reached by a resolved direct call is distinguishable from one reached only
through interface fanout. Reflect-dispatched edges carry `Unknown` plus a
separate reflect attribute. See [`callgraph`](callgraph.md) for edge confidence
semantics.

## Partial graphs

A report is flagged `Partial` and carries a caveat whenever it does not rest on a
fully extracted graph. The caveat says which of two things happened, because they
send a reader to different places:

- **The analysis could not finish** — `Partial`, `LoadFailed`, `OutOfMemory`,
  `Cancelled`, `ExtractionFailed` or an unrecorded status. The capability set is
  a lower bound, never presented as clean.
- **The module was excluded from call-graph analysis by configuration**
  (`callgraph.exclude`). No graph was produced and nothing was searched for, so
  the empty set is not a measurement. It is the operator's own decision, not a
  tool failure to investigate.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--against` | _(none)_ | Second `<module>@<version>`; diff the two versions instead of reporting one |
| `--include-tests` | `false` | Also root the traversal at test functions, which a consumer of the module does not compile |
| `--show-suppressed` | `false` | Also print what text hides by default: `RUNTIME_INTERNAL` and unexported plumbing rows. JSON always carries them |
| `--target <GOOS/GOARCH>` | _(this host's platform)_ | Read the call graph extracted under this build target, e.g. `--target wasip1/wasm`. Refused by name beside `--walk-id`: the named walk's own frame is the read frame. A refusal raised under a declared target prints a remedy carrying it. See [Composition](callgraph.md#composition) and [Declaring the build target](walk.md#declaring-the-build-target---target) |
| `--goos` / `--goarch` | _(this host's)_ | The two halves of `--target`, for a caller holding them separately. Both are required, and neither combines with `--target` |
| `--tinygo <target>` | _(none)_ | Read the call graph extracted under this TinyGo target, e.g. `--tinygo pico`; refused by name beside `--walk-id`. The `tinygo` command on `PATH` defines the target. Mutually exclusive with `--target`, `--goos` and `--goarch`. See [Declaring a TinyGo target](walk.md#declaring-a-tinygo-target---tinygo) |
| `--walk-id` | _(none)_ | Read the call graph extracted under the frame this walk was resolved for |
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--json` | `false` | Emit the report (or diff) as JSON |
| `--log-level` | `warn` | Log level: `debug`, `info`, `warn`, `error` |

## Report

```
$ kanonarion capability github.com/spf13/cobra@v1.8.1
github.com/spf13/cobra@v1.8.1 capabilities:
  frame: linux/amd64
  roots: all of this module's own code; test functions excluded (widen with --include-tests)
  ENV_READ         [Direct]  [EXPORTED_API]  DIRECT_CALL  via os.Getenv
    path: github.com/spf13/cobra.CompDebug → os.Getenv
  FS_WRITE         [Direct]  [EXPORTED_API]  DIRECT_CALL  via os.Create
    path: github.com/spf13/cobra.(*Command).GenBashCompletionFile → os.Create
  …
  PROC_CONTROL     [Direct]  [EXPORTED_API]  DIRECT_CALL  via os.Exit
    path: github.com/spf13/cobra.CheckErr → os.Exit
  REFLECT_INSPECT  [Unknown]  [EXPORTED_API]  DIRECT_CALL  via reflect.Int  (package default)
    path: github.com/spf13/cobra.Eq → reflect.(Value).Int
  1 finding hidden: RUNTIME_INTERNAL is suppressed by default (--show-suppressed shows it)
  sensitive calls (3): exported sensitive functions called over at least one Direct edge
    ENV_READ       os.Getenv  from EXPORTED_API, INTERNAL (8 callers)
    FS_WRITE       os.Create  from EXPORTED_API, INTERNAL (9 callers)
    FS_WRITE       os.OpenFile  from EXPORTED_API (1 caller)
  co-location: no function collects and egresses, and no initialiser reaches both
  unanalysed callees: 12 external functions with an assembly or //go:linkname body and no capability label
  package defaults: net 10, os 5, path/filepath 1, reflect 8 (callees labelled by their package's default, not a named rule)
  not capabilities of this module — what the path establishes instead:
    EXEC_PROCESS     [Direct]  [INIT]  PKG_LINKAGE  via os/exec.init  (package default)
      linkage only: the package is linked and its initialiser ran; nothing in it was called
      path: github.com/spf13/cobra.init → os/exec.init
    UNSAFE_POINTER   [Direct]  [EXPORTED_API]  DIRECT_CALL  via sync.Lock
      callee body fact: the fact is recorded on that external function, not on this module's code
      path: github.com/spf13/cobra.(*Command).RegisterFlagCompletionFunc → sync.(*RWMutex).Lock
```

The `frame:` line names the build frame the call graph read was extracted
under, as [`callgraph-show`](callgraph.md#callgraph-show) prints it. A
coordinate holding no graph of that frame is refused with exit `4`, naming the
frames the store does hold, the flag that reads each, and the command that
produces this one.

Each finding line reads: capability, the path's weakest edge confidence, the
caller kind, the reach, and the callee. Read the confidence as well as the name:
`REFLECT_INSPECT` rests on an `Unknown` edge, where `FS_WRITE` names a call
anyone can look up. A module's own assembly or linkname functions, when it has
any, are listed under `unanalysed bodies`.

JSON (`--json`) emits `module`, `version`, `test_roots` (`excluded` or
`included`), `frame` (in `callgraph-show`'s shape; each side of a diff carries
its own), `partial`, `caveat`, `capabilities` (the sorted set), `findings`,
`observations`, `row_count`, `sensitive_calls`, `collects_and_egresses`,
`init_reaches_both`, `unanalyzed`, `unanalyzed_callees` and `package_defaults`.

- Each entry of `findings` and `observations` carries `capability`,
  `capslock_category`, `weakest_confidence`, `basis`, `basis_note` (absent for
  `use`), `reach`, `caller_kind`, `classified_by`, `suppressed`,
  `plumbing_only`, `sink_package`, `sink_symbol` and `path`.
- Each `sensitive_calls` entry carries `callee`, `capability`,
  `capslock_category`, `caller_kinds` and `callers`.
- Each `collects_and_egresses` entry carries `function`, `caller_kind`,
  `collection` and `egress`; each `init_reaches_both` entry carries `init`,
  `caller_kind`, `depth`, `collection_depth`, `egress_depth`, `collection` and
  `egress`.
- `package_defaults` entries carry `package` and `callees`.

Every list is present, empty when there is nothing to report, and `partial` is
always emitted.

## Diff

`--against` compares two versions **row by row**. A row is one piece of
evidence: a function the module owns calling a labelled external callee with
basis `use`, or that function's own `unsafe.Pointer` use. Its identity is
(caller kind, capability, reach, callee) plus the caller; it carries the
strongest confidence among the edges it stands for. Observations are not rows.

Text prints, in this order, each with its own added and removed counts:

1. **sensitive calls** added and removed, first because it is the short list;
2. **co-location** facts added and removed: a function by name, an initialiser
   by name and the two members it reaches. An initialiser reaching the same two
   members at another depth is printed once as a change of depth
   (`~ init reaches both: … depth 6 → 7`), not as an add and a remove;
3. **unanalysed bodies** added and removed;
4. the **capability set** added and removed;
5. **rows added**, then **rows removed**.

Additions and removals are always separate blocks. No net figure is printed.

Rows rank by caller kind — `INIT`, `TEST_INIT`, `EXPORTED_API`, `TEST`,
`INTERNAL`, `MAIN` — then tier (Act, Context, Suppressed), then `Direct` before
weaker confidence, then capability, callee and caller. `INIT`, `TEST_INIT`,
`EXPORTED_API` and `MAIN` rows are listed per caller; `TEST` and `INTERNAL` rows
are collapsed to one line per (capability, reach, callee) with a caller count.
Suppressed rows are counted on the block's heading and shown with
`--show-suppressed`.

```
$ kanonarion capability github.com/lib/pq@v1.10.9 --against github.com/lib/pq@v1.12.3
capability diff github.com/lib/pq@v1.10.9 → github.com/lib/pq@v1.12.3:
  roots: all of this module's own code; test functions excluded (widen with --include-tests)
  sensitive calls: 5 added, 0 removed
    + NET_LISTEN     net.Listen  from INTERNAL (1 caller)
    + FS_WRITE       os.Chmod  from INTERNAL (1 caller)
    + FS_WRITE       os.MkdirAll  from INTERNAL (1 caller)
    + FS_WRITE       os.WriteFile  from INTERNAL (2 callers)
    + ENV_READ       os.LookupEnv  from INTERNAL (2 callers)
  co-location: 0 added, 0 removed, 0 changed depth
  unanalysed bodies: 0 added, 0 removed
  capabilities: 2 (FS_WRITE, NET_LISTEN) added, 0 removed
  rows added: 486 (319 suppressed: runtime internals and unexported plumbing; --show-suppressed shows them)
    + [EXPORTED_API] …
  rows removed: 38 …
```

When nothing moved, the line names what was compared:

```
$ kanonarion capability github.com/go-sql-driver/mysql@v1.6.0 --against github.com/go-sql-driver/mysql@v1.7.1
capability diff github.com/go-sql-driver/mysql@v1.6.0 → github.com/go-sql-driver/mysql@v1.7.1:
  roots: all of this module's own code; test functions excluded (widen with --include-tests)
  no change: no row, no sensitive call and no unanalysed body changed; both versions hold 726 rows
```

The diff is only valid when neither side is `Partial`; otherwise it is flagged
with a caveat and everything added or removed is provisional.

JSON keeps `parity_ok`, `caveat`, `added`, `removed` and `common` — the
capability set, in the vocabulary above — and the full `from`/`to` reports, and
adds `from_rows`, `to_rows`, `rows_added`, `rows_removed`,
`sensitive_calls_added`, `sensitive_calls_removed`,
`collects_and_egresses_added`, `collects_and_egresses_removed`,
`init_reaches_both_added`, `init_reaches_both_removed`,
`init_reaches_both_depth_changed` (each with `init`, `collection`, `egress`,
`from_depth` and `to_depth`), `unanalyzed_added` and
`unanalyzed_removed`. Each row carries `caller_kind`, `capability`,
`capslock_category`, `reach`, `callee`, `caller`, `body_fact`,
`classified_by`, `confidence`, `suppressed` and `plumbing_only`. JSON lists
every row per caller; the collapse is a text presentation.

## Relation to other stages

- **Requires:** `kanonarion fetch <module>@<version> && kanonarion callgraph
  <module>@<version>` - the stored call graph the analysis reads.

A coordinate the store has no call graph for exits `4`, not `20`: the request
was well formed and the store was empty. The message names the invocation that
produces the record, with the coordinate filled in, so it can be run as printed.
It names the fetch as well: `callgraph` reads bytes the store already holds, and
fetching a module the store holds returns at once.

```
$ kanonarion capability example.com/mod@v1.2.0
error: execute root command: no callgraph record for example.com/mod@v1.2.0 — analyse it first:
  kanonarion fetch example.com/mod@v1.2.0 && kanonarion callgraph example.com/mod@v1.2.0
$ echo $?
4
```

"Absent" is asked of the store rather than asserted over it. Where the store
does hold the coordinate, but only under a pipeline version this build no longer
serves, the refusal says which - the same sentence `callgraph-show` prints from
the same rows, because it is the same fact. The exit code and the remedy do not
change; re-analysing is what fixes both.

```
$ kanonarion capability golang.org/x/sys@v0.47.0
no callgraph record for golang.org/x/sys@v0.47.0 at pipeline 0.10.0 - the store
holds it at superseded pipeline 0.5.0, 0.6.0, which this build does not serve.
Re-analyse it:
  kanonarion fetch golang.org/x/sys@v0.47.0 && kanonarion callgraph golang.org/x/sys@v0.47.0
```

A malformed coordinate, an unreadable store or an unknown flag stays `20`.

## If you also run capslock

Every finding and row carries `capslock_category`, the capslock `CAPABILITY_*`
name (without the prefix) its capability maps onto:

| `capability` | `capslock_category` |
|---|---|
| `EXEC_PROCESS` | `EXEC` |
| `EXEC_DYNAMIC` | `ARBITRARY_EXECUTION` |
| `NET_DIAL`, `NET_LISTEN`, `NET_TRANSFER`, `NET_INSPECT` | `NETWORK` |
| `FS_READ`, `FS_WRITE`, `FS_STREAM`, `PATH_PURE` | `FILES` |
| `ENV_READ`, `HOST_IDENTITY` | `READ_SYSTEM_STATE` |
| `ENV_WRITE`, `LOG_WRITE` | `MODIFY_SYSTEM_STATE` |
| `PROC_CONTROL` | `OPERATING_SYSTEM` |
| `SYSCALL_DIRECT` | `SYSTEM_CALLS` |
| `CGO_CALL` | `CGO` |
| `UNSAFE_POINTER` | `UNSAFE_POINTER` |
| `REFLECT_DYNAMIC`, `REFLECT_INSPECT` | `REFLECT` |
| `RUNTIME_INTERNAL` | `RUNTIME` |

The map is many-to-one and lossy, and it follows this command's labels, not
capslock's own assignment of each function. `os/signal` is `PROC_CONTROL` here,
so it maps to `OPERATING_SYSTEM`, where capslock labels the package
`MODIFY_SYSTEM_STATE`. A module's own assembly or linkname function maps to
nothing: this command lists it as unanalysed rather than labelling it.

The two tools are not directly comparable without normalising: capslock reports
an `UNANALYZED` marker in the same list as capabilities, and it qualifies some
names (`MODIFY_SYSTEM_STATE/ENV`). More importantly capslock analyses the module
**and its dependencies' bodies** as one program, so it sees a capability reached
only by passing through a dependency — where this command analyses one module
with its dependencies at type level and stops at that edge.

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
