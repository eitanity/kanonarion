# `kanonarion native` - the native library a cgo module compiles into, or links into, your binary

## Synopsis

```
kanonarion native <module>@<version> [--json] [--force]
kanonarion native-list [--presence <values>] [--all-generations] [--limit N] [--offset M] [--json]
```

## Description

A cgo module can carry a complete third-party C library inside its published zip
and compile it into your binary. It can also link one it does not carry at all.
`native` records both: what the library is when the module ships it, and what
the module says it links when it does not.

The facts come out of the module zip the fetch ledger already verified, so they
inherit that artefact's verification status. Nothing is built and no C toolchain
is invoked - the command reads bytes that are already in the store.

```
kanonarion native github.com/mattn/go-sqlite3@v1.14.12
```

```
Module:     github.com/mattn/go-sqlite3@v1.14.12
Artefact:   zip:h1:TJ1bhYJPV44phC+IMu1u2K/i5RriLTPe+yc68XDJ1Z0=
Generation: 0.3.0+recipes.1
Presence:   present_identified
Statement:  4 native source file(s) compiled in; 1 component(s) identified by declaration

Components
COMPONENT  VERSION  CONFIDENCE  EVIDENCE
SQLite     3.38.0   declared    sqlite3-binding.c: #define SQLITE_VERSION        "3.38.0"
                                sqlite3-binding.h: #define SQLITE_VERSION        "3.38.0"

Native sources compiled into the binary (4)
FILE                         BYTES    SHA256
sqlite3-binding.c            8469484  bfd6018c8a2ec69f4ccf2464997cee18b35512374a0f98a7171321bb914618ef
sqlite3-binding.h            615366   e42f83f66d4b878523b711d91a6542f72214870ed9c98c8078d191dd794eade6
sqlite3_opt_unlock_notify.c  1716     90bf6d96b09e438bda52ab63dc75c17487b7a566b025178de049aabf7273875f
sqlite3ext.h                 36970    688a910adf085a17cc9c1beebffcba987d0bd02a1e3dbdbd0104d89cfcdbebf9
```

The module's licence record says MIT, which is the Go wrapper's licence. The
8.4 MB of SQLite it compiles is a separate component with a separate version and
its own advisories, and this is where the store records it.

Where that record then goes:

- **[`sbom`](sbom.md)** lists an identified component as a component of its own,
  under a `pkg:generic/…` purl, with the evidence that named it. A
  `present_unidentified` record emits no component and the run says so on stderr.
- **[`vuln-show` and `vuln-scan-show`](vuln.md)** state which of five native
  situations a module is in and, for an identified component, that its
  advisories were **not** searched. Kanonarion has no non-Go advisory source;
  what it can do is say so rather than let a Go-only `Clean` stand for the whole
  binary.

(The real output ends with a **Linked libraries** table as well - this module
also names `sqlite3`, `icuuc`, `icui18n` and the C runtime in its `#cgo LDFLAGS`
directives. It is elided here; see
[What is linked](#what-is-linked) below.)

## The four answers

| Presence | Meaning |
|---|---|
| `absent` | no native source is compiled in, and no cgo directive links anything external |
| `linked_not_shipped` | no native source is compiled in, and a cgo directive links an external native library the artefact does not carry |
| `present_identified` | native source is compiled in, and a recipe named the library |
| `present_unidentified` | native source is compiled in, and no recipe names it |

**Only `absent` is an absence.** The other three are spelled differently for
that reason: two are coverage gaps a reader can act on, and collapsing either
into `absent` would put a limit of the tool under the word for an absence.

`present_unidentified` lists the files, so a reader can see exactly what is
unaccounted for:

```
kanonarion native github.com/fluent/fluent-bit-go@v0.0.0-20260616051939-71a89c3094aa
```

```
Presence:   present_unidentified
Statement:  4 native source file(s) compiled in; no recipe names the library they belong to
```

`linked_not_shipped` names what is linked. Nothing native is in these bytes, and
something native still reaches your binary:

```
kanonarion native golang.org/x/text@v0.17.0
```

```
Module:     golang.org/x/text@v0.17.0
Artefact:   zip:h1:XtiM5bkSOt+ewxlOE/aE/AKEHibwj/6gvWMl9Rsh0Qc=
Generation: 0.3.0+recipes.1
Presence:   linked_not_shipped
Statement:  no native source is compiled in from this artefact; it names 5 external native libraries it links but does not ship, so no version could be read

Linked libraries named by cgo directives (5)
LIBRARY         KIND      FILE                            DIRECTIVE
CoreFoundation  external  collate/tools/colcmp/darwin.go  #cgo LDFLAGS: -framework CoreFoundation
icui18n         external  collate/tools/colcmp/icu.go     #cgo LDFLAGS: -licui18n -licuuc
icui18n.57      external  cases/icu.go                    #cgo LDFLAGS: -licui18n.57 -licuuc.57
icuuc           external  collate/tools/colcmp/icu.go     #cgo LDFLAGS: -licui18n -licuuc
icuuc.57        external  cases/icu.go                    #cgo LDFLAGS: -licui18n.57 -licuuc.57
```

**No version is stated, and none is invented.** `-licui18n` cannot be resolved
from an artefact: which ICU build the linker finds is a property of the machine
doing the build, not of these bytes. Scoping that measurement out is not the
same as calling it absent, and this value is the difference.

## What is linked

Every library the module's `#cgo LDFLAGS` directives name is listed, **whatever
the presence**. A module that ships its own sources and links something else
states both, so neither hides the other.

Every library the module's `#cgo LDFLAGS` **and** `#cgo pkg-config` directives
name is listed. Four operand forms are read, and nothing else:

| Directive | Operand | Library |
|---|---|---|
| `#cgo LDFLAGS:` | `-licui18n` | `icui18n` |
| `#cgo LDFLAGS:` | `-framework CoreFoundation` | `CoreFoundation` |
| `#cgo LDFLAGS:` | `${SRCDIR}/../target/release/libpdf_oxide.a` | `pdf_oxide` |
| `#cgo pkg-config:` | `libxml-2.0` | `libxml-2.0` |

A `-L` search path names no library. A `-Wl,` option is an instruction to the
linker, not a component. A `#cgo CFLAGS:`, `CPPFLAGS:`, `CXXFLAGS:` or `FFLAGS:`
line says how the compiler is invoked, not what ends up linked. A flag on a
pkg-config line - `--static` - names no package. A token a build system
substitutes later - `{{.LinuxAmd64LDFLAGS}}` - names nothing this artefact can
state. **Nothing is resolved**: no path is opened, `${SRCDIR}` is not expanded,
and no version is read for any of them.

### pkg-config names are a different namespace

A pkg-config package name is recorded **verbatim**. `libxml-2.0` is written as
`libxml-2.0`: the `lib` prefix is not stripped, and it is not translated to the
`xml2` a linker would call it. That translation lives in a `.pc` file on the
machine doing the build, not in the artefact, so performing it here would state
a fact these bytes do not carry. A pkg-config package is always `external` -
pkg-config is never how the C runtime is linked.

The verbatim directive is what tells the two apart, so the record needs no extra
field. `go.mongodb.org/mongo-driver/v2@v2.6.0` names both in one module, and
they stay separate entries:

```
libmongocrypt  external  x/mongo/driver/mongocrypt/mongocrypt.go  #cgo linux solaris darwin pkg-config: libmongocrypt
mongocrypt     external  x/mongo/driver/mongocrypt/mongocrypt.go  #cgo windows LDFLAGS: -lmongocrypt -Lc:/libmongocrypt/bin
```

Only text inside the **cgo preamble** - the comment attached to `import "C"` -
is read. A `#cgo pkg-config:` line quoted in package documentation or sitting in
a Go string literal is not a build directive and is not read as one. Measured on
`golang.org/toolchain@v0.0.1-go1.26.6.linux-amd64`: 13 Go files mention
`pkg-config`, `src/cmd/cgo/doc.go` documents the directive by example and
`src/cmd/go/go_test.go` holds several in string literals; **0** reach a preamble
and **0** produce an entry.

Each entry carries the **verbatim directive** it was read from and the file it
sits in, so the claim can be checked against the artefact.

### `external` and `system`

| Kind | Meaning |
|---|---|
| `system` | the C runtime a cgo binary links by construction: `m`, `c`, `dl`, `pthread`, `rt`, `util`, `resolv`, `nsl`, `crypt`, `anl`, `stdc++`, `gcc`, `gcc_s`, `objc`, `System` |
| `external` | everything else, frameworks included |

Only an **external** link earns `linked_not_shipped`. Every cgo binary links
libc and libdl; flagging those would make the value mean nothing. So a module
whose only directive is `#cgo LDFLAGS: -ldl` stays `absent`, and the link is
still listed so the reader can see why:

```
kanonarion native github.com/coreos/go-systemd/v22@v22.7.0
```

```
Module:     github.com/coreos/go-systemd/v22@v22.7.0
Artefact:   zip:h1:JceLXa5a+mEpGoVZMoAHzHfmDdZ0dFSvXINCPCbP37o=
Generation: 0.3.0+recipes.1
Presence:   absent
Statement:  no native source is compiled into a binary from this module's own artefact

Linked libraries named by cgo directives (1)
LIBRARY  KIND    FILE                       DIRECTIVE
dl       system  internal/dlopen/dlopen.go  #cgo LDFLAGS: -ldl
```

A framework is deliberately **not** on the system list. `-framework
CoreFoundation` names a component from outside the module that a reader may want
to see; this tool reports evidence, not verdicts, so it lists it and lets the
reader decide.

## What counts as compiled in

Shipping a `.c` file is not enough. A module can carry C it never builds, and
several in any real store do. A native source counts only when it sits in a
**package directory that declares cgo** with `import "C"`, because that is the
only thing that makes the go tool hand a directory's C sources to a C compiler.

Three consequences follow, and each is a decision rather than a heuristic:

- **A pure-Go transpilation is never flagged.** `modernc.org/sqlite` is SQLite
  translated to Go; it links no C, and the `.c` files in its zip sit under
  `testdata/` where the toolchain never looks. It reads `absent`.
- **Test-only cgo is out of scope.** A package whose only `import "C"` is in a
  `_test.go` file compiles its C into the test binary and into nothing you ship.
- **A directory the go tool ignores is out of scope** - any path element
  beginning with `_` or `.`, and any `testdata` element.

The same three rules scope the linked libraries: a `#cgo` directive in a
`_test.go` file, under `testdata/`, or in a `_`-prefixed directory names nothing
a consumer's binary links.

Assembly (`.s`, `.S`) is deliberately not counted: a `.s` file in a Go package
directory is ordinarily input to Go's own assembler, and the extension does not
tell the two apart. The extensions that do count are `.c`, `.cc`, `.cpp`,
`.cxx`, `.h`, `.hh`, `.hpp`, `.hxx`, `.m`, `.mm`, `.f`, `.F` and `.f90`.

Build constraints are **not** evaluated. A cgo package selected only by a
non-default build tag is recorded as present, and the file evidence names the
files so a reader can see which build would compile them. The same holds for
directives: a `#cgo linux,amd64 LDFLAGS:` line counts, and the verbatim
directive shows its own constraint, so a reader sees which build links the
library without the tool having to pick a platform.

### Known limit: a `.syso` is invisible to this command

**A `.syso` file is native code this command cannot see at any presence value,
and `absent` does not rule one out.**

A `.syso` is a prebuilt object file. The Go **linker** picks it up by extension
and links it straight into your binary - no cgo, no `import "C"`, no C compiler.
Every scope rule above hangs off the `import "C"` gate, because that is the only
thing that makes the go tool hand *source* to a C compiler. A `.syso` never
reaches that gate, so a module shipping one can read `absent` while shipping
compiled native code in the artefact you are holding.

Measured across 1201 module zips: **15 `.syso` files totalling 13,468,734
bytes** sit in a directory the go tool builds, all inside
`golang.org/toolchain`, the largest being
`src/crypto/internal/boring/syso/goboringcrypto_linux_amd64.syso` at **2,429,120
bytes**. (22 `.syso` files are present in all; the other 7, totalling 1,890
bytes, sit under `testdata/` and are out of scope for the same reason
`modernc.org/sqlite`'s `.c` files are.)

It is out of reach for a reason the other limits do not share. The rules above
read a *declaration* - an import, a directive - and record it verbatim. A
`.syso` declares nothing: it is an object file whose contents are already
compiled, so naming the library inside one would mean parsing object code and
matching symbols against a catalogue, which is a different kind of measurement
from anything this command does. Reporting it would need its own presence value
and its own evidence, not a wider rule here.

## How a version is established

Identification is a **per-library recipe against a named declaration**. There is
no C parser here, and nothing is inferred from a file name, a path or a version
heuristic. The recipe for SQLite reads the macro SQLite publishes as part of its
own API:

```
#define SQLITE_VERSION        "3.38.0"
```

Only the exact form `#define <macro> "<value>"` matches. `SQLITE_VERSION_NUMBER`
does not; a concatenation does not; a macro that expands to another macro does
not. Anything a recipe does not match is recorded as `present_unidentified`
rather than guessed at.

The matched line is recorded verbatim as evidence, so the claim can be checked
against the artefact without re-running the tool. Every component carries a
confidence; `declared` means the version was read from the named declaration
inside a source file the build compiles.

If two sources in one artefact declare **different** versions of one library,
both are recorded. Picking one would report a version the artefact does not
unambiguously declare.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Path to fact store root (or `KANONARION_STORE` env var) |
| `--json` | `false` | Emit the `native` section as JSON |
| `--force` | `false` | Re-measure even when a record for this generation is held |

A held record is served rather than re-measured: the answer is a function of the
artefact's bytes at a fixed generation. A record is keyed on the pipeline version
folded with the recipe catalogue version, so adding a recipe re-measures a module
that was previously `present_unidentified` instead of serving the older answer.

## JSON

```
kanonarion native github.com/mattn/go-sqlite3@v1.14.12 --json
```

```json
{
  "schema_version": "1",
  "ecosystem": "go",
  "pipeline_version": "0.3.0",
  "recipe_catalogue_version": "1",
  "module": "github.com/mattn/go-sqlite3",
  "version": "v1.14.12",
  "artefact_identity": "zip:h1:TJ1bhYJPV44phC+IMu1u2K/i5RriLTPe+yc68XDJ1Z0=",
  "presence": "present_identified",
  "statement": "4 native source file(s) compiled in; 1 component(s) identified by declaration",
  "components": [
    {
      "name": "SQLite",
      "version": "3.38.0",
      "confidence": "declared",
      "evidence": [
        {
          "file": "sqlite3-binding.c",
          "declaration": "#define SQLITE_VERSION        \"3.38.0\""
        }
      ]
    }
  ],
  "sources": [
    {
      "file": "sqlite3-binding.c",
      "bytes": 8469484,
      "sha256": "bfd6018c8a2ec69f4ccf2464997cee18b35512374a0f98a7171321bb914618ef"
    }
  ],
  "linked_libraries": [
    {
      "name": "icui18n",
      "kind": "external",
      "directive": "#cgo LDFLAGS: -licuuc -licui18n",
      "file": "sqlite3_opt_icu.go"
    }
  ],
  "extracted_at": "2026-08-25T00:00:00Z",
  "content_hash": "sha256:…",
  "from_cache": false
}
```

`components`, `sources` and `linked_libraries` are always arrays, never `null`,
so a consumer iterates uniformly whatever the answer was.

## `native-list` - reading the records back in bulk

`native` records one module. `native-list` reads back every record the store
holds, so the question the fact exists to answer can be asked of a whole
dependency set at once.

```
kanonarion native-list --presence linked_not_shipped,present_identified,present_unidentified
```

```
github.com/rqlite/go-sqlite3@v1.47.0                    present_identified     4 native source file(s); SQLite 3.53.0; links icui18n, icuuc, sqlite3
rsc.io/qr@v0.2.0                                        linked_not_shipped     links qrencode
golang.org/x/text@v0.21.0                               linked_not_shipped     links CoreFoundation, icui18n, icui18n.57, icuuc, icuuc.57
golang.org/x/sys@v0.28.0                                present_unidentified   1 native source file(s)
golang.org/x/text@v0.17.0                               linked_not_shipped     links CoreFoundation, icui18n, icui18n.57, icuuc, icuuc.57
gonum.org/v1/gonum@v0.17.0                              present_unidentified   49 native source file(s)
github.com/moby/moby/v2@v2.0.0-beta.21                  linked_not_shipped     links libnftables, libsystemd
github.com/mattn/go-sqlite3@v1.14.12                    present_identified     4 native source file(s); SQLite 3.38.0; links icui18n, icuuc, mingw32, mingwex, sqlite3
github.com/terminalstatic/go-xsd-validate@v0.1.6        linked_not_shipped     links libxml-2.0
go.mongodb.org/mongo-driver/v2@v2.6.0                   present_unidentified   4 native source file(s); links GSS, gssapi_krb5, krb5, libmongocrypt, mongocrypt
listing native records at generation 0.3.0+recipes.1, the generation this build serves; records from a superseded generation are not shown (--all-generations)
```

Measured on a store holding 186 records at this generation: **176 read `absent`
and 10 report something.** The listing is how you find those 10 without opening
186.

`--presence` takes one or more of the four values, comma-separated or repeated,
and lists a record matching any of them. The three that are not `absent` are the
answer to "which of my dependencies ship or link native code", which is the
invocation above. A value outside the four is **refused**, not matched: inside a
list a typo would otherwise narrow the answer with nothing in the output to say
so.

Each row names what was found rather than counting it - the component and its
version for `present_identified`, the external libraries for anything that links
some, the file count for `present_unidentified` - so a reader does not have to
open a module to learn which library it is. An `absent` row prints an em dash,
because a measured absence is an answer and not an empty cell.

### Which generation you are reading

A record is stored under a **generation**: the detection logic folded with the
recipe catalogue, e.g. `0.3.0+recipes.1`. A record taken at an earlier
generation answers no query - it was measured by logic this build has replaced -
so `native-list` lists only the generation this build serves, and says so on
every listing.

`--all-generations` includes the rest and marks each one:

```
github.com/terminalstatic/go-xsd-validate@v0.1.6        absent                 —  [superseded generation 0.2.0+recipes.1]
github.com/mattn/go-sqlite3@v1.14.12                    present_identified     4 native source file(s); SQLite 3.38.0  [superseded generation 0.1.0+recipes.1]
16 of 202 listed record(s) were taken at a superseded detection generation; this build serves 0.3.0+recipes.1 and answers no query from them. Re-measure one:
  kanonarion native <module>@<version>
```

The first row is why this matters. At generation `0.2.0` that module read
`absent`; `0.3.0` added `#cgo pkg-config` as a fourth operand form, and at the
generation this build serves the same module reads `linked_not_shipped` and
names `libxml-2.0`. Listing the old record beside the new one would show the
module as carrying nothing.

Under `--json` every row carries `generation` and `superseded`, whether or not
the record is superseded, so a consumer reads one field rather than inferring a
fact from a key's absence.

### Two records for one version

If the store holds two records describing **different artefacts** for one pinned
version, they disagree about what that version's bytes are. `native <coord>`
refuses to answer for it. `native-list` lists both, marks both, and exits
non-zero - every other row still answers, and a store that disagrees with itself
must not read as a clean run.

### Paging and zeros

`native-list` follows the listing rules in
[`conventions.md`](conventions.md#listing-documents): `--limit` (default 50) with
`--offset`, a truncation line whenever the limit bit, and a zero-result notice
that says which of three things happened - the store holds no native record, the
presence filter matched none of the ones it does hold, or the page starts past
the last match.

```
$ kanonarion native-list --presence present_identified --offset 5
no native record on this page — the store holds 186 native record(s), and --offset 5 starts past the last of the 2 matching presence "present_identified"
  to list from the start: kanonarion native-list
```

### `native-list` JSON

```
kanonarion native-list --presence present_identified --json
```

```json
{
  "records": [
    {
      "module": "github.com/mattn/go-sqlite3",
      "version": "v1.14.12",
      "presence": "present_identified",
      "generation": "0.3.0+recipes.1",
      "superseded": false,
      "artefact_identity": "zip:h1:TJ1bhYJPV44phC+IMu1u2K/i5RriLTPe+yc68XDJ1Z0=",
      "components": [
        { "name": "SQLite", "version": "3.38.0", "confidence": "declared" }
      ],
      "linked_libraries": ["icui18n", "icuuc", "mingw32", "mingwex", "sqlite3"],
      "source_count": 4,
      "extracted_at": "2026-08-29T22:20:22Z",
      "content_hash": "sha256:605bab75e041c4ac49a81ead9552100bb6bddc1368dedd3e7eb6fed675230fa4"
    }
  ],
  "truncated": false,
  "limit": 50,
  "subject": "native records at generation 0.3.0+recipes.1",
  "remedy": "--limit 0",
  "offset": 0,
  "next_offset": 50
}
```

`components` and `linked_libraries` are always arrays, never `null`.
`linked_libraries` holds the **distinct** external libraries the cgo directives
name: one library named by five per-platform directives is one library, and the
C runtime every cgo binary links is excluded. A row for a disputed coordinate
carries a `conflict` string; no other row does.

### `native-list` flags

| Flag | Default | Description |
|------|---------|-------------|
| `--presence` | (none) | List only records with one of these presences, comma-separated or repeated |
| `--all-generations` | `false` | Also list records taken at a superseded detection generation |
| `--limit` | `50` | Maximum records to return (`0` = unlimited) |
| `--offset` | `0` | Skip this many records |
| `--json` | `false` | Emit the listing document |

## Where the composite commands report it

`audit`, `inspect` and `context` state the native fact as part of their own
answer, so a reader does not have to know the command exists to be told a build
links libxml2.

- **[`context`](context.md)** carries a `Native code:` line per module, and a
  `native_coverage` object per module under `--json`. It is the same object
  [`vuln-show`](vuln.md) publishes, so a consumer reads one shape.
- **[`audit`](audit.md)** states the build-level roll-up beside its other basis
  lines, and publishes it under `native_coverage` inside the run object of
  `audit --json`.
- **[`inspect --gomod`](inspect.md)** states the same roll-up in its summary and
  publishes the same key.

The roll-up states its own coverage first - how many modules were examined at
all - and then the exceptions. From an `audit` over this repository's own
go.mod, with four of its modules examined:

```
native code: 4 of 21 module(s) examined for native code compiled into or linked into the binary; 0 with an identified component, 1 with native source no recipe names, 0 linking an external library it does not ship
  a module holding no native record was not looked at; that is not a finding of no native code — run: kanonarion native <module>@<version>, or list what is held: kanonarion native-list
  Kanonarion has no non-Go advisory source, so no advisories were searched for any of it
Native source compiled in but not identified (1 module(s)):
  These modules compile native source into the binary and no recipe names the library it belongs to,
  so no component could be named. Run 'kanonarion native <module>@<version>' to see the files.
  golang.org/x/sys@v0.47.0
```

A build that links a library it does not ship gets its own section, naming the
library. This one is from a 474-module walk in which exactly one module links
one:

```
External native library this build links but does not ship (1 in 1 module(s)):
  These modules compile no native source of their own and link a library the host provides. Which build of it
  the linker finds is a property of the build machine, not of these bytes, so no version was read and no
  advisories were searched. These are not findings.
  github.com/terminalstatic/go-xsd-validate@v0.1.6
    libxml-2.0
```

**A module holding no record is "nobody looked", never "no native code".**
`native` is not an extraction stage - `inspect` does not measure it, and puts no
wall time on it - so a freshly walked project reports every module as not
examined until `native` has been run over them.

## Prerequisites

The module must have been fetched, because there is no artefact to read
otherwise:

```
kanonarion fetch github.com/mattn/go-sqlite3@v1.14.12
```

An unfetched module is refused, naming that command. It is never answered as
carrying no native component.

## Exit codes

`0` on success, `20` on a bad invocation or an unfetched module. See
[`conventions.md`](conventions.md#exit-codes).
