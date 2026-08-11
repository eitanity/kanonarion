# `kanonarion use` - Copy stored modules into the Go module cache

## Synopsis

```
kanonarion use <module@version> [--recursive] [--mod-cache <dir>] [--walk-id <id>]
```

## Description

`use` copies modules that kanonarion has already walked and verified from its
own store into a local **Go module cache**, so a normal `go build` / `go test`
can consume them - including offline, since the bytes come from the store, not
the network.

It answers in the frame of one walk of the target coordinate, then
materialises each module into the cache's `cache/download/<path>/@v/` layout
(`.zip`, `.mod`, `.info`, `.ziphash`, `.lock`). Every copied artefact is
**re-verified against the recorded hash** (`dirhash` over the zip and go.mod);
a checksum mismatch fails that module rather than writing suspect bytes.

By default only the target module is copied. With `--recursive`, every node in
the walk's resolved graph is copied - the full closure that walk selected.

## Which walk supplies the bytes

A store can hold several walks of one target, and they need not carry the same
version set: a `code` walk and a `complete` walk of one project select different
modules, and so do two platforms' walks. The walk `use` copies from is therefore
part of the answer, and every run names it on stderr:

```
==> use: copying the version set of walk 01KZ42BGN0T95D932JMC1GXX3C (frame linux/amd64)
```

`--walk-id <id>` pins the walk. An id the store does not hold, or one rooted at
a different target, is refused with exit `20` before anything is written to the
cache.

Without `--walk-id`, one walk is chosen and, when there was more than one to
choose from, the run says so and which rule applied: a walk whose recorded
resolution still agrees with the project's `go.mod` is preferred over a more
recent one that does not, and recency is the fallback. `kanonarion walk-list
--target <module@version>` lists the walks available to pin.

## Output

```
Copied github.com/google/uuid@v1.6.0 to local cache
```

One line per successfully copied module on stdout. The walk that supplied the
bytes is named on stderr before the first copy. A module that cannot be copied
(no fact record, checksum mismatch) is logged as a warning to stderr and
skipped; other modules still proceed.

## Flags

| Flag | Default | Description |
|---|---|---|
| `<module@version>` | _(required)_ | Coordinate to copy (must have a successful walk) |
| `--recursive` | false | Copy the walk's whole resolved closure, not just the target |
| `--walk-id <id>` | _(chosen)_ | Copy this walk's version set instead of the one the default rule picks |
| `--mod-cache <dir>` | `$GOMODCACHE`, else `$GOPATH/pkg/mod`, else `~/go/pkg/mod` | Destination module cache |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |

## Relationship to other commands

- **Requires:** a stored `WalkRecord` - run [`kanonarion walk`](walk.md) first
  (`use` errors with a pointer to `walk` when none exists).
- **Complementary:** `fetch` populates the store from the network; `use`
  projects the store into a consumable module cache.

## Air-gapped operation

`use --recursive` is the offline remedy the fetch-capable commands name. In an
environment that declares no module fetching (`GOPROXY=off`), `fetch`, `walk`,
`latest` and `audit` refuse before any network I/O and exit `20`; the way to
put a module and its whole closure in front of a `go build` there is this
command, whose bytes come from the store and are re-verified against the
recorded hashes on the way out. `use` itself is unaffected by `GOPROXY` - it
never opens a socket. See
[`fetch`: `GOPROXY=off` and `direct`](fetch.md#goproxyoff-and-direct).

## Notes

- The destination layout matches what the Go toolchain expects under
  `GOMODCACHE`, so no further import is needed - point `go` at the same cache.
- `.info` / `.ziphash` / `.lock` files are only written when absent; existing
  cache entries are left untouched.
- The recorded VCS origin (git URL, commit, ref) is written into the `.info`
  file so provenance is preserved in the cache.

See also: [`walk`](walk.md), [`fetch`](fetch.md).
