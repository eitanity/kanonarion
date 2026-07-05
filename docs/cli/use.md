# `kanonarion use` - Copy stored modules into the Go module cache

## Synopsis

```
kanonarion use <module@version> [--recursive] [--mod-cache <dir>]
```

## Description

`use` copies modules that kanonarion has already walked and verified from its
own store into a local **Go module cache**, so a normal `go build` / `go test`
can consume them - including offline, since the bytes come from the store, not
the network.

It locates the latest successful walk for the target coordinate, then
materialises each module into the cache's `cache/download/<path>/@v/` layout
(`.zip`, `.mod`, `.info`, `.ziphash`, `.lock`). Every copied artefact is
**re-verified against the recorded hash** (`dirhash` over the zip and go.mod);
a checksum mismatch fails that module rather than writing suspect bytes.

By default only the target module is copied. With `--recursive`, every node in
the walk's resolved graph is copied - the full closure that walk selected.

## Output

```
Copied github.com/google/uuid@v1.6.0 to local cache
```

One line per successfully copied module. A module that cannot be copied (no
fact record, checksum mismatch) is logged as a warning to stderr and skipped;
other modules still proceed.

## Flags

| Flag | Default | Description |
|---|---|---|
| `<module@version>` | _(required)_ | Coordinate to copy (must have a successful walk) |
| `--recursive` | false | Copy the walk's whole resolved closure, not just the target |
| `--mod-cache <dir>` | `$GOMODCACHE`, else `$GOPATH/pkg/mod`, else `~/go/pkg/mod` | Destination module cache |
| `--store-root <path>` | `~/.kanonarion` | Root directory for blobs and SQLite |

## Relationship to other commands

- **Requires:** a stored `WalkRecord` - run [`kanonarion walk`](walk.md) first
  (`use` errors with a pointer to `walk` when none exists).
- **Complementary:** `fetch` populates the store from the network; `use`
  projects the store into a consumable module cache.

## Notes

- The destination layout matches what the Go toolchain expects under
  `GOMODCACHE`, so no further import is needed - point `go` at the same cache.
- `.info` / `.ziphash` / `.lock` files are only written when absent; existing
  cache entries are left untouched.
- The recorded VCS origin (git URL, commit, ref) is written into the `.info`
  file so provenance is preserved in the cache.

See also: [`walk`](walk.md), [`fetch`](fetch.md).
