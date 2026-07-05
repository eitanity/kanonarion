# `kanonarion latest` - Latest published version lookup

## Synopsis

```
kanonarion latest <module> [<module>...]
kanonarion latest [--gomod <path>] [flags]
```

## Description

`latest` queries the Go module proxy for the latest published version of one or
more modules.

With `--gomod` (or from a directory containing `go.mod`), it resolves the
project's dependency **scope** and reports the pinned version of each module
against the latest available - letting you see version staleness across your
dependency tree in a single call. The scope is consistent with every other
go.mod command: the default is the project's own **code** dependencies (`go list
-deps -test ./...`); `--tool` reports the tooling supply chain; `--project`
reports the complete set (code + tooling, the full Go build list). `--tool` and
`--project` are mutually exclusive. See
[`walk` Scopes](walk.md#scopes-code-tool-complete).

Without a module argument or `--gomod`, `latest` defaults to `./go.mod` in the
current directory. If no `go.mod` exists there, it returns an error.

Without `--gomod`, one or more module paths may be passed as positional
arguments and the result shows the latest version with its release date
for each. With a single module, `--json` emits an object; with multiple,
`--json` emits an array (matching the `--gomod` shape) so the output is
trivially `jq`-pipeable. Argument order is preserved.

### Integration with `fetch` and `audit`

Version staleness is baked into the two most common commands, so agents rarely
need to call `latest` directly:

- **`fetch <module@pinned>`** - annotates its output with `[latest: vX.Y.Z, N
  days ago]` when the pinned version is not the current latest.
- **`audit --gomod ./go.mod`** - includes a staleness column for every direct
  dependency alongside verification, license, and vulnerability status.

Use `latest` when you specifically want *only* version information, or when you
need the `--json` output for a structured pipeline.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--gomod` | `./go.mod` | Path to `go.mod`; report latest vs pinned for the project's code dependencies |
| `--tool` | false | Scope to the tooling supply chain (the `go.mod` tool directives' closure). Mutually exclusive with `--project` |
| `--project` | false | Scope to the complete set: the project's code **and** tooling (the full Go build list). Mutually exclusive with `--tool` |
| `--goproxy` | `$GOPROXY` or `proxy.golang.org` | Override the Go module proxy |
| `--json` | false | Emit output as JSON (global flag) |

## Text output

### Single module

```
github.com/spf13/cobra@v1.10.2 (released 45 days ago, 2025-03-28)
```

### `--gomod` table (one line per direct dependency)

```
github.com/CycloneDX/cyclonedx-go@v0.9.2      latest: v0.11.0 (released today)
github.com/google/licensecheck@v0.3.1          current
golang.org/x/mod@v0.35.0                       latest: v0.36.0 (6 days ago)
modernc.org/sqlite@v1.50.0                     latest: v1.50.1 (3 days ago)
```

## JSON output

### Single module

```json
{
  "module": "github.com/spf13/cobra",
  "latest": "v1.10.2",
  "latest_date": "2025-03-28T...",
  "days_behind": 0,
  "is_latest": true
}
```

### `--gomod` array

```json
[
  {
    "module": "golang.org/x/mod",
    "pinned": "v0.35.0",
    "latest": "v0.36.0",
    "latest_date": "2025-05-08T...",
    "days_behind": 6,
    "is_latest": false
  },
  {
    "module": "golang.org/x/sync",
    "pinned": "v0.20.0",
    "latest": "v0.20.0",
    "latest_date": "2025-04-01T...",
    "days_behind": 0,
    "is_latest": true
  }
]
```

## Agentic workflow

The recommended pattern for an agent answering "which of my deps need an
upgrade?":

```bash
# Step 1: get a full snapshot - versions, staleness, licenses, vulns - one call
kanonarion audit --gomod ./go.mod --json

# Step 2: for any dep where is_latest=false, fetch the candidate and compare
kanonarion fetch github.com/foo/bar@v1.5.0 --json
```

`audit` calls the proxy for every direct dep internally, so the staleness data
is already there at no extra cost.

## Examples

```bash
# Latest version of a single module
kanonarion latest github.com/spf13/cobra

# Latest versions of multiple modules in one call
kanonarion latest github.com/spf13/cobra github.com/stretchr/testify

# Machine-readable version info (object for single, array for multiple)
kanonarion latest github.com/spf13/cobra --json
kanonarion latest github.com/spf13/cobra github.com/stretchr/testify --json

# Staleness report using ./go.mod (auto-detected from current directory)
kanonarion latest

# Staleness report with explicit path
kanonarion latest --gomod ./go.mod

# JSON staleness report for pipeline use
kanonarion latest --gomod ./go.mod --json

# Check staleness of the tooling supply chain
kanonarion latest --gomod ./go.mod --tool

# Check staleness of the complete set (code + tooling)
kanonarion latest --gomod ./go.mod --project
```

## See also

- [`audit`](audit.md) - full check suite including staleness, licenses, and vulns
- [`fetch`](fetch.md) - fetches a module and annotates staleness inline
