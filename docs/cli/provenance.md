# `kanonarion provenance` - Fork/copy provenance facts (name-path heuristic)

## Synopsis

```
kanonarion provenance <module>[@<version>] [flags]
```

## Description

`provenance` runs the cheap-tier name-path fork heuristic over a module path:
when the path shares its trailing name element with a catalogued canonical
module under a different owner or host, it reports a **caveated fork
inference** - *"path suggests a fork of `<canonical>` - verify"*.

This is an inference, never a verdict. A developer evaluating
`github.com/someuser/cobra` cannot easily tell that it shares its name with
the canonical `github.com/spf13/cobra`; the heuristic surfaces that collision
as a fact to follow up on. Confirming or refuting a fork requires the strong
tier of evidence - shared VCS origin or content overlap - which this command
deliberately does not attempt.

The heuristic is a pure function of the module path against a versioned static
catalogue of canonical module paths (`catalogue_version` in the output):

- The trailing path element is compared after stripping version markers - a
  `/vN` major-version element and a gopkg.in-style `.vN` suffix - and
  case-insensitively. Only an **identical** trailing element is a signal;
  affix variants (`jwt-go` vs `jwt`) are below the cheap tier's bar.
- A catalogued canonical itself (at any major version) never yields an
  indicator.
- No store record is needed; a `@version`, when given, is echoed in the output
  but does not influence the result.

The same fact appears as the `provenance` section of `kanonarion context`.

Per the absence-vs-zero discipline, `"none"` means *analysed, no fork
indicators* - it is a distinct state from `"not_analysed"`, which only appears
on surfaces that did not run the heuristic.

## Output format

### Text

```
github.com/someuser/cobra
  Fork Heuristic: path_match (catalogue 1.0.0)
    path suggests a fork of github.com/spf13/cobra - verify via VCS origin or content comparison
```

```
example.com/some/app
  Fork Heuristic: no fork indicators (catalogue 1.0.0)
```

### JSON (`--json`)

```json
{
  "module": "github.com/someuser/cobra",
  "version": "v1.0.0",
  "fork_heuristic": {
    "status": "path_match",
    "catalogue_version": "1.0.0",
    "fork_indicators": [
      {
        "canonical": "github.com/spf13/cobra",
        "statement": "path suggests a fork of github.com/spf13/cobra - verify via VCS origin or content comparison"
      }
    ]
  }
}
```

| `status` | Meaning |
|---|---|
| `path_match` | The path shares a trailing name element with one or more catalogued canonicals under a different owner/host. `fork_indicators` is non-empty, sorted by canonical path. |
| `none` | Analysed; no name collision with any catalogued canonical. |
| `not_analysed` | The heuristic was not run. Never emitted by this command; reserved for other surfaces. |

## Exit codes

| Code | Condition |
|---|---|
| 0 | Always - a fork indicator is a fact view, not a policy gate. |
| ≠0 | Usage error (missing or empty module path). |

## Examples

```bash
# Bare module path
kanonarion provenance github.com/someuser/cobra

# Machine-readable, with a version echo
kanonarion provenance github.com/someuser/cobra@v1.0.0 --json
```
