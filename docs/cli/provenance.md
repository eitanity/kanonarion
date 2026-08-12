# `kanonarion provenance` - Fork/republication provenance facts

## Synopsis

```
kanonarion provenance <module>[@<version>] [flags]
```

## Description

`provenance` runs **two independent signals** over a module and reports each
separately. Both are inferences, never verdicts.

| Signal | Reads | Sees |
|---|---|---|
| Name-path heuristic | the module path alone | a fork published under a *different owner at the same name* |
| Copyright-attribution signal | the module's stored **licence record** | a **republication**: the same project continued under a *different path* |

The two are complementary because each is blind to what the other catches. A
republication changes the path, so no element of the new path collides with the
old one and the trailing-name comparison has nothing to fire on. The signal is
in the licence text instead: a republished `LICENSE` carries the original
author's copyright line beside the new maintainers'.

### Name-path heuristic

Runs the cheap-tier name-path fork heuristic over a module path:
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

### Copyright-attribution signal

Reads the module's stored licence record and reports a caveated republication
inference when either rule fires:

- **`multiple_copyright_holders`** - the licence text (excluding vendored
  licence files, whose holders describe a bundled dependency rather than this
  module) attributes copyright to more than one distinct holder. A project that
  has always lived at one path normally carries one.
- **`holder_matches_other_module_path`** - a copyright holder's name names the
  owner of a *different* module path this store knows of. The other path comes
  from one of two places, and the rule reads them differently:
  - **the licence ledger** - any module the store holds a licence record for.
    Here the two module names must also overlap: the owner match alone fires on
    every module a large copyright holder appears in, and the name overlap alone
    fires on any unrelated project sharing a word.
  - **a `go.mod` replace directive** recorded in a walk - the module the
    subject replaces. No name comparison is applied: the directive already says
    the two modules stand in for each other, and a fork is free to rename
    itself. This is what catches the commonest fork shape, a republication that
    keeps the upstream copyright line and adds none of its own - a single
    holder, which the `multiple_copyright_holders` rule can never see, at a path
    whose upstream may never have been licence-analysed here.

  Replace directives are read from the 50 most recent walks. Where the store
  holds more, or where the walks could not be read, a `none` answer states what
  it did not cover rather than presenting a bounded search as an exhausted one.

Every indicator **quotes the copyright lines it rests on** as `evidence`, so
the reader being asked to verify has something to verify against. An unfilled
licence-template placeholder (`<name of author>`, `[fullname]`, `{yyyy}`) never
counts as a holder.

This signal needs a stored licence record. A module without one reports
`not_analysed` with the reason and the command that produces one - never
`none`, which would assert a negative nothing measured.

### Which record answers

With `@<version>` the record is that coordinate's, and nothing is chosen.

Without one, the answer comes from the record for the **newest version** the
store holds - not the most recently extracted one, which is a fact about when
this store was busy and moves the stated basis whenever an unrelated walk lands.
Where the store holds records for more than one version, the output says so, out
of which versions, and how to pin one:

```
notice: no version was named and the store holds licence records for 3 versions of github.com/golang-jwt/jwt/v4 (v4.5.2, v4.5.1, v4.5.0), so one was chosen: github.com/golang-jwt/jwt/v4@v4.5.2, the newest version; pin one with: kanonarion provenance github.com/golang-jwt/jwt/v4@<version>
```

Where the candidate versions **disagree** about the copyright signal, the
disagreement is reported instead of being resolved by picking:

```
notice: no version was named and the store holds licence records for 2 versions of github.com/minio/md5-simd whose copyright signals disagree (v1.1.2 none; v1.1.0 republication) - the answer below is github.com/minio/md5-simd@v1.1.2, the newest version; pin one with: kanonarion provenance github.com/minio/md5-simd@<version>
```

Only versions that produced a signal are compared. A record carrying no
copyright lines measured nothing, and its silence is not the opposite answer; it
is still listed among the candidates when a real disagreement is reported.

**Base rate.** Measured over a working store of 2,454 licence records, 219
(8.9%) name two or more distinct copyright holders. This is an indicator to
follow up on, not a rare alarm: derived and vendored-from projects legitimately
carry a second holder.

## Output format

### Text

```
github.com/someuser/cobra
  Fork Heuristic:    path_match (name-path, catalogue 1.0.0)
    path suggests a fork of github.com/spf13/cobra - verify via VCS origin or content comparison
  Copyright Signal:  not analysed - no licence record for github.com/someuser/cobra; run: kanonarion license github.com/someuser/cobra
```

```
example.com/republished/lib@v4.5.1
  Fork Heuristic:    no indicators (name-path, catalogue 1.0.0)
  Copyright Signal:  republication (licence record example.com/republished/lib@v4.5.1)
    licence text attributes copyright to 2 distinct holders (Original Author; New Maintainers) - a project republished under a new path carries the original author's line beside the new maintainers'; verify via VCS origin or content comparison
      evidence: Copyright (c) 2012 Original Author
      evidence: Copyright (c) 2021 New Maintainers
    copyright holder "Original Author" names the owner of example.com/originalauthor/lib-go, a differently-owned module of the same name held in this store - path suggests a republication of it; verify via VCS origin or content comparison
      evidence: Copyright (c) 2012 Original Author
```

```
example.com/some/app
  Fork Heuristic:    no indicators (name-path, catalogue 1.0.0)
  Copyright Signal:  no indicators (licence copyright lines, record example.com/some/app@v1.0.0)
```

### JSON (`--json`)

```json
{
  "module": "github.com/someuser/cobra",
  "version": "v1.0.0",
  "selection": {
    "rule": "pinned",
    "basis": "github.com/someuser/cobra@v1.0.0"
  },
  "fork_heuristic": {
    "status": "path_match",
    "catalogue_version": "1.0.0",
    "fork_indicators": [
      {
        "canonical": "github.com/spf13/cobra",
        "statement": "path suggests a fork of github.com/spf13/cobra - verify via VCS origin or content comparison"
      }
    ]
  },
  "copyright_signal": {
    "status": "republication",
    "source": "example.com/republished/lib@v4.5.1",
    "indicators": [
      {
        "signal": "multiple_copyright_holders",
        "holders": ["New Maintainers", "Original Author"],
        "evidence": [
          "Copyright (c) 2012 Original Author",
          "Copyright (c) 2021 New Maintainers"
        ],
        "statement": "licence text attributes copyright to 2 distinct holders (...) - ... verify via VCS origin or content comparison"
      }
    ]
  }
}
```

| `copyright_signal.status` | Meaning |
|---|---|
| `republication` | At least one rule fired. `indicators` is non-empty, each quoting its evidence. |
| `none` | The licence record's copyright lines were read; neither rule fired. |
| `not_analysed` | No licence record was read - absent, unreadable, or carrying no copyright lines. `detail` says which, and names the remedy. Never a negative result. |

`copyright_signal.coverage` is present only when the search behind the answer
was bounded - no walk store, walks that could not be listed, or more walks than
the replace-directive search reads.

| `selection` field | Meaning |
|---|---|
| `rule` | `pinned` when the caller named the version, `newest_version` otherwise. |
| `basis` | The coordinate whose licence record answered. Always the same as `copyright_signal.source` when a record was read. |
| `candidates` | The versions the store holds records for, newest first. Absent for a pinned read, which chose nothing. |
| `disagreement` | One `"<version> <status>"` entry per candidate, present only when the candidates that produced a signal do not agree. |
| `statement` | The human-readable notice, absent when nothing was chosen. |

| `status` | Meaning |
|---|---|
| `path_match` | The path shares a trailing name element with one or more catalogued canonicals under a different owner/host. `fork_indicators` is non-empty, sorted by canonical path. |
| `none` | Analysed; no name collision with any catalogued canonical. |
| `not_analysed` | The heuristic was not run. Never emitted by this command; reserved for other surfaces. |

## Exit codes

| Code | Condition |
|---|---|
| 0 | Always - an indicator is a fact view, not a policy gate. This includes `not_analysed`: a missing licence record is reported in the payload, not as a failure. |
| ≠0 | Usage error (missing or empty module path), or the store could not be opened. |

## Examples

```bash
# Bare module path: the copyright signal reads the record for the newest
# version the store holds, names it, and says a choice was made.
kanonarion provenance github.com/someuser/cobra

# Pin the record the evidence comes from
kanonarion provenance github.com/someuser/cobra@v1.0.0 --json
```

The command opens the store read-only. To populate the copyright signal for a
module, extract its licence first:

```bash
kanonarion license <module>@<version>
kanonarion provenance <module>@<version>
```
