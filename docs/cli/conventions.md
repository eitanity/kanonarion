# kanonarion CLI conventions

Shared semantics that apply across every `kanonarion` subcommand:
configuration layering, depth policy, on-disk layout, and exit codes.
Per-command pages link back here instead of restating these rules.

## Global conventions

- All commands write logs to **stderr** and data to **stdout**.
- Pass `--json` to get machine-readable output on stdout. Log lines remain on stderr.
- `--store-root` defaults to `~/.kanonarion`. It holds the SQLite database, blob store, sumdb cache, audit log, and `config.yaml`.
- The `<module@version>` argument follows standard Go module coordinate syntax, e.g. `github.com/spf13/cobra@v1.8.1`.

### Layered configuration

Flag values take precedence over store config, which in turn takes precedence over built-in defaults:

```
flag > <store-root>/config.yaml > built-in default
```

On first run kanonarion writes a fully commented `config.yaml` to your store root with all defaults populated. Edit it to set sticky preferences. When a new binary version adds sections, they are appended non-destructively on the next invocation - existing content and comments are preserved.

To inspect the effective configuration:

```
kanonarion store config show          # raw file with comments
kanonarion store config show --json   # parsed effective config as JSON
```

```yaml
version: "1"
preferences:
  json: false
  log_level: warn
license_policy:
  categories:
    permissive:      [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
    weak_copyleft:   [LGPL-2.1-only, LGPL-3.0-only, MPL-2.0]
    strong_copyleft: [GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only, AGPL-3.0-only]
    restricted:      [SSPL-1.0, BSL-1.1, AGPL-3.0-only]
  rules:
    - scope: production
      allow:   [permissive]
      notify:  [weak_copyleft]
      warn:    [strong_copyleft, restricted]
      default: allow
    - scope: tool
      allow:   [permissive, weak_copyleft, strong_copyleft]
      notify:  [restricted]
      default: allow
license_overrides:
  # golang.org/x/mod: MIT
callgraph:
  exclude: []
```

Policy outcomes are `allow`, `notify`, and `warn` - there is no blocking mechanism. Categories not listed in any outcome list resolve to `default`; an absent `default` resolves to `allow`. The same implicit allow applies when no rule exists for a scope.

---

## Depth policy

Walk behaviour is governed by a depth policy file (YAML). kanonarion searches for `.kanonarion/policy.yaml` starting from the current directory and walking up to the filesystem root. If no file is found, built-in defaults are used.

**Policy file format**

```yaml
version: "1"
stages:
  fetch:
    max_depth: 0        # 0 = unlimited
    follow_replace: true
    follow_test: false
    follow_indirect: true
```

The `stages` map is keyed by stage name. Only `fetch` is used in Phase 1; additional stages (`licence`, `interface`) will be consumed in later phases and are preserved for forward compatibility.

Example policies are available in `docs/examples/policies/`.

---

## Store layout

All state lives under `--store-root` (default `~/.kanonarion`):

```
~/.kanonarion/
  mirror.db       # SQLite - all records (fetch, walk, callgraph, license, …)
  audit.jsonl     # append-only audit log of every fetch
  sumdb/          # go.sum database tile cache
  blobs/          # fetched module ZIP content
```

---

## Exit codes

This is the authoritative table. Every command uses these codes and no others;
where a command gives one of them a command-specific meaning it is listed below
and repeated in that command's `--help`.

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | Success |
| 1 | Partial | The work completed but is known-incomplete: walk partial, or an SBOM generated with incomplete licence data |
| 2 | Failed | The work could not complete: walk failed, or `license-compat` found unmodelled licence pairs needing review |
| 3 | Cancelled | The context was cancelled before the work completed |
| 4 | NotFound | A record requested by ID or coordinate does not exist. The message names the command that produces it |
| 5 | Policy | A governance or publication gate fired on real findings. The scan succeeded and the finding is genuine |
| 10 | Integrity | Recorded evidence is in doubt: a record failed its content-hash check, or two records for one coordinate diverge |
| 20 | Config | The command never got as far as an answer: malformed argument, unparseable coordinate, missing toolchain, absent policy *file*, or a store whose schema is newer than this binary |

The distinction that matters to an automation caller is **4 vs 5 vs 20**. A 4
means the request was well-formed and the named remedy command fixes it. A 5
means the command did its job and the answer is one a human must accept or
reject — it must not be routed to whoever fixes broken invocations. A 20 means
the invocation itself was wrong.

### Which commands use which codes

| Code | Commands |
|---|---|
| 1 | `walk`, `inspect` (partial closure); `sbom` (incomplete licence data — the document IS still written); `license-compat` (confirmed incompatible pairs) |
| 2 | `walk`, `inspect` (target unfetchable); `license-compat` (unknown pairs, never silently "compatible"); `license-compat` (root has a licence record but no SPDX identity) |
| 4 | `walk-show`, `walk-list --walk-id`, `walk-diff`, `dependents`, `context --walk-id`, `verification-coverage`, `vuln-show`, `vuln --history`, `scan-show`, `snapshot-show`, `vuln-scan --snapshot`, `reachability --vuln`, `callgraph-show`, `interface-show`, `interface-list`, `examples-show`, `examples-list`, `license`, `license-compat`, `license-diff`, `directives-show`, `directives-diff`, `use` |
| 5 | `audit` (unknown licence blocked by policy), `directives`, `godebug`, `vendor`, `fips`, `notice` (modules require human review) |
| 10 | any command consuming a walk whose node failed integrity, or that meets a divergence |
| 20 | every command, for a malformed invocation |

A policy gate is only a 5 when it *fired on findings*. A policy **file** that
cannot be found or parsed is a 20 — that is a broken invocation, not a verdict.

### Store schema newer than the binary

Every command that writes to the store refuses to run when `mirror.db` carries
schema migrations the binary does not know — that is, when the store was last
written by a newer build of kanonarion. Exit code is **20**: the store is intact
and a current binary reads it fine, so this is a precondition failure, not a
record-integrity failure (10).

The refusal names the unrecognised migrations and the remedy, which is to upgrade
kanonarion. `kanonarion store info` is exempt: it opens the store without
applying migrations and never writes, so the command that diagnoses the refusal
stays available. This mirrors how a divergence is handled — a store-inspection
command reports and exits 0 while a consuming command fails closed.

Running an older binary against a newer store without this gate is not a
harmless no-op: writes fail per statement against tables shaped by a later
build, so a scan can complete, print a summary and have persisted nothing.
