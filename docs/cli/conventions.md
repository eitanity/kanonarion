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

## Common exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Walk partial |
| 2 | Walk failed |
| 3 | Walk cancelled |
| 10 | Record integrity check failed |
| 20 | Configuration or lookup error (bad ID, invalid coordinate, etc.) |
