# `kanonarion config` - Read and write configuration values

`config` reads and writes the operator configuration file
(`<store-root>/config.yaml`, or the file `--config` or `KANONARION_CONFIG`
names) using a git-config style interface: dotted key
paths, `get` reads a single value, `set` writes it. Writes are non-destructive
- only the targeted key is modified, comments and unrelated keys are preserved.

## Commands

### `kanonarion config init`

Write a commented config template to `<store-root>/config.yaml` so the
available settings are easy to discover and edit.

```
kanonarion config init [--store-root <dir>] [--json]
```

Every key in the template is commented out, so the file changes nothing until
you uncomment a value. Keys left commented keep their live built-in default and
continue to track default changes across upgrades (nothing is frozen to disk).
An existing file is preserved - only sections this binary knows about but that
are missing are appended.

This is the only way to *materialise* the file proactively; no other command
creates `config.yaml` as a side effect.

Under `--json` the run is a document naming the file, whether one was already
there, and what this run did to it. Creating a file, completing one and leaving
one untouched are three different events:

```json
{
  "config_file": "/home/you/.kanonarion/config.yaml",
  "existed": true,
  "action": "sections_appended"
}
```

`action` is one of `created`, `sections_appended` or `unchanged`.

---

### `kanonarion config show`

Print the full effective configuration (after defaults and flag overrides).

```
kanonarion config show [--store-root <dir>] [--json]
```

When `--json` is not given, the raw `config.yaml` file is printed (including
comments), followed by an **effective configuration** block: every enforced key,
the value actually in force, and `(default)` when that value comes from the
built-in default rather than from the file.

```
# effective configuration (resolved; (default) = not set in this file)
preferences.log_level                             warn  (default)
license_policy.rules[production].unknown_license  block  (default)
license_policy.rules[tool].unknown_license        warn  (default)
fetch_policy.allowed_vcs_hosts                    (unset: built-in host set, advisory)  (default)
...
```

A key absent from the file still resolves to its built-in default, so the
block, not the file, is what is in force.

**No `config.yaml` in the store is a normal state, not an error.** The command
exits `0`, says which path was looked for, and marks every key `(default)`.

**A file that exists but is rejected still prints**: the file, a notice naming
the rejection, then the effective block with *every* key `(default)`, because a
rejected file sets nothing.

The same notice goes to stderr, so it is visible when stdout is redirected or
`--json` is used. `config show` itself exits `0` — it answered.

When `--json` is given, the resolved config is emitted as JSON. Each licence
rule carries `unknown_license` (the value in force) and
`unknown_license_is_default` (whether it came from the built-in default). The
document opens with `config_file`, giving the `path` looked for, whether it is
`present`, whether it was `rejected`, and `rejection_reason` when it was.
`"present": false` and `"rejected": true` both mean every value below is a
built-in default, and they are different states: nothing was written versus
something was written and refused.

The document also carries `settings`: one entry per resolved key, holding the
dotted `key` a `config get` or `config set` takes, the `value` in force, and its
`source` - `"file"` when the config file names that key, `"default"` when the
value is the shipped built-in, as the `(default)` marker says in the text:

```json
{
  "settings": [
    { "key": "preferences.json",     "value": "true",  "source": "file" },
    { "key": "preferences.progress", "value": "true",  "source": "default" },
    { "key": "staleness.ttl",        "value": "6h0m0s", "source": "file" }
  ]
}
```

The source is per value, not per section. `license_overrides.*` and
`copyright_declarations.*` exist only when the file names them, so `"file"`
there means the entry is present; they have no default. A rejected file sets nothing, so
every entry reads `"default"`, matching the `(default)` markers in the text.

---

### `kanonarion config get <key>`

Print the value for a single dotted key path.

```
kanonarion config get <key> [--json]
```

Scalar values (booleans, strings) are printed as plain text. Sequences and maps
are printed as YAML. Exits with code 20 on unknown key.

Under `--json` the value comes with its `source`, in the same vocabulary
`config show` uses:

```json
{
  "key": "preferences.json",
  "value": "false",
  "source": "default"
}
```

`source` is `file` when the operator wrote the key and `default` when the value
was merged in from the built-in defaults - which a bare `false` cannot say. A
rejected `config.yaml` sets nothing, so every key reads `default` while it is
rejected.

---

### `kanonarion config set <key> <value>`

Write a value to the configuration file, creating it from the commented
template if absent. Only that key changes - other content and comments are
kept, and keys you have not set stay absent, resolving to the built-in default.

```
kanonarion config set <key> <value> [--json]
```

Exits with code 20 if the key is unknown, read-only, or the value has the
wrong type.

Under `--json` the run states what it changed, including the value it
displaced - which the write itself destroys:

```json
{
  "key": "preferences.log_level",
  "previous_value": "warn",
  "previous_source": "default",
  "value": "debug",
  "config_file": "/home/you/.kanonarion/config.yaml"
}
```

`previous_source` is `file` when the file already carried the key and `default`
when nothing had been set and the built-in default is what the write displaced.

## Defaults and precedence

A value is resolved with the precedence **flag > `config.yaml` > built-in
default**. The config file holds only the keys you explicitly write with
`config set` (or by hand); every other key stays absent and resolves to the
*live* built-in default at runtime.

Unset keys are never written to disk, so after an upgrade a changed built-in
default reaches every key you never set; a value you set keeps winning.

The template (`config init` writes it, `config set` creates it on demand)
leaves every key commented out for exactly this reason - uncomment a line only
when you want to pin a value and stop tracking the built-in default.

Only `config init` and `config set` create or modify `config.yaml`; with no
file, every key is a built-in default.

## Which file is read

Every command reads one configuration file:

1. the path given with `--config <path>`, if any;
2. otherwise the path in the `KANONARION_CONFIG` environment variable, if set;
3. otherwise `<store-root>/config.yaml`.

`config init`, `config set`, `config get` and `config show` read and write the
same file. The store root still decides where the store lives; `--config` only
moves the configuration.

## The config hash

`config show` prints `config hash sha256:…` (JSON `config_hash`): the hash of
the configuration in force, defaults applied, over every section but
`preferences` and `storage`. Reordered keys, comments or a default written out
keep the hash. `audit`, `directives`, `godebug`, `vendor`, `fips` and
`inspect --json` name it on their answer and record it; an older record reads
`no config hash recorded`.

The ledger (`store ledger`) holds every hash in use. `config set` appends
`config_changed` when the hash moves; if the store cannot record it, it says so
on stderr and exits 0. The next gate-evaluating command appends
`config_drift_observed` for a change not yet recorded - observed at first use.
`vendor --vendor-only`, with `vendor_policy.vendor_only` unset, is named on the
answer and appends `config_override`.

## Choosing the storage backend

The `storage` section says where the store keeps its records:

```yaml
storage:
  backend: sqlite      # default
  sumdb_cache: ""      # default: <store-root>/sumdb
```

`storage.backend` names a storage backend the running kanonarion binary
registered. The standard binary registers `sqlite`, which keeps `mirror.db`,
`blobs/` and `audit.jsonl` under the store root. A file that names a backend the
binary does not have is refused with exit `20`:

```
error: execute root command: backend "postgres" is not registered in this binary (registered: sqlite)
```

`storage.sumdb_cache` is the checksum-database tile cache directory. Empty
means `<store-root>/sumdb`; a relative path is resolved against the store root.

A backend with settings reads them from a top-level section named after it;
any other unknown section is refused. `config init` writes one, commented out,
for every registered backend; `sqlite` has no settings. Edit them by hand, not
with `config set`; `config show --json` lists them under `sections`.

## When the config file is rejected

A `config.yaml` that exists and cannot be loaded — unreadable, unparseable YAML,
a key the schema does not define, or a value `config set` would refuse — is a
refusal, not a fallback. **Every command exits `20`** and names the file and the
key or value, with the nearest known key for a misspelling:

```
$ kanonarion audit --gomod ./go.mod
error: execute root command: config file /home/you/.kanonarion/config.yaml was rejected: rule 0 (scope "production"): unknown policy outcome "block": must be allow, notify, or warn
  nothing in that file is in force; the built-in defaults would apply instead
  fix the named value, then re-run. To see the file and this rejection: kanonarion config show
  To rewrite one key: kanonarion config set <key> <value>
```

Nothing in a rejected file applies, including the parts that parsed. A rejected
`license_policy` means the built-in policy would be the one gating `audit`, so
the run is refused rather than answered under a policy you did not write.

These commands keep working, because they are how you see the problem and fix
it. Each states the rejection on stderr:

| Command | Why it is exempt |
|---------|------------------|
| `config show`, `store config show` | Report the file and what is actually in force |
| `config get <key>` | Reports one value in force (the built-in, while the file is rejected) |
| `config set <key> <value>` | Repairs the file; edits the YAML directly and never reads the loaded config |
| `config init` | Writes the commented template, where the legal values are listed |

`--help` and `--version` answer on any store; they are resolved before the
config file is read.

**No config file is not a rejection.** A store without `config.yaml` runs the
full built-in policy at exit `0`, unchanged.

### License policy is a sparse overlay

`license_policy` is treated as a sparse overlay on the built-in defaults so a
mostly-commented file never silently drops the rest of the policy:

- **Categories merge by name.** Setting `license_policy.categories.<name>`
  adds or overrides that one category; the built-in categories you don't
  mention are kept. (You can override or add a category, but not delete a
  built-in one - set it to an empty list to neutralise it.)
- **Rules replace when present.** If you define `license_policy.rules`, your
  list fully replaces the built-in rules (they are a scope-keyed whole). If
  you omit `rules`, the built-in rules apply.

## Key paths

Keys follow the dotted-path structure of `config.yaml`.

| Key | Type | Example value |
|-----|------|---------------|
| `version` | string (read-only) | `"3"` |
| `preferences.json` | bool | `true` |
| `preferences.log_level` | string | `debug` / `info` / `warn` / `error` |
| `preferences.progress` | bool | `false` (default `true`) - throttled stderr fetch heartbeat on long `walk`/`inspect`/`audit`/`sbom` runs, the traversal lines a `callers`/`callees` `--transitive` walk writes, and the staleness re-ask lines on `latest`, `fetch` and `audit`; never affects stdout/`--json`. Equivalent to `--no-progress` when `false`. |
| `license_policy.categories.<name>` | sequence | `[MIT, Apache-2.0]` |
| `license_policy.rules` | sequence (read-only) | - |
| `license_policy.rules[].unknown_license` | string (read-only, edit the file) | `allow` / `notify` / `warn` / `block` - see below |
| `license_overrides.<module>` | string, or a mapping (see below) | `MIT` |
| `copyright_declarations.<module>` | mapping (read-only, edit the file) | see below |
| `callgraph.exclude` | sequence | `[github.com/foo/bar]` |
| `callgraph.toolchain` | string | `go1.26.6` - the toolchain a read prefers when one coordinate holds graphs built by two of them. It only breaks that tie: a coordinate naming one toolchain, or none, is served exactly as it is with this unset. An explicit `--toolchain` wins over it. See [`callgraph`](callgraph.md#naming-a-toolchain-on-a-query) |
| `staleness.ttl` | duration | `1h` |
| `staleness.probe_concurrency` | int | `16` - newer-major probe requests in flight at once. A probe the proxy has not finished is re-asked after each round, whatever the width. `0` is serial. |
| `fetch_policy.allowed_vcs_hosts` | sequence | `[github.com, git.example.org]` - absent leaves the built-in host set advisory; naming it switches to enforcing |
| `storage.backend` | string | `sqlite` - the storage backend that holds the store's records; see [Choosing the storage backend](#choosing-the-storage-backend) |
| `storage.sumdb_cache` | string | `/var/cache/kanonarion/sumdb` - empty means `<store-root>/sumdb` |
| `vulndb.url` | string | `https://mirror.example.com/go` - a mirror serving `vuln.go.dev`'s `vulndb.zip`, `index/db.json` and `index/modules.json.gz`; `https://` with a host only. Unset is `https://vuln.go.dev`. A snapshot from it keeps source `vuln.go.dev` and records the mirror as `origin` |

The unified governance blocks (`directive_policy`, `godebug_policy`,
`vendor_policy`, `fips_policy`) are edited in the file rather than through
`config set`; each is documented on its own page
([`directives`](directives.md), [`godebug`](godebug.md),
[`vendor`](vendor.md), [`fips`](fips.md)). All of them appear in the effective
configuration block of `config show`.

### `license_overrides` - the licence you determined

`license_overrides` records your licence determination for a module: a
correction where the detector read the files and got it wrong, an election
where a module offers a choice of arms, and an identity where the detector
found none at all. Every surface that reports a licence honours it -
`license-compat`, `audit`, `license-list` and `notice`.

An entry is written either as the bare SPDX identifier

```yaml
license_overrides:
  golang.org/x/mod: MIT
```

or with the provenance of the determination:

```yaml
license_overrides:
  github.com/example/mod:
    spdx: "Apache-2.0"
    declared_by: "you@example.com"
    declared_on: "2026-01-31"
    basis: "README.md at github.com/example/mod v1.2.3, read 2026-01-31"
```

The key is a module path, optionally pinned to a version
(`github.com/example/mod@v1.2.3`); a pinned entry wins over a module-level one.

**Which form to use.** An SPDX identifier is self-evidencing where the module
ships the licence text: a reviewer checks the two against each other. Where it
ships none - the case `notice` refuses on - there is nothing to check it
against, and who determined it, when, and what they read is the only thing that
makes the entry auditable. `notice` publishes all three beside the module and
marks the identity as yours rather than as a detection; recorded as a bare
identifier, it still settles the module, and the document says the
determination names nobody.

**Provenance is all-or-nothing.** An entry giving some of `declared_by`,
`declared_on` and `basis` but not all is refused when the config file loads,
naming the coordinate and the field. `declared_on` must be an ISO 8601 date
(`YYYY-MM-DD`).

**The detector's own answer is untouched.** An override is not an edit of the
extraction record: `kanonarion license <module>@<version>` keeps reporting what
the detector read, and `license-list` reports the override with its source
column reading `override`.

`config set license_overrides.<module> <SPDX>` writes the bare form. On a module
whose entry carries provenance it refuses rather than deleting it - edit that
entry in the file.

### `copyright_declarations` - copyright a human read upstream

Some modules ship no copyright statement anywhere `licence` extraction can
reach it: not in a licence file, not in a `NOTICE`, not in source headers.
`notice` refuses to publish an attribution document for them, correctly - a
NOTICE that silently omits an attribution the licence requires is worse than
none. `copyright_declarations` is where the operator records what they read in
the upstream repository so the document can be published.

```yaml
copyright_declarations:
  github.com/example/mod:
    copyright: "Copyright 2019 Example Authors"
    declared_by: "you@example.com"
    declared_on: "2026-01-31"
    basis: "LICENSE header at github.com/example/mod v1.2.3, read 2026-01-31"
```

The key is a module path, optionally pinned to a version
(`github.com/example/mod@v1.2.3`); a pinned entry wins over a module-level one,
the same precedence `license_overrides` uses.

**All four fields are required.** An entry missing any of them is refused when
the config file loads, naming the coordinate and the field. An SPDX identifier
is self-evidencing - a reviewer checks it against the licence text - but a
copyright line is an assertion about what a person read somewhere, and without
an author, a date and a cited basis nobody reading the document can check it.
`declared_on` must be an ISO 8601 date (`YYYY-MM-DD`).

**An extracted notice always wins.** Where `licence` extraction found a
copyright, that is what the document attributes; a declaration recorded beside
it is kept and printed as corroboration, never as a replacement. See
[`notice`](notice.md#recording-a-copyright-a-human-read).

Declarations are edited in the file rather than through `config set`, which
writes scalar values. `config get copyright_declarations` and
`config show` report what is in force.

### `license_policy.rules[].unknown_license` - the unknown-licence gate

A dependency whose licence could not be resolved to any SPDX identifier is
**undetermined** - no licence record, or an extraction that produced
`None` / `Multiple` / `ExtractionFailed` / `Cancelled`, with no
`license_overrides` entry. Undetermined is not the same as "uncategorised": a
named-but-unlisted licence like `Totally-Unknown-1.0` still resolves through the
rule's `default`.

`unknown_license` is the per-scope control for undetermined licences, and it is
the only setting that can fail a build:

| Value | Effect |
|-------|--------|
| `allow` | accepted silently |
| `notify` | surfaced for awareness |
| `warn` | flagged as needing attention |
| `block` | hard compliance failure - `audit` exits non-zero (code `5`) and names the blocked modules |

**Defaults, when the key is not set:** `block` for `scope: production`, `warn`
for every other scope. Uncertainty fails closed in production rather than being
rendered as a clean allow.

```yaml
license_policy:
  rules:
    - scope: production
      allow: [permissive]
      default: allow
      unknown_license: block
    - scope: tool
      allow: [permissive, weak_copyleft, strong_copyleft]
      default: allow
      unknown_license: warn
```

Run `kanonarion config show` to see the value in force for each scope, including
whether it is the default.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--store-root` | `~/.kanonarion` | Root directory for blobs and SQLite |
| `--config` | `<store-root>/config.yaml` | Configuration file to read and write; `KANONARION_CONFIG` names it when the flag is not given |
| `--json` | `false` | Emit output as JSON (every `config` subcommand) |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `20` | Unknown key, read-only key, wrong value type, I/O error, a `storage.backend` this binary did not register, or a `config.yaml` the loader rejected (every command except those listed under [When the config file is rejected](#when-the-config-file-is-rejected)) |

## Examples

```
# Write a commented template to discover the available settings
kanonarion config init

# Inspect the full config
kanonarion config show

# Read a single value, with where it came from
kanonarion config get preferences.json
kanonarion config get preferences.json --json
kanonarion config get license_policy.categories.permissive
kanonarion config get copyright_declarations

# Write values
kanonarion config set preferences.json true
kanonarion config set preferences.log_level debug
kanonarion config set license_policy.categories.permissive '[MIT, Apache-2.0, ISC]'
kanonarion config set license_overrides.golang.org/x/mod MIT
kanonarion config set callgraph.exclude '[]'
kanonarion config set callgraph.toolchain go1.26.6
kanonarion config set staleness.ttl 6h
kanonarion config set storage.backend sqlite

# Use a configuration file kept outside the store
kanonarion walk-list --config /etc/kanonarion/config.yaml
```

## See also

- [`kanonarion store config show`](store.md) - alias for `config show`
- [`kanonarion policy`](policy.md) - inspect and validate depth policy files
