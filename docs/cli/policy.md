# `kanonarion policy` - Depth policy inspection & validation

`policy` inspects and validates **depth policy** files - the
`.kanonarion/policy.yaml` documents that control how deep `kanonarion walk`
resolves the dependency closure per module. It is a CLI-only utility, not a
bounded context.

## Commands

### `kanonarion policy validate <path>`

Validate a policy YAML file (or a directory of policy files) against the
current policy schema. `<path>` may be a single file or a directory; in the
directory case every policy file found is validated.

```
kanonarion policy validate <path> [--json]
```

Exits non-zero if the path does not exist or any file fails schema
validation, so it is suitable for use in CI as a pre-merge check on policy
changes.

`--json` changes only the rendering, never the result: the exit code is the
same with and without it. The document is one array with one object per file
validated - a directory with no policy files is `[]`, not prose:

```
kanonarion policy validate ./policies --json
[
  {
    "file": "policies/default.yaml",
    "schema": "depth-policy",
    "passed": true
  },
  {
    "file": "policies/broken.yaml",
    "schema": "depth-policy",
    "passed": false,
    "error": "invalid policy (depth-policy schema): ..."
  }
]
```

### `kanonarion policy show`

Print the effective depth policy for the current invocation - the policy that
`walk` would apply, after auto-discovery (searching upward from the cwd for
`.kanonarion/policy.yaml`) or the explicit `--policy` path.

```
kanonarion policy show [--policy <file>] [--json]
```

`policy show` also prints `effective_vcs_hosts`: the VCS forge allowlist that
will actually be used, resolved rather than as authored. Use it when syncing an
egress allowlist (see below) - a policy that omits the field still
cross-verifies against the built-in set.

## Schema

```yaml
version: "1"

stages:
  fetch:
    max_depth: 0            # 0 = unlimited
    follow_replace: true
    follow_test: false
    follow_indirect: true
    allowed_vcs_hosts:      # optional; see below
      - github.com
```

Stage fields other than `allowed_vcs_hosts` are whole-struct replacement: a
stage present in the file is taken as authored, and an omitted boolean is
`false`. That is why the shipped `default.yaml` writes `follow_replace: true`
and `follow_indirect: true` explicitly.

## Trusted VCS forges (`allowed_vcs_hosts`)

The fetch stage cross-verifies each module by cloning its repository and
comparing the tree against the proxy zip, so the set of hosts kanonarion is
willing to hand to `git` is an allowlist. The built-in default is:

```
bitbucket.org  codeberg.org  github.com  gitlab.com  go.googlesource.com  gopkg.in
```

`allowed_vcs_hosts` replaces that set for the run. Two things it is for, neither
expressible with a flag:

- **Widen** - trust an additional forge (a self-hosted Forgejo, a corporate
  GitLab) so its modules cross-verify instead of degrading to
  checksum-database-only, without a rebuild.
- **Narrow** - trust fewer forges, so the set kanonarion claims to VCS-verify
  matches the egress your runner can actually reach. A CI job whose network
  allowlist is GitHub-only should not claim to VCS-verify GitLab.

```yaml
stages:
  fetch:
    allowed_vcs_hosts:
      - github.com
      - git.example.org
```

**This field keys on presence, not on its zero value** - a deliberate
divergence from the boolean stage fields above. Setting an unrelated fetch
field (say `max_depth`) while omitting `allowed_vcs_hosts` leaves the built-in
set in force; it does not empty the list. Zero-value-on-omit is fine for a
traversal toggle and a footgun for a trust list, where an unrelated edit must
never silently weaken verification.

| `allowed_vcs_hosts` | Effect |
|---------------------|--------|
| absent | built-in default set |
| present, non-empty | replaces the default set wholesale (no merge) |
| present, empty (`[]`) | **load error** - see below |
| present on any stage but `fetch` | **load error** - see below |

An explicitly empty list is rejected at load with an error naming
`--skip-vcs-verify`. "Trust no forge" is not a value of this field: the
allowlist selects **which** forges are trusted, never **whether**
cross-verification runs. `--skip-vcs-verify` skips the git leg cleanly, with
checksum-database verification still running; an empty allowlist would instead
resolve every Origin and then reject it, producing noise for the same outcome.

The field belongs to the `fetch` stage and nowhere else - that is where VCS
cross-verification runs. Putting it under `license`, `callgraph` or any other
stage is a load error naming the stage, not a no-op: a policy that appears to
narrow trust while every forge stays trusted is the exact silent weakening this
field exists to prevent. Unknown stage *names* are still accepted for forward
compatibility; it is the misplaced trust list that is refused.

### Entry format

Each entry must be a bare, lowercased hostname - no scheme, no port, no path, no
user info, no wildcard. Matching is exact; there is no subdomain matching. A
malformed entry is a load error naming the offending entry rather than a silent
narrowing of trust:

```
kanonarion policy show
Error: ... allowed_vcs_hosts: VCS host "https://github.com" must be a bare hostname, not a URL (drop the scheme)
```

Every other checkout invariant holds regardless of this field: https-only
clone URLs, a full hex commit, and rejection of `ext::`, `file://`, `ssh://`,
`git://` and leading-dash values. The policy only changes **which** https hosts
may be handed to `git`.

### Scope of the field

`allowed_vcs_hosts` selects the host in the clone URL kanonarion hands to
`git`. It is not a git setting: git's own configuration and environment
(`protocol.<name>.allow`, `GIT_ALLOW_PROTOCOL`, `url.<base>.insteadOf`) are
separate and apply independently. kanonarion pins every git invocation to the
https transport regardless of how the machine's git is configured.

The standard library is not covered by this field. It is acquired as the
`go.dev/dl` source tarball and anchored on Go's published SHA-256
(`VerifiedGoDevChecksum`), or on the local toolchain when offline
(`VerifiedLocalToolchain`) - it is never reproduced from a repository, so there
is no repository comparison here to govern. The release-tag commit it records
(`vcs_commit`) is a provenance annotation, suppressed by `--skip-vcs-verify`.

### Keeping an egress allowlist in sync

If your CI blocks egress (e.g. `step-security/harden-runner`), the hosts it
permits must match the **policy-resolved** set, not the built-in default -
widening the policy without widening egress means kanonarion resolves an Origin
it cannot reach. `kanonarion policy show` prints the effective set for exactly
this purpose:

```
kanonarion policy show | jq -r '.effective_vcs_hosts[]'
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | _(auto-discover)_ | Explicit policy file path (`policy show` only) |
| `--json` | `false` | Emit output as JSON |
| `--log-level` | `warn` | Log level: `debug`/`info`/`warn`/`error` |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Valid / shown successfully |
| `20` | Policy path not found, failed schema validation, or any other error |

## Examples

```
kanonarion policy validate .kanonarion/policy.yaml
kanonarion policy validate ./policies
kanonarion policy show --policy .kanonarion/policy.yaml
```

## See also

- [`kanonarion walk`](walk.md) - applies the depth policy when resolving a closure
- [`kanonarion fetch`](fetch.md) - honours `allowed_vcs_hosts` when cross-verifying a module
- [`kanonarion store`](store.md) - inspect and maintain the store
