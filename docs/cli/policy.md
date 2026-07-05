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

### `kanonarion policy show`

Print the effective depth policy for the current invocation - the policy that
`walk` would apply, after auto-discovery (searching upward from the cwd for
`.kanonarion/policy.yaml`) or the explicit `--policy` path.

```
kanonarion policy show [--policy <file>] [--json]
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
- [`kanonarion store`](store.md) - inspect and maintain the store
