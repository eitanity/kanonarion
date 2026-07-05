# Fuzzing

kanonarion fuzzes every parser that consumes untrusted or drift-prone input.
Untrusted bytes that reach a parser must never crash the process or corrupt a
persisted fact, so each parser carries a fuzz harness as a standing regression.

## Targets

One `FuzzXxx` per untrusted-input parser, discovered dynamically (the build is
the registry - no central list to maintain):

| Package | Target | Input |
|---|---|---|
| `internal/walk/adapters/gomod/xmod` | `FuzzParse` | `go.mod` |
| `internal/adapters/ziparchive` | `FuzzArchive` | module zips |
| `internal/iface/adapters/extractor/godoc` | `FuzzExtract` | Go source AST |
| `internal/example/adapters/parser/goast` | `FuzzParse`, `FuzzParseSource` | Go source AST |
| `internal/vuln/adapters/vulndb/osv` | `FuzzDecode` | OSV / vuln-DB JSON |
| `internal/vuln/adapters/vulndb/osv` | `FuzzValidateSnapshotZip` | vuln-DB snapshot zips |
| `internal/vuln/adapters/vuln/govulncheck` | `FuzzParseResults` | govulncheck stream |
| `internal/adapters/proxy/direct` | `FuzzProxyResponses` | module-proxy responses |
| `internal/adapters/sumdb/gosum` | `FuzzSumDBNote` | sumdb signed notes |
| `internal/adapters/vcs/gitexec` | `FuzzResolveTagParse` | git resolve-tag output |
| `internal/walk/adapters/policy/localfile` | `FuzzParse` | `policy.yaml` |
| `internal/config/adapters/store/yaml` | `FuzzParse` | config YAML |

## Running

```bash
make fuzz                 # every target, 30s each (default)
make fuzz FUZZTIME=2m     # longer budget

# A single target:
go test -run='^$' -fuzz='^FuzzDecode$' -fuzztime=1m \
  ./internal/vuln/adapters/vulndb/osv
```

## Seed corpora

The `f.Add(...)` calls in each harness **are** the persistent seed corpus -
in-tree, reviewed via normal PR flow, versioned with the code. There is no
external corpus repository.

## Crasher → regression

Go's native mechanism, no per-bug harness:

1. Fuzzing finds a failing input → Go writes it minimised to
   `testdata/fuzz/<FuzzName>/<id>`.
2. `testdata/` is **not** git-ignored. Commit the file.
3. The CI `test` job (`go test ./...`) replays every committed crasher as an
   ordinary deterministic test - the regression is now permanent.

When the scheduled job finds a crasher in CI it uploads `testdata/fuzz/**`
as the `fuzz-crashers-*` artifact; download, commit, fix.

## Continuous CI

`.github/workflows/fuzz.yml` runs daily (03:17 UTC) and on manual dispatch.
It enumerates fuzz packages and fans them out across a matrix so each gets a
bounded budget in parallel, with failures attributable to one package.

## OSS-Fuzz

Evaluated and intentionally deferred until the untrusted-input parsers ship
in the public open-core module.
