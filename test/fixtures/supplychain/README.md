# Supply-chain test corpus

Shared fixture layout for the four supply-chain analyses. It exists so each
analysis **extends** a common corpus instead of inventing per-analysis ad-hoc
fixtures. Each leaf directory is a self-contained Go module (its own `go.mod`)
so `go test ./...` and the parent build ignore it - these are *data*, not
compiled code. Go **source** fixtures are stored with a `.go.txt` extension
for the same reason: the pre-commit linter typechecks staged `.go` paths
against the main module and does not honour nested `go.mod`. The detectors read
these as text (the godebug detector parses `//go:debug` from source text; the
vendor detector hashes file bytes), so the extension does not matter to
detection.

## Layout

```
supplychain/
  directives/   replace / exclude detection & classification
    clean/          no directives                → expect: clean
    local-replace/  replace → local path (+go.work) → expect: highest-risk
    exclude-newer/  exclude of newer-than-resolved  → expect: high-risk
  godebug/       GODEBUG / //go:debug audit
    clean/          no //go:debug                → expect: clean
    red-main/       //go:debug tlsrsakex=1 in main → expect: red violation
    dep-not-applied/ //go:debug in vendored dep   → expect: recorded not-applied
  vendor/        vendored-tree analysis & drift
    matching/       vendor/ + go.sum match       → expect: clean
    drift/          one vendored file altered    → expect: drift detected
    missing-module/ modules.txt lists, vendor/ omits → expect: inconsistency
  fips/          FIPS toolchain detection
    stock/          stock Go build marker        → expect: not FIPS-capable
    boringcrypto/   BoringCrypto build marker    → expect: FIPS-capable
```

## Contract for gap tickets

- **Add cases here**, do not fork the structure. A new scenario is a new leaf
  directory under the relevant gap folder with its own `go.mod`.
- Every leaf states its **expected verdict** in this README's table above so
  the corpus stays self-documenting.
- The corpus is consumed by per-gap unit/integration tests; keep fixtures
  minimal (smallest input that exercises the classification).
- `fips/*/buildinfo.txt` holds a `debug.BuildInfo`-style `GoVersion:` line -
  the FIPS detector parses the variant string, it does not build these.
- `vendor/{matching,drift}/go.sum` carries the `h1:` of the *pristine*
  vendored `example.com/dep` tree (the `matching` tree). The vendor detector
  recomputes the vendored-tree `dirhash` and compares: `matching` equals it (clean),
  `drift` differs (one injected function) → drift. Regenerate with
  `dirhash.HashDir("…/matching/vendor/example.com/dep","example.com/dep@v1.2.0",dirhash.Hash1)`
  if the matching fixture ever changes.
