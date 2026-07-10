# CI hardening

How the GitHub Actions workflows in `.github/workflows/` are hardened against
supply-chain tampering, and which checks a branch-protection rule should
require. Scope here is the workflow security posture (KN-158). Enabling branch
protection, the signed-commit policy, and pinned-dependency automation
(Dependabot) is tracked separately in KN-160.

## Threat model

The workflows have write access to the repository and (on release) to signing
identity via OIDC. The self-protection concern is a malicious or compromised
third-party action, or unexpected network egress from a runner exfiltrating
secrets or the OIDC token. The mitigations below are defence-in-depth against
exactly that.

## Pinned actions (full commit SHA)

Every third-party action is pinned to a **full commit SHA**, never a tag. A tag
like `@v6` is mutable — whoever controls the action's repo can repoint it at new
code, which then runs with our token. A 40-char commit SHA is immutable. The
trailing `# vX` comment records the human-readable tag the SHA resolved from so
the pin stays auditable and Dependabot (KN-160) can bump it.

To re-resolve a tag to its commit SHA:

```bash
git ls-remote https://github.com/<owner>/<repo> "refs/tags/<tag>" "refs/tags/<tag>^{}"
```

Use the peeled (`^{}`) SHA when the tag is annotated.

## Least-privilege `GITHUB_TOKEN`

Each workflow sets `permissions: {}` at the top level — the default token has
**no** scopes — and each job re-grants only what it needs:

| Workflow | Job(s) | Granted scopes |
|---|---|---|
| ci.yml | all | `contents: read` |
| fuzz.yml | all | `contents: read` |
| release.yml | release | `contents: write`, `id-token: write`, `attestations: write` |

The release job's three scopes map to: creating the GitHub Release
(`contents: write`), keyless cosign signing + attestations over OIDC
(`id-token: write`), and the `actions/attest-*` steps (`attestations: write`).

## Egress control (harden-runner)

`step-security/harden-runner` is the first step of every job. It monitors (and
optionally blocks) network egress from the runner.

- **ci.yml, fuzz.yml** — `egress-policy: block` with an explicit
  `allowed-endpoints` allowlist (GitHub + the Go module proxy/checksum-db). Any
  connection outside the list fails the step, so an injected dependency cannot
  phone home. These run on every PR, so a missing endpoint surfaces immediately
  and the allowlist is cheap to tune.
- **release.yml** — `egress-policy: block` with a wider `allowed-endpoints`
  allowlist. Beyond GitHub and the signing infrastructure (Sigstore
  Fulcio/Rekor/TUF, OIDC, GitHub upload hosts), the release job runs
  kanonarion's **self-audit**, which cross-verifies each dependency's repo
  against `go.sum` at the repo's real VCS host. That host is resolved from the
  module proxy's Origin metadata, **not** from the vanity-import path — so
  `go.uber.org`, `honnef.co`, `mvdan.cc`, etc. are never contacted, only the
  forge they live on. The allowlist was built empirically by capturing the
  egress of a cold-store `kanonarion audit --fresh` over this repo's `go.mod`;
  the complete observed set is:

  | Purpose | Hosts |
  |---|---|
  | Go module proxy / checksum DB | `proxy.golang.org`, `sum.golang.org`, `storage.googleapis.com` |
  | Vulnerability DB (OSV) | `vuln.go.dev` |
  | Dependency VCS forges | `github.com`, `go.googlesource.com`, `gitlab.com`, `codeberg.org`, `gopkg.in` |

  The VCS-forge row is exactly the non-`github.com` entries of
  `allowedVCSHosts` in `internal/fetch/domain/origintrust.go` that this repo's
  dependencies actually resolve to. **The two lists must stay in sync**: a forge
  added to `origintrust.go` (so the audit will try to clone it) must also be
  added here (so the runner can reach it), and vice versa. Adding a dependency
  hosted on a forge in neither list drops that module to checksum-DB-only
  verification in the self-audit until both are updated.

## Cross-platform audit coverage

The release job builds seven `GOOS/GOARCH` targets, but a single
`kanonarion audit` sees only **one** platform's view. The default scope resolves
its dependency set with `go list -deps ./...` (the *package* import graph), which
the Go toolchain evaluates against the ambient `GOOS`/`GOARCH` and build
constraints. A dependency imported only under `//go:build windows` (or a specific
arch) is invisible when the audit runs on `linux/amd64`, so it is never fetched,
verified, licence-checked, or vuln-scanned for that target. govulncheck's
symbol-level reachability is `GOOS`/`GOARCH`-sensitive for the same reason: a vuln
reachable only on a Windows syscall path is not flagged when the scan runs on
Linux.

`kanonarion audit` inherits `GOOS`/`GOARCH` from the environment (it shells out to
`go list`, which honours them), so full coverage needs no flag changes — just one
run per target with the pair exported. Mirror the build matrix:

```bash
set -euo pipefail
for t in darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 linux/amd64 linux/arm64 linux/arm; do
  os=${t%/*}; arch=${t#*/}
  echo "auditing $t"
  # --fresh only on the first iteration; the OSV snapshot is cached after.
  fresh=""; [ "$os/$arch" = darwin/amd64 ] && fresh="--fresh"
  GOOS=$os GOARCH=$arch ./dist/kanonarion_linux_amd64 audit $fresh --json \
    > "dist/kanonarion-audit-${VERSION}-${os}-${arch}.json"
done
```

The host binary stays `kanonarion_linux_amd64` (the runner is Linux); only the
`GOOS`/`GOARCH` seen by the `go list` subprocess changes. The hyphenated report
names stay out of the `kanonarion_*` binary glob used for checksums and signing.

For a single platform-independent inventory pass (licences, verification, the full
module build list via MVS regardless of platform), add `--project`: that scope
uses `go list -m all`, which is not gated by build constraints and returns a
superset spanning every target.

### Per-target SBOMs in the release

`sbom --package` has the same platform sensitivity: its component set is the
binary's import closure, resolved by `go list -deps` against the ambient
`GOOS`/`GOARCH`. `release.yml` therefore generates **one SBOM per released
binary**, exporting the target pair on each iteration so the closure matches the
binary it describes. Two things make this correct rather than cosmetic:

- **`--force` is mandatory, not an optimisation.** Without it `sbom --package`
  reuses the latest succeeded project walk in the store (the one the self-audit
  step builds for `linux/amd64`), pinning every SBOM to that platform's graph.
  Filtering a Linux walk down to a Windows allow-list can never surface a
  Windows-only module. `--force` rebuilds the project walk under the current
  `GOOS`/`GOARCH` so the walk and the allow-list agree.
- **Attestation is per binary.** Each binary gets its own `actions/attest-sbom`
  step binding *its* SBOM to *its* digest — the goreleaser/syft convention. A
  single SBOM attested to all binaries would misattribute the dependency set.
  Because `attest-sbom` is a `uses:` action and cannot loop, the target list is
  duplicated across the build loop, the SBOM loop, and the attestation steps; a
  post-loop guard fails the release if the binary and SBOM counts diverge, and
  the three lists must be kept in sync when a target is added or removed.

## Concurrency

`ci.yml` and `fuzz.yml` cancel superseded in-flight runs
(`cancel-in-progress: true`) to save runner minutes. `release.yml` uses
`cancel-in-progress: false` on purpose — a half-signed, half-published release
must never be cancelled mid-flight; it serializes instead.

## Required status checks

A branch-protection rule on `main` (enablement tracked in KN-160) should require
these checks — the `name:` values produced by `ci.yml`:

- `Test (Go 1.26.x)`
- `Coverage`
- `Lint`
- `Restricted Imports Check`
- `Resource Benchmarks`

`fuzz.yml` (scheduled/dispatch) and `release.yml` (tag-triggered) are not PR
gates and must **not** be added to the required set.
