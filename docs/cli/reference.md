# kanonarion CLI reference

Index of the per-command documentation. Each command's authoritative page
lives in its own file in this directory; this page only links to them.

New to kanonarion? Start with the
[getting-started guide](../getting-started.md) - it sequences these
commands from a fresh checkout to per-module dependency answers.

For semantics that apply across every command - configuration layering,
depth policy, store layout, and exit codes - see
[`conventions.md`](conventions.md).

## Commands by area

### Fetch & walk

- [`fetch`](fetch.md) - fetch, verify, and persist a Go module
- [`walk`](walk.md) - walk a module's dependency closure and persist the walk record (also `walk-list`, `walk-show`, `walk-diff`)
- [`latest`](latest.md) - resolve the latest published version of one or more modules
- [`use`](use.md) - copy walked, verified modules from the store into a local Go module cache

### Extraction stages

- [`extract`](extract.md) - run extraction stages for all modules in a walk
- [`interface`](interface.md) - extract and summarise a module's public API (also `symbol-find`)
- [`callgraph`](callgraph.md) - extract and summarise a module's call graph (also `callers`, `callees`)
- [`local`](local.md) - ingest the working tree's call graph so `callers`/`callees` resolve internal symbols
- [`examples`](examples.md) - harvest Example\* functions
- [`symbol-context`](symbol-context.md) - assemble a per-module symbol record (signature, godoc, examples) for AI context
- [`context`](context.md) - aggregate all stored records for a module into AI-ready context
- [`dependents`](dependents.md) - find which modules in a walk depend on a given module

### Licence & attribution

- [`licence`](license.md) - extract and persist licence information for a Go module
- [`license-compat`](license-compat.md) - report licence conflicts in a closure against a target SPDX expression
- [`license-diff`](license-diff.md) - report licence changes between two versions of a module
- [`notice`](notice.md) - generate a deterministic THIRD-PARTY-LICENSES attribution document
- [`licence-model`](licence-model.md) - shared explainers: SPDX expressions, copyright extraction, per-file mode

### Vulnerability & SBOM

- [`vuln-scan`](vuln.md) - scan all modules in a walk for vulnerabilities (and all `vuln-*` companions)
- [`reachability`](reachability.md) - determine whether CVE-affected symbols are reachable in the shipped binary
- [`capability`](capability.md) - report the sensitive capabilities a module's reachable code can use (also diffs two versions)
- [`rescan`](rescan.md) - re-scan an existing walk against a fresh vulnerability snapshot
- [`sbom`](sbom.md) - generate a Software Bill of Materials for a walk

### Compliance, policy & inspection

- [`audit`](audit.md) - audit direct dependencies from a go.mod (fetch, licence, vuln in one line per module)
- [`directives`](directives.md) - detect, classify & policy-check go.mod/go.work replace & exclude directives
- [`godebug`](godebug.md) - detect, classify & policy-check `//go:debug` settings
- [`vendor`](vendor.md) - analyse a vendored project; detect drift and `modules.txt` inconsistency
- [`fips`](fips.md) - assess FIPS toolchain eligibility and non-FIPS algorithm / cgo-crypto usage
- [`policy`](policy.md) - `policy validate` and `policy show`
- [`inspect`](inspect.md) - run the full pipeline (walk → extract → vuln-scan → context) for a module
- [`provenance`](provenance.md) - fork/copy provenance facts for a module path (name-path heuristic)
- [`config`](config.md) - read and write configuration values
- [`store`](store.md) - inspect and manage the kanonarion store

## Conventions

See [`conventions.md`](conventions.md) for:

- Global conventions (output, exit codes, store discovery)
- Layered configuration (file → env → flag)
- Depth policy
- Store layout
- Common exit codes
