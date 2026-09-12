# Contributing to Kanonarion

Thanks for your interest in contributing. Kanonarion is the open-core
foundation of a supply-chain analysis platform; this repository is **canonical
and upstream** - all core development happens here.

## Contributor License Agreement (CLA)

**A signed CLA is required before we can merge your contribution.** Kanonarion
follows an open-core model: the commercial product builds on top of this public
core, so we need you to grant the rights that make that possible. The CLA
confirms you have the right to contribute your work and licenses it so it can be
distributed both in this Apache-2.0 project and in derived commercial builds.

The CLA bot will prompt you on your first pull request. You only sign once.

## Ground Rules

- **By contributing, you agree your work is licensed under
  [Apache-2.0](./LICENSE).**
- Be respectful and constructive. Assume good faith.
- Security issues do **not** go in public issues - see [SECURITY.md](./SECURITY.md).

## Development

Build, test, and lint before opening a PR - all three must pass:

```bash
make build
make test    # all packages, race detector
make lint    # vet, staticcheck, govulncheck, gosec
```

`make lint` does **not** run golangci-lint. Run it separately, and expect zero
issues:

```bash
go tool golangci-lint run ./...
```

gosec runs standalone there, which means `//nolint:gosec` is ignored - a
suppression it will honour must be written `// #nosec Gxxx -- reason`.

### Documentation

`docs/cli/*.md` documents behaviour: what a command does, and the nuance a reader
needs in order to act on the answer. Why it was built that way belongs in the
commit message and the issue.

**A section that states a rule must also state what goes wrong without it.** "This
line names the toolchain the walk was resolved under" tells a reader what they are
looking at. It does not tell them that scanning under one toolchain and shipping
under another means the standard library findings belong to a build they never
release. The second sentence is the one that changes what they do, and it is the
one that keeps getting left out of new material.

Lead with the consequence where there is a real one. Mechanism after.

Examples in a fenced block are checked by `make test`: across every shipped
document, an invocation must use flags the command accepts and must not name one
the command refuses, and a ```json block must not name a key nothing emits. In
the onboarding documents, example coordinates must not be this repository's own
pinned dependencies.

### Changing dependencies

`THIRD-PARTY-LICENSES` is generated, not hand-edited. If your change adds,
removes or bumps a dependency of `./cmd/kanonarion`, regenerate it:

```bash
kanonarion notice --package ./cmd/kanonarion > THIRD-PARTY-LICENSES
```

The release workflow regenerates the file and fails on any difference, so a
stale one blocks the release rather than shipping. Regenerating needs a
populated store: run `kanonarion audit` in the checkout first if a module has
no licence record yet.

### Architecture

Kanonarion follows strict Domain-Driven Design layering across bounded
contexts. Dependencies point inward only:

```
cmd → internal/cli → internal/{ctx}/adapters → application → ports → domain
```

- No cross-context imports except through `ports` interfaces.
- No wall-clock access in `application`/`domain` layers - inject a clock.
- All JSON / graph output must be deterministic (sorted keys, sorted edges).

These rules are enforced by lint and architecture tests, so a conforming change
passes CI mechanically. See `docs/ARCHITECTURE.md` for the rationale.

### The public API surface

`pkg/kanonarion` is the curated public API façade. It is the only surface
external consumers may import (everything else lives under `internal/`). Every
exported identifier needs a doc comment and a `Stability:` line; CI rejects
undocumented exports. Grow published ports only by adding a new optional
interface, never by widening an existing one.

## Pull Requests

1. Fork and create a topic branch.
2. Keep changes focused; one logical change per PR.
3. Write a regression test for every bug fix - name it after the behaviour.
4. Use Conventional Commit style for the title: `type(scope): description`.
5. Ensure `make build && make test && make lint` are green.
6. Open the PR and sign the CLA when prompted.

## Reporting Bugs and Requesting Features

Open a GitHub issue with a clear title, what you expected, what happened, and
the version/commit. For supply-chain analysis discrepancies, include the module
coordinate and the command you ran.
