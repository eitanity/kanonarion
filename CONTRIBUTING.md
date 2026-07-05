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
make lint    # golangci-lint; write lint-clean code the first time
```

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
