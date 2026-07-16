# Contributing to exver

How to build, test, and change the `exver` crate.

## Documentation

- README.md — what the crate is and how to use it (version format, range grammar, `satisfies`,
  algebraic laws).
- ARCHITECTURE.md — how it works internally (types, parsing, satisfiability, and its
  relationship to the TypeScript reimplementation).
- CONTRIBUTING.md — this file: toolchain and workflow.
- AGENTS.md — agent-facing rules and gotchas. `CLAUDE.md` is a one-line `@AGENTS.md` import.

## Prerequisites

- Rust stable (the workspace toolchain). That is the whole toolchain — this crate is Rust only.

## Building

From the repo root:

```bash
cargo build -p exver
```

## Testing

From the repo root:

```bash
cargo test -p exver
```

`src/test.rs` runs proptest property tests over the `VersionRange` laws (commutativity,
associativity, identity, annihilator, distributivity, De Morgan). Failing seeds are persisted
under `proptest-regressions/` — commit those if a new regression case is found.

## Formatting

From the repo root (this crate formats as part of the shared Rust crates):

```bash
make start-core-format
make start-core-format-check
```

## Making a change

- If you change the version or range string format, update `src/grammar.pest` and the `FromStr`
  impls together, and update README.md/ARCHITECTURE.md to match.
- Any change to the format or to ordering must also land in the TypeScript reimplementation at
  `shared-libs/ts-modules/start-core/lib/exver/` (`exver.pegjs` + `index.ts`). The two share a
  spec but no code, and nothing enforces that they agree.
