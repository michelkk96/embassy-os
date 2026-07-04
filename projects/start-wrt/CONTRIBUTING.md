# Contributing to StartWRT

Build/test/format and commit/PR conventions that apply repo-wide live in the root
[`CONTRIBUTING.md`](../../CONTRIBUTING.md); this file covers only what is specific to start-wrt.
For structure and data flow see [ARCHITECTURE.md](ARCHITECTURE.md); for the RPC contract see
[API_CONTRACT.md](API_CONTRACT.md).

All commands below run from the **repo root**.

## Backend (Rust)

The three crates (`startwrt-core`/`ctrl`, `uciedit`, `uciedit_macros`) are members of the root
Cargo workspace.

```bash
cargo build -p startwrt-core --bin startwrt                     # host build of the daemon+CLI binary
cargo check -p startwrt-core --bin startwrt                     # fast type-check
cargo test  -p startwrt-core -p uciedit -p uciedit_macros       # all start-wrt unit tests
make start-wrt-test                                              # same tests, containerized (mirrors start-core-test)
```

> **Always scope `cargo test` with `-p`.** A bare `cargo test` (or `cargo test` run from
> `backend/`) now tests the *entire* monorepo workspace — including `startos-backup-fs`, whose
> `fuser` dependency needs FUSE dev libs that exist only in the build container, so it fails on a
> bare host. start-wrt's own crates are fuser-free, so the `-p`-scoped command above runs cleanly
> on the host. `make start-wrt-test` runs the same scoped set inside `start9/cargo-zigbuild`.

`startwrt-core` depends on the shared `start-core` crate (aliased as `startos`), plus the
vendored `rpc-toolkit` and `imbl-value`. For dev authentication set `STARTWRT_DEV_PASSWORD` to
bypass `/etc/shadow`.

> The host build embeds the web UI via `include_dir!`, so it needs `projects/start-wrt/web/dist/`
> to exist — run the web build first (below), or build the full binary with `make start-wrt`.

## Frontend (Angular, in the root workspace)

The web app is the `start-wrt` project in the root Angular workspace — it shares the root
`package.json`/`node_modules`/`tsconfig.json`. Run everything from the repo root:

```bash
npm ci                  # install the whole workspace
npm run build:deps      # build the file: deps (@start9labs/start-core, patch-db client) — once after install
npm run start:wrt       # dev server (mock API, no backend needed) — stamps config.json first
npm run build:wrt       # production build → projects/start-wrt/web/dist/startwrt/browser/
npm run check:wrt       # type-check
npm run check:i18n:wrt  # i18n dictionary check
```

## Building / deploying (via the root Makefile)

start-wrt's targets live in [`build.mk`](build.mk) (included by the root `Makefile`):

| Target | Description |
|--------|-------------|
| `make start-wrt` | web → riscv64 binary (cross-compiled via dockerized cargo-zigbuild) |
| `make start-wrt-openwrt-setup` | one-time: openwrt feeds/config/download (needs the `openwrt` submodule) |
| `make start-wrt-image` | full flashable OpenWrt image → `results/` (**hours**) |
| `make start-wrt-update STARTWRT_REMOTE=root@IP` | deploy binary over SSH (default `root@192.168.0.1`) |
| `make start-wrt-clean` | remove start-wrt build artifacts |

Deployment is atomic (temp file → sync → rename → daemon restart). The web UI is embedded in
the binary, so deploying the binary updates everything.

## Cutting a release

StartWRT is a first-class project of the monorepo-wide release tool,
[`scripts/manage-release.sh`](../../scripts/manage-release.sh) (the `wrt` kind). The version is
read from `backend/ctrl/Cargo.toml`; the git tag / GitHub release is `start-wrt/v<version>`.
Releases stage through a beta registry before promotion to production, mirroring the OS.

1. Bump `backend/ctrl/Cargo.toml` and turn the changelog's `## [Unreleased]` into an explicit
   `## [<version>]` heading (`pre-check` requires it), then land that on `master`.
2. Run the **start-wrt** workflow with `deploy: release`. It builds the OpenWrt image, uploads
   the images to `s3://startwrt-images`, and registers + indexes the version into the **beta
   registry** (signing with the `DEV_KEY` repo secret). Beta routers — any router whose UCI
   `startwrt.system.registry` points at the beta registry (`uci set
   startwrt.system.registry=<beta url>; uci commit startwrt`) — now soak the version as a
   normal OTA update. (If the register step failed or must be redone, the manual fallback is
   `RUN_ID=<the deploy run> ./scripts/manage-release.sh pull-gha start-wrt` followed by
   `./scripts/manage-release.sh register start-wrt` — needs `gh`, `start-cli`, and
   `~/.startos/developer.key.pem`.)
3. Once the version has soaked, cut the release from the repo root (needs `gh`, `gpg` with the
   Start9 org key, `start-cli`, and `~/.startos/developer.key.pem`):

   ```
   ./scripts/manage-release.sh release start-wrt
   ```

   This runs pre-check → pull the images from the beta registry (signature-verified) → tag →
   create the GitHub release → promote beta → production → sign. See `manage-release.sh --help`
   for the individual subcommands (`pull-gha`, `register`, `index`, `sign`, `cosign`, …) and env
   vars (`STARTWRT_SOURCE_REGISTRY`, `STARTWRT_TARGET_REGISTRY`, `STARTWRT_COMPAT_FLOOR`,
   `FORCE=1` to re-run an idempotent release).

> **⚠ UNVALIDATED since the monorepo migration.** The riscv dockerized cross-build (`make
> start-wrt`) and the OpenWrt image assembly (`make start-wrt-image`) have not yet been run on a
> build host. The backend host `cargo check` passes. Validate `make start-wrt` first (it does not
> need the multi-GB `openwrt` submodule), then `make start-wrt-image`. The OpenWrt build needs a
> consistent environment — Docker is recommended; native builds on some distros fail silently.

## Coupled changes

When you change a build input in `build.mk`, mirror it into the `paths:` filter of
`.github/workflows/start-wrt.yaml` (see root AGENTS.md "Coupled changes"). Cross-frontend/backend
changes must update `API_CONTRACT.md`, the Rust handler, and the web `api.service.ts` +
`live-api.service.ts` + `mock-api.service.ts` together.

## Key documents

- [ARCHITECTURE.md](ARCHITECTURE.md) — system architecture, data flow, build pipeline
- [API_CONTRACT.md](API_CONTRACT.md) — complete RPC endpoint contract with Rust types
- [backend/AGENTS.md](backend/AGENTS.md) / [web/AGENTS.md](web/AGENTS.md) — component rules
- [docs/init-reflash.md](docs/init-reflash.md) — manufacturing, setup, and reflash specification
