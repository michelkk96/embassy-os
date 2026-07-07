use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::Parser;
use ed25519_dalek::SigningKey;
use futures::future::{BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use url::Url;

use crate::PackageId;
use crate::context::CliContext;
use crate::context::config::local_config_path;
use crate::developer::{default_developer_key_path, load_signing_key, write_developer_key};
use crate::prelude::*;
use crate::util::Invoke;
use crate::util::serde::IoFormat;

/// Per-workspace state directory, created at the workspace root. Its presence is
/// the marker that both `init-package` and start-cli walk up from cwd to find;
/// `schema` (in config.yaml) lets a future change migrate the contract.
pub const STARTOS_DIR: &str = ".startos";
/// Workspace-scoped ed25519 signing key (PKCS#8 PEM). Generated once and never
/// overwritten — it signs the packages built in this workspace.
pub const BUILD_KEY_FILE: &str = "build-key";
/// Workspace config: named host and registry targets the packager switches
/// between. Scaffolded with defaults; the `host` entries are placeholders to
/// point at your own StartOS boxes.
const CONFIG_FILE: &str = "config.yaml";

/// Published packaging guide, surfaced whenever init-workspace has to explain the
/// per-workspace model (legacy migration, wrong-directory refusals).
const DOCS_URL: &str = "https://docs.start9.com/packaging/environment-setup.html";

/// Default source for the packaging guide (which also carries the package
/// template). The guide lives in the start-technologies monorepo; the clone is
/// sparse (see GUIDE_SUBPATH) so packagers don't pull the whole repo. Re-point the
/// `start-technologies` remote afterward to track a fork; the session-start sync
/// follows whatever remote is configured.
const MONOREPO_URL: &str = "https://github.com/Start9Labs/start-technologies.git";
/// Workspace-relative path to the sparse monorepo checkout that carries the guide.
const MONOREPO_DIR: &str = "start-technologies";
/// Monorepo subtree holding the packaging guide + package template; the clone is
/// sparse-checked-out to just this path.
const GUIDE_SUBPATH: &str = "projects/start-sdk/docs";
/// Symlink target for the workspace `AGENTS.md` — the guide's canonical copy, so
/// a sync keeps the workspace context current with no extra step.
const AGENTS_SYMLINK_TARGET: &str = "start-technologies/projects/start-sdk/docs/AGENTS.md";
/// Path to the package template inside the cloned guide (joined onto MONOREPO_DIR).
const TEMPLATE_SUBPATH: &str = "projects/start-sdk/docs/package-template";

/// Claude Code does not auto-read `AGENTS.md`, so the workspace `CLAUDE.md`
/// imports both it and the user's local prefs.
const CLAUDE_MD_CONTENTS: &str = "@AGENTS.md\n@AGENTS.local.md\n";

/// Created once and never overwritten by a sync — the user's own context.
const AGENTS_LOCAL_STUB: &str = r#"# AGENTS.local.md — your workspace preferences

<!--
Notes and preferences for AI assistants working in this workspace. This file is yours;
syncing the guide never overwrites it. Put anything you want always in scope here — the
registry you publish to, the packages you're focused on, local conventions, and so on.
-->
"#;

#[derive(Deserialize, Serialize, Parser)]
#[group(skip)]
pub struct InitWorkspaceParams {
    #[arg(help = "help.arg.workspace-path")]
    path: Option<PathBuf>,
}

/// Prepare a directory so any AI assistant working in it has the latest packaging
/// context in scope. Clones the guide, links the context files, and provisions
/// `.startos/` (a workspace signing key + target config). Idempotent: a re-run only
/// fills in what's missing; updates to the guide happen via the session-start sync
/// documented in `AGENTS.md`.
pub async fn init_workspace(
    _: CliContext,
    InitWorkspaceParams { path }: InitWorkspaceParams,
) -> Result<(), Error> {
    let root = if let Some(path) = path {
        path
    } else {
        std::env::current_dir().with_kind(ErrorKind::Filesystem)?
    };
    tokio::fs::create_dir_all(&root)
        .await
        .with_ctx(|_| (ErrorKind::Filesystem, root.display().to_string()))?;
    let root = tokio::fs::canonicalize(&root)
        .await
        .with_ctx(|_| (ErrorKind::Filesystem, root.display().to_string()))?;

    // Refuse to turn a package repo into a workspace. A workspace is the *parent*
    // directory that holds package repos; a `*-startos` package is not one.
    if let Some(repo) = find_enclosing_package_repo(&root) {
        return Err(Error::new(
            eyre!(
                "{}",
                t!(
                    "s9pk.init.in-package-repo",
                    path = repo.display().to_string(),
                    docs = DOCS_URL
                )
            ),
            ErrorKind::InvalidRequest,
        ));
    }

    // The home directory already hosts the legacy global `~/.startos`; making it a
    // workspace would collide the workspace marker with that global config.
    if is_home_dir(&root) {
        return Err(Error::new(
            eyre!("{}", t!("s9pk.init.home-dir-workspace", docs = DOCS_URL)),
            ErrorKind::InvalidRequest,
        ));
    }

    // Refuse nesting inside an existing *workspace* (a real marker — the legacy global
    // config no longer counts). A marker at `root` itself is just a re-run, allowed.
    if let Some(outer) = root
        .parent()
        .map(find_workspace_root)
        .transpose()?
        .flatten()
    {
        return Err(Error::new(
            eyre!(
                "{}",
                t!(
                    "s9pk.init.nested-workspace",
                    path = outer.display().to_string()
                )
            ),
            ErrorKind::InvalidRequest,
        ));
    }

    // Provision the guide. Clone only when absent — refreshing is the session-start
    // sync's job, not this command's, so an existing checkout is left untouched. A
    // blobless, sparse, depth-1 clone fetches only GUIDE_SUBPATH, not the whole monorepo.
    let docs = root.join(MONOREPO_DIR);
    if !docs.exists() {
        eprintln!("{}", t!("s9pk.init.cloning-guide"));
        Command::new("git")
            .arg("clone")
            .arg("--filter=blob:none")
            .arg("--no-checkout")
            .arg("--depth")
            .arg("1")
            .arg("--branch")
            .arg("master")
            .arg(MONOREPO_URL)
            .arg(&docs)
            .capture(false)
            .invoke(ErrorKind::Git)
            .await?;
        Command::new("git")
            .arg("-C")
            .arg(&docs)
            .arg("sparse-checkout")
            .arg("set")
            .arg("--no-cone")
            .arg(GUIDE_SUBPATH)
            .capture(false)
            .invoke(ErrorKind::Git)
            .await?;
        Command::new("git")
            .arg("-C")
            .arg(&docs)
            .arg("checkout")
            .capture(false)
            .invoke(ErrorKind::Git)
            .await?;
    }

    // Symlink (not a copy) so a guide sync keeps the workspace AGENTS.md current.
    // symlink_metadata treats a broken link as present, so a re-run never clobbers.
    let agents = root.join("AGENTS.md");
    if tokio::fs::symlink_metadata(&agents).await.is_err() {
        tokio::fs::symlink(AGENTS_SYMLINK_TARGET, &agents)
            .await
            .with_ctx(|_| (ErrorKind::Filesystem, agents.display().to_string()))?;
    }
    write_if_absent(&root.join("AGENTS.local.md"), AGENTS_LOCAL_STUB).await?;
    write_if_absent(&root.join("CLAUDE.md"), CLAUDE_MD_CONTENTS).await?;
    // .startos/ is the workspace marker (see find_workspace_root) and holds the
    // signing key + target config. The build-key is generated once and never
    // regenerated — overwriting it would change the workspace's signing identity.
    let startos = root.join(STARTOS_DIR);
    tokio::fs::create_dir_all(&startos)
        .await
        .with_ctx(|_| (ErrorKind::Filesystem, startos.display().to_string()))?;
    let build_key = startos.join(BUILD_KEY_FILE);
    let config = startos.join(CONFIG_FILE);

    // Accommodate packagers upgrading from the pre-workspace start-cli: offer to copy
    // their existing signing key + targets out of the global `~/.startos` (which is
    // never modified) rather than silently ignoring the old setup. Gated on the
    // workspace still missing a key or config — so a fully provisioned re-run doesn't
    // re-prompt, but a partially migrated one (e.g. key written, config write failed)
    // still retries instead of falling through to default placeholders.
    if !(build_key.exists() && config.exists()) {
        if let Some(legacy) = legacy_global_startos() {
            eprintln!(
                "{}",
                t!(
                    "s9pk.init.legacy-config-found",
                    path = legacy.display().to_string(),
                    docs = DOCS_URL
                )
            );
            // Only a real terminal is prompted; non-interactive runs skip migration
            // and print the docs pointer instead of blocking.
            let interactive = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
            let migrate = interactive && prompt_yes_no(&t!("s9pk.init.migrate-prompt"));
            if migrate {
                migrate_build_key(&build_key).await?;
                migrate_config(&legacy, &config).await?;
                eprintln!(
                    "{}",
                    t!(
                        "s9pk.init.migrated",
                        path = startos.display().to_string(),
                        legacy = legacy.display().to_string()
                    )
                );
            } else {
                eprintln!("{}", t!("s9pk.init.migration-skipped", docs = DOCS_URL));
            }
        }
    }

    write_if_absent(&config, &workspace_config(None, None)).await?;
    if tokio::fs::symlink_metadata(&build_key).await.is_err() {
        // bind before the await so the !Send ThreadRng isn't held across it
        let key = SigningKey::generate(&mut crate::util::crypto::os_rng());
        write_developer_key(&key, &build_key).await?;
    }

    println!(
        "{}",
        t!(
            "s9pk.init.workspace-ready",
            path = root.display().to_string()
        )
    );
    Ok(())
}

#[derive(Deserialize, Serialize, Parser)]
#[group(skip)]
pub struct InitPackageParams {
    #[arg(help = "help.arg.package-display-name")]
    name: String,
}

/// Scaffold a new package from the workspace's bundled template, interpolating the
/// display name and a normalized ID, then `npm install` the result. Leaves a
/// `TODO.md` worklist that drives the package from clone to release-ready.
pub async fn init_package(
    _: CliContext,
    InitPackageParams { name }: InitPackageParams,
) -> Result<(), Error> {
    let cwd = std::env::current_dir().with_kind(ErrorKind::Filesystem)?;
    let root = find_workspace_root(&cwd)?.ok_or_else(|| {
        Error::new(
            eyre!("{}", t!("s9pk.init.not-in-workspace")),
            ErrorKind::InvalidRequest,
        )
    })?;

    // Normalize to a candidate ID, then validate it through the manifest's own
    // rules rather than re-implementing them.
    let id = normalize_id(&name);
    PackageId::from_str(&id).map_err(|_| {
        Error::new(
            eyre!(
                "{}",
                t!("s9pk.init.invalid-package-name", name = name.as_str())
            ),
            ErrorKind::InvalidId,
        )
    })?;

    let dst = cwd.join(format!("{id}-startos"));
    if dst.exists() {
        return Err(Error::new(
            eyre!(
                "{}",
                t!("s9pk.init.package-exists", path = dst.display().to_string())
            ),
            ErrorKind::InvalidRequest,
        ));
    }

    let template = root.join(MONOREPO_DIR).join(TEMPLATE_SUBPATH);
    if !template.exists() {
        return Err(Error::new(
            eyre!(
                "{}",
                t!(
                    "s9pk.init.template-missing",
                    path = template.display().to_string()
                )
            ),
            ErrorKind::NotFound,
        ));
    }

    copy_template_interpolated(&template, &dst, &id, &name).await?;

    eprintln!("{}", t!("s9pk.init.installing-deps"));
    Command::new("npm")
        .arg("install")
        .current_dir(&dst)
        .capture(false)
        .invoke(ErrorKind::Network)
        .await?;

    println!(
        "{}",
        t!(
            "s9pk.init.package-created",
            id = id,
            path = dst.display().to_string()
        )
    );
    Ok(())
}

/// Walk up from `start` (inclusive) for the nearest workspace — a directory whose
/// `.startos` is a provisioned marker (`build-key` or a schema config). The legacy
/// global `~/.startos` (flat config, no build-key) is intentionally excluded, so it
/// never trips the nested-workspace guard or misdirects `init-package`.
fn find_workspace_root(start: &Path) -> Result<Option<PathBuf>, Error> {
    let mut dir = start.to_path_buf();
    loop {
        let startos = dir.join(STARTOS_DIR);
        match std::fs::metadata(&startos) {
            Ok(meta) if meta.is_dir() && startos_dir_is_marker(&startos) => {
                return Ok(Some(dir));
            }
            // Present but not a provisioned marker (e.g. the legacy global config) —
            // keep walking up.
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // EACCES (or any other IO error) on an ancestor — treat as "no
            // accessible workspace here" and stop walking.
            Err(_) => return Ok(None),
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

/// Scaffolds a workspace `config.yaml`. `host`/`registry` seed the `default` profile
/// when migrating from a legacy config; `None` falls back to the placeholder targets.
fn workspace_config(host: Option<&str>, registry: Option<&str>) -> String {
    let host = host.unwrap_or("https://dev-vm.local");
    let registry = registry.unwrap_or("https://alpha-registry-x.start9.com");
    format!(
        "schema: 1\nhost:\n  default: {host}\n  prod: https://prodbox.local\nregistry:\n  default: {registry}\n  beta: https://beta-registry.start9.com\n  prod: https://registry.start9.com\n"
    )
}

/// Minimal probe: a workspace `config.yaml` is schema-tagged; the legacy flat config
/// is not, so it fails to deserialize here.
#[derive(Deserialize)]
struct SchemaProbe {
    #[allow(dead_code)]
    schema: u64,
}

/// The two fields the legacy flat `~/.startos/config.yaml` carried that map onto a
/// workspace: a single host URL and a single registry URL.
#[derive(Deserialize, Default)]
struct LegacyClientConfig {
    host: Option<String>,
    registry: Option<String>,
}

/// A `.startos` dir counts as a provisioned workspace once it holds a build-key or a
/// schema-tagged config. The legacy global `~/.startos` matches neither.
fn startos_dir_is_marker(startos: &Path) -> bool {
    if startos.join(BUILD_KEY_FILE).exists() {
        return true;
    }
    std::fs::File::open(startos.join(CONFIG_FILE))
        .ok()
        .and_then(|f| IoFormat::Yaml.from_reader::<_, SchemaProbe>(f).ok())
        .is_some()
}

/// Heuristic for a StartOS package repo: a `package.json` that depends on the
/// packaging SDK, or the scaffolded `startos/` source layout.
fn is_package_repo(dir: &Path) -> bool {
    if let Ok(pkg) = std::fs::read_to_string(dir.join("package.json")) {
        if pkg.contains("@start9labs/start-sdk") {
            return true;
        }
    }
    let startos = dir.join("startos");
    startos.join("manifest").is_dir() || startos.join("index.ts").is_file()
}

/// Walk up from `start` (inclusive) for the nearest enclosing package repo, so a
/// workspace is never initialized inside one. Stops at a real workspace marker — that
/// boundary is the nested-workspace guard's job.
fn find_enclosing_package_repo(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if is_package_repo(&dir) {
            return Some(dir);
        }
        let startos = dir.join(STARTOS_DIR);
        if std::fs::metadata(&startos)
            .map(|m| m.is_dir())
            .unwrap_or(false)
            && startos_dir_is_marker(&startos)
        {
            return None;
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// True when `root` is the user's home directory, where the global `~/.startos` lives.
fn is_home_dir(root: &Path) -> bool {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .and_then(|h| std::fs::canonicalize(h).ok())
        .map(|h| h == root)
        .unwrap_or(false)
}

/// The legacy global config dir (`~/.startos`) when it exists and is *not* already a
/// workspace marker — i.e. a leftover from the pre-workspace start-cli.
fn legacy_global_startos() -> Option<PathBuf> {
    let dir = local_config_path()?.parent()?.to_path_buf();
    (dir.is_dir() && !startos_dir_is_marker(&dir)).then_some(dir)
}

/// Copy the legacy developer key into the new workspace as its build-key, preserving
/// the packager's signing identity. No-op if a build-key already exists or there is no
/// legacy key. The global key is left in place (still used for auth). If a legacy key
/// exists but can't be read, warn — otherwise the later fresh-key generation would
/// silently change the workspace's signing identity.
async fn migrate_build_key(build_key: &Path) -> Result<(), Error> {
    if build_key.exists() {
        return Ok(());
    }
    let legacy_key = default_developer_key_path();
    if !legacy_key.exists() {
        return Ok(());
    }
    match load_signing_key(&legacy_key) {
        Ok(key) => write_developer_key(&key, build_key).await?,
        Err(_) => eprintln!(
            "{}",
            t!(
                "s9pk.init.legacy-key-unreadable",
                path = legacy_key.display().to_string()
            )
        ),
    }
    Ok(())
}

/// Seed this workspace's config from the legacy flat config's single host/registry
/// (well-formed URLs only). No-op if a config already exists.
async fn migrate_config(legacy: &Path, config: &Path) -> Result<(), Error> {
    if config.exists() {
        return Ok(());
    }
    let legacy_config = std::fs::File::open(legacy.join(CONFIG_FILE))
        .ok()
        .and_then(|f| IoFormat::Yaml.from_reader::<_, LegacyClientConfig>(f).ok())
        .unwrap_or_default();
    let host = legacy_config
        .host
        .as_deref()
        .filter(|h| Url::parse(h).is_ok());
    let registry = legacy_config
        .registry
        .as_deref()
        .filter(|r| Url::parse(r).is_ok());
    tokio::fs::write(config, workspace_config(host, registry))
        .await
        .with_ctx(|_| (ErrorKind::Filesystem, config.display().to_string()))?;
    Ok(())
}

/// Lenient yes/no parser accepting the affirmatives/negatives of the CLI's locales.
fn parse_yes_no(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" | "j" | "ja" | "o" | "oui" | "s" | "si" | "sí" | "t" | "tak" => Ok(true),
        "n" | "no" | "nein" | "non" | "nie" => Ok(false),
        _ => Err(t!("s9pk.init.answer-yes-no").to_string()),
    }
}

/// Synchronous y/n prompt on stderr, defaulting to yes on empty input or EOF. Blocking
/// (not held across an await) so the handler future stays `Send`, matching how the
/// password prompts read stdin. Callers gate on an interactive terminal first.
fn prompt_yes_no(prompt: &str) -> bool {
    use std::io::Write;
    loop {
        eprint!("{prompt} ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => return true,
            Ok(_) => match line.trim() {
                "" => return true,
                answer => match parse_yes_no(answer) {
                    Ok(choice) => return choice,
                    Err(msg) => eprintln!("{msg}"),
                },
            },
        }
    }
}

/// Normalize a human display name to a candidate package ID: lowercase ASCII
/// alphanumerics, runs of whitespace/underscore/hyphen collapsed to a single
/// hyphen, every other character dropped, no leading or trailing hyphen. Validity
/// (non-empty, matches the manifest's ID rules) is the caller's check.
fn normalize_id(name: &str) -> String {
    let mut out = String::new();
    let mut pending_sep = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_sep && !out.is_empty() {
                out.push('-');
            }
            pending_sep = false;
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() || ch == '_' || ch == '-' {
            pending_sep = true;
        }
        // any other character is dropped without forcing a separator
    }
    out
}

/// Recursively copy `src` to `dst`, replacing `{{id}}`/`{{name}}` in text files.
/// `{{id}}` is already validated as safe; `{{name}}` is escaped for TypeScript
/// string literals when writing `.ts` files. Non-UTF-8 files are copied verbatim.
fn copy_template_interpolated<'a>(
    src: &'a Path,
    dst: &'a Path,
    id: &'a str,
    name: &'a str,
) -> BoxFuture<'a, Result<(), Error>> {
    async move {
        tokio::fs::create_dir_all(dst)
            .await
            .with_ctx(|_| (ErrorKind::Filesystem, dst.display().to_string()))?;
        let mut entries = tokio::fs::read_dir(src)
            .await
            .with_ctx(|_| (ErrorKind::Filesystem, src.display().to_string()))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_kind(ErrorKind::Filesystem)?
        {
            let file_name = entry.file_name();
            // Defensive: never carry build/VCS cruft into the scaffold.
            if matches!(
                file_name.to_str(),
                Some("node_modules") | Some(".git") | Some("javascript")
            ) {
                continue;
            }
            let from = entry.path();
            let to = dst.join(&file_name);
            let file_type = entry.file_type().await.with_kind(ErrorKind::Filesystem)?;
            if file_type.is_dir() {
                copy_template_interpolated(&from, &to, id, name).await?;
            } else if file_type.is_file() {
                let bytes = tokio::fs::read(&from)
                    .await
                    .with_ctx(|_| (ErrorKind::Filesystem, from.display().to_string()))?;
                let escape_for_ts = from.extension().and_then(|e| e.to_str()) == Some("ts");
                let rendered = match String::from_utf8(bytes) {
                    Ok(text) => interpolate(&text, id, name, escape_for_ts).into_bytes(),
                    Err(e) => e.into_bytes(),
                };
                tokio::fs::write(&to, rendered)
                    .await
                    .with_ctx(|_| (ErrorKind::Filesystem, to.display().to_string()))?;
            }
            // symlinks (none expected in the template) are skipped
        }
        Ok(())
    }
    .boxed()
}

fn interpolate(content: &str, id: &str, name: &str, escape_for_ts: bool) -> String {
    let name = if escape_for_ts {
        name.replace('\\', "\\\\").replace('\'', "\\'")
    } else {
        name.to_owned()
    };
    content.replace("{{id}}", id).replace("{{name}}", &name)
}

/// Write `contents` to `path` only if nothing is there yet (a broken symlink
/// counts as present, so a re-run never clobbers).
async fn write_if_absent(path: &Path, contents: &str) -> Result<(), Error> {
    if tokio::fs::symlink_metadata(path).await.is_err() {
        tokio::fs::write(path, contents)
            .await
            .with_ctx(|_| (ErrorKind::Filesystem, path.display().to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// A fresh, empty temp dir unique to each call (no external crate needed).
    fn tmp() -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "s9pk-init-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn yes_no_parses_locale_variants() {
        for y in [
            "y", "Yes", "  YES ", "j", "ja", "o", "oui", "s", "si", "t", "tak",
        ] {
            assert_eq!(parse_yes_no(y), Ok(true), "{y}");
        }
        for n in ["n", "No", "nein", "non", "nie"] {
            assert_eq!(parse_yes_no(n), Ok(false), "{n}");
        }
        assert!(parse_yes_no("maybe").is_err());
    }

    #[test]
    fn workspace_config_default_and_seeded() {
        let def = workspace_config(None, None);
        assert!(def.starts_with("schema: 1\n"));
        assert!(def.contains("  default: https://dev-vm.local\n"));
        assert!(def.contains("  default: https://alpha-registry-x.start9.com\n"));

        let seeded = workspace_config(Some("https://box.local"), Some("https://reg.example"));
        assert!(seeded.contains("  default: https://box.local\n"));
        assert!(seeded.contains("  default: https://reg.example\n"));
        // both must parse as a full WorkspaceConfig (typed host/registry URL maps),
        // which is what the runtime actually loads — not merely as schema-tagged YAML.
        assert!(parses_as_workspace(&def));
        assert!(parses_as_workspace(&seeded));
    }

    fn parses_as_workspace(yaml: &str) -> bool {
        IoFormat::Yaml
            .from_reader::<_, crate::context::config::WorkspaceConfig>(yaml.as_bytes())
            .is_ok()
    }

    #[test]
    fn marker_requires_build_key_or_schema_config() {
        // empty .startos — not a marker
        let d = tmp();
        let startos = d.join(STARTOS_DIR);
        std::fs::create_dir_all(&startos).unwrap();
        assert!(!startos_dir_is_marker(&startos));

        // legacy flat config (no schema) — not a marker
        std::fs::write(startos.join(CONFIG_FILE), "host: https://x\n").unwrap();
        assert!(!startos_dir_is_marker(&startos));

        // schema config — marker
        std::fs::write(startos.join(CONFIG_FILE), workspace_config(None, None)).unwrap();
        assert!(startos_dir_is_marker(&startos));

        // build-key alone — marker (even with a flat config)
        let d2 = tmp();
        let s2 = d2.join(STARTOS_DIR);
        std::fs::create_dir_all(&s2).unwrap();
        std::fs::write(s2.join(CONFIG_FILE), "host: https://x\n").unwrap();
        std::fs::write(s2.join(BUILD_KEY_FILE), "key").unwrap();
        assert!(startos_dir_is_marker(&s2));
    }

    #[test]
    fn detects_package_repo() {
        let d = tmp();
        assert!(!is_package_repo(&d));

        std::fs::write(
            d.join("package.json"),
            r#"{ "dependencies": { "@start9labs/start-sdk": "2.0.1" } }"#,
        )
        .unwrap();
        assert!(is_package_repo(&d));

        let d2 = tmp();
        std::fs::create_dir_all(d2.join("startos").join("manifest")).unwrap();
        assert!(is_package_repo(&d2));

        let d3 = tmp();
        std::fs::create_dir_all(d3.join("startos")).unwrap();
        std::fs::write(d3.join("startos").join("index.ts"), "export {}").unwrap();
        assert!(is_package_repo(&d3));
    }

    #[test]
    fn enclosing_package_repo_walks_up_and_stops_at_workspace() {
        // a package repo with a nested subdir
        let repo = tmp();
        std::fs::write(
            repo.join("package.json"),
            r#"{ "dependencies": { "@start9labs/start-sdk": "2.0.1" } }"#,
        )
        .unwrap();
        let nested = repo.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            find_enclosing_package_repo(&nested).and_then(|p| p.canonicalize().ok()),
            repo.canonicalize().ok()
        );

        // a workspace marker between the dir and any package repo halts the walk
        let ws = tmp();
        std::fs::create_dir_all(ws.join(STARTOS_DIR)).unwrap();
        std::fs::write(
            ws.join(STARTOS_DIR).join(CONFIG_FILE),
            workspace_config(None, None),
        )
        .unwrap();
        let inside = ws.join("pkgs");
        std::fs::create_dir_all(&inside).unwrap();
        assert_eq!(find_enclosing_package_repo(&inside), None);
    }
}
