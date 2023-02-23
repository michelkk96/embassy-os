use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::time::Duration;

use color_eyre::eyre::eyre;
use emver::VersionRange;
use futures::future::BoxFuture;
use futures::FutureExt;
use patch_db::{HasModel, Map, MapModel, Model, PatchDb};
use rpc_toolkit::command;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::config::action::{ConfigActions, ConfigRes};
use crate::config::{not_found, Config, ConfigureContext};
use crate::context::RpcContext;
use crate::db::model::{CurrentDependencies, InstalledPackageDataEntry};
use crate::prelude::*;
use crate::procedure::docker::DockerContainers;
use crate::procedure::{NoOutput, PackageProcedure, ProcedureName};
use crate::s9pk::manifest::{Manifest, PackageId};
use crate::status::health_check::{HealthCheckId, HealthCheckResult};
use crate::status::{MainStatus, Status};
use crate::util::serde::display_serializable;
use crate::util::{display_none, Version};
use crate::volume::Volumes;

#[command(subcommands(configure))]
pub fn dependency() -> Result<(), Error> {
    Ok(())
}

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum DependencyError {
    NotInstalled, // { "type": "not-installed" }
    #[serde(rename_all = "kebab-case")]
    IncorrectVersion {
        expected: VersionRange,
        received: Version,
    }, // { "type": "incorrect-version", "expected": "0.1.0", "received": "^0.2.0" }
    #[serde(rename_all = "kebab-case")]
    ConfigUnsatisfied {
        error: String,
    }, // { "type": "config-unsatisfied", "error": "Bitcoin Core must have pruning set to manual." }
    NotRunning,   // { "type": "not-running" }
    #[serde(rename_all = "kebab-case")]
    HealthChecksFailed {
        failures: BTreeMap<HealthCheckId, HealthCheckResult>,
    }, // { "type": "health-checks-failed", "checks": { "rpc": { "time": "2021-05-11T18:21:29Z", "result": "starting" } } }
    #[serde(rename_all = "kebab-case")]
    Transitive, // { "type": "transitive" }
}

impl DependencyError {
    pub fn cmp_priority(&self, other: &DependencyError) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;

        use DependencyError::*;
        match (self, other) {
            (NotInstalled, NotInstalled) => Equal,
            (NotInstalled, _) => Greater,
            (_, NotInstalled) => Less,
            (IncorrectVersion { .. }, IncorrectVersion { .. }) => Equal,
            (IncorrectVersion { .. }, _) => Greater,
            (_, IncorrectVersion { .. }) => Less,
            (ConfigUnsatisfied { .. }, ConfigUnsatisfied { .. }) => Equal,
            (ConfigUnsatisfied { .. }, _) => Greater,
            (_, ConfigUnsatisfied { .. }) => Less,
            (NotRunning, NotRunning) => Equal,
            (NotRunning, _) => Greater,
            (_, NotRunning) => Less,
            (HealthChecksFailed { .. }, HealthChecksFailed { .. }) => Equal,
            (HealthChecksFailed { .. }, _) => Greater,
            (_, HealthChecksFailed { .. }) => Less,
            (Transitive, Transitive) => Equal,
        }
    }
    pub fn merge_with(self, other: DependencyError) -> DependencyError {
        match (self, other) {
            (DependencyError::NotInstalled, _) | (_, DependencyError::NotInstalled) => {
                DependencyError::NotInstalled
            }
            (DependencyError::IncorrectVersion { expected, received }, _)
            | (_, DependencyError::IncorrectVersion { expected, received }) => {
                DependencyError::IncorrectVersion { expected, received }
            }
            (
                DependencyError::ConfigUnsatisfied { error: e0 },
                DependencyError::ConfigUnsatisfied { error: e1 },
            ) => DependencyError::ConfigUnsatisfied {
                error: e0 + "\n" + &e1,
            },
            (DependencyError::ConfigUnsatisfied { error }, _)
            | (_, DependencyError::ConfigUnsatisfied { error }) => {
                DependencyError::ConfigUnsatisfied { error }
            }
            (DependencyError::NotRunning, _) | (_, DependencyError::NotRunning) => {
                DependencyError::NotRunning
            }
            (
                DependencyError::HealthChecksFailed { failures: f0 },
                DependencyError::HealthChecksFailed { failures: f1 },
            ) => DependencyError::HealthChecksFailed {
                failures: f0.into_iter().chain(f1.into_iter()).collect(),
            },
            (DependencyError::HealthChecksFailed { failures }, _)
            | (_, DependencyError::HealthChecksFailed { failures }) => {
                DependencyError::HealthChecksFailed { failures }
            }
            (DependencyError::Transitive, _) => DependencyError::Transitive,
        }
    }
    #[instrument(skip(ctx, receipts))]
    pub fn try_heal<'a>(
        self,
        ctx: &'a RpcContext,
        id: &'a PackageId,
        dependency: &'a PackageId,
        mut dependency_config: Option<Config>,
        info: &'a DepInfo,
        receipts: (), // &'a TryHealReceipts,
    ) -> BoxFuture<'a, Result<Option<Self>, Error>> {
        let db = todo!();
        async move {
            let container = receipts.docker_containers.get(db, id).await?;
            Ok(match self {
                DependencyError::NotInstalled => {
                    if receipts.status.get(db, dependency).await?.is_some() {
                        DependencyError::IncorrectVersion {
                            expected: info.version.clone(),
                            received: Default::default(),
                        }
                        .try_heal(ctx, id, dependency, dependency_config, info, receipts)
                        .await?
                    } else {
                        Some(DependencyError::NotInstalled)
                    }
                }
                DependencyError::IncorrectVersion { expected, .. } => {
                    let version: Version = receipts
                        .manifest_version
                        .get(db, dependency)
                        .await?
                        .unwrap_or_default();
                    if version.satisfies(&expected) {
                        DependencyError::ConfigUnsatisfied {
                            error: String::new(),
                        }
                        .try_heal(ctx, id, dependency, dependency_config, info, receipts)
                        .await?
                    } else {
                        Some(DependencyError::IncorrectVersion {
                            expected,
                            received: version,
                        })
                    }
                }
                DependencyError::ConfigUnsatisfied { .. } => {
                    let dependent_manifest =
                        receipts.manifest.get(db, id).await?.ok_or_else(not_found)?;
                    let dependency_manifest = receipts
                        .manifest
                        .get(db, dependency)
                        .await?
                        .ok_or_else(not_found)?;

                    let dependency_config = if let Some(cfg) = dependency_config.take() {
                        cfg
                    } else if let Some(cfg_info) = &dependency_manifest.config {
                        cfg_info
                            .get(
                                // ctx,
                                // dependency,
                                // &dependency_manifest.version,
                                // &dependency_manifest.volumes,
                            )
                            .await?
                            .config
                            .unwrap_or_default()
                    } else {
                        Config::default()
                    };
                    if let Some(cfg_req) = &info.config {
                        if let Err(error) = cfg_req
                            .check(
                                ctx,
                                &container,
                                id,
                                &dependent_manifest.version,
                                &dependent_manifest.volumes,
                                dependency,
                                &dependency_config,
                            )
                            .await?
                        {
                            return Ok(Some(DependencyError::ConfigUnsatisfied { error }));
                        }
                    }
                    DependencyError::NotRunning
                        .try_heal(ctx, id, dependency, Some(dependency_config), info, receipts)
                        .await?
                }
                DependencyError::NotRunning => {
                    let status = receipts
                        .status
                        .get(db, dependency)
                        .await?
                        .ok_or_else(not_found)?;
                    if status.main.running() {
                        DependencyError::HealthChecksFailed {
                            failures: BTreeMap::new(),
                        }
                        .try_heal(ctx, id, dependency, dependency_config, info, receipts)
                        .await?
                    } else {
                        Some(DependencyError::NotRunning)
                    }
                }
                DependencyError::HealthChecksFailed { .. } => {
                    let status = receipts
                        .status
                        .get(db, dependency)
                        .await?
                        .ok_or_else(not_found)?;
                    match status.main {
                        MainStatus::BackingUp {
                            started: Some(_),
                            health,
                        }
                        | MainStatus::Running { health, .. } => {
                            let mut failures = BTreeMap::new();
                            for (check, res) in health {
                                if !matches!(res, HealthCheckResult::Success)
                                    && receipts
                                        .current_dependencies
                                        .get(db, id)
                                        .await?
                                        .ok_or_else(not_found)?
                                        .get(dependency)
                                        .map(|x| x.health_checks.contains(&check))
                                        .unwrap_or(false)
                                {
                                    failures.insert(check.clone(), res.clone());
                                }
                            }
                            if !failures.is_empty() {
                                Some(DependencyError::HealthChecksFailed { failures })
                            } else {
                                DependencyError::Transitive
                                    .try_heal(
                                        ctx,
                                        id,
                                        dependency,
                                        dependency_config,
                                        info,
                                        receipts,
                                    )
                                    .await?
                            }
                        }
                        MainStatus::Starting { .. } | MainStatus::Restarting => {
                            DependencyError::Transitive
                                .try_heal(ctx, id, dependency, dependency_config, info, receipts)
                                .await?
                        }
                        _ => return Ok(Some(DependencyError::NotRunning)),
                    }
                }
                DependencyError::Transitive => {
                    if receipts
                        .dependency_errors
                        .get(db, dependency)
                        .await?
                        .unwrap_or_default()
                        .0
                        .is_empty()
                    {
                        None
                    } else {
                        Some(DependencyError::Transitive)
                    }
                }
            })
        }
        .boxed()
    }
}
impl std::fmt::Display for DependencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DependencyError::NotInstalled => write!(f, "Not Installed"),
            DependencyError::IncorrectVersion { expected, received } => write!(
                f,
                "Incorrect Version: Expected {}, Received {}",
                expected,
                received.as_str()
            ),
            DependencyError::ConfigUnsatisfied { error } => {
                write!(f, "Configuration Requirements Not Satisfied: {}", error)
            }
            DependencyError::NotRunning => write!(f, "Not Running"),
            DependencyError::HealthChecksFailed { failures } => {
                write!(f, "Failed Health Check(s): ")?;
                let mut comma = false;
                for (check, res) in failures {
                    if !comma {
                        comma = true;
                    } else {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", check, res)?;
                }
                Ok(())
            }
            DependencyError::Transitive => {
                write!(f, "Dependency Error(s)")
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TaggedDependencyError {
    pub dependency: PackageId,
    pub error: DependencyError,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BreakageRes(pub BTreeMap<PackageId, TaggedDependencyError>);

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Dependencies(pub BTreeMap<PackageId, DepInfo>);
impl<'a> Map<'a> for Dependencies {
    type Key = PackageId;
    type Value = DepInfo;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.0.get(key)
    }
}
impl<'a> HasModel<'a> for Dependencies {
    type Model = MapModel<'a, Self>;
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum DependencyRequirement {
    OptIn { how: String },
    OptOut { how: String },
    Required,
}
impl DependencyRequirement {
    pub fn required(&self) -> bool {
        matches!(self, &DependencyRequirement::Required)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, HasModel)]
#[serde(rename_all = "kebab-case")]
pub struct DepInfo {
    pub version: VersionRange,
    pub requirement: DependencyRequirement,
    pub description: Option<String>,
    #[serde(default)]
    // #[model]
    pub config: Option<DependencyConfig>,
}
impl DepInfo {
    pub async fn satisfied(
        &self,
        ctx: &RpcContext,
        dependency_id: &PackageId,
        dependency_config: Option<Config>, // fetch if none
        dependent_id: &PackageId,
        receipts: (), // &TryHealReceipts,
    ) -> Result<Result<(), DependencyError>, Error> {
        Ok(
            if let Some(err) = DependencyError::NotInstalled
                .try_heal(
                    ctx,
                    dependent_id,
                    dependency_id,
                    dependency_config,
                    self,
                    receipts,
                )
                .await?
            {
                Err(err)
            } else {
                Ok(())
            },
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, HasModel)]
#[serde(rename_all = "kebab-case")]
pub struct DependencyConfig {
    check: PackageProcedure,
    auto_configure: PackageProcedure,
}
impl DependencyConfig {
    pub async fn check(
        &self,
        ctx: &RpcContext,
        container: &Option<DockerContainers>,
        dependent_id: &PackageId,
        dependent_version: &Version,
        dependent_volumes: &Volumes,
        dependency_id: &PackageId,
        dependency_config: &Config,
    ) -> Result<Result<NoOutput, String>, Error> {
        Ok(self
            .check
            .sandboxed(
                container,
                ctx,
                dependent_id,
                dependent_version,
                dependent_volumes,
                Some(dependency_config),
                None,
                ProcedureName::Check(dependency_id.clone()),
            )
            .await?
            .map_err(|(_, e)| e))
    }
    pub async fn auto_configure(
        &self,
        ctx: &RpcContext,
        container: &Option<DockerContainers>,
        dependent_id: &PackageId,
        dependent_version: &Version,
        dependent_volumes: &Volumes,
        old: &Config,
    ) -> Result<Config, Error> {
        self.auto_configure
            .sandboxed(
                container,
                ctx,
                dependent_id,
                dependent_version,
                dependent_volumes,
                Some(old),
                None,
                ProcedureName::AutoConfig(dependent_id.clone()),
            )
            .await?
            .map_err(|e| Error::new(eyre!("{}", e.1), ErrorKind::AutoConfigure))
    }
}

#[command(
    subcommands(self(configure_impl(async)), configure_dry),
    display(display_none)
)]
pub async fn configure(
    #[arg(rename = "dependent-id")] dependent_id: PackageId,
    #[arg(rename = "dependency-id")] dependency_id: PackageId,
) -> Result<(PackageId, PackageId), Error> {
    Ok((dependent_id, dependency_id))
}

pub async fn configure_impl(
    ctx: RpcContext,
    (pkg_id, dep_id): (PackageId, PackageId),
) -> Result<(), Error> {
    let mut db = ctx.db.handle();
    let breakages = BTreeMap::new();
    let overrides = Default::default();
    let receipts = todo!(); // DependencyConfigReceipts::new(&pkg_id, &dep_id).await?;
    let ConfigDryRes {
        old_config: _,
        new_config,
    } = configure_logic(ctx.clone(), (pkg_id, dep_id.clone()), &receipts).await?;

    let configure_context = ConfigureContext {
        breakages,
        timeout: Some(Duration::from_secs(3).into()),
        config: Some(new_config),
        dry_run: false,
        overrides,
    };
    crate::config::configure(&ctx, &dep_id, configure_context).await?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConfigDryRes {
    pub old_config: Option<Config>,
    pub new_config: Config,
}

#[command(rename = "dry", display(display_serializable))]
#[instrument(skip(ctx))]
pub async fn configure_dry(
    #[context] ctx: RpcContext,
    #[parent_data] (pkg_id, dependency_id): (PackageId, PackageId),
) -> Result<ConfigDryRes, Error> {
    let mut db = ctx.db.handle();
    let receipts = todo!(); // DependencyConfigReceipts::new(&pkg_id, &dependency_id).await?;
    configure_logic(ctx, (pkg_id, dependency_id), &receipts).await
}

pub async fn configure_logic(
    ctx: RpcContext,
    (pkg_id, dependency_id): (PackageId, PackageId),
    receipts: (), // &DependencyConfigReceipts,
) -> Result<ConfigDryRes, Error> {
    let db = todo!();
    let pkg_version = receipts.package_version.get(db).await?;
    let pkg_volumes = receipts.package_volumes.get(db).await?;
    let dependency_config_action = receipts.dependency_config_action.get(db).await?;
    let dependency_version = receipts.dependency_version.get(db).await?;
    let dependency_volumes = receipts.dependency_volumes.get(db).await?;
    let dependencies = receipts.dependencies.get(db).await?;
    let pkg_docker_container = receipts.docker_containers.get(db, &*pkg_id).await?;

    let dependency = dependencies
        .0
        .get(&dependency_id)
        .ok_or_else(|| {
            Error::new(
                eyre!(
                    "dependency for {} not found in the manifest for {}",
                    dependency_id,
                    pkg_id
                ),
                ErrorKind::NotFound,
            )
        })?
        .config
        .as_ref()
        .ok_or_else(|| {
            Error::new(
                eyre!(
                    "dependency config for {} not found on {}",
                    dependency_id,
                    pkg_id
                ),
                ErrorKind::NotFound,
            )
        })?;
    let ConfigRes {
        config: old_config,
        spec,
    } = dependency_config_action
        .get(
            &ctx,
            &dependency_id,
            &dependency_version,
            &dependency_volumes,
        )
        .await?;

    let new_config = dependency
        .auto_configure
        .sandboxed(
            &pkg_docker_container,
            &ctx,
            &pkg_id,
            &pkg_version,
            &pkg_volumes,
            Some(&old_config),
            None,
            ProcedureName::AutoConfig(dependency_id.clone()),
        )
        .await?
        .map_err(|e| Error::new(eyre!("{}", e.1), ErrorKind::AutoConfigure))?;

    Ok(ConfigDryRes {
        old_config,
        new_config,
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DependencyErrors(pub BTreeMap<PackageId, DependencyError>);
impl<'a> Map<'a> for DependencyErrors {
    type Key = PackageId;
    type Value = DependencyError;
    fn get(&self, key: &Self::Key) -> Option<&Self::Value> {
        self.0.get(key)
    }
}
impl<'a> HasModel<'a> for DependencyErrors {
    type Model = MapModel<'a, Self>;
}
impl DependencyErrors {
    pub async fn init(
        ctx: &RpcContext,
        manifest: &Manifest,
        current_dependencies: &CurrentDependencies,
        receipts: (), // &TryHealReceipts,
    ) -> Result<DependencyErrors, Error> {
        let mut res = BTreeMap::new();
        for (dependency_id, info) in current_dependencies.0.keys().filter_map(|dependency_id| {
            manifest
                .dependencies
                .0
                .get(dependency_id)
                .map(|info| (dependency_id, info))
        }) {
            if let Err(e) = info
                .satisfied(ctx, dependency_id, None, &manifest.id, receipts)
                .await?
            {
                res.insert(dependency_id.clone(), e);
            }
        }
        Ok(DependencyErrors(res))
    }
}
impl std::fmt::Display for DependencyErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ ")?;
        for (idx, (id, err)) in self.0.iter().enumerate() {
            write!(f, "{}: {}", id, err)?;
            if idx < self.0.len() - 1 {
                // not last
                write!(f, ", ")?;
            }
        }
        write!(f, " }}")
    }
}

pub async fn break_all_dependents_transitive<'a>(
    db: &PatchDb,
    id: &'a PackageId,
    error: DependencyError,
    breakages: &'a mut BTreeMap<PackageId, TaggedDependencyError>,
    receipts: (), // &'a BreakTransitiveReceipts,
) -> Result<(), Error> {
    for dependent in receipts
        .current_dependents
        .get(db, id)
        .await?
        .iter()
        .flat_map(|x| x.0.keys())
        .filter(|dependent| id != *dependent)
    {
        break_transitive(dependent, id, error.clone(), breakages, receipts).await?;
    }
    Ok(())
}

#[instrument(skip(receipts))]
pub fn break_transitive<'a>(
    id: &'a PackageId,
    dependency: &'a PackageId,
    error: DependencyError,
    breakages: &'a mut BTreeMap<PackageId, TaggedDependencyError>,
    receipts: (), // &'a BreakTransitiveReceipts,
) -> BoxFuture<'a, Result<(), Error>> {
    let db = todo!();
    async move {
        let mut tx = todo!(); // db.begin().await?;
        let mut dependency_errors = receipts
            .dependency_errors
            .get(&mut tx, id)
            .await?
            .ok_or_else(not_found)?;

        let old = dependency_errors.0.remove(dependency);
        let newly_broken = if let Some(e) = &old {
            error.cmp_priority(&e) == Ordering::Greater
        } else {
            true
        };
        dependency_errors.0.insert(
            dependency.clone(),
            if let Some(old) = old {
                old.merge_with(error.clone())
            } else {
                error.clone()
            },
        );
        if newly_broken {
            breakages.insert(
                id.clone(),
                TaggedDependencyError {
                    dependency: dependency.clone(),
                    error: error.clone(),
                },
            );
            receipts
                .dependency_errors
                .set(&mut tx, dependency_errors, id)
                .await?;

            tx.save().await?;
            break_all_dependents_transitive(
                db,
                id,
                DependencyError::Transitive,
                breakages,
                receipts,
            )
            .await?;
        } else {
            receipts
                .dependency_errors
                .set(&mut tx, dependency_errors, id)
                .await?;

            tx.save().await?;
        }

        Ok(())
    }
    .boxed()
}

#[instrument(skip(ctx, locks))]
pub async fn heal_all_dependents_transitive<'a>(
    ctx: &'a RpcContext,
    id: &'a PackageId,
    locks: (), // &'a DependencyReceipt,
) -> Result<(), Error> {
    let db = todo!();
    let dependents = locks
        .current_dependents
        .get(db, id)
        .await?
        .ok_or_else(not_found)?;
    for dependent in dependents.0.keys().filter(|dependent| id != *dependent) {
        heal_transitive(ctx, dependent, id, locks).await?;
    }
    Ok(())
}

#[instrument(skip(ctx, receipts))]
pub fn heal_transitive<'a>(
    ctx: &'a RpcContext,
    id: &'a PackageId,
    dependency: &'a PackageId,
    receipts: (), // &'a DependencyReceipt,
) -> BoxFuture<'a, Result<(), Error>> {
    let db = todo!();
    async move {
        let mut status = receipts.status.get(id).await?.ok_or_else(not_found)?;

        let old = status.dependency_errors.0.remove(dependency);

        if let Some(old) = old {
            let info = receipts
                .dependency
                .get(db, (id, dependency))
                .await?
                .ok_or_else(not_found)?;
            if let Some(new) = old
                .try_heal(ctx, id, dependency, None, &info, &receipts.try_heal)
                .await?
            {
                status.dependency_errors.0.insert(dependency.clone(), new);
                receipts.status.set(db, status, id).await?;
            } else {
                receipts.status.set(db, status, id).await?;
                heal_all_dependents_transitive(ctx, id, receipts).await?;
            }
        }

        Ok(())
    }
    .boxed()
}
