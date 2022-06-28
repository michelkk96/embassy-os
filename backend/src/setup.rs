use std::path::{Path, PathBuf};
use std::sync::Arc;

use color_eyre::eyre::eyre;
use futures::future::BoxFuture;
use futures::TryFutureExt;
use openssl::x509::X509;
use patch_db::DbHandle;
use rpc_toolkit::command;
use rpc_toolkit::yajrc::RpcError;
use serde::{Deserialize, Serialize};
use sqlx::{Connection, Executor, Sqlite};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use torut::onion::{OnionAddressV3, TorSecretKeyV3};
use tracing::instrument;

use crate::backup::restore::legacy::recover_v2;
use crate::backup::restore::recover_full_embassy;
use crate::backup::restore::umbrel::{prep_umbrel_migration, recover_umbrel};
use crate::backup::target::BackupTargetFS;
use crate::context::rpc::RpcContextConfig;
use crate::context::setup::SetupResult;
use crate::context::SetupContext;
use crate::disk::fsck::RepairStrategy;
use crate::disk::main::DEFAULT_PASSWORD;
use crate::disk::mount::filesystem::block_dev::BlockDev;
use crate::disk::mount::filesystem::cifs::Cifs;
use crate::disk::mount::filesystem::ReadOnly;
use crate::disk::mount::guard::TmpMountGuard;
use crate::disk::util::{pvscan, recovery_info, DiskListResponse, EmbassyOsRecoveryInfo};
use crate::disk::REPAIR_DISK_PATH;
use crate::hostname::PRODUCT_KEY_PATH;
use crate::init::init;
use crate::net::ssl::SslManager;
use crate::sound::BEETHOVEN;
use crate::util::Version;
use crate::{Error, ErrorKind, ResultExt};

#[instrument(skip(secrets))]
pub async fn password_hash<Ex>(secrets: &mut Ex) -> Result<String, Error>
where
    for<'a> &'a mut Ex: Executor<'a, Database = Sqlite>,
{
    let password = sqlx::query!("SELECT password FROM account")
        .fetch_one(secrets)
        .await?
        .password;

    Ok(password)
}

#[command(subcommands(status, disk, attach, execute, recovery, cifs, complete))]
pub fn setup() -> Result<(), Error> {
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct StatusRes {
    product_key: bool,
    migrating: bool,
}

#[command(rpc_only, metadata(authenticated = false))]
pub async fn status(#[context] ctx: SetupContext) -> Result<StatusRes, Error> {
    Ok(StatusRes {
        product_key: tokio::fs::metadata(PRODUCT_KEY_PATH).await.is_ok(),
        migrating: ctx.recovery_status.read().await.is_some(),
    })
}

#[command(subcommands(list_disks))]
pub fn disk() -> Result<(), Error> {
    Ok(())
}

#[command(rename = "list", rpc_only, metadata(authenticated = false))]
pub async fn list_disks() -> Result<DiskListResponse, Error> {
    crate::disk::list(None).await
}

#[command(rpc_only)]
pub async fn attach(
    #[context] ctx: SetupContext,
    #[arg] guid: Arc<String>,
    #[arg(rename = "embassy-password")] password: Option<String>,
) -> Result<SetupResult, Error> {
    let requires_reboot = crate::disk::main::import(
        &*guid,
        &ctx.datadir,
        if tokio::fs::metadata(REPAIR_DISK_PATH).await.is_ok() {
            RepairStrategy::Aggressive
        } else {
            RepairStrategy::Preen
        },
        DEFAULT_PASSWORD,
    )
    .await?;
    if tokio::fs::metadata(REPAIR_DISK_PATH).await.is_ok() {
        tokio::fs::remove_file(REPAIR_DISK_PATH)
            .await
            .with_ctx(|_| (ErrorKind::Filesystem, REPAIR_DISK_PATH))?;
    }
    if requires_reboot.0 {
        crate::disk::main::export(&*guid, &ctx.datadir).await?;
        return Err(Error::new(
            eyre!(
                "Errors were corrected with your disk, but the Embassy must be restarted in order to proceed"
            ),
            ErrorKind::DiskManagement,
        ));
    }
    let product_key = ctx.product_key().await?;
    let product_key_path = Path::new("/embassy-data/main/product_key.txt");
    if tokio::fs::metadata(product_key_path).await.is_ok() {
        let pkey = Arc::new(
            tokio::fs::read_to_string(product_key_path)
                .await?
                .trim()
                .to_owned(),
        );
        if pkey != product_key {
            crate::disk::main::export(&*guid, &ctx.datadir).await?;
            return Err(Error::new(
                eyre!(
                    "The EmbassyOS product key does not match the supplied drive: {}",
                    pkey
                ),
                ErrorKind::ProductKeyMismatch,
            ));
        }
    }
    init(
        &RpcContextConfig::load(ctx.config_path.as_ref()).await?,
        &*product_key,
    )
    .await?;
    let secrets = ctx.secret_store().await?;
    let db = ctx.db(&secrets).await?;
    let mut secrets_handle = secrets.acquire().await?;
    let mut db_handle = db.handle();
    let mut secrets_tx = secrets_handle.begin().await?;
    let mut db_tx = db_handle.begin().await?;

    if let Some(password) = password {
        let set_password_receipt = crate::auth::SetPasswordReceipt::new(&mut db_tx).await?;
        crate::auth::set_password(
            &mut db_tx,
            &set_password_receipt,
            &mut secrets_tx,
            &password,
        )
        .await?;
    }

    let tor_key = crate::net::tor::os_key(&mut secrets_tx).await?;

    db_tx.commit(None).await?;
    secrets_tx.commit().await?;

    let (_, root_ca) = SslManager::init(secrets).await?.export_root_ca().await?;
    let setup_result = SetupResult {
        tor_address: format!("http://{}", tor_key.public().get_onion_address()),
        lan_address: format!(
            "https://embassy-{}.local",
            crate::hostname::derive_id(&*product_key)
        ),
        root_ca: String::from_utf8(root_ca.to_pem()?)?,
    };
    *ctx.setup_result.write().await = Some((guid, setup_result.clone()));
    Ok(setup_result)
}

#[command(subcommands(v2, recovery_status))]
pub fn recovery() -> Result<(), Error> {
    Ok(())
}

#[command(subcommands(set))]
pub fn v2() -> Result<(), Error> {
    Ok(())
}

#[command(rpc_only, metadata(authenticated = false))]
pub async fn set(#[context] ctx: SetupContext, #[arg] logicalname: PathBuf) -> Result<(), Error> {
    let guard = TmpMountGuard::mount(&BlockDev::new(&logicalname), ReadOnly).await?;
    let product_key = tokio::fs::read_to_string(guard.as_ref().join("root/agent/product_key"))
        .await?
        .trim()
        .to_owned();
    guard.unmount().await?;
    *ctx.cached_product_key.write().await = Some(Arc::new(product_key));
    *ctx.selected_v2_drive.write().await = Some(logicalname);
    Ok(())
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RecoveryStatus {
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub complete: bool,
}

#[command(rename = "status", rpc_only, metadata(authenticated = false))]
pub async fn recovery_status(
    #[context] ctx: SetupContext,
) -> Result<Option<RecoveryStatus>, RpcError> {
    ctx.recovery_status.read().await.clone().transpose()
}

#[command(subcommands(verify_cifs))]
pub fn cifs() -> Result<(), Error> {
    Ok(())
}

#[command(rename = "verify", rpc_only)]
pub async fn verify_cifs(
    #[arg] hostname: String,
    #[arg] path: PathBuf,
    #[arg] username: String,
    #[arg] password: Option<String>,
) -> Result<EmbassyOsRecoveryInfo, Error> {
    let guard = TmpMountGuard::mount(
        &Cifs {
            hostname,
            path,
            username,
            password,
        },
        ReadOnly,
    )
    .await?;
    let embassy_os = recovery_info(&guard).await?;
    guard.unmount().await?;
    embassy_os.ok_or_else(|| Error::new(eyre!("No Backup Found"), crate::ErrorKind::NotFound))
}

#[command(rpc_only)]
pub async fn execute(
    #[context] ctx: SetupContext,
    #[arg(rename = "embassy-logicalname")] embassy_logicalname: PathBuf,
    #[arg(rename = "embassy-password")] embassy_password: String,
    #[arg(rename = "recovery-source")] mut recovery_source: Option<BackupTargetFS>,
    #[arg(rename = "recovery-password")] recovery_password: Option<String>,
    #[arg(rename = "umbrel-version")] umbrel_version: Option<Version>,
) -> Result<SetupResult, Error> {
    if let Some(v2_drive) = &*ctx.selected_v2_drive.read().await {
        recovery_source = Some(BackupTargetFS::Disk(BlockDev::new(v2_drive.clone())))
    }
    match execute_inner(
        ctx.clone(),
        embassy_logicalname,
        embassy_password,
        recovery_source,
        recovery_password,
        umbrel_version,
    )
    .await
    {
        Ok((tor_addr, root_ca)) => {
            tracing::info!("Setup Successful! Tor Address: {}", tor_addr);
            Ok(SetupResult {
                tor_address: format!("http://{}", tor_addr),
                lan_address: format!(
                    "https://embassy-{}.local",
                    crate::hostname::derive_id(&ctx.product_key().await?)
                ),
                root_ca: String::from_utf8(root_ca.to_pem()?)?,
            })
        }
        Err(e) => {
            tracing::error!("Error Setting Up Embassy: {}", e);
            tracing::debug!("{:?}", e);
            Err(e)
        }
    }
}

#[instrument(skip(ctx))]
#[command(rpc_only)]
pub async fn complete(#[context] ctx: SetupContext) -> Result<SetupResult, Error> {
    let (guid, setup_result) = if let Some((guid, setup_result)) = &*ctx.setup_result.read().await {
        (guid.clone(), setup_result.clone())
    } else {
        return Err(Error::new(
            eyre!("setup.execute has not completed successfully"),
            crate::ErrorKind::InvalidRequest,
        ));
    };
    if tokio::fs::metadata(PRODUCT_KEY_PATH).await.is_err() {
        crate::hostname::set_product_key(&*ctx.product_key().await?).await?;
    } else {
        let key_on_disk = crate::hostname::get_product_key().await?;
        let key_in_cache = ctx.product_key().await?;
        if *key_in_cache != key_on_disk {
            crate::hostname::set_product_key(&*ctx.product_key().await?).await?;
        }
    }
    tokio::fs::write(
        Path::new("/embassy-data/main/product_key.txt"),
        &*ctx.product_key().await?,
    )
    .await?;
    let secrets = ctx.secret_store().await?;
    let mut db = ctx.db(&secrets).await?.handle();
    let hostname = crate::hostname::get_hostname().await?;
    let si = crate::db::DatabaseModel::new().server_info();
    si.clone()
        .id()
        .put(&mut db, &crate::hostname::get_id().await?)
        .await?;
    si.lan_address()
        .put(
            &mut db,
            &format!("https://{}.local", &hostname).parse().unwrap(),
        )
        .await?;
    let mut guid_file = File::create("/embassy-os/disk.guid").await?;
    guid_file.write_all(guid.as_bytes()).await?;
    guid_file.sync_all().await?;
    ctx.shutdown.send(()).expect("failed to shutdown");
    Ok(setup_result)
}

#[instrument(skip(ctx, embassy_password, recovery_password))]
pub async fn execute_inner(
    ctx: SetupContext,
    embassy_logicalname: PathBuf,
    embassy_password: String,
    recovery_source: Option<BackupTargetFS>,
    recovery_password: Option<String>,
    umbrel_version: Option<Version>,
) -> Result<(OnionAddressV3, X509), Error> {
    if ctx.recovery_status.read().await.is_some() {
        return Err(Error::new(
            eyre!("Cannot execute setup while in recovery!"),
            crate::ErrorKind::InvalidRequest,
        ));
    }
    if let (Some(version), Some(source)) = (&umbrel_version, &recovery_source) {
        if version.minor() == 4 {
            prep_umbrel_migration(source).await?;
        } else {
            return Err(Error::new(
                eyre!("Unsupported Umbrel Version: {}", version),
                crate::ErrorKind::VersionIncompatible,
            ));
        }
    }
    let guid = Arc::new(
        crate::disk::main::create(
            &[embassy_logicalname],
            &pvscan().await?,
            &ctx.datadir,
            DEFAULT_PASSWORD,
        )
        .await?,
    );
    let _ = crate::disk::main::import(
        &*guid,
        &ctx.datadir,
        RepairStrategy::Preen,
        DEFAULT_PASSWORD,
    )
    .await?;

    let res = if let Some(recovery_source) = recovery_source {
        let (tor_addr, root_ca, recover_fut) = recover(
            ctx.clone(),
            guid.clone(),
            embassy_password,
            recovery_source,
            recovery_password,
            umbrel_version,
        )
        .await?;
        init(
            &RpcContextConfig::load(ctx.config_path.as_ref()).await?,
            &ctx.product_key().await?,
        )
        .await?;
        let res = (tor_addr, root_ca.clone());
        tokio::spawn(async move {
            if let Err(e) = recover_fut
                .and_then(|_| async {
                    *ctx.setup_result.write().await = Some((
                        guid,
                        SetupResult {
                            tor_address: format!("http://{}", tor_addr),
                            lan_address: format!(
                                "https://embassy-{}.local",
                                crate::hostname::derive_id(&ctx.product_key().await?)
                            ),
                            root_ca: String::from_utf8(root_ca.to_pem()?)?,
                        },
                    ));
                    if let Some(Ok(recovery_status)) = &mut *ctx.recovery_status.write().await {
                        recovery_status.complete = true;
                    }
                    Ok(())
                })
                .await
            {
                (&BEETHOVEN).play().await.unwrap_or_default(); // ignore error in playing the song
                tracing::error!("Error recovering drive!: {}", e);
                tracing::debug!("{:?}", e);
                *ctx.recovery_status.write().await = Some(Err(e.into()));
            } else {
                tracing::info!("Recovery Complete!");
            }
        });
        res
    } else {
        let (tor_addr, root_ca) = fresh_setup(&ctx, &embassy_password).await?;
        init(
            &RpcContextConfig::load(ctx.config_path.as_ref()).await?,
            &ctx.product_key().await?,
        )
        .await?;
        *ctx.setup_result.write().await = Some((
            guid,
            SetupResult {
                tor_address: format!("http://{}", tor_addr),
                lan_address: format!(
                    "https://embassy-{}.local",
                    crate::hostname::derive_id(&ctx.product_key().await?)
                ),
                root_ca: String::from_utf8(root_ca.to_pem()?)?,
            },
        ));
        (tor_addr, root_ca)
    };

    Ok(res)
}

pub async fn fresh_setup(
    ctx: &SetupContext,
    embassy_password: &str,
) -> Result<(OnionAddressV3, X509), Error> {
    let password = argon2::hash_encoded(
        embassy_password.as_bytes(),
        &rand::random::<[u8; 16]>()[..],
        &argon2::Config::default(),
    )
    .with_kind(crate::ErrorKind::PasswordHashGeneration)?;
    let tor_key = TorSecretKeyV3::generate();
    let key_vec = tor_key.as_bytes().to_vec();
    let sqlite_pool = ctx.secret_store().await?;
    sqlx::query!(
        "REPLACE INTO account (id, password, tor_key) VALUES (?, ?, ?)",
        0,
        password,
        key_vec,
    )
    .execute(&mut sqlite_pool.acquire().await?)
    .await?;
    let (_, root_ca) = SslManager::init(sqlite_pool.clone())
        .await?
        .export_root_ca()
        .await?;
    sqlite_pool.close().await;
    Ok((tor_key.public().get_onion_address(), root_ca))
}

#[instrument(skip(ctx, embassy_password, recovery_password))]
async fn recover(
    ctx: SetupContext,
    guid: Arc<String>,
    embassy_password: String,
    recovery_source: BackupTargetFS,
    recovery_password: Option<String>,
    umbrel_version: Option<Version>,
) -> Result<(OnionAddressV3, X509, BoxFuture<'static, Result<(), Error>>), Error> {
    let recovery_source = TmpMountGuard::mount(&recovery_source, ReadOnly).await?;
    if let Some(_) = umbrel_version {
        recover_umbrel(ctx.clone(), &embassy_password).await
    } else {
        let recovery_version = recovery_info(&recovery_source)
            .await?
            .as_ref()
            .map(|i| i.version.clone())
            .unwrap_or_else(|| emver::Version::new(0, 2, 0, 0).into());
        let res = if recovery_version.major() == 0 && recovery_version.minor() == 2 {
            recover_v2(ctx.clone(), &embassy_password, recovery_source).await?
        } else if recovery_version.major() == 0 && recovery_version.minor() == 3 {
            recover_full_embassy(
                ctx.clone(),
                guid.clone(),
                embassy_password,
                recovery_source,
                recovery_password,
            )
            .await?
        } else {
            return Err(Error::new(
                eyre!("Unsupported version of EmbassyOS: {}", recovery_version),
                crate::ErrorKind::VersionIncompatible,
            ));
        };

        Ok(res)
    }
}
