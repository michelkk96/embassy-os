use std::collections::BTreeMap;
use std::os::unix::prelude::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use color_eyre::eyre::eyre;
use digest::generic_array::GenericArray;
use digest::{Digest, OutputSizeUser};
use futures::future::BoxFuture;
use futures::{FutureExt, TryStreamExt};
use models::{Id, PackageId, Version, VolumeId};
use nix::unistd::{Gid, Uid};
use openssl::x509::X509;
use patch_db::LockType;
use serde::Deserialize;
use sha2::Sha256;
use tokio::fs::File;
use torut::onion::{OnionAddressV3, TorSecretKeyV3};
use tracing::instrument;

use crate::context::SetupContext;
use crate::db::model::RecoveredPackageInfo;
use crate::disk::mount::guard::TmpMountGuard;
use crate::install::PKG_PUBLIC_DIR;
use crate::setup::RecoveryStatus;
use crate::util::io::{dir_size, from_yaml_async_reader};
use crate::volume::data_dir;
use crate::{ensure_code, Error, ResultExt};

#[instrument(skip(ctx))]
pub async fn recover_v2(
    ctx: SetupContext,
    embassy_password: &str,
    recovery_source: TmpMountGuard,
) -> Result<(OnionAddressV3, X509, BoxFuture<'static, Result<(), Error>>), Error> {
    let secret_store = ctx.secret_store().await?;

    // migrate the root CA
    let root_ca_key_path = recovery_source
        .as_ref()
        .join("root")
        .join("agent")
        .join("ca")
        .join("private")
        .join("embassy-root-ca.key.pem");
    let root_ca_cert_path = recovery_source
        .as_ref()
        .join("root")
        .join("agent")
        .join("ca")
        .join("certs")
        .join("embassy-root-ca.cert.pem");
    let (root_ca_key_bytes, root_ca_cert_bytes) = tokio::try_join!(
        tokio::fs::read(root_ca_key_path),
        tokio::fs::read(root_ca_cert_path)
    )?;
    let root_ca_key = openssl::pkey::PKey::private_key_from_pem(&root_ca_key_bytes)?;
    let root_ca_cert = openssl::x509::X509::from_pem(&root_ca_cert_bytes)?;
    crate::net::ssl::SslManager::import_root_ca(
        secret_store.clone(),
        root_ca_key,
        root_ca_cert.clone(),
    )
    .await?;

    // migrate the tor address
    let tor_key_path = recovery_source
        .as_ref()
        .join("var")
        .join("lib")
        .join("tor")
        .join("agent")
        .join("hs_ed25519_secret_key");
    let tor_key_bytes = tokio::fs::read(tor_key_path).await?;
    let mut tor_key_array_tmp = [0u8; 64];
    tor_key_array_tmp.clone_from_slice(&tor_key_bytes[32..]);
    let tor_key: TorSecretKeyV3 = tor_key_array_tmp.into();
    let key_vec = tor_key.as_bytes().to_vec();
    let password = argon2::hash_encoded(
        embassy_password.as_bytes(),
        &rand::random::<[u8; 16]>()[..],
        &argon2::Config::default(),
    )
    .with_kind(crate::ErrorKind::PasswordHashGeneration)?;
    let sqlite_pool = ctx.secret_store().await?;
    sqlx::query!(
        "REPLACE INTO account (id, password, tor_key) VALUES (?, ?, ?)",
        0,
        password,
        key_vec
    )
    .execute(&mut sqlite_pool.acquire().await?)
    .await?;

    // rest of migration as future
    let fut = async move {
        let db = ctx.db(&secret_store).await?;
        let mut handle = db.handle();
        // lock everything to avoid issues with renamed packages (bitwarden)
        crate::db::DatabaseModel::new()
            .lock(&mut handle, LockType::Write)
            .await?;

        let apps_yaml_path = recovery_source
            .as_ref()
            .join("root")
            .join("appmgr")
            .join("apps.yaml");
        #[derive(Deserialize)]
        struct LegacyAppInfo {
            title: String,
            version: Version,
        }
        let packages: BTreeMap<PackageId, LegacyAppInfo> =
            from_yaml_async_reader(File::open(&apps_yaml_path).await.with_ctx(|_| {
                (
                    crate::ErrorKind::Filesystem,
                    apps_yaml_path.display().to_string(),
                )
            })?)
            .await?;

        let volume_path = recovery_source.as_ref().join("root/volumes");
        let mut total_bytes = 0;
        for (pkg_id, _) in &packages {
            let volume_src_path = volume_path.join(&pkg_id);
            total_bytes += dir_size(&volume_src_path).await.with_ctx(|_| {
                (
                    crate::ErrorKind::Filesystem,
                    volume_src_path.display().to_string(),
                )
            })?;
        }
        *ctx.recovery_status.write().await = Some(Ok(RecoveryStatus {
            bytes_transferred: 0,
            total_bytes,
            complete: false,
        }));
        let bytes_transferred = AtomicU64::new(0);
        let volume_id = VolumeId::Custom(Id::try_from("main".to_owned())?);
        for (pkg_id, info) in packages {
            let (src_id, dst_id) = rename_pkg_id(pkg_id);
            let volume_src_path = volume_path.join(&src_id);
            let volume_dst_path = data_dir(&ctx.datadir, &dst_id, &volume_id);
            tokio::select!(
                res = dir_copy(
                    &volume_src_path,
                    &volume_dst_path,
                    &bytes_transferred
                ) => res?,
                _ = async {
                    loop {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        *ctx.recovery_status.write().await = Some(Ok(RecoveryStatus {
                            bytes_transferred: bytes_transferred.load(Ordering::Relaxed),
                            total_bytes,
                            complete: false
                        }));
                    }
                } => (),
            );
            let tor_src_path = recovery_source
                .as_ref()
                .join("var/lib/tor")
                .join(format!("app-{}", src_id))
                .join("hs_ed25519_secret_key");
            let key_vec = tokio::fs::read(&tor_src_path).await.with_ctx(|_| {
                (
                    crate::ErrorKind::Filesystem,
                    tor_src_path.display().to_string(),
                )
            })?;
            ensure_code!(
                key_vec.len() == 96,
                crate::ErrorKind::Tor,
                "{} not 96 bytes",
                tor_src_path.display()
            );
            let key_vec = key_vec[32..].to_vec();
            sqlx::query!(
                "REPLACE INTO tor (package, interface, key) VALUES (?, 'main', ?)",
                *dst_id,
                key_vec,
            )
            .execute(&mut secret_store.acquire().await?)
            .await?;
            let icon_leaf = AsRef::<Path>::as_ref(&dst_id)
                .join(info.version.as_str())
                .join("icon.png");
            let icon_src_path = recovery_source
                .as_ref()
                .join("root/agent/icons")
                .join(format!("{}.png", src_id));
            let icon_dst_path = ctx.datadir.join(PKG_PUBLIC_DIR).join(&icon_leaf);
            if let Some(parent) = icon_dst_path.parent() {
                tokio::fs::create_dir_all(&parent)
                    .await
                    .with_ctx(|_| (crate::ErrorKind::Filesystem, parent.display().to_string()))?;
            }
            tokio::fs::copy(&icon_src_path, &icon_dst_path)
                .await
                .with_ctx(|_| {
                    (
                        crate::ErrorKind::Filesystem,
                        format!(
                            "cp {} -> {}",
                            icon_src_path.display(),
                            icon_dst_path.display()
                        ),
                    )
                })?;
            let icon_url = Path::new("/public/package-data").join(&icon_leaf);
            crate::db::DatabaseModel::new()
                .recovered_packages()
                .idx_model(&dst_id)
                .put(
                    &mut handle,
                    &RecoveredPackageInfo {
                        title: info.title,
                        icon: icon_url.display().to_string(),
                        version: info.version,
                    },
                )
                .await?;
        }

        secret_store.close().await;
        recovery_source.unmount().await?;
        Ok(())
    };
    Ok((
        tor_key.public().get_onion_address(),
        root_ca_cert,
        fut.boxed(),
    ))
}

async fn shasum(
    path: impl AsRef<Path>,
) -> Result<GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>, Error> {
    use tokio::io::AsyncReadExt;

    let mut rdr = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0; 1024];
    let mut read;
    while {
        read = rdr.read(&mut buf).await?;
        read != 0
    } {
        hasher.update(&buf[0..read]);
    }
    Ok(hasher.finalize())
}

async fn validated_copy(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<(), Error> {
    let src_path = src.as_ref();
    let dst_path = dst.as_ref();
    tokio::fs::copy(src_path, dst_path).await.with_ctx(|_| {
        (
            crate::ErrorKind::Filesystem,
            format!("cp {} -> {}", src_path.display(), dst_path.display()),
        )
    })?;
    let (src_hash, dst_hash) = tokio::try_join!(shasum(src_path), shasum(dst_path))?;
    if src_hash != dst_hash {
        Err(Error::new(
            eyre!(
                "source hash does not match destination hash for {}",
                dst_path.display()
            ),
            crate::ErrorKind::Filesystem,
        ))
    } else {
        Ok(())
    }
}

fn dir_copy<'a, P0: AsRef<Path> + 'a + Send + Sync, P1: AsRef<Path> + 'a + Send + Sync>(
    src: P0,
    dst: P1,
    ctr: &'a AtomicU64,
) -> BoxFuture<'a, Result<(), Error>> {
    async move {
        let m = tokio::fs::metadata(&src).await?;
        let dst_path = dst.as_ref();
        tokio::fs::create_dir_all(&dst_path).await.with_ctx(|_| {
            (
                crate::ErrorKind::Filesystem,
                format!("mkdir {}", dst_path.display()),
            )
        })?;
        tokio::fs::set_permissions(&dst_path, m.permissions())
            .await
            .with_ctx(|_| {
                (
                    crate::ErrorKind::Filesystem,
                    format!("chmod {}", dst_path.display()),
                )
            })?;
        let tmp_dst_path = dst_path.to_owned();
        tokio::task::spawn_blocking(move || {
            nix::unistd::chown(
                &tmp_dst_path,
                Some(Uid::from_raw(m.uid())),
                Some(Gid::from_raw(m.gid())),
            )
        })
        .await
        .with_kind(crate::ErrorKind::Unknown)?
        .with_ctx(|_| {
            (
                crate::ErrorKind::Filesystem,
                format!("chown {}", dst_path.display()),
            )
        })?;
        tokio_stream::wrappers::ReadDirStream::new(tokio::fs::read_dir(src.as_ref()).await?)
            .map_err(|e| Error::new(e, crate::ErrorKind::Filesystem))
            .try_for_each(|e| async move {
                let m = e.metadata().await?;
                let src_path = e.path();
                let dst_path = dst_path.join(e.file_name());
                if m.is_file() {
                    let len = m.len();
                    let mut cp_res = Ok(());
                    for _ in 0..10 {
                        cp_res = validated_copy(&src_path, &dst_path).await;
                        if cp_res.is_ok() {
                            break;
                        }
                    }
                    cp_res?;
                    let tmp_dst_path = dst_path.clone();
                    tokio::task::spawn_blocking(move || {
                        nix::unistd::chown(
                            &tmp_dst_path,
                            Some(Uid::from_raw(m.uid())),
                            Some(Gid::from_raw(m.gid())),
                        )
                    })
                    .await
                    .with_kind(crate::ErrorKind::Unknown)?
                    .with_ctx(|_| {
                        (
                            crate::ErrorKind::Filesystem,
                            format!("chown {}", dst_path.display()),
                        )
                    })?;
                    ctr.fetch_add(len, Ordering::Relaxed);
                } else if m.is_dir() {
                    dir_copy(src_path, dst_path, ctr).await?;
                } else if m.file_type().is_symlink() {
                    tokio::fs::symlink(
                        tokio::fs::read_link(&src_path).await.with_ctx(|_| {
                            (
                                crate::ErrorKind::Filesystem,
                                format!("readlink {}", src_path.display()),
                            )
                        })?,
                        &dst_path,
                    )
                    .await
                    .with_ctx(|_| {
                        (
                            crate::ErrorKind::Filesystem,
                            format!("cp -P {} -> {}", src_path.display(), dst_path.display()),
                        )
                    })?;
                    // Do not set permissions (see https://unix.stackexchange.com/questions/87200/change-permissions-for-a-symbolic-link)
                }
                Ok(())
            })
            .await?;
        Ok(())
    }
    .boxed()
}

fn rename_pkg_id(src_pkg_id: PackageId) -> (PackageId, PackageId) {
    if &*src_pkg_id == "bitwarden" {
        (src_pkg_id, "vaultwarden".parse().unwrap())
    } else {
        (src_pkg_id.clone(), src_pkg_id)
    }
}
