use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use async_compression::tokio::bufread::GzipDecoder;
use async_compression::tokio::write::GzipEncoder;
use futures::future::BoxFuture;
use futures::FutureExt;
use models::{PackageId, VolumeId};
use openssl::x509::X509;
use tokio::fs::File;
use tokio::io::BufReader;
use torut::onion::OnionAddressV3;
use tracing::instrument;

use crate::context::SetupContext;
use crate::disk::mount::filesystem::{FileSystem, ReadOnly, ReadWrite};
use crate::disk::mount::guard::TmpMountGuard;
use crate::install::{install, MinMax};
use crate::setup::{fresh_setup, RecoveryStatus};
use crate::update::query_mounted_label;
use crate::util::io::ProgressTracker;
use crate::volume::data_dir;
use crate::{Error, ResultExt};

#[instrument(skip(ctx))]
pub async fn recover_umbrel(
    ctx: SetupContext,
    embassy_password: &str,
) -> Result<(OnionAddressV3, X509, BoxFuture<'static, Result<(), Error>>), Error> {
    let (addr, cert) = fresh_setup(&ctx, embassy_password).await?;
    let fut = async move {
        let (source_fs, _) = query_mounted_label().await?;
        let source_guard = TmpMountGuard::mount(&source_fs.0.as_fs(), ReadWrite).await?;
        let source_path = source_guard.as_ref().join("lnd.tar.gz");
        let source_file = File::open(&source_path).await.with_ctx(|_| {
            (
                crate::ErrorKind::Filesystem,
                source_path.display().to_string(),
            )
        })?;
        let total_bytes = source_file.metadata().await?.len();
        *ctx.recovery_status.write().await = Some(Ok(RecoveryStatus {
            bytes_transferred: 0,
            total_bytes,
            complete: false,
        }));
        let progress = Arc::new(AtomicU64::new(0));
        let mut source_archive = tokio_tar::Archive::new(GzipDecoder::new(BufReader::new(
            ProgressTracker::new(source_file, progress),
        )));
        let lnd_id: PackageId = "lnd".parse()?;
        let main_id: VolumeId = "main".parse()?;
        let target_path = data_dir(&ctx.datadir, &lnd_id, &main_id);
        if tokio::fs::metadata(&target_path).await.is_err() {
            tokio::fs::create_dir_all(&target_path)
                .await
                .with_ctx(|_| {
                    (
                        crate::ErrorKind::Filesystem,
                        format!("mkdir {}", target_path.display()),
                    )
                })?;
        }
        source_archive.unpack(&target_path).await?;
        source_guard.unmount().await?;
        install(todo!(), lnd_id.into(), None, None, Some(MinMax::Min)).await?;
        Ok(())
    }
    .boxed();
    Ok((addr, cert, fut))
}

pub async fn prep_umbrel_migration(source: &impl FileSystem) -> Result<(), Error> {
    let umbrel_guard = TmpMountGuard::mount(source, ReadOnly).await?;
    let (target_fs, _) = query_mounted_label().await?;
    let target_guard = TmpMountGuard::mount(&target_fs.0.as_fs(), ReadWrite).await?;
    let target_path = target_guard.as_ref().join("lnd.tar.gz");
    let mut target_archive = tokio_tar::Builder::new(GzipEncoder::new(
        File::create(&target_path).await.with_ctx(|_| {
            (
                crate::ErrorKind::Filesystem,
                target_path.display().to_string(),
            )
        })?,
    ));
    target_archive
        .append_dir_all("/", umbrel_guard.as_ref().join("umbrel/lnd"))
        .await?;
    target_guard.unmount().await?;
    umbrel_guard.unmount().await?;

    Ok(())
}
