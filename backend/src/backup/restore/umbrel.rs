use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use async_compression::tokio::bufread::GzipDecoder;
use futures::future::BoxFuture;
use futures::FutureExt;
use openssl::x509::X509;
use tokio::fs::File;
use tokio::io::BufReader;
use torut::onion::OnionAddressV3;
use tracing::instrument;

use crate::context::SetupContext;
use crate::disk::mount::filesystem::{ReadOnly, ReadWrite};
use crate::disk::mount::guard::TmpMountGuard;
use crate::setup::{fresh_setup, RecoveryStatus};
use crate::update::query_mounted_label;
use crate::util::io::ProgressTracker;
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
        source_guard.unmount().await?;
        Ok(())
    }
    .boxed();
    Ok((addr, cert, fut))
}
