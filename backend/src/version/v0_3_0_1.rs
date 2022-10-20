use std::path::Path;

use emver::VersionRange;
use tokio::process::Command;

use super::*;
use crate::disk::BOOT_RW_PATH;
use crate::util::Invoke;

const V0_3_0_1: emver::Version = emver::Version::new(0, 3, 0, 1);

#[derive(Debug, Clone)]
pub struct Version;
#[async_trait]
impl VersionT for Version {
    type Previous = v0_3_0::Version;
    fn new() -> Self {
        Version
    }
    fn semver(&self) -> emver::Version {
        V0_3_0_1
    }
    fn compat(&self) -> &'static VersionRange {
        &*v0_3_0::V0_3_0_COMPAT
    }
    async fn up<Db: DbHandle>(&self, _db: &mut Db) -> Result<(), Error> {
        Ok(())
    }
    async fn down<Db: DbHandle>(&self, _db: &mut Db) -> Result<(), Error> {
        Ok(())
    }
}
