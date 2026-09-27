//! Companion files: a `$MFT` next to a `$I30`/`$J` resolves paths; a `$Secure:$SDS` next to a
//! `$MFT` resolves owners. Loaded once per run and shared.

use std::collections::BTreeMap;
use std::sync::Arc;

use forensic_rs::prelude::*;

use super::discovery::{self, companion};
use crate::mft::Mft;
use crate::source::StreamSource;

/// Per-run cache of companion `$MFT`s, keyed by their path.
#[derive(Default)]
pub struct MftCache {
    loaded: BTreeMap<FPathBuf, Option<Arc<Mft>>>,
}

impl MftCache {
    /// The `$MFT` next to `artifact`, if there is one and it parses. A companion that fails to
    /// parse is reported once through `on_error` (it is analyst-relevant: paths will be missing)
    /// and cached as absent.
    pub fn for_artifact(
        &mut self,
        fs: &dyn FileSystem,
        artifact: &FPath,
        cancelled: &dyn Fn() -> bool,
        on_error: &mut dyn FnMut(ForensicError),
    ) -> Option<Arc<Mft>> {
        let path = companion(fs, artifact, discovery::MFT_NAMES)?;
        if let Some(hit) = self.loaded.get(&path) {
            return hit.clone();
        }
        let loaded = fs
            .open(path.as_path())
            .and_then(StreamSource::new)
            .and_then(|src| Mft::open(Box::new(src), None, cancelled));
        let value = match loaded {
            Ok(m) => Some(Arc::new(m)),
            Err(e) => {
                on_error(e.with_path(path.as_path()));
                None
            }
        };
        self.loaded.insert(path, value.clone());
        value
    }
}
