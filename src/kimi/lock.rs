//! Cross-process lock around a Kimi Code CLI credential refresh, speaking the
//! CLI's own lock protocol.
//!
//! kimi-code locks its credential store with `proper-lockfile`: `lock(target)`
//! creates the directory `<target>.lock`. The protocol itself lives in
//! [`crate::proper_lockfile`]; this module supplies kimi-code's lock path and
//! timing.
//!
//! Windows is deliberately unlocked: kimi-code disables its own lock there
//! (`if (process.platform === "win32") return undefined`), so taking one would
//! only be a lock against ourselves.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{AppError, Result};
use crate::proper_lockfile::{self, AcquireError, HeldLock, Timing};

/// proper-lockfile's default `stale` for kimi-code's OAuth lock (5 s), after
/// which an abandoned lock directory may be taken over.
pub const STALE: Duration = Duration::from_secs(5);
/// proper-lockfile refreshes at `stale / 2`; matching that keeps a slow
/// refresh from looking abandoned. The acquire timeout is long enough to
/// outlast a peer's refresh round trip, and short enough that a widget tick
/// never hangs on it.
const TIMING: Timing = Timing {
    stale: STALE,
    heartbeat: Duration::from_millis(2_500),
    poll: Duration::from_millis(250),
    timeout: Duration::from_secs(20),
};

/// The directory `proper-lockfile` actually creates for `target`.
pub fn lock_dir_for(target: &Path) -> PathBuf {
    let mut dir = target.as_os_str().to_os_string();
    dir.push(".lock");
    PathBuf::from(dir)
}

/// Acquire the lock for `target` (kimi-code's `<home>/oauth/kimi-code`),
/// taking it over only once it has been abandoned for [`STALE`].
pub async fn acquire(target: &Path) -> Result<HeldLock> {
    acquire_with(target, TIMING).await
}

async fn acquire_with(target: &Path, timing: Timing) -> Result<HeldLock> {
    let dir = lock_dir_for(target);
    proper_lockfile::acquire(&dir, timing)
        .await
        .map_err(|error| match error {
            AcquireError::Contended => AppError::Transport(format!(
                "timed out waiting for the Kimi Code CLI credential lock at {}",
                crate::display::sanitize_untrusted_path(&dir)
            )),
            AcquireError::Failed(error) => error,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn lock_dir_matches_proper_lockfile_naming() {
        assert_eq!(
            lock_dir_for(Path::new("/home/u/.kimi-code/oauth/kimi-code")),
            PathBuf::from("/home/u/.kimi-code/oauth/kimi-code.lock")
        );
    }

    #[tokio::test]
    async fn a_contended_lock_reports_a_transport_error_naming_the_lock() {
        let root = TempDir::new().unwrap();
        let target = root.path().join("oauth").join("kimi-code");
        let dir = lock_dir_for(&target);
        std::fs::create_dir_all(&dir).unwrap();

        let timing = Timing {
            timeout: Duration::from_millis(60),
            poll: Duration::from_millis(10),
            ..TIMING
        };
        let error = acquire_with(&target, timing).await.unwrap_err();
        match error {
            AppError::Transport(message) => {
                assert!(message.contains("Kimi Code CLI credential lock"));
                assert!(message.contains("kimi-code.lock"));
            }
            other => panic!("expected a transport error, got {other:?}"),
        }
        assert!(dir.is_dir(), "a live peer's lock must survive");
    }
}
