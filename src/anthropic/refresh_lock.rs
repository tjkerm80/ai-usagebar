//! Claude Code's own lock around an OAuth token refresh.
//!
//! Claude Code and ai-usagebar refresh the same rotating refresh token. When
//! both refresh at once, one of them spends a token the other has just
//! replaced, and whichever saves last can leave Claude Code logged out. Claude
//! Code serialises its own refreshes with two `proper-lockfile` locks, taken
//! in this order:
//!
//! 1. `<claude dir>/.oauth_refresh.lock`;
//! 2. the older lock `<real path of the claude dir>.lock`, which earlier
//!    Claude Code versions still take. Claude Code ignores a failure to take
//!    this one for any reason other than contention, and so does this module.
//!
//! Both use a 60 s `stale`; Claude Code touches its locks every 5 s. Taking
//! the same locks in the same order makes a refresh here and a refresh in
//! Claude Code wait for each other instead of racing. The protocol itself is
//! [`crate::proper_lockfile`].
//!
//! If the claude directory does not allow creating the lock, Claude Code
//! cannot take it either, so there is nothing to coordinate with and the
//! refresh proceeds unlocked, as it did before this lock existed.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{AppError, Result};
use crate::proper_lockfile::{self, AcquireError, HeldLock, Timing};

/// The lock directory inside the claude directory.
pub const LOCK_NAME: &str = ".oauth_refresh.lock";

/// Claude Code's `stale` is 60 s. It treats a holder whose lock mtime has not
/// moved within 7.5 s as gone, so the heartbeat stays well under that. The
/// timeout outlasts one refresh round trip by Claude Code.
const TIMING: Timing = Timing {
    stale: Duration::from_secs(60),
    heartbeat: Duration::from_millis(2_500),
    poll: Duration::from_millis(250),
    timeout: Duration::from_secs(20),
};

/// Both of Claude Code's refresh locks, as far as they could be taken.
/// Dropping it releases them.
#[derive(Debug)]
pub struct RefreshLock {
    // Field order is drop order: the legacy lock was taken last, so it is
    // released first.
    _legacy: Option<HeldLock>,
    _primary: Option<HeldLock>,
}

/// `<claude dir>/.oauth_refresh.lock`.
pub fn primary_lock_dir(claude_dir: &Path) -> PathBuf {
    claude_dir.join(LOCK_NAME)
}

/// `<real path of the claude dir>.lock`, or `None` when the claude directory
/// has no real path, in which case Claude Code cannot take this lock either.
pub fn legacy_lock_dir(claude_dir: &Path) -> Option<PathBuf> {
    let mut dir = std::fs::canonicalize(claude_dir).ok()?.into_os_string();
    dir.push(".lock");
    Some(PathBuf::from(dir))
}

/// Take Claude Code's refresh locks for `claude_dir`, holding them with a
/// heartbeat on the current Tokio runtime. A lock held by a live Claude Code
/// for the whole timeout is a transient [`AppError::Transport`].
pub async fn acquire(claude_dir: &Path) -> Result<RefreshLock> {
    acquire_with(claude_dir, TIMING).await
}

/// [`acquire`] for synchronous callers that hold the locks only briefly, such
/// as switching the account the `claude` CLI uses.
pub fn acquire_blocking(claude_dir: &Path) -> Result<RefreshLock> {
    acquire_blocking_with(claude_dir, TIMING)
}

pub(crate) async fn acquire_with(claude_dir: &Path, timing: Timing) -> Result<RefreshLock> {
    let primary_dir = primary_lock_dir(claude_dir);
    let primary = tolerate_failure(proper_lockfile::acquire(&primary_dir, timing).await)
        .map_err(|()| contended(&primary_dir))?;
    let legacy = match legacy_lock_dir(claude_dir) {
        Some(legacy_dir) => tolerate_failure(proper_lockfile::acquire(&legacy_dir, timing).await)
            .map_err(|()| contended(&legacy_dir))?,
        None => None,
    };
    Ok(RefreshLock {
        _legacy: legacy,
        _primary: primary,
    })
}

pub(crate) fn acquire_blocking_with(claude_dir: &Path, timing: Timing) -> Result<RefreshLock> {
    let primary_dir = primary_lock_dir(claude_dir);
    let primary = tolerate_failure(proper_lockfile::acquire_blocking(&primary_dir, timing))
        .map_err(|()| contended(&primary_dir))?;
    let legacy = match legacy_lock_dir(claude_dir) {
        Some(legacy_dir) => {
            tolerate_failure(proper_lockfile::acquire_blocking(&legacy_dir, timing))
                .map_err(|()| contended(&legacy_dir))?
        }
        None => None,
    };
    Ok(RefreshLock {
        _legacy: legacy,
        _primary: primary,
    })
}

/// `Ok(None)` for a lock that could not be created at all, `Err(())` for one
/// that a live holder kept.
fn tolerate_failure(
    result: std::result::Result<HeldLock, AcquireError>,
) -> std::result::Result<Option<HeldLock>, ()> {
    match result {
        Ok(lock) => Ok(Some(lock)),
        Err(AcquireError::Failed(_)) => Ok(None),
        Err(AcquireError::Contended) => Err(()),
    }
}

fn contended(dir: &Path) -> AppError {
    AppError::Transport(format!(
        "timed out waiting for Claude Code's token refresh lock at {}",
        crate::display::sanitize_untrusted_path(dir)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const QUICK: Timing = Timing {
        stale: Duration::from_secs(60),
        heartbeat: Duration::from_millis(20),
        poll: Duration::from_millis(10),
        timeout: Duration::from_millis(80),
    };

    /// A claude directory inside a temp root, so the legacy lock (a sibling
    /// of the claude directory) also lands inside the temp root.
    fn claude_dir(root: &TempDir) -> PathBuf {
        let dir = root.path().join(".claude");
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn the_lock_paths_match_claude_codes() {
        let root = TempDir::new().unwrap();
        let dir = claude_dir(&root);
        assert_eq!(primary_lock_dir(&dir), dir.join(".oauth_refresh.lock"));
        let real = std::fs::canonicalize(&dir).unwrap();
        let mut expected = real.into_os_string();
        expected.push(".lock");
        assert_eq!(legacy_lock_dir(&dir), Some(PathBuf::from(expected)));
        assert_eq!(legacy_lock_dir(&root.path().join("missing")), None);
    }

    #[tokio::test]
    async fn acquire_takes_both_locks_and_drop_releases_them() {
        let root = TempDir::new().unwrap();
        let dir = claude_dir(&root);
        let legacy = legacy_lock_dir(&dir).unwrap();
        {
            let _lock = acquire_with(&dir, QUICK).await.unwrap();
            assert!(primary_lock_dir(&dir).is_dir());
            assert!(legacy.is_dir());
        }
        assert!(!primary_lock_dir(&dir).exists());
        assert!(!legacy.exists());
    }

    #[tokio::test]
    async fn a_live_claude_code_refresh_is_a_transient_error() {
        let root = TempDir::new().unwrap();
        let dir = claude_dir(&root);
        std::fs::create_dir(primary_lock_dir(&dir)).unwrap();

        let error = acquire_with(&dir, QUICK).await.unwrap_err();
        assert!(error.is_transient(), "{error:?}");
        assert!(error.to_string().contains(".oauth_refresh.lock"));
        // The legacy lock is never taken while the primary one is held.
        assert!(!legacy_lock_dir(&dir).unwrap().exists());
    }

    #[test]
    fn a_held_legacy_lock_is_also_waited_for() {
        let root = TempDir::new().unwrap();
        let dir = claude_dir(&root);
        let legacy = legacy_lock_dir(&dir).unwrap();
        std::fs::create_dir(&legacy).unwrap();

        let error = acquire_blocking_with(&dir, QUICK).unwrap_err();
        assert!(error.to_string().contains("token refresh lock"));
        // The primary lock taken before the wait is released again.
        assert!(!primary_lock_dir(&dir).exists());
        assert!(legacy.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn a_claude_dir_that_refuses_the_lock_proceeds_unlocked() {
        use std::os::unix::fs::PermissionsExt;
        let root = TempDir::new().unwrap();
        let dir = claude_dir(&root);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o500)).unwrap();

        let result = acquire_blocking_with(&dir, QUICK);

        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Running as root ignores the permission bits; the lock is then
        // simply taken, which is also not an error.
        assert!(result.is_ok(), "{result:?}");
    }
}
