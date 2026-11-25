//! The lock protocol of the npm package `proper-lockfile`, for coordinating
//! with programs that use it to guard files they own.
//!
//! Every other lock in this codebase guards a file ai-usagebar owns and uses
//! `flock` via `cache::acquire_lock_async`. A file **another program** owns and
//! refreshes on its own schedule has to be locked the way that program locks
//! it, or each process would be invisible to the other and both would rotate
//! the same refresh token at once. Kimi Code and Claude Code both use
//! `proper-lockfile` (Claude Code bundles its own copy), whose contract is a
//! *directory*:
//!
//! - taking the lock is `mkdir`ing the lock directory, which fails if it exists;
//! - the holder keeps moving the directory's mtime forward while it works;
//! - a lock directory whose mtime is older than `stale` was abandoned, and may
//!   be removed and taken over.
//!
//! The other program removes an abandoned lock with `rmdir`, which fails on a
//! directory that is not empty. So this module never puts anything inside the
//! lock directory: a file left there by a holder that was killed would block
//! the other program for good. The holder recognises its own lock by the mtime
//! it last set (and, on Unix, the directory's inode), which is also how
//! `proper-lockfile` detects that its lock was taken over.
//!
//! Callers choose the directory and the timing, because each program picks its
//! own lock path and `stale`/`update` values.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::error::AppError;

/// How long a lock may go untouched before it counts as abandoned, how often
/// the holder touches it, how often a waiter retries, and how long a waiter
/// waits in total.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Must match the `stale` the other program uses, so neither side takes
    /// over a lock the other still considers live.
    pub stale: Duration,
    /// Must be shorter than the other program's `stale`, and shorter than any
    /// liveness check it makes by watching the mtime.
    pub heartbeat: Duration,
    pub poll: Duration,
    pub timeout: Duration,
}

/// Why a lock was not acquired.
#[derive(Debug)]
pub enum AcquireError {
    /// Another holder kept the lock live for the whole timeout.
    Contended,
    /// The lock directory could not be created for a reason other than
    /// contention: a missing permission, a read-only file system, and so on.
    Failed(AppError),
}

/// What identifies one holder's lock directory: the mtime the holder last
/// set, and on Unix the directory's inode. A process that took the lock over
/// created a new directory and set its own mtime, so either differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: SystemTime,
    inode: u64,
}

/// A held lock. Dropping it releases the lock and stops the heartbeat.
#[derive(Debug)]
pub struct HeldLock {
    dir: PathBuf,
    stamp: Arc<Mutex<Stamp>>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

impl HeldLock {
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat.take() {
            handle.abort();
        }
        // Only release what is still ours. A holder delayed past `stale` can
        // resume after another process took the lock over and rebuilt the
        // directory; deleting unconditionally would destroy the replacement
        // (#495). The cost of leaving a lock behind is one stale interval for
        // the next acquirer, never data loss.
        let ours = self
            .stamp
            .lock()
            .is_ok_and(|stamp| stamp_of(&self.dir) == Some(*stamp));
        if ours {
            // `remove_dir_all`, not `remove_dir`: a directory we fail to remove
            // would block the other program for `stale` on every one of its
            // refreshes, and this one is known to be ours.
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Acquire the lock directory `dir`, waiting for a live holder and taking over
/// an abandoned one. The holder's mtime heartbeat runs on the current Tokio
/// runtime for as long as the lock is held.
pub async fn acquire(dir: &Path, timing: Timing) -> Result<HeldLock, AcquireError> {
    let deadline = tokio::time::Instant::now() + timing.timeout;
    loop {
        if let Some(stamp) = try_once(dir, timing.stale)? {
            return Ok(hold(dir.to_path_buf(), stamp, Some(timing.heartbeat)));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AcquireError::Contended);
        }
        tokio::time::sleep(timing.poll).await;
    }
}

/// [`acquire`] for synchronous callers. It runs no heartbeat, so it is only
/// for holds much shorter than `timing.stale`; `timing.heartbeat` is unused.
pub fn acquire_blocking(dir: &Path, timing: Timing) -> Result<HeldLock, AcquireError> {
    let deadline = std::time::Instant::now() + timing.timeout;
    loop {
        if let Some(stamp) = try_once(dir, timing.stale)? {
            return Ok(hold(dir.to_path_buf(), stamp, None));
        }
        if std::time::Instant::now() >= deadline {
            return Err(AcquireError::Contended);
        }
        std::thread::sleep(timing.poll);
    }
}

/// One attempt: `Some(stamp)` when the directory is now ours, `None` when a
/// live holder has it.
fn try_once(dir: &Path, stale: Duration) -> Result<Option<Stamp>, AcquireError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| AcquireError::Failed(AppError::io_at(parent, error)))?;
    }
    match std::fs::create_dir(dir) {
        Ok(()) => match touch(dir) {
            Some(stamp) => Ok(Some(stamp)),
            None => {
                // A lock we cannot stamp is one we could never prove is ours
                // at release, so it would sit there until it went stale.
                let _ = std::fs::remove_dir(dir);
                let error = std::io::Error::other("could not set the lock directory's mtime");
                Err(AcquireError::Failed(AppError::io_at(dir, error)))
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if is_stale(dir, stale) {
                // Best effort: losing this race means another process took
                // the lock over first, and the next attempt waits for it.
                // `remove_dir_all` also clears directories that older
                // ai-usagebar versions left with files inside.
                let _ = std::fs::remove_dir_all(dir);
            }
            Ok(None)
        }
        Err(error) => Err(AcquireError::Failed(AppError::io_at(dir, error))),
    }
}

fn hold(dir: PathBuf, stamp: Stamp, heartbeat: Option<Duration>) -> HeldLock {
    let stamp = Arc::new(Mutex::new(stamp));
    let heartbeat = heartbeat
        .filter(|_| tokio::runtime::Handle::try_current().is_ok())
        .map(|interval| {
            let beat_dir = dir.clone();
            let beat_stamp = Arc::clone(&stamp);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if !beat(&beat_dir, &beat_stamp) {
                        // The lock was taken over while we slept: stop
                        // touching a directory that belongs to someone else.
                        break;
                    }
                }
            })
        });
    HeldLock {
        dir,
        stamp,
        heartbeat,
    }
}

/// One heartbeat: move the mtime forward if the directory is still ours.
/// Returns false when it is not, so the heartbeat stops (#495).
fn beat(dir: &Path, stamp: &Mutex<Stamp>) -> bool {
    let Ok(mut held) = stamp.lock() else {
        return false;
    };
    if stamp_of(dir) != Some(*held) {
        return false;
    }
    // A failed touch leaves the old stamp in place, and the next beat tries
    // again, as `proper-lockfile` does.
    if let Some(next) = touch(dir) {
        *held = next;
    }
    true
}

/// Set the directory's mtime to now and return the stamp the file system
/// recorded, which may be coarser than what was set.
fn touch(dir: &Path) -> Option<Stamp> {
    open_directory(dir)
        .ok()?
        .set_times(std::fs::FileTimes::new().set_modified(SystemTime::now()))
        .ok()?;
    stamp_of(dir)
}

#[cfg(not(windows))]
fn open_directory(dir: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(dir)
}

/// Windows opens a directory only with `FILE_FLAG_BACKUP_SEMANTICS`, and
/// setting its times needs `FILE_WRITE_ATTRIBUTES`.
#[cfg(windows)]
fn open_directory(dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
}

fn stamp_of(dir: &Path) -> Option<Stamp> {
    let metadata = std::fs::metadata(dir).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&metadata);
    #[cfg(not(unix))]
    let inode = 0;
    Some(Stamp {
        modified: metadata.modified().ok()?,
        inode,
    })
}

fn is_stale(dir: &Path, stale: Duration) -> bool {
    let Ok(modified) = std::fs::metadata(dir).and_then(|metadata| metadata.modified()) else {
        // No mtime to trust: leave the lock alone rather than take it blindly.
        return false;
    };
    SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age > stale)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const QUICK: Timing = Timing {
        stale: Duration::from_secs(3_600),
        heartbeat: Duration::from_millis(20),
        poll: Duration::from_millis(10),
        timeout: Duration::from_secs(1),
    };

    fn lock_dir(root: &TempDir) -> PathBuf {
        root.path().join("nested").join("target.lock")
    }

    fn set_modified(dir: &Path, modified: SystemTime) {
        open_directory(dir)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
    }

    #[tokio::test]
    async fn acquire_creates_an_empty_lock_directory_and_drop_removes_it() {
        let root = TempDir::new().unwrap();
        let dir = lock_dir(&root);
        {
            let lock = acquire(&dir, QUICK).await.unwrap();
            assert!(dir.is_dir());
            assert_eq!(lock.dir(), dir);
            // Several heartbeats later the directory is still empty, so the
            // other program's `rmdir` can remove it if this process dies.
            tokio::time::sleep(QUICK.heartbeat * 4).await;
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        }
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn the_heartbeat_moves_the_mtime_of_a_lock_it_still_owns() {
        let root = TempDir::new().unwrap();
        let dir = lock_dir(&root);
        let lock = acquire(&dir, QUICK).await.unwrap();
        // Backdate the directory and record the backdated stamp as the
        // holder's own, so the heartbeat still recognises the lock.
        let old = SystemTime::now() - Duration::from_secs(600);
        {
            let mut held = lock.stamp.lock().unwrap();
            set_modified(&dir, old);
            *held = stamp_of(&dir).unwrap();
        }
        tokio::time::sleep(QUICK.heartbeat * 5).await;
        let modified = std::fs::metadata(&dir).unwrap().modified().unwrap();
        assert!(modified > old + Duration::from_secs(500));
        drop(lock);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn a_fresh_foreign_lock_is_waited_out_not_taken() {
        let root = TempDir::new().unwrap();
        let dir = lock_dir(&root);
        std::fs::create_dir_all(&dir).unwrap();

        let timing = Timing {
            timeout: Duration::from_millis(60),
            ..QUICK
        };
        let error = acquire(&dir, timing).await.unwrap_err();
        assert!(matches!(error, AcquireError::Contended), "{error:?}");
        assert!(dir.is_dir(), "a live holder's lock must survive");
    }

    #[test]
    fn the_blocking_variant_waits_out_a_live_lock_and_takes_an_abandoned_one() {
        let root = TempDir::new().unwrap();
        let dir = lock_dir(&root);
        std::fs::create_dir_all(&dir).unwrap();

        let short = Timing {
            timeout: Duration::from_millis(60),
            ..QUICK
        };
        assert!(matches!(
            acquire_blocking(&dir, short),
            Err(AcquireError::Contended)
        ));
        assert!(dir.is_dir());

        set_modified(&dir, SystemTime::now() - Duration::from_secs(7_200));
        let lock = acquire_blocking(&dir, QUICK).unwrap();
        assert!(dir.is_dir());
        drop(lock);
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn an_abandoned_lock_is_taken_even_with_files_inside() {
        let root = TempDir::new().unwrap();
        let dir = lock_dir(&root);
        std::fs::create_dir_all(&dir).unwrap();
        // What an older ai-usagebar left behind when it was killed.
        std::fs::write(dir.join(".ai-usagebar-owner"), b"old").unwrap();
        set_modified(&dir, SystemTime::now() - Duration::from_secs(7_200));

        let lock = acquire(&dir, QUICK).await.unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        drop(lock);
        assert!(!dir.exists());
    }

    /// Regression for #495: a holder delayed past `stale` resumes after
    /// another process took the lock over; dropping it must preserve the
    /// replacement, and its heartbeat must stop touching the foreign
    /// directory. Reproduction contributed with the issue.
    #[tokio::test]
    async fn dropping_previous_holder_preserves_replacement_lock() {
        let root = TempDir::new().unwrap();
        let dir = lock_dir(&root);
        let stale = Duration::from_secs(5);
        let timing = Timing { stale, ..QUICK };
        let first = acquire(&dir, timing).await.unwrap();

        set_modified(&dir, SystemTime::now() - stale - Duration::from_secs(1));

        let replacement = acquire(&dir, timing).await.unwrap();
        assert!(dir.is_dir());

        // Give the original holder several heartbeats to notice the
        // replacement before releasing it. This does not restore ownership.
        tokio::time::sleep(timing.heartbeat * 5).await;
        drop(first);

        assert!(dir.is_dir(), "old holder removed replacement holder's lock");
        {
            // Holding the stamp's mutex keeps the replacement's heartbeat
            // from moving the mtime between the two reads.
            let held = replacement.stamp.lock().unwrap();
            assert_eq!(
                stamp_of(&dir),
                Some(*held),
                "the directory must still carry the replacement's own stamp"
            );
        }
        drop(replacement);
        assert!(!dir.exists());
    }
}
