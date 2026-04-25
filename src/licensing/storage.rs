//! On-disk persistence for licensing state.
//!
//! Layout under `~/.threatclaw/licensing/`:
//!
//! ```text
//! install_id      Stable UUID v4, generated once at first activation.
//!                 Persists across restarts, regenerated on a fresh install.
//! state.json      Active license_key + activation metadata. Written
//!                 atomically (tmp + rename) so a crash never leaves a
//!                 truncated file. Empty/missing = no license configured.
//! cert.tcl        Current signed license certificate, base64. Mirrors
//!                 the `state.json` and is the source of truth for the
//!                 [`super::PremiumGate`] at process boot.
//! ```
//!
//! Files are owner-only readable (mode 0600 on Unix). The directory is
//! created lazily on first write — read paths tolerate its absence so a
//! pristine install never trips on a missing directory.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::bootstrap::threatclaw_base_dir;

const LICENSING_SUBDIR: &str = "licensing";
const INSTALL_ID_FILE: &str = "install_id";
const STATE_FILE: &str = "state.json";
const CERT_FILE: &str = "cert.tcl";

#[cfg(test)]
thread_local! {
    /// Per-thread override for the base dir, used only by tests. The
    /// real `threatclaw_base_dir()` is a process-wide `LazyLock` that
    /// cannot be redirected at runtime; this thread-local lets each
    /// test sandbox itself in its own tmp dir without coordinating
    /// with other parallel tests.
    static TEST_BASE_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn current_base_dir() -> PathBuf {
    TEST_BASE_DIR.with(|d| d.borrow().clone()).unwrap_or_else(threatclaw_base_dir)
}

#[cfg(not(test))]
#[inline]
fn current_base_dir() -> PathBuf {
    threatclaw_base_dir()
}

/// Returns the licensing data directory, creating it if it does not exist.
/// Sets owner-only permissions (0700) on Unix.
pub fn licensing_dir() -> io::Result<PathBuf> {
    licensing_dir_under(&current_base_dir())
}

/// Same as [`licensing_dir`] but rooted at an explicit base directory.
/// Used by tests that need full filesystem isolation, since the public
/// `threatclaw_base_dir()` caches its result via `LazyLock` and cannot
/// be redirected at test runtime.
pub fn licensing_dir_under(base: &Path) -> io::Result<PathBuf> {
    let dir = base.join(LICENSING_SUBDIR);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        set_owner_only_dir(&dir)?;
    }
    Ok(dir)
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn set_owner_only_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Atomically write a file by going through a sibling tmp file + rename.
/// Crash-safe: a reader will either see the previous contents or the new
/// ones, never a partial write.
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;
    set_owner_only_dir(parent).ok(); // best-effort, dir might pre-exist with looser perms

    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("licensing")
    ));
    fs::write(&tmp, bytes)?;
    set_owner_only_file(&tmp).ok();
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Read or generate the install id. Stable across restarts.
///
/// The install id is the only piece of identity strictly required to
/// activate a license. It is a random UUID v4 — not derived from machine
/// hardware — so OS reinstalls or container rebuilds get a fresh id, which
/// is the desired behavior (re-activation against the license server).
pub fn load_or_create_install_id() -> io::Result<String> {
    let dir = licensing_dir()?;
    let path = dir.join(INSTALL_ID_FILE);

    if let Ok(contents) = fs::read_to_string(&path) {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    atomic_write(&path, id.as_bytes())?;
    set_owner_only_file(&path).ok();
    Ok(id)
}

/// Snapshot of the licensing state persisted between runs.
///
/// `cert.tcl` (the signed cert) is stored separately to keep the JSON
/// readable for support diagnostics — it contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicensingState {
    /// Master license key (e.g. `TC-AP24-X7K9-M2P4-VN5R`). Empty when
    /// the install runs only AGPL skills.
    #[serde(default)]
    pub license_key: String,
    /// UNIX seconds of the last successful activation/heartbeat against
    /// the license server. Zero if never reached.
    #[serde(default)]
    pub last_heartbeat: u64,
    /// UNIX seconds of the last attempted heartbeat (success or fail).
    #[serde(default)]
    pub last_attempt: u64,
    /// Whether this install previously consumed its 60-day trial. Set by
    /// the server response, persisted to discourage repeated trial loops
    /// after manual `state.json` resets — defense in depth, not the main
    /// anti-abuse mechanism (server is authoritative).
    #[serde(default)]
    pub trial_consumed: bool,
}

impl LicensingState {
    pub fn has_license(&self) -> bool {
        !self.license_key.is_empty()
    }
}

/// Read the persisted licensing state. Returns `Default::default()` if
/// the file does not exist (pristine install).
pub fn read_state() -> io::Result<LicensingState> {
    let path = licensing_dir()?.join(STATE_FILE);
    match fs::read(&path) {
        Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        _ => Ok(LicensingState::default()),
    }
}

pub fn write_state(state: &LicensingState) -> io::Result<()> {
    let path = licensing_dir()?.join(STATE_FILE);
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(&path, &bytes)?;
    set_owner_only_file(&path).ok();
    Ok(())
}

/// Read the current signed cert (base64 `.tcl` envelope), if any.
pub fn read_cert() -> io::Result<Option<String>> {
    let path = licensing_dir()?.join(CERT_FILE);
    match fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn write_cert(encoded: &str) -> io::Result<()> {
    let path = licensing_dir()?.join(CERT_FILE);
    atomic_write(&path, encoded.as_bytes())?;
    set_owner_only_file(&path).ok();
    Ok(())
}

/// Wipe the cert + state files. Used by `tc license deactivate` after a
/// successful server-side deactivation.
pub fn clear_all() -> io::Result<()> {
    let dir = licensing_dir()?;
    for name in [STATE_FILE, CERT_FILE] {
        let p = dir.join(name);
        match fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-test sandbox: redirects [`current_base_dir`] to a fresh tmp
    /// directory via the test-only `TEST_BASE_DIR` thread-local. Each
    /// test thread gets its own override, so parallel tests do not
    /// interfere.
    struct Sandbox {
        _tmp: tempfile::TempDir,
    }

    impl Sandbox {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            TEST_BASE_DIR.with(|d| *d.borrow_mut() = Some(tmp.path().to_path_buf()));
            Self { _tmp: tmp }
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            TEST_BASE_DIR.with(|d| *d.borrow_mut() = None);
        }
    }

    #[test]
    fn install_id_persists_across_calls() {
        let _h = Sandbox::new();
        let a = load_or_create_install_id().unwrap();
        let b = load_or_create_install_id().unwrap();
        assert_eq!(a, b, "install_id must be stable once written");
        assert!(uuid::Uuid::parse_str(&a).is_ok(), "must be a valid UUID");
    }

    #[test]
    fn state_roundtrip() {
        let _h = Sandbox::new();
        assert!(!read_state().unwrap().has_license());

        let s = LicensingState {
            license_key: "TC-AP24-XXXX".into(),
            last_heartbeat: 1_700_000_000,
            last_attempt: 1_700_000_000,
            trial_consumed: true,
        };
        write_state(&s).unwrap();
        let back = read_state().unwrap();
        assert_eq!(back.license_key, s.license_key);
        assert_eq!(back.last_heartbeat, s.last_heartbeat);
        assert!(back.trial_consumed);
    }

    #[test]
    fn cert_roundtrip_and_clear() {
        let _h = Sandbox::new();
        assert!(read_cert().unwrap().is_none());
        write_cert("base64content==").unwrap();
        assert_eq!(read_cert().unwrap().as_deref(), Some("base64content=="));

        // Persist a state alongside, then clear everything.
        write_state(&LicensingState {
            license_key: "TC-1".into(),
            ..Default::default()
        })
        .unwrap();
        clear_all().unwrap();
        assert!(read_cert().unwrap().is_none());
        assert!(!read_state().unwrap().has_license());
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let _h = Sandbox::new();
        write_state(&LicensingState {
            license_key: "TC-X".into(),
            ..Default::default()
        })
        .unwrap();
        let perms = fs::metadata(licensing_dir().unwrap().join(STATE_FILE))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
