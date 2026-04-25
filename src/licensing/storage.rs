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
const CERTS_SUBDIR: &str = "certs";
/// Legacy single-cert filename. Read once for migration to the new
/// `certs/{license_key}.tcl` layout, then deleted.
const LEGACY_CERT_FILE: &str = "cert.tcl";

/// Sub-directory holding one signed cert per active license.
fn certs_dir() -> io::Result<PathBuf> {
    let dir = licensing_dir()?.join(CERTS_SUBDIR);
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        set_owner_only_dir(&dir)?;
    }
    Ok(dir)
}

/// Sanitise a license key for use as a filename. Already strict format
/// (`TC-XXXX-XXXX-XXXX-XXXX`) — this is just defence in depth.
fn cert_filename(license_key: &str) -> String {
    let safe: String = license_key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(64)
        .collect();
    format!("{safe}.tcl")
}

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
    TEST_BASE_DIR
        .with(|d| d.borrow().clone())
        .unwrap_or_else(threatclaw_base_dir)
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

/// One row per active license_key on this install.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LicenseEntry {
    pub license_key: String,
    /// UNIX seconds of the last successful activation/heartbeat against
    /// the license server. Zero if never reached.
    #[serde(default)]
    pub last_heartbeat: u64,
    /// UNIX seconds of the last attempted heartbeat (success or fail).
    #[serde(default)]
    pub last_attempt: u64,
}

/// Snapshot of the licensing state persisted between runs.
///
/// Each `licenses[]` entry corresponds to a separate Stripe purchase.
/// A customer who later buys an additional skill receives a new
/// license_key and pastes it next to the first one.
///
/// Cert files (one per license) live in `licensing/certs/{key}.tcl`.
/// They are kept separate from `state.json` so the latter stays
/// human-readable for support diagnostics and contains no secret
/// material.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicensingState {
    #[serde(default)]
    pub licenses: Vec<LicenseEntry>,
    /// Whether this install previously consumed its 60-day trial. Set
    /// by the server response, persisted to discourage repeated trial
    /// loops after manual `state.json` resets — defense in depth, not
    /// the main anti-abuse mechanism (server is authoritative).
    #[serde(default)]
    pub trial_consumed: bool,
}

impl LicensingState {
    pub fn has_any_license(&self) -> bool {
        !self.licenses.is_empty()
    }

    pub fn find(&self, license_key: &str) -> Option<&LicenseEntry> {
        self.licenses.iter().find(|l| l.license_key == license_key)
    }

    pub fn find_mut(&mut self, license_key: &str) -> Option<&mut LicenseEntry> {
        self.licenses
            .iter_mut()
            .find(|l| l.license_key == license_key)
    }

    pub fn upsert(&mut self, license_key: &str, now: u64) -> &mut LicenseEntry {
        if self.find(license_key).is_none() {
            self.licenses.push(LicenseEntry {
                license_key: license_key.to_string(),
                last_heartbeat: now,
                last_attempt: now,
            });
        }
        self.find_mut(license_key).expect("just inserted")
    }

    pub fn remove(&mut self, license_key: &str) -> bool {
        let before = self.licenses.len();
        self.licenses.retain(|l| l.license_key != license_key);
        before != self.licenses.len()
    }
}

/// Legacy v0 layout (single license_key + cert.tcl). Kept around only
/// for the migration path inside [`read_state`].
#[derive(Debug, Deserialize, Default)]
struct LegacyLicensingState {
    #[serde(default)]
    license_key: String,
    #[serde(default)]
    last_heartbeat: u64,
    #[serde(default)]
    last_attempt: u64,
    #[serde(default)]
    trial_consumed: bool,
}

/// Read the persisted licensing state, migrating the v0 single-license
/// layout transparently if encountered.
pub fn read_state() -> io::Result<LicensingState> {
    let path = licensing_dir()?.join(STATE_FILE);
    let bytes = match fs::read(&path) {
        Ok(b) if !b.is_empty() => b,
        _ => return Ok(LicensingState::default()),
    };

    // Try the new format first.
    if let Ok(state) = serde_json::from_slice::<LicensingState>(&bytes) {
        if !state.licenses.is_empty() || !looks_like_legacy(&bytes) {
            return Ok(state);
        }
    }

    // Fall through to legacy parsing.
    let legacy: LegacyLicensingState = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut state = LicensingState {
        licenses: Vec::new(),
        trial_consumed: legacy.trial_consumed,
    };
    if !legacy.license_key.is_empty() {
        state.licenses.push(LicenseEntry {
            license_key: legacy.license_key.clone(),
            last_heartbeat: legacy.last_heartbeat,
            last_attempt: legacy.last_attempt,
        });
        // Migrate the cert.tcl file in place.
        if let Some(encoded) = read_legacy_cert()? {
            write_cert(&legacy.license_key, &encoded)?;
            remove_legacy_cert()?;
        }
    }
    write_state(&state)?;
    Ok(state)
}

fn looks_like_legacy(bytes: &[u8]) -> bool {
    // Cheap heuristic: the v0 schema has `license_key` at the top level
    // and no `licenses` array.
    let s = std::str::from_utf8(bytes).unwrap_or("");
    s.contains("\"license_key\"") && !s.contains("\"licenses\"")
}

pub fn write_state(state: &LicensingState) -> io::Result<()> {
    let path = licensing_dir()?.join(STATE_FILE);
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(&path, &bytes)?;
    set_owner_only_file(&path).ok();
    Ok(())
}

/// Read the signed cert for a specific license key, if any.
pub fn read_cert(license_key: &str) -> io::Result<Option<String>> {
    let path = certs_dir()?.join(cert_filename(license_key));
    match fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the signed cert for a specific license key.
pub fn write_cert(license_key: &str, encoded: &str) -> io::Result<()> {
    let path = certs_dir()?.join(cert_filename(license_key));
    atomic_write(&path, encoded.as_bytes())?;
    set_owner_only_file(&path).ok();
    Ok(())
}

/// Wipe the cert file for one license key (idempotent).
pub fn remove_cert(license_key: &str) -> io::Result<()> {
    let path = certs_dir()?.join(cert_filename(license_key));
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read all certs currently on disk. Returns `(license_key, encoded)`
/// pairs. Used by [`super::manager::LicenseManager::bootstrap`] to
/// rebuild every gate at process boot.
pub fn read_all_certs() -> io::Result<Vec<(String, String)>> {
    let dir = match certs_dir() {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };
    let entries = match fs::read_dir(&dir) {
        Ok(it) => it,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("tcl") {
            continue;
        }
        let key = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        if let Ok(encoded) = fs::read_to_string(&path) {
            let trimmed = encoded.trim();
            if !trimmed.is_empty() {
                out.push((key, trimmed.to_string()));
            }
        }
    }
    Ok(out)
}

/// Wipe state.json + every cert file. Use sparingly — usually
/// [`remove_cert`] + state mutation is what you want.
pub fn clear_all() -> io::Result<()> {
    let dir = licensing_dir()?;
    let _ = fs::remove_file(dir.join(STATE_FILE));
    if let Ok(certs) = certs_dir() {
        if let Ok(entries) = fs::read_dir(&certs) {
            for entry in entries.flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let _ = fs::remove_file(dir.join(LEGACY_CERT_FILE));
    Ok(())
}

fn read_legacy_cert() -> io::Result<Option<String>> {
    let path = licensing_dir()?.join(LEGACY_CERT_FILE);
    match fs::read_to_string(&path) {
        Ok(s) if !s.trim().is_empty() => Ok(Some(s)),
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn remove_legacy_cert() -> io::Result<()> {
    let path = licensing_dir()?.join(LEGACY_CERT_FILE);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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
    fn state_roundtrip_multi_license() {
        let _h = Sandbox::new();
        assert!(!read_state().unwrap().has_any_license());

        let s = LicensingState {
            licenses: vec![
                LicenseEntry {
                    license_key: "TC-AAAA-BBBB-CCCC-DDDD".into(),
                    last_heartbeat: 1_700_000_000,
                    last_attempt: 1_700_000_000,
                },
                LicenseEntry {
                    license_key: "TC-EEEE-FFFF-GGGG-HHHH".into(),
                    last_heartbeat: 1_700_000_500,
                    last_attempt: 1_700_000_500,
                },
            ],
            trial_consumed: true,
        };
        write_state(&s).unwrap();
        let back = read_state().unwrap();
        assert_eq!(back.licenses.len(), 2);
        assert!(back.find("TC-AAAA-BBBB-CCCC-DDDD").is_some());
        assert!(back.find("TC-EEEE-FFFF-GGGG-HHHH").is_some());
        assert!(back.trial_consumed);
    }

    #[test]
    fn state_helpers_upsert_remove_find() {
        let mut s = LicensingState::default();
        let now = 1_700_000_000;
        s.upsert("TC-1", now);
        s.upsert("TC-2", now + 10);
        assert_eq!(s.licenses.len(), 2);

        // Upserting an existing key should not duplicate.
        s.upsert("TC-1", now + 100);
        assert_eq!(s.licenses.len(), 2);

        assert!(s.remove("TC-1"));
        assert!(!s.remove("TC-1"));
        assert_eq!(s.licenses.len(), 1);
        assert!(s.find("TC-2").is_some());
    }

    #[test]
    fn cert_roundtrip_per_license() {
        let _h = Sandbox::new();
        let key = "TC-AAAA-BBBB-CCCC-DDDD";
        assert!(read_cert(key).unwrap().is_none());

        write_cert(key, "base64content==").unwrap();
        assert_eq!(read_cert(key).unwrap().as_deref(), Some("base64content=="));

        // A second cert for a different key lives alongside.
        let key2 = "TC-EEEE-FFFF-GGGG-HHHH";
        write_cert(key2, "second==").unwrap();
        assert_eq!(read_cert(key2).unwrap().as_deref(), Some("second=="));
        assert_eq!(read_cert(key).unwrap().as_deref(), Some("base64content=="));

        // read_all_certs returns both.
        let all = read_all_certs().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|(k, _)| k == key));
        assert!(all.iter().any(|(k, _)| k == key2));

        // remove_cert wipes only one.
        remove_cert(key).unwrap();
        assert!(read_cert(key).unwrap().is_none());
        assert!(read_cert(key2).unwrap().is_some());
    }

    #[test]
    fn legacy_state_migrates_on_first_read() {
        let _h = Sandbox::new();
        // Hand-write the v0 layout (single license_key + cert.tcl).
        let dir = licensing_dir().unwrap();
        let legacy_state = serde_json::json!({
            "license_key": "TC-LEGACY-AAAA-BBBB-CCCC",
            "last_heartbeat": 1_700_000_000_u64,
            "last_attempt": 1_700_000_000_u64,
            "trial_consumed": true
        });
        fs::write(
            dir.join(STATE_FILE),
            serde_json::to_vec(&legacy_state).unwrap(),
        )
        .unwrap();
        fs::write(dir.join(LEGACY_CERT_FILE), "legacycert==").unwrap();

        // Read should migrate transparently.
        let state = read_state().unwrap();
        assert_eq!(state.licenses.len(), 1);
        assert_eq!(state.licenses[0].license_key, "TC-LEGACY-AAAA-BBBB-CCCC");
        assert!(state.trial_consumed);

        // Cert should now live under certs/{key}.tcl.
        assert_eq!(
            read_cert("TC-LEGACY-AAAA-BBBB-CCCC").unwrap().as_deref(),
            Some("legacycert==")
        );
        // Legacy cert file should be gone.
        assert!(!dir.join(LEGACY_CERT_FILE).exists());
    }

    #[test]
    fn clear_all_wipes_state_and_certs() {
        let _h = Sandbox::new();
        write_cert("TC-1", "a").unwrap();
        write_cert("TC-2", "b").unwrap();
        write_state(&LicensingState {
            licenses: vec![LicenseEntry {
                license_key: "TC-1".into(),
                last_heartbeat: 0,
                last_attempt: 0,
            }],
            trial_consumed: false,
        })
        .unwrap();

        clear_all().unwrap();
        assert!(read_cert("TC-1").unwrap().is_none());
        assert!(read_cert("TC-2").unwrap().is_none());
        assert!(!read_state().unwrap().has_any_license());
    }

    #[cfg(unix)]
    #[test]
    fn state_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let _h = Sandbox::new();
        write_state(&LicensingState::default()).unwrap();
        let perms = fs::metadata(licensing_dir().unwrap().join(STATE_FILE))
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}
