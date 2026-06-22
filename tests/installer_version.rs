//! Guard: the installer's pinned version must match the crate version.
//!
//! `installer/install.sh` hardcodes `TC_VERSION`, which also pins the git tag
//! its config files are fetched from (`REPO_RAW=.../v${TC_VERSION}`). A release
//! that bumps `Cargo.toml` but forgets the installer ships a banner with the
//! wrong version AND pulls config from a stale tag (exactly what happened across
//! 1.0.50/51/52). This test fails the build until both are back in sync, so the
//! drift cannot recur silently — bump `TC_VERSION` on every release.

#[test]
fn installer_version_matches_crate_version() {
    let installer = include_str!("../installer/install.sh");
    let crate_version = env!("CARGO_PKG_VERSION");
    let expected = format!("readonly TC_VERSION=\"{crate_version}\"");
    assert!(
        installer.contains(&expected),
        "installer/install.sh must declare `{expected}` to match Cargo.toml \
         version {crate_version}. Bump TC_VERSION in install.sh as part of the release."
    );
}
