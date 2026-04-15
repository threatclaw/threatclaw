//! Build script: compile Telegram channel WASM from source.
//!
//! Do not commit compiled WASM binaries — they are a supply chain risk.
//! This script builds telegram.wasm from channels-src/telegram before the main crate compiles.
//!
//! Reproducible build:
//!   cargo build --release
//! (build.rs invokes the channel build automatically)
//!
//! Prerequisites: rustup target add wasm32-wasip2, cargo install wasm-tools

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = PathBuf::from(&manifest_dir);

    // ── Generate BUILD_ID (version + date + git hash) ─────────────────
    generate_build_id(&root);

    // ── Compute AGENT_SOUL.toml hash (Pilier I — immuable) ──────────────
    compute_soul_hash(&root);

    // ── Embed registry manifests ────────────────────────────────────────
    embed_registry_catalog(&root);

    // ── Build Telegram channel WASM ─────────────────────────────────────
    let channel_dir = root.join("channels-src/telegram");
    let wasm_out = channel_dir.join("telegram.wasm");

    // Rerun when channel source or build script changes
    println!("cargo:rerun-if-changed=channels-src/telegram/src");
    println!("cargo:rerun-if-changed=channels-src/telegram/Cargo.toml");
    println!("cargo:rerun-if-changed=wit/channel.wit");

    if !channel_dir.is_dir() {
        return;
    }

    // Build WASM module
    let status = match Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            "wasm32-wasip2",
            "--manifest-path",
            channel_dir.join("Cargo.toml").to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
    {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "cargo:warning=Telegram channel build failed. Run: ./channels-src/telegram/build.sh"
            );
            return;
        }
    };

    if !status.success() {
        eprintln!(
            "cargo:warning=Telegram channel build failed. Run: ./channels-src/telegram/build.sh"
        );
        return;
    }

    let raw_wasm = channel_dir.join("target/wasm32-wasip2/release/telegram_channel.wasm");
    if !raw_wasm.exists() {
        eprintln!(
            "cargo:warning=Telegram WASM output not found at {:?}",
            raw_wasm
        );
        return;
    }

    // Convert to component and strip (wasm-tools)
    let component_ok = Command::new("wasm-tools")
        .args([
            "component",
            "new",
            raw_wasm.to_str().unwrap(),
            "-o",
            wasm_out.to_str().unwrap(),
        ])
        .current_dir(&root)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !component_ok {
        // Fallback: copy raw module if wasm-tools unavailable
        if std::fs::copy(&raw_wasm, &wasm_out).is_err() {
            eprintln!("cargo:warning=wasm-tools not found. Run: cargo install wasm-tools");
        }
    } else {
        // Strip debug info (use temp file to avoid clobbering)
        let stripped = wasm_out.with_extension("wasm.stripped");
        let strip_ok = Command::new("wasm-tools")
            .args([
                "strip",
                wasm_out.to_str().unwrap(),
                "-o",
                stripped.to_str().unwrap(),
            ])
            .current_dir(&root)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if strip_ok {
            let _ = std::fs::rename(&stripped, &wasm_out);
        }
    }
}

/// Collect all registry manifests into a single JSON blob at compile time.
///
/// Output: `$OUT_DIR/embedded_catalog.json` with structure:
/// ```json
/// { "tools": [...], "channels": [...], "bundles": {...} }
/// ```
fn embed_registry_catalog(root: &Path) {
    use std::fs;

    let registry_dir = root.join("registry");

    // Rerun if the bundles file changes (per-file watches for tools/channels
    // are emitted inside collect_json_files to track content changes reliably).
    println!("cargo:rerun-if-changed=registry/_bundles.json");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let out_path = out_dir.join("embedded_catalog.json");

    if !registry_dir.is_dir() {
        // No registry dir: write empty catalog
        fs::write(
            &out_path,
            r#"{"tools":[],"channels":[],"mcp_servers":[],"bundles":{"bundles":{}}}"#,
        )
        .unwrap();
        return;
    }

    let mut tools = Vec::new();
    let mut channels = Vec::new();
    let mut mcp_servers = Vec::new();

    // Collect tool manifests
    let tools_dir = registry_dir.join("tools");
    if tools_dir.is_dir() {
        collect_json_files(&tools_dir, &mut tools);
    }

    // Collect channel manifests
    let channels_dir = registry_dir.join("channels");
    if channels_dir.is_dir() {
        collect_json_files(&channels_dir, &mut channels);
    }

    // Collect MCP server manifests
    let mcp_servers_dir = registry_dir.join("mcp-servers");
    if mcp_servers_dir.is_dir() {
        collect_json_files(&mcp_servers_dir, &mut mcp_servers);
    }

    // Read bundles
    let bundles_path = registry_dir.join("_bundles.json");
    let bundles_raw = if bundles_path.is_file() {
        fs::read_to_string(&bundles_path).unwrap_or_else(|_| r#"{"bundles":{}}"#.to_string())
    } else {
        r#"{"bundles":{}}"#.to_string()
    };

    // Build the combined JSON
    let catalog = format!(
        r#"{{"tools":[{}],"channels":[{}],"mcp_servers":[{}],"bundles":{}}}"#,
        tools.join(","),
        channels.join(","),
        mcp_servers.join(","),
        bundles_raw,
    );

    fs::write(&out_path, catalog).unwrap();
}

/// Compute SHA-256 hash of AGENT_SOUL.toml and write it to OUT_DIR/soul_hash.txt.
/// The hash is included at compile time via include_str! in soul.rs.
fn compute_soul_hash(root: &Path) {
    use sha2::{Digest, Sha256};
    use std::fs;

    let soul_path = root.join("AGENT_SOUL.toml");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let hash_path = out_dir.join("soul_hash.txt");

    println!("cargo:rerun-if-changed=AGENT_SOUL.toml");

    if soul_path.is_file() {
        let content = fs::read(&soul_path).expect("Failed to read AGENT_SOUL.toml");
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = format!("{:x}", hasher.finalize());
        fs::write(&hash_path, &hash).expect("Failed to write soul_hash.txt");
    } else {
        // No soul file: write empty hash (agent will refuse to start)
        fs::write(&hash_path, "NO_SOUL_FILE").expect("Failed to write soul_hash.txt");
    }
}

/// Read all .json files from a directory and push their raw contents into `out`.
fn collect_json_files(dir: &Path, out: &mut Vec<String>) {
    use std::fs;

    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().is_file() && e.path().extension().and_then(|x| x.to_str()) == Some("json")
        })
        .collect();

    // Sort for deterministic output
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        // Emit per-file watch so Cargo reruns when file contents change
        println!("cargo:rerun-if-changed={}", entry.path().display());
        if let Ok(content) = fs::read_to_string(entry.path()) {
            out.push(content);
        }
    }
}

/// Generate a unique BUILD_ID combining version + date + git hash.
/// Accessible in code via: env!("TC_BUILD_ID")
fn generate_build_id(_root: &Path) {
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());

    // Build date (UTC)
    let date = Command::new("date")
        .args(["+%Y%m%d"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());

    // Git short hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "nogit".into());

    // Git dirty flag
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| if o.stdout.is_empty() { "" } else { "-dirty" })
        .unwrap_or("");

    let build_id = format!("{}-{}-{}{}", version, date, git_hash, dirty);

    println!("cargo:rustc-env=TC_BUILD_ID={}", build_id);
    println!("cargo:rustc-env=TC_BUILD_DATE={}", date);
    println!("cargo:rustc-env=TC_BUILD_GIT={}{}", git_hash, dirty);

    // Rerun on git changes
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
}
