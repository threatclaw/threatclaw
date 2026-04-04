//! WASM sandbox for untrusted tool execution. See ADR-013, ADR-014.
//!
//! # Example
//!
//! ```ignore
//! use threatclaw::tools::wasm::{WasmToolRuntime, WasmRuntimeConfig, WasmToolWrapper};
//! use threatclaw::tools::wasm::Capabilities;
//! use std::sync::Arc;
//!
//! // Create runtime
//! let runtime = Arc::new(WasmToolRuntime::new(WasmRuntimeConfig::default())?);
//!
//! // Prepare a tool from WASM bytes
//! let wasm_bytes = std::fs::read("my_tool.wasm")?;
//! let prepared = runtime.prepare("my_tool", &wasm_bytes, None).await?;
//!
//! // Create wrapper with HTTP capability
//! let capabilities = Capabilities::none()
//!     .with_http(HttpCapability::new(vec![
//!         EndpointPattern::host("api.openai.com").with_path_prefix("/v1/"),
//!     ]));
//! let tool = WasmToolWrapper::new(runtime, prepared, capabilities);
//!
//! // Execute (implements Tool trait)
//! let output = tool.execute(serde_json::json!({"input": "test"}), &ctx).await?;
//! ```

/// Host WIT version for tool extensions.
///
/// Extensions declaring a `wit_version` in their capabilities file are checked
/// against this at load time: same major, not greater than host.
pub const WIT_TOOL_VERSION: &str = "0.3.0";

/// Host WIT version for channel extensions.
pub const WIT_CHANNEL_VERSION: &str = "0.3.0";

mod allowlist;
mod capabilities;
mod capabilities_schema;
pub(crate) mod credential_injector;
mod error;
mod host;
mod limits;
pub(crate) mod loader;
mod rate_limiter;
mod runtime;
pub(crate) mod storage;
mod wrapper;

// Core types
pub use error::WasmError;
pub use host::{HostState, LogEntry, LogLevel};
pub use limits::{
    DEFAULT_FUEL_LIMIT, DEFAULT_MEMORY_LIMIT, DEFAULT_TIMEOUT, FuelConfig, ResourceLimits,
    WasmResourceLimiter,
};
pub use runtime::{PreparedModule, WasmRuntimeConfig, WasmToolRuntime, enable_compilation_cache};
pub use wrapper::{OAuthRefreshConfig, WasmToolWrapper};

// Capabilities (V2)
pub use capabilities::{
    Capabilities, EndpointPattern, HttpCapability, RateLimitConfig, SecretsCapability,
    ToolInvokeCapability, WebhookCapability, WorkspaceCapability, WorkspaceReader,
};

// Security components (V2)
pub use allowlist::{AllowlistResult, AllowlistValidator, DenyReason};
pub(crate) use credential_injector::inject_credential;
pub use credential_injector::{
    CredentialInjector, InjectedCredentials, InjectionError, SharedCredentialRegistry,
};
pub use rate_limiter::{LimitType, RateLimitError, RateLimitResult, RateLimiter};

// Storage (V2)
#[cfg(feature = "libsql")]
pub use storage::LibSqlWasmToolStore;
#[cfg(feature = "postgres")]
pub use storage::PostgresWasmToolStore;
pub use storage::{
    StoreToolParams, StoredCapabilities, StoredWasmTool, StoredWasmToolWithBinary, ToolStatus,
    TrustLevel, WasmStorageError, WasmToolStore, compute_binary_hash, verify_binary_integrity,
};

// Loader
pub use loader::{
    DiscoveredTool, LoadResults, WasmLoadError, WasmToolLoader, check_wit_version_compat,
    discover_dev_tools, discover_tools, load_dev_tools, resolve_wasm_target_dir,
    wasm_artifact_path,
};

// Capabilities schema (for parsing *.capabilities.json files)
pub use capabilities_schema::{
    AuthCapabilitySchema, CapabilitiesFile, OAuthConfigSchema, RateLimitSchema,
    ValidationEndpointSchema,
};
