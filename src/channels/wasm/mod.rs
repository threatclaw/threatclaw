//! WASM channel runtime. See ADR-013.
//!
//! # Example Usage
//!
//! ```ignore
//! use threatclaw::channels::wasm::{WasmChannelLoader, WasmChannelRuntime};
//!
//! // Create runtime (can share engine with tool runtime)
//! let runtime = WasmChannelRuntime::new(config)?;
//!
//! // Load channels from directory
//! let loader = WasmChannelLoader::new(runtime, pairing_store, settings_store, owner_scope_id);
//! let channels = loader.load_from_dir(Path::new("~/.threatclaw/channels/")).await?;
//!
//! // Add to channel manager
//! for channel in channels {
//!     manager.add(Box::new(channel));
//! }
//! ```

mod bundled;
mod capabilities;
mod error;
mod host;
mod loader;
mod router;
mod runtime;
mod schema;
pub mod setup;
pub(crate) mod signature;
#[allow(dead_code)]
pub(crate) mod storage;
mod telegram_host_config;
mod wrapper;

// Core types
pub use bundled::{available_channel_names, bundled_channel_names, install_bundled_channel};
pub use capabilities::{ChannelCapabilities, EmitRateLimitConfig, HttpEndpointConfig, PollConfig};
pub use error::WasmChannelError;
pub use host::{ChannelEmitRateLimiter, ChannelHostState, EmittedMessage};
pub use loader::{
    DiscoveredChannel, LoadResults, LoadedChannel, WasmChannelLoader, default_channels_dir,
    discover_channels,
};
pub use router::{RegisteredEndpoint, WasmChannelRouter, create_wasm_channel_router};
pub use runtime::{PreparedChannelModule, WasmChannelRuntime, WasmChannelRuntimeConfig};
pub use schema::{
    ChannelCapabilitiesFile, ChannelConfig, SecretSetupSchema, SetupSchema, WebhookSchema,
};
pub use setup::{WasmChannelSetup, inject_channel_credentials, setup_wasm_channels};
pub(crate) use telegram_host_config::{TELEGRAM_CHANNEL_NAME, bot_username_setting_key};
pub use wrapper::{HttpResponse, SharedWasmChannel, WasmChannel};
