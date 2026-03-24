//! Connectors — integrate with existing client infrastructure.
//!
//! Each connector speaks to a specific tool the client already has
//! (Active Directory, pfSense, Proxmox, etc.) and feeds discovered
//! assets/users into the ThreatClaw graph via the Asset Resolution Pipeline.

pub mod active_directory;
pub mod docker_executor;
pub mod nmap_discovery;
pub mod pfsense;
pub mod proxmox;
pub mod remediation;
