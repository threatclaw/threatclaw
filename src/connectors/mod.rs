//! Connectors — integrate with existing client infrastructure.
//!
//! Each connector speaks to a specific tool the client already has
//! (Active Directory, pfSense, Proxmox, etc.) and feeds discovered
//! assets/users into the ThreatClaw graph via the Asset Resolution Pipeline.

pub mod active_directory;
pub mod cloudflare;
pub mod freebox;
pub mod crowdsec;
pub mod defectdojo;
pub mod dhcp_parser;
pub mod docker_executor;
pub mod fortinet;
pub mod glpi;
pub mod nmap_discovery;
pub mod pfsense;
pub mod pihole;
pub mod suricata;
pub mod unifi;
pub mod zeek;
pub mod proxmox;
pub mod remediation;
pub mod uptimerobot;
pub mod wazuh;
pub mod sync_scheduler;
pub mod webhook_ingest;
