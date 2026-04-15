//! Connectors — integrate with existing client infrastructure.
//!
//! Each connector speaks to a specific tool the client already has
//! (Active Directory, pfSense, Proxmox, etc.) and feeds discovered
//! assets/users into the ThreatClaw graph via the Asset Resolution Pipeline.

pub mod active_directory;
pub mod authentik;
pub mod cloudflare;
pub mod crowdsec;
pub mod defectdojo;
pub mod dfir_iris;
pub mod dhcp_parser;
pub mod docker_executor;
pub mod elastic_siem;
pub mod fortinet;
pub mod freebox;
pub mod glpi;
pub mod graylog;
pub mod keycloak;
pub mod mikrotik;
pub mod nmap_discovery;
pub mod olvid;
pub mod osquery;
pub mod pfsense;
pub mod pihole;
pub mod proxmox;
pub mod proxmox_backup;
pub mod remediation;
pub mod shuffle;
pub mod suricata;
pub mod sync_scheduler;
pub mod thehive;
pub mod unifi;
pub mod uptimerobot;
pub mod veeam;
pub mod wazuh;
pub mod webhook_ingest;
pub mod zeek;
