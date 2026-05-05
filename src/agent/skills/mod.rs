//! Abstractions sur les skills connecteurs (firewall, SIEM, EDR) pour le
//! cross-skill enrichment opportuniste du dossier.
//!
//! Voir `internal/roadmap-mai.md` Phase 3 pour le design détaillé.
//!
//! ## Principe
//!
//! Le code IE/forensic ne doit pas savoir si le client a un OPNsense, un
//! Fortigate, un Mikrotik ou une autre équipement firewall. Il appelle un
//! `FirewallSkill` (trait) qui retourne la même structure peu importe le vendor.
//! Idem pour `SiemSkill` (Elastic, Graylog, Wazuh) et `EdrSkill` (Velociraptor,
//! CrowdStrike).
//!
//! Le `SkillRegistry` instancie les implémentations selon ce qui est
//! configuré dans `skill_configs` (enabled + credentials). Si rien n'est
//! configuré, le registry est vide pour cette catégorie — pas de plantage,
//! juste pas d'enrichissement pour ce déploiement.

pub mod edr;
pub mod elastic_siem;
pub mod firewall;
pub mod fortinet;
pub mod graylog;
pub mod mikrotik;
pub mod opnsense;
pub mod pfsense;
pub mod registry;
pub mod siem;
pub mod velociraptor;
pub mod wazuh;
