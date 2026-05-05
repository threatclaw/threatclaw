//! Implémentation `EdrSkill` pour Velociraptor.
//!
//! Velociraptor expose ses données via VQL (Velociraptor Query Language).
//! Pour le contexte processus/réseau, on lance des artefacts standards
//! (pslist, netstat) ou des collections déjà ingérées en DB.
//!
//! Cette implémentation est **stub-friendly** : si les credentials ou les
//! collections ne sont pas configurés, elle retourne un ProcessContext vide
//! plutôt que de crasher. C'est cohérent avec le pattern opportuniste des
//! autres skills.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::agent::skills::edr::{
    EdrError, EdrEvent, EdrSkill, NetworkConnection, ProcessContext, ProcessRecord,
};
use crate::db::Database;

/// Configuration runtime de l'instance Velociraptor connectée chez le client.
pub struct VelociraptorEdrSkill {
    pub url: String,
    pub api_cert_pem: Option<String>,
    pub api_key_pem: Option<String>,
    pub ca_pem: Option<String>,
    pub username: Option<String>,
}

#[async_trait]
impl EdrSkill for VelociraptorEdrSkill {
    fn skill_id(&self) -> &'static str {
        "skill-velociraptor"
    }

    async fn get_process_context(
        &self,
        store: &dyn Database,
        asset: &str,
        timestamp: DateTime<Utc>,
    ) -> Result<ProcessContext, EdrError> {
        // Vérification config minimale avant d'appeler le connector gRPC.
        if self.api_cert_pem.is_none() {
            return Err(EdrError::NotConfigured);
        }

        // VQL pour résoudre le client_id à partir du hostname/asset.
        let resolve_vql = format!(
            "SELECT * FROM clients(search='host:{}') LIMIT 1",
            escape_vql(asset)
        );
        let resolve = crate::connectors::velociraptor::tool_query(store, &resolve_vql)
            .await
            .map_err(|e| EdrError::Network(e))?;

        let client_id = extract_client_id(&resolve).ok_or_else(|| {
            EdrError::Other(format!("no Velociraptor client matches asset '{asset}'"))
        })?;

        let pslist_vql = format!(
            "SELECT Pid, Name, CommandLine, Ppid, Username, CreateTime FROM \
             collect_client(client_id='{}', artifacts=['Generic.Client.Stats'])",
            escape_vql(&client_id)
        );
        let pslist_raw = crate::connectors::velociraptor::tool_query(store, &pslist_vql)
            .await
            .ok();
        let processes = pslist_raw
            .as_ref()
            .and_then(parse_processes)
            .unwrap_or_default();

        let netstat_vql = format!(
            "SELECT Laddr.IP AS local_ip, Laddr.Port AS local_port, \
                    Raddr.IP AS remote_ip, Raddr.Port AS remote_port, \
                    Type AS proto, Status AS state, Pid \
             FROM netstat(client_id='{}')",
            escape_vql(&client_id)
        );
        let netstat_raw = crate::connectors::velociraptor::tool_query(store, &netstat_vql)
            .await
            .ok();
        let network_connections = netstat_raw
            .as_ref()
            .and_then(parse_network_connections)
            .unwrap_or_default();

        let events: Vec<EdrEvent> = vec![];
        let _ = timestamp;

        Ok(ProcessContext {
            processes,
            network_connections,
            events,
            source_skill: self.skill_id().to_string(),
        })
    }
}

fn escape_vql(s: &str) -> String {
    // VQL strings utilisent `'` comme délimiteur ; on échappe les apostrophes.
    s.replace('\'', "\\'")
}

fn extract_client_id(resolve: &serde_json::Value) -> Option<String> {
    // `tool_query` retourne typiquement {"rows": [...]} ou un array direct
    let rows = resolve["rows"].as_array().or_else(|| resolve.as_array())?;
    let first = rows.first()?;
    first["client_id"]
        .as_str()
        .or_else(|| first["ClientId"].as_str())
        .map(String::from)
}

fn parse_processes(v: &serde_json::Value) -> Option<Vec<ProcessRecord>> {
    let rows = v["rows"].as_array().or_else(|| v.as_array())?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let pid = r["Pid"].as_u64().and_then(|n| u32::try_from(n).ok())?;
        let name = r["Name"].as_str()?.to_string();
        out.push(ProcessRecord {
            pid,
            name,
            cmdline: r["CommandLine"].as_str().map(String::from),
            parent_pid: r["Ppid"].as_u64().and_then(|n| u32::try_from(n).ok()),
            user: r["Username"].as_str().map(String::from),
            start_time: r["CreateTime"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc)),
        });
    }
    Some(out)
}

fn parse_network_connections(v: &serde_json::Value) -> Option<Vec<NetworkConnection>> {
    let rows = v["rows"].as_array().or_else(|| v.as_array())?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let local_ip = r["local_ip"].as_str()?.to_string();
        let remote_ip = r["remote_ip"].as_str().unwrap_or("").to_string();
        let local_port = r["local_port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())?;
        let remote_port = r["remote_port"]
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .unwrap_or(0);
        out.push(NetworkConnection {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            proto: r["proto"].as_str().unwrap_or("").to_string(),
            state: r["state"].as_str().map(String::from),
            pid: r["Pid"].as_u64().and_then(|n| u32::try_from(n).ok()),
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_client_id_from_rows_wrapped() {
        let v = json!({"rows": [{"client_id": "C.abc123", "hostname": "srv-01"}]});
        assert_eq!(extract_client_id(&v).as_deref(), Some("C.abc123"));
    }

    #[test]
    fn extract_client_id_from_bare_array() {
        let v = json!([{"ClientId": "C.xyz", "Hostname": "srv-02"}]);
        assert_eq!(extract_client_id(&v).as_deref(), Some("C.xyz"));
    }

    #[test]
    fn parse_processes_basic() {
        let v = json!({"rows": [
            {"Pid": 1234, "Name": "explorer.exe", "CommandLine": "explorer.exe /e", "Ppid": 100, "Username": "alice"},
            {"Pid": 5678, "Name": "firefox.exe", "Ppid": 1234},
        ]});
        let procs = parse_processes(&v).unwrap();
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 1234);
        assert_eq!(procs[0].name, "explorer.exe");
        assert_eq!(procs[0].user.as_deref(), Some("alice"));
        assert_eq!(procs[1].parent_pid, Some(1234));
    }

    #[test]
    fn parse_netstat_basic() {
        let v = json!({"rows": [
            {"local_ip": "10.0.0.10", "local_port": 51078, "remote_ip": "14.102.231.203", "remote_port": 80, "proto": "TCP", "state": "ESTABLISHED", "Pid": 4444}
        ]});
        let conns = parse_network_connections(&v).unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].local_ip, "10.0.0.10");
        assert_eq!(conns[0].remote_ip, "14.102.231.203");
        assert_eq!(conns[0].remote_port, 80);
        assert_eq!(conns[0].proto, "TCP");
        assert_eq!(conns[0].pid, Some(4444));
    }

    #[test]
    fn escape_vql_quotes() {
        assert_eq!(escape_vql("foo'bar"), "foo\\'bar");
    }
}
