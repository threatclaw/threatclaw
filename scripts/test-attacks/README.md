# Attack Scenario Harness

Runs known attacks from DEV against the TARS lab (OpenCanary honeypots +
exposed services), then polls the ThreatClaw API on CASE staging to verify
that each attack produced the expected `sigma_alert`.

**Pipeline green ≠ detection working.** These scripts close that gap: they
go through every link — network hit → Wazuh agent → Wazuh manager → indexer
→ TC connector → sigma_alerts — with a real attack payload, in under 10 min.

## Usage

```bash
# Run the full suite (6 scenarios, ~8 min total)
./scripts/test-attacks/run.sh

# Run a single scenario
./scripts/test-attacks/run.sh mssql_brute
```

Exits 0 if every scenario confirmed detection, non-zero otherwise. Intended
to be wired into `.forgejo/workflows/` as a nightly job so staging health
includes real-detection coverage, not just API-up smoke tests.

## Scenarios

Each scenario targets one OpenCanary emulator that we have validated
end-to-end: probe → Wazuh agent on TARS → Wazuh manager on CASE →
ThreatClaw sigma_alert. All six pass cleanly in ~90 s each.

| id | attack | target | expected rule_id | MITRE |
|---|---|---|---|---|
| `mssql_brute`   | raw TCP pre-login  | tars:1433 (OpenCanary MSSQL) | wazuh-100701 | T1110 |
| `ssh_canary`    | ssh banner fetch   | tars:2223 (OpenCanary SSH)   | wazuh-100702 | T1110 |
| `mysql_canary`  | MySQL handshake    | tars:3306 (OpenCanary MySQL) | wazuh-100703 | T1110 |
| `ftp_canary`    | curl ftp://        | tars:21 (OpenCanary FTP)     | wazuh-100705 | T1110 |
| `telnet_canary` | telnet login prompt| tars:23 (OpenCanary Telnet)  | wazuh-100704 | T1110 |
| `port_scan`     | SNMP v1 GET public | tars:161 (OpenCanary SNMP)   | wazuh-100707 | T1046 |

**Removed during 1.0.10 iteration**:

- `smb_canary` — thinkst/opencanary's SMB module emulates via a Samba
  server auth log, not a listening TCP service. TARS would need to run
  Samba for this scenario to work. Out of scope for the lab.
- `ssh_target_brute` — the linuxserver/openssh-server container on :2222
  logs authentication to stdout only; the Wazuh host agent cannot tail
  docker json logs. Not a ThreatClaw bug; the existing `ssh_canary`
  scenario already covers the SSH detection path.

## How a scenario works

1. Snapshot the `sigma_alerts` count for `rule_id=<expected>` and
   `source_ip=<my egress IP>` via `/api/tc/alerts/counts`.
2. Run the attack from DEV.
3. Wait up to 5 min (Wazuh agent collector + manager rules + TC sync cycle).
4. Re-query the count. Pass if it grew, fail otherwise.

The scripts never rely on any state local to TARS/CASE — only the TC HTTP
API. Missing curl/nmap/hydra on DEV triggers an explicit install hint,
never a silent skip.
