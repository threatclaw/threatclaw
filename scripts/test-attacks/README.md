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

| id | attack source | target | expected rule_id | MITRE |
|---|---|---|---|---|
| `mssql_brute` | tsql or nmap | tars:1433 (OpenCanary fake MSSQL) | wazuh-100701 | T1110 |
| `ssh_canary` | ssh | tars:2223 (OpenCanary SSH) | wazuh-100702 | T1110 |
| `smb_canary` | smbclient | tars:445 (OpenCanary SMB) | wazuh-100706 | T1021.002 |
| `port_scan` | nmap -sS | tars: broad | wazuh-100707 | T1046 |
| `ftp_canary` | curl ftp:// | tars:21 | wazuh-100705 | T1110 |
| `ssh_target_brute` | hydra | tars:2222 (real openssh-server) | wazuh-5716 | T1110 |

## How a scenario works

1. Snapshot the `sigma_alerts` count for `rule_id=<expected>` and
   `source_ip=<my egress IP>` via `/api/tc/alerts/counts`.
2. Run the attack from DEV.
3. Wait up to 5 min (Wazuh agent collector + manager rules + TC sync cycle).
4. Re-query the count. Pass if it grew, fail otherwise.

The scripts never rely on any state local to TARS/CASE — only the TC HTTP
API. Missing curl/nmap/hydra on DEV triggers an explicit install hint,
never a silent skip.
