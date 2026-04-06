# ThreatClaw — Zeek package configuration
# Copy this file to your Zeek installation: /opt/zeek/share/zeek/site/local.zeek
# Or mount as volume in Docker: -v ./local.zeek:/opt/zeek/share/zeek/site/local.zeek
#
# Required packages (install once):
#   zkg install zeek/mitre-attack/bzar
#   zkg install salesforce/hassh
#   zkg install foxio/ja4
#   zkg install corelight/zeek-long-connections
#   zkg install jbaggs/anomalous-dns

# ── Standard Zeek protocol analyzers ──
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/smb
@load base/protocols/dce-rpc
@load base/protocols/krb

# ── Hash computation on all files (always on, no disk extraction needed) ──
@load frameworks/files/hash-all-files

# ── ThreatClaw NDR packages ──

# BZAR — MITRE ATT&CK lateral movement detection via SMB/DCE-RPC
# Detects: DCSync, svcctl exec, scheduled tasks, Event Log clearing, etc.
@load bzar

# HASSH — SSH client/server fingerprinting via KEXINIT
# Detects: Paramiko, Metasploit, PowerShell SSH, Dropbear (IoT botnets)
@load hassh

# JA4 — Next-gen TLS fingerprinting (immune to Chrome randomization)
# Replaces JA3 for browser fingerprinting while JA3 remains valid for C2
@load ja4

# Long connections — log active connections before termination
# Catches C2 sessions lasting hours/days that conn.log misses
@load zeek-long-connections
redef LongConnection::default_durations += { 30mins, 1hrs, 4hrs, 12hrs };

# Anomalous DNS — DNS tunneling, fast flux, C2 communication
@load anomalous-dns

# ── Optional: File extraction for Strelka scanning (Phase 2) ──
# Uncomment to extract suspicious file types to disk for malware scanning.
# Requires Strelka or ClamAV container watching the extract directory.
#
# @load base/files/extract-all-files
# redef FileExtract::prefix = "/opt/zeek/extracted/";
#
# event file_sniff(f: fa_file, meta: fa_metadata) {
#     local dominated_types = set(
#         "application/x-dosexec",
#         "application/x-executable",
#         "application/x-mach-o-executable",
#         "application/x-msdownload",
#         "application/msword",
#         "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
#         "application/vnd.ms-excel",
#         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
#         "application/pdf",
#         "application/zip",
#         "application/x-rar-compressed",
#         "application/x-7z-compressed",
#         "application/javascript",
#         "application/x-sh",
#         "application/x-powershell",
#         "application/hta"
#     );
#     if ( meta?$mime_type && meta$mime_type in dominated_types ) {
#         Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
#     }
# }
