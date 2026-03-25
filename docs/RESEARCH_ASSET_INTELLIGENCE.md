Now I have comprehensive data across all 7 topics. Let me compile the final research report.

---

# Comprehensive Research Report: Network Security, Asset Discovery & Behavioral Analysis

## 1. Asset Categorization in Cybersecurity

### How Enterprise Tools Categorize Assets

**Qualys Global AssetView** uses a multi-level taxonomy based on the UNSPSC (United Nations Standard Products and Services Code). Categories include Hardware, Software, Operating Systems, IoT, and OT. Their passive network sniffer discovers systems unsuited for agents -- IoT, medical, SCADA. AI normalizes and classifies assets into functional categories automatically.

**Armis** (now acquired by ServiceNow for $7.75B) passively monitors network traffic without agents, references a knowledgebase of 6.5+ billion asset profiles. It identifies OT devices by manufacturer/model and understands "normal" behavior. Covers IT, IoT, OT, IoMT (medical), and unmanaged personal devices.

**Darktrace** uses behavioral AI rather than static categories. Expanded ICS and IoMT device classification with broader industrial protocol coverage across manufacturing, energy, healthcare, IIoT.

**Forescout** automates discovery and classification of OT, IT, and IoT systems. Real-time monitoring detects deviations from established baselines.

**Claroty** specializes in OT/IoT with deep protocol understanding for ICS environments.

### Complete Asset Type Taxonomy (compiled from all sources)

**IT Assets:**
- Servers (physical, virtual)
- Workstations / Desktops / Laptops
- Mobile devices (phones, tablets)
- Printers / MFPs

**Network Infrastructure:**
- Switches, Routers, Firewalls
- Load balancers, WAFs
- WiFi access points / controllers
- VPN concentrators
- Packet brokers / TAPs

**Cloud Assets:**
- Virtual machines (EC2, Azure VM, GCE)
- Containers (Docker, Kubernetes pods)
- Serverless functions (Lambda, Cloud Functions)
- SaaS accounts (M365, Google Workspace)
- Cloud storage (S3 buckets, blob storage)
- Cloud databases (RDS, CosmosDB)

**OT/ICS Assets:**
- PLCs (Programmable Logic Controllers)
- RTUs (Remote Terminal Units)
- HMIs (Human-Machine Interfaces)
- DCS (Distributed Control Systems)
- SCADA master stations
- Engineering workstations
- Data historians
- Safety Instrumented Systems (SIS)
- Variable Frequency Drives (VFDs)
- Protection relays, circuit breakers (electricity)
- Pumps, valves, actuators (water/process)

**IoT Assets:**
- IP cameras / CCTV
- Smart TVs / digital signage
- Badge readers / access control
- Environmental sensors (temperature, humidity)
- Smart lighting / HVAC controllers
- Voice assistants / smart speakers

**Medical (IoMT):**
- Infusion pumps
- Patient monitors
- Imaging systems (MRI, CT, X-ray)
- Laboratory equipment
- Connected implants

**Vehicles / Logistics:**
- Connected fleet vehicles (GPS trackers, telematics)
- Autonomous vehicles
- Warehouse robots / AGVs

### CISA 2025 OT Taxonomy Guidance

CISA published "Foundations for OT Cybersecurity: Asset Inventory" (August 2025) with sector-specific taxonomies for Oil & Gas, Electricity, and Water/Wastewater. Two classification axes:
- **Criticality-based**: High (safety systems, primary control), Medium (processing, monitoring, communications), Low (auxiliary, peripheral)
- **Function-based**: grouped by role in OT environment

Key attributes to collect: protocols, criticality level, IP/MAC, manufacturer, model, OS, firmware version, physical location.

Sources:
- [CISA OT Asset Inventory Guidance](https://www.cisa.gov/resources-tools/resources/foundations-ot-cybersecurity-asset-inventory-guidance-owners-and-operators)
- [Qualys Global AssetView](https://www.qualys.com/apps/global-assetview)
- [Qualys Taxonomy Table](https://docs.qualys.com/en/gav/latest/Appendix/taxanomy_table.htm)
- [Armis Platform](https://www.armis.com/armis-platform/)
- [Darktrace OT Updates 2026](https://www.darktrace.com/blog/advancing-ot-security-with-architecture-visibility-operational-reporting-and-industrial-context)
- [Forescout vs Armis](https://www.forescout.com/compare/forescout-vs-armis/)
- [Elisity: CISA OT Guide Analysis](https://www.elisity.com/blog/ot-asset-inventory-cisas-2025-guide-to-modern-defensible-architecture)

---

## 2. Network Traffic Analysis Tools

### Zeek (formerly Bro)

- **URL**: https://zeek.org/
- **What it does**: Passive network monitor that produces structured metadata logs from traffic. NOT an IDS per se -- it extracts protocol-level metadata.
- **Output**: 70+ log file types, 3000+ event types. Default TSV, configurable to JSON with `@load policy/tuning/json-logs`. Key logs:
  - `conn.log`: every connection (src/dst IP, port, proto, service, duration, bytes, packets)
  - `dns.log`: all DNS queries/responses (query, qtype, rcode, answers, TTLs)
  - `dhcp.log`: DHCP transactions (MAC, assigned_ip, lease_time)
  - `ssl.log`: TLS handshakes (version, cipher, server_name, JA3/JA4)
  - `http.log`: HTTP requests (method, host, URI, user_agent, status_code)
  - `ssh.log`: SSH connections (version, auth attempts, HASSH)
  - `software.log`: detected software versions
  - `known_hosts.log`, `known_services.log`: discovered hosts/services
  - `x509.log`: certificate details
  - `files.log`: file transfers
- **API/Integration**: Read JSON log files directly. Integrates with Elastic, Splunk, Wazuh, Datadog. Zeek scripts can generate custom logs.
- **Resources**: ~1 CPU core per 250 Mbps of traffic. 1-2 GB RAM typical. Disk depends on log volume.
- **License**: BSD
- **ThreatClaw integration**: Read Zeek JSON logs from disk or via filebeat. Parse conn.log for network flows, dns.log for DNS enrichment, dhcp.log for MAC-to-IP mapping, ssl.log for JA3/JA4 fingerprints, software.log for asset inventory.

### Suricata

- **URL**: https://suricata.io/
- **What it does**: IDS/IPS + network monitoring. Signature-based detection AND protocol logging.
- **Output**: `eve.json` -- single JSON firehose with event types: alert, dns, http, tls, flow, fileinfo, anomaly, dhcp, smtp, ssh, stats. Configurable in `suricata.yaml`. Supports output to file, syslog, unix socket, or Redis.
- **API/Integration**: No built-in REST API. Output consumed via log files, Redis pub/sub, or unix socket. Integrates with Elastic, Splunk, Wazuh.
- **Resources**: ~1 CPU core per 200-500 Mbps. 2-4 GB RAM. Multi-threaded.
- **License**: GPL v2
- **ThreatClaw integration**: Parse eve.json for alerts and flow metadata. Can run alongside Zeek -- Suricata for signature alerts, Zeek for metadata. Suricata also does PCAP capture.

### ntopng

- **URL**: https://www.ntop.org/products/traffic-analysis/ntopng/ | [GitHub](https://github.com/ntop/ntopng)
- **What it does**: Web-based real-time network traffic monitoring. Handles 250+ L7 protocols. Captures via libpcap/PF_RING or ingests NetFlow/sFlow/IPFIX.
- **Output**: Web UI + **REST API (OpenAPI/Swagger)**. JSON responses.
- **API**: Full REST API with 3 endpoint categories: Interface, Host, Alert. Documented at `/lua/openapi.html` on the running instance. Can query hosts, flows, alerts, historical data.
- **Resources**: 2-4 GB RAM for small networks, scales with traffic. Moderate CPU.
- **License**: GPLv3 (Community Edition is fully open source). Enterprise/Professional editions exist.
- **ThreatClaw integration**: Query REST API for real-time host inventory, flow data, alerts. Excellent for SMB networks -- gives ThreatClaw live network visibility without heavy infrastructure.

### Arkime (formerly Moloch)

- **URL**: https://arkime.com/ | [GitHub](https://github.com/arkime/arkime)
- **What it does**: Full packet capture, indexing, and database system. Stores every packet in PCAP format with metadata indexed in OpenSearch/Elasticsearch.
- **Output**: PCAP files + JSON session metadata in Elasticsearch. REST API for session search and PCAP download.
- **API**: Full REST API for querying sessions, downloading PCAPs, accessing metadata. Node.js viewer per capture machine.
- **Resources**: HEAVY. Designed for tens of Gbps. Needs significant disk (stores all packets), Elasticsearch cluster. Not suitable for lightweight SMB deployment.
- **License**: Apache 2.0
- **ThreatClaw integration**: Query via Elasticsearch API for forensic investigations. Too heavy for default deployment -- recommend as optional "forensic mode" integration.

### p0f v3

- **URL**: https://lcamtuf.coredump.cx/p0f3/ | [GitHub mirror](https://github.com/skord/p0f)
- **What it does**: Purely passive OS fingerprinting from TCP/IP stack behavior. Identifies OS, browser, network distance, NAT detection without sending any traffic.
- **Output**: Log file or API socket. Provides: OS family/version, link type, distance, uptime, network sharing/NAT.
- **API**: Unix socket API for real-time queries by IP.
- **Resources**: Extremely lightweight. <50 MB RAM. Minimal CPU.
- **License**: LGPL v2.1
- **ThreatClaw integration**: Run p0f alongside ThreatClaw. Query socket API to get OS fingerprint for any observed IP. Excellent for passive asset inventory enrichment with near-zero overhead.

### PRADS (Passive Real-time Asset Detection System)

- **URL**: [GitHub](https://github.com/gamelinux/prads)
- **What it does**: Combined replacement for p0f + PADS + sancp. OS fingerprinting (SYN and SYN+ACK), TCP/UDP service fingerprinting, ARP discovery, MAC vendor lookup, ICMP fingerprinting.
- **Output**: Log file or FIFO. CSV-like format.
- **Resources**: Very lightweight.
- **License**: GPLv2
- **Status**: Last meaningful commits are older. AlienVault used PRADS from 2012 but the project appears mostly dormant. p0f v3 is more actively maintained for OS fingerprinting.
- **ThreatClaw integration**: Could parse output for asset discovery. However, p0f + Zeek together cover the same ground with more active maintenance.

### softflowd

- **URL**: Available in most Linux package repos
- **What it does**: Listens on an interface and generates NetFlow v1/v5/v9 data. Lightweight flow generator that exports to a collector.
- **Resources**: Very lightweight. <20 MB RAM.
- **License**: BSD
- **ThreatClaw integration**: Generate NetFlow from a SPAN port, send to nfcapd or ntopng for collection. Useful if the SMB's switches do not natively export NetFlow.

### nfdump/nfcapd

- **URL**: [GitHub](https://github.com/phaag/nfdump)
- **What it does**: nfcapd = NetFlow/IPFIX collector daemon. nfdump = query/analysis tool. Supports export to CSV, JSON, InfluxDB, Prometheus.
- **Resources**: Lightweight. Depends on flow volume.
- **License**: BSD
- **ThreatClaw integration**: Collect NetFlow with nfcapd, query with nfdump to JSON. Can feed flow data into ThreatClaw's behavioral analysis.

### PassiveDNS

- **URL**: [GitHub](https://github.com/gamelinux/passivedns) | Go version: [gopassivedns](https://github.com/Phillipmartin/gopassivedns)
- **What it does**: Sniffs DNS traffic passively, logs all DNS responses. Aggregates/deduplicates in memory.
- **Output**: Log file or JSON (Go version). Go version also supports Kafka output.
- **Resources**: Very lightweight.
- **License**: GPLv2 (C version), MIT (Go version)
- **ThreatClaw integration**: Collect DNS resolution history for all network assets. Useful for threat detection (DGA, C2 domains) and asset inventory (reverse DNS).

### DNSMonster

- **URL**: [GitHub](https://github.com/mosajjal/dnsmonster)
- **What it does**: High-performance passive DNS monitoring in Go. Accepts pcap, live interface, or dnstap. Can index hundreds of thousands of queries/sec.
- **Resources**: Moderate. Written in Go, efficient.
- **License**: MIT
- **ThreatClaw integration**: Modern alternative to PassiveDNS. Better performance, dnstap support. Feed into ThreatClaw for DNS-based threat detection.

### Security Onion (Integrated Suite)

- **URL**: https://securityonionsolutions.com/
- **What it does**: Pre-integrated suite of Zeek + Suricata + Elasticsearch + Kibana + Strelka (file analysis) + osquery. Turnkey network security monitoring.
- **Resources**: Heavy (minimum 4 cores, 16 GB RAM for evaluation; 12+ cores and 128 GB+ for production).
- **License**: GPLv2
- **ThreatClaw integration**: If an SMB already runs Security Onion, ThreatClaw can query its Elasticsearch instance for Zeek/Suricata data. Too heavy to deploy as part of ThreatClaw itself, but excellent as an upstream data source.

Sources:
- [Zeek Official](https://zeek.org/)
- [Zeek Log Files Reference](https://docs.zeek.org/en/master/script-reference/log-files.html)
- [Suricata EVE JSON Output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [ntopng GitHub](https://github.com/ntop/ntopng)
- [ntopng REST API (OpenAPI)](https://www.ntop.org/openapi-ntopng-rest-api-for-software-developers/)
- [Arkime GitHub](https://github.com/arkime/arkime)
- [p0f v3](https://lcamtuf.coredump.cx/p0f3/)
- [PRADS GitHub](https://github.com/gamelinux/prads)
- [nfdump GitHub](https://github.com/phaag/nfdump)
- [PassiveDNS GitHub](https://github.com/gamelinux/passivedns)
- [GoPassiveDNS GitHub](https://github.com/Phillipmartin/gopassivedns)
- [DNSMonster GitHub](https://github.com/FenkoHQ/dnsmonster)
- [Security Onion](https://securityonionsolutions.com/software/)

---

## 3. Asset Fingerprinting and Classification

### MAC OUI Database

- **IEEE OUI Database**: Authoritative source from IEEE Registration Authority (MA-L, MA-M, MA-S registries). Free download from IEEE.
- **Wireshark manuf file**: Maintained list, used by Wireshark OUI lookup tool. Available at https://www.wireshark.org/tools/oui-lookup.html
- **OUI-Master-Database**: [GitHub](https://github.com/Ringmast4r/OUI-Master-Database) -- consolidated 85,905+ vendors from IEEE, Nmap, and Wireshark.
- **Rust crate**: `mac_oui` on crates.io -- built-in OUI database, direct lookup. Also `oui` crate from [rs-oui](https://github.com/pwrdwnsys/rs-oui) using Wireshark manuf database.
- **Python library**: `manuf` -- reads entire Wireshark manuf file into memory for fast lookups. `pip install manuf`. Also `mac-vendor-lookup` on PyPI.
- **CSV download**: https://maclookup.app/downloads/csv-database -- 57,000+ prefixes.
- **ThreatClaw integration**: Embed the OUI database directly (the Rust `mac_oui` crate is ideal). Look up manufacturer from every discovered MAC address. Zero external API dependency.

### DHCP Fingerprinting -- Fingerbank

- **URL**: https://www.fingerbank.org/ | [API](https://api.fingerbank.org/) | [GitHub](https://github.com/karottc/fingerbank)
- **What it does**: Identifies devices from DHCP fingerprints (option 55 parameter request list), DHCP vendor strings, MAC OUI, HTTP User-Agents, and TLS ClientHello. 110K+ devices, 6M+ fingerprints.
- **API**: REST API at `api.fingerbank.org/api/v2/combinations/interrogate`. Free tier: 300 requests/hour with GitHub account. Send DHCP fingerprint + MAC + User-Agent, get back device type, OS, manufacturer.
- **Offline mode**: SQLite3 database available for download (a few GB). Local-first matching: queries hit local DB first, falls back to upstream API for unknown combinations.
- **License**: Open-source (GPL). Used by PacketFence (largest open-source NAC).
- **ThreatClaw integration**: Collect DHCP fingerprints from dhcpd logs or Zeek dhcp.log. Query Fingerbank API or use local SQLite DB to identify device types. This is THE key tool for automated device classification.

### JA3/JA4 TLS Fingerprinting

- **JA3**: [GitHub](https://github.com/salesforce/ja3) | Created by Salesforce. Hashes TLS ClientHello fields (version, ciphers, extensions, curves). BSD 3-Clause license. Widely supported but weakened by TLS extension randomization in modern browsers.
- **JA4+**: [GitHub](https://github.com/FoxIO-LLC/ja4) | Next-generation suite by FoxIO. Resists randomization. Includes:
  - **JA4**: TLS client fingerprint (BSD 3-Clause, fully open)
  - **JA4S**: TLS server fingerprint
  - **JA4H**: HTTP client fingerprint
  - **JA4L/JA4LS**: Latency measurement
  - **JA4X**: X.509 certificate fingerprint
  - **JA4SSH**: SSH traffic fingerprint
  - **JA4T/JA4TS**: TCP client/server fingerprint
  - **JA4D/JA4D6**: DHCP/DHCPv6 fingerprint
- **Supported in**: Zeek, Suricata, Wireshark, Arkime, AWS (CloudFront, WAF, ALB), Cloudflare, Google Cloud, F5, Palo Alto, Fortinet, Zscaler.
- **License**: JA4 (TLS client) is BSD 3-Clause. Others require OEM license for commercial products.
- **Implementations**: Python, Rust, C available in the repo.
- **ThreatClaw integration**: Enable JA4 in Zeek (built-in since Zeek 6.1). Read JA4 hashes from ssl.log. Build a database of known JA4 fingerprints per device type. Detect anomalies (e.g., a PLC suddenly using a browser-like JA4).

### HASSH -- SSH Fingerprinting

- **URL**: [GitHub](https://github.com/salesforce/hassh) | By Salesforce.
- **What it does**: Fingerprints SSH client and server implementations based on SSH key exchange init message. Produces a hash similar to JA3 for SSH.
- **Supported in**: Zeek (plugin), Suricata.
- **License**: BSD 3-Clause
- **ThreatClaw integration**: Read from Zeek ssh.log. Detect unusual SSH clients connecting to infrastructure.

### HTTP User-Agent Analysis

- Standard technique. Parse User-Agent strings from HTTP/HTTPS traffic (via Zeek http.log or Suricata eve.json).
- Libraries: `ua-parser` (Python/JS), `woothee` (Rust crate), `user_agent` Rust crate.
- Reveals: browser type/version, OS type/version, device type (mobile/desktop/bot/smart TV).
- Combine with Fingerbank for richer device classification.

Sources:
- [Fingerbank](https://www.fingerbank.org/)
- [Fingerbank API](https://api.fingerbank.org/api_doc/1/combinations/interogate.html)
- [JA4+ GitHub](https://github.com/FoxIO-LLC/ja4)
- [JA3 GitHub](https://github.com/salesforce/ja3)
- [HASSH GitHub](https://github.com/salesforce/hassh)
- [mac_oui Rust crate](https://crates.io/crates/mac_oui)
- [rs-oui Rust crate](https://github.com/pwrdwnsys/rs-oui)
- [manuf Python library](https://github.com/coolbho3k/manuf)
- [OUI-Master-Database](https://github.com/Ringmast4r/OUI-Master-Database)

---

## 4. Machine Learning for Network Security (Lightweight, No GPU)

### Kitsune (KitNET) -- Autoencoder Anomaly Detection

- **URL**: [GitHub](https://github.com/ymirsky/Kitsune-py) | [Paper](https://arxiv.org/abs/1802.09089) (NDSS 2018)
- **What it does**: Online, unsupervised network intrusion detection. An ensemble of small autoencoders learns to reconstruct "normal" network patterns. High reconstruction error = anomaly.
- **Architecture**: AfterImage (feature extractor using damped incremental statistics) + KitNET (ensemble of autoencoders with RMSE voting).
- **Input**: PCAP files or TSV (via Scapy or tshark).
- **Output**: RMSE anomaly score per packet. Score of 0 during training, then continuous anomaly scores.
- **Resources**: Python implementation is NOT optimized for production speed. Needs Cython or C++ for production. However, the algorithm itself is lightweight -- processes one instance at a time in memory.
- **License**: MIT
- **PyTorch version**: [GitHub](https://github.com/Guillem96/kitsune-pytorch)
- **ThreatClaw integration**: Implement the KitNET algorithm in Rust for production speed. Feed features from Zeek conn.log (flow duration, bytes, packets, inter-arrival times). Train on 7-14 days of "normal" traffic per network. Alert when RMSE exceeds threshold. IDEAL for ThreatClaw's behavioral baseline.

### CICFlowMeter -- Network Flow Feature Extraction

- **URL**: [GitHub](https://github.com/ahlashkari/CICFlowMeter) | Python version: [GitHub](https://github.com/datthinh1801/cicflowmeter)
- **What it does**: Generates bidirectional flows from PCAP and extracts 80+ statistical features (duration, packet counts/sizes, inter-arrival times, flags, flow bytes/s, etc.).
- **Output**: CSV with FlowID, src/dst IP/port, protocol, and 80+ feature columns.
- **Java version**: Requires libpcap. GUI or CLI.
- **Python version**: `pip install cicflowmeter`. CLI: `cicflowmeter -i eth0 -c output.csv`.
- **License**: MIT
- **ThreatClaw integration**: Use the Python version or port feature extraction logic to Rust. Feed extracted features into scikit-learn models (Isolation Forest, LOF) or KitNET.

### Scikit-learn Anomaly Detection (CPU-only, lightweight)

- **Isolation Forest**: `sklearn.ensemble.IsolationForest`. O(n log n). Randomly splits features to isolate anomalies. Works well with high-dimensional data. No distribution assumptions.
- **Local Outlier Factor (LOF)**: `sklearn.neighbors.LocalOutlierFactor`. Density-based. Detects anomalies in local neighborhoods. Better at catching small, localized anomalies.
- **One-Class SVM**: For when you only have "normal" training data.
- **Resources**: All CPU-only. Scikit-learn has zero GPU dependency. A model on ~100K samples trains in seconds on a single core.
- **ThreatClaw integration**: Train Isolation Forest on CICFlowMeter features from "normal" network traffic. Retrain weekly. Score incoming flows. Flag anomalies above threshold. This is the simplest, most practical ML pipeline for ThreatClaw.

### DGA Detection

- **What**: Detect algorithmically-generated domain names used by malware for C2 communication.
- **Approach**: Character-level analysis of domain names. Features: entropy, length, consonant ratio, n-gram frequency, vowel ratio. Or deep learning: LSTM/BiLSTM on character sequences.
- **Open-source**: [DGA_Detection](https://github.com/hmaccelerate/DGA_Detection) -- ML and DL models. Multiple repos on [GitHub topic](https://github.com/topics/dga-detection).
- **Performance**: F1 scores >99% reported with deep learning.
- **Lightweight approach**: Random Forest or Gradient Boosting on statistical features (entropy, length, n-grams) -- no GPU needed, <1ms per domain.
- **ThreatClaw integration**: Parse dns.log from Zeek. Score every queried domain. Flag DGA-like domains. Simple Random Forest model is sufficient and runs on any hardware.

### IoT Device Identification via ML

- **IoTDevID**: [GitHub](https://github.com/kahramankostas/IoTDevID) -- behavior-based device fingerprinting from network packets. Uses inter-arrival time, packet sizes, protocol distributions. Open source.
- **IoTSentinel**: [Paper](https://arxiv.org/pdf/1611.04880) -- classifies IoT devices from DHCP + first-minute traffic patterns. 31 device types tested.
- **IoTFinder**: DNS-fingerprint-based IoT identification at scale.
- **ThreatClaw integration**: Collect flow features per MAC address over a time window (1 hour). Classify device type using a Random Forest trained on public IoT datasets. Combine with Fingerbank DHCP data for high-confidence classification.

Sources:
- [Kitsune-py GitHub](https://github.com/ymirsky/Kitsune-py)
- [Kitsune Paper (ArXiv)](https://arxiv.org/abs/1802.09089)
- [CICFlowMeter GitHub](https://github.com/ahlashkari/CICFlowMeter)
- [CICFlowMeter Python](https://github.com/datthinh1801/cicflowmeter)
- [Scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html)
- [Scikit-learn LOF](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html)
- [DGA Detection GitHub](https://github.com/hmaccelerate/DGA_Detection)
- [IoTDevID GitHub](https://github.com/kahramankostas/IoTDevID)
- [IoTSentinel Paper](https://arxiv.org/pdf/1611.04880)

---

## 5. Behavioral Analysis and UEBA

### How UEBA Works in Practice

1. **Data Collection** (60-90 day training period): Ingest from 5-7+ sources -- authentication logs, endpoint logs, DNS, VPN, proxy, cloud apps, file access.
2. **Baseline Building**: ML creates behavioral profile per entity (user, device, service). Features: login times, typical destinations, data volumes, protocols used, geographic locations.
3. **Peer Groups**: Cluster entities by role, department, geography, access patterns. Compare individual against peer group norm.
4. **Anomaly Scoring**: Real-time activity scored against baseline. Deviations increase risk score. Dynamic thresholds.
5. **Alert Generation**: When cumulative risk score exceeds threshold, generate alert with context (which behaviors deviated, by how much).

### "Normal Behavior" Features by Entity Type

For **network hosts/devices**:
- Typical communication partners (which IPs/ports)
- Data volume patterns (bytes in/out per hour)
- Protocol distribution (% HTTP, DNS, SSH, etc.)
- Active hours (when the device communicates)
- DNS query patterns (domains queried, frequency)
- Connection frequency and duration

For **users**:
- Login times and locations
- Applications accessed
- Data transfer volumes
- Authentication patterns (MFA, failed attempts)
- Email patterns (recipients, volumes)

### Time Windows

- **Training period**: 60-90 days minimum for reliable baselines (industry consensus from Exabeam, Syteca, Vectra)
- **Detection windows**: Sliding windows of 1h, 4h, 24h, 7d for different feature types
- **Baseline refresh**: Continuous learning with exponential decay (recent behavior weighted more)

### OpenUBA -- Open Source UEBA Framework

- **URL**: [GitHub](https://github.com/GACWR/OpenUBA) | [Model Hub](https://openuba.org/)
- **Status**: BETA (v0.0.2), 214 commits
- **Tech stack**: Python 3.9+ (FastAPI backend), TypeScript (Next.js 14 frontend), PostgreSQL, Elasticsearch, Apache Spark, Kubernetes
- **Models**: Framework-agnostic. Examples include Isolation Forest (sklearn), PyTorch, TensorFlow, NetworkX for graph analysis. Model registry at openuba.org.
- **Architecture**: Kubernetes-native. Each model runs in isolated Docker container or K8s Job.
- **Data Sources**: CSV, Elasticsearch indices, PySpark, aggregated source groups.
- **ThreatClaw integration**: OpenUBA is too heavy for ThreatClaw's target SMBs (requires Spark + K8s). However, its model architecture and approach are a good reference. ThreatClaw should implement a lightweight version: per-device behavioral baselines using Isolation Forest, stored in local DB, retrained nightly.

### How Commercial UEBA Products Work

**Elastic SIEM**: 100+ out-of-box anomaly detection ML jobs. Uses unsupervised learning (clustering, Bayesian modeling, time series decomposition, correlation analysis). UEBA packages discover unusual entity behaviors. Pre-built jobs for auth anomalies, network anomalies, rare processes.

**Microsoft Sentinel**: Entity behavior analytics with built-in UEBA capabilities. Correlates across Azure AD, endpoints, network. Uses peer group analysis.

**Splunk UBA**: Proprietary ML models. 30-day minimum training. Risk scoring per entity.

Sources:
- [OpenUBA GitHub](https://github.com/GACWR/OpenUBA)
- [OpenUBA Model Hub](https://openuba.org/)
- [Exabeam UEBA Guide](https://www.exabeam.com/explainers/ueba/what-ueba-stands-for-and-a-5-minute-ueba-primer/)
- [Syteca Behavioral Baselines](https://www.syteca.com/en/blog/best-practices-building-baseline-user-behavior)
- [Microsoft Sentinel UEBA](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics)
- [Elastic Security ML Jobs](https://www.elastic.co/docs/reference/data-analysis/machine-learning/ootb-ml-jobs-siem)
- [Elastic Anomaly Detection Algorithms](https://www.elastic.co/docs/explore-analyze/machine-learning/anomaly-detection/ml-ad-algorithms)

---

## 6. Network Visibility Connectors

### DNS Log Sources

**Pi-hole v6** (released Feb 2025):
- Full REST API built into pihole-FTL binary (no more lighttpd/PHP).
- Endpoints for query log with server-side pagination. JSON responses.
- Self-hosted API docs at `http://pi.hole/api/docs`.
- Query log stored as NDJSON in `data/querylog.json`.
- Authentication required for most endpoints.
- **ThreatClaw integration**: Query Pi-hole API for DNS query history per client. Map client IPs to queried domains.

**AdGuard Home**:
- REST API with query log endpoints.
- Query logs stored as NDJSON in `data/querylog.json`.
- DNS answers in base64-encoded wire format.
- **ThreatClaw integration**: Same approach as Pi-hole. Parse query log API.

**Unbound**: Can log queries to file with `log-queries: yes`. Format is syslog-style text. Parse with regex.

**BIND**: Query logging via `querylog` channel. Syslog format.

### DHCP Server Logs

**ISC DHCP (dhcpd)**: Logs to syslog. Contains MAC, assigned IP, hostname, lease time. Parse with regex from `/var/log/syslog` or dedicated log file.

**Kea DHCP** (ISC's modern replacement): Has a REST API (Control Agent). JSON format. Can query leases directly.

**Windows DHCP**: Logs to `%windir%\System32\Dhcp\DhcpSrvLog-*.log`. CSV-like format.

**dnsmasq** (common on consumer routers, OpenWrt): Logs to syslog. Combined DHCP/DNS.

### WiFi Controller APIs

**Cisco Meraki** (cloud-managed):
- Full REST API at `api.meraki.com/api/v1`.
- Endpoints: `GET /organizations/{orgId}/inventory/devices`, `GET /devices/{serial}/clients`, `GET /networks/{networkId}/clients`.
- Returns: device model, MAC, IP, name, VLAN, SSID, signal, usage stats, switchport.
- Rate limit: 10 requests/second.
- **ThreatClaw integration**: Poll Meraki API for client inventory. Rich data -- device name, VLAN, SSID, usage. Ideal connector.

**Ubiquiti UniFi**:
- Local controller API (unofficial but well-documented by community).
- Key endpoint: `api/s/{site}/stat/sta` -- all active clients (MAC, IP, hostname, signal, traffic stats).
- `api/s/{site}/stat/device` -- all UniFi devices.
- Requires cookie-based authentication (login to `/api/login`).
- Python libraries: `unifi-controller-api`, `pyunifi`.
- Official API announced 2024: https://developer.ui.com/
- **ThreatClaw integration**: Poll UniFi controller every 5 minutes for client list. Get MAC, IP, hostname, SSID, traffic stats.

**Aruba Central**: REST API available. OAuth2 authentication. Endpoints for clients, devices, monitoring.

### ARP Table Sources

Beyond pfSense (already integrated):
- **Linux routers/servers**: `/proc/net/arp` or `ip neigh show`. Parse text output.
- **SNMP**: Query `ipNetToMediaTable` (OID 1.3.6.1.2.1.4.22) on any SNMP-enabled device. Works with any managed switch/router.
- **OpenWrt/DD-WRT**: SSH + `cat /proc/net/arp` or SNMP.
- **MikroTik**: REST API (`/rest/ip/arp`) or SSH + `/ip arp print`.
- **OPNsense**: API similar to pfSense.
- **Zeek**: conn.log + dhcp.log give you MAC-to-IP mappings.

### NetFlow/sFlow Exporters

Most managed switches/routers have built-in NetFlow or sFlow:
- **Cisco**: NetFlow v5/v9/IPFIX on IOS routers/switches.
- **Juniper**: J-Flow (NetFlow compatible).
- **MikroTik**: Built-in Traffic Flow (NetFlow v5/v9).
- **HP/Aruba switches**: sFlow.
- **Ubiquiti EdgeRouter**: NetFlow v5/v9.
- **Linux (softflowd)**: Generate NetFlow from any Linux box with a mirror port.
- **Collect with**: nfcapd (nfdump suite) or ntopng.

Sources:
- [Pi-hole API Docs](https://docs.pi-hole.net/api/)
- [Pi-hole v6 Announcement](https://pi-hole.net/blog/2025/02/18/introducing-pi-hole-v6/)
- [AdGuard Home Query Log](https://deepwiki.com/AdguardTeam/AdGuardHome/7.3-query-log-web-interface)
- [Meraki Dashboard API](https://developer.cisco.com/meraki/api-v1/)
- [Meraki Get Device Clients](https://developer.cisco.com/meraki/api-v1/get-device-clients/)
- [UniFi API Wiki](https://ubntwiki.com/products/software/unifi-controller/api)
- [UniFi Official API](https://developer.ui.com/site-manager-api/list-devices)
- [UniFi API Best Practices](https://github.com/uchkunrakhimow/unifi-best-practices)

---

## 7. Company Context Enrichment

### Industry-Specific Threat Models

**MITRE ATT&CK** provides three separate matrices:
- **Enterprise**: Traditional IT -- 14 tactics, 200+ techniques. Covers cloud, SaaS, Linux, Windows, macOS.
- **ICS**: Industrial control systems -- 12 tactics (includes unique "Inhibit Response Function" and "Impair Process Control"). Covers PLCs, RTUs, HMIs, SCADA.
- **Mobile**: Mobile devices.
- MITRE is developing **hybrid ATT&CK** for smart manufacturing / IIoT that combines Enterprise and ICS matrices.

**How industry changes threat model:**
- **Healthcare**: IoMT devices (infusion pumps, monitors), HIPAA compliance, ransomware targeting patient data, lateral movement to medical devices running end-of-life OS.
- **Manufacturing**: OT/ICS threats, production disruption, safety system manipulation. IEC 62443 standard.
- **Retail**: PCI-DSS compliance, POS system attacks, payment card theft, e-commerce fraud.
- **Logistics**: Connected fleet vehicles, GPS spoofing, warehouse automation systems.
- **Energy**: SCADA/ICS attacks, grid manipulation, physical safety risks.

### Compliance by Industry

| Industry | Primary Framework | Key Requirements |
|----------|------------------|------------------|
| Healthcare | HIPAA (2025 update) | MFA mandatory, encryption at rest + transit, all controls now "required" (no more "addressable") |
| Retail/Finance | PCI-DSS v4.0 | 12 requirements, network segmentation, cardholder data protection |
| EU Critical Infrastructure | NIS2 (2024 directive) | Fines up to 10M EUR or 2% global revenue, management personally liable, IEC 62443 for OT |
| EU General | GDPR | Data protection, breach notification 72h |
| Industrial/Manufacturing | IEC 62443 | OT security lifecycle, zone/conduit model |

### NACE/NAF Code for Auto-Configuration

NACE (EU) / NAF (France) are industry classification codes. For example:
- C.26: Manufacture of computer, electronic and optical products
- Q.86: Human health activities
- G.47: Retail trade
- H.49: Land transport
- D.35: Electricity, gas supply

**Practical application for ThreatClaw**: When an SMB enters their NACE/NAF code during setup:
1. Map NACE code to a **threat profile** (which MITRE ATT&CK techniques are most relevant)
2. Enable **compliance checklist** (HIPAA for healthcare NACE codes, PCI-DSS for retail)
3. Adjust **asset type expectations** (expect IoMT for healthcare, PLC/SCADA for manufacturing)
4. Configure **default alerting priorities** (ransomware critical for healthcare, POS attacks for retail)
5. Set **industry-specific baselines** (OT traffic patterns for manufacturing, payment flows for retail)

No existing open-source tool does this mapping automatically. ThreatClaw could build a NACE-to-threat-profile mapping table (~20 industry groups covering 95% of SMBs). NLP-based approaches exist in commercial tools like ThreatConnect's CAL (Automated Threat Library) which classifies threat reports by industry.

Sources:
- [MITRE ATT&CK ICS Techniques](https://attack.mitre.org/techniques/ics/)
- [MITRE ATT&CK ICS Philosophy Paper](https://attack.mitre.org/docs/ATTACK_for_ICS_Philosophy_March_2020.pdf)
- [MITRE ATT&CK Applications Survey (2025)](https://arxiv.org/html/2502.10825)
- [HIPAA 2025 Security Rule Update](https://www.federalregister.gov/documents/2025/01/06/2024-30983/hipaa-security-rule-to-strengthen-the-cybersecurity-of-electronic-protected-health-information)
- [NIS2 Directive](https://digital-strategy.ec.europa.eu/en/policies/nis2-directive)
- [PCI-DSS Standards](https://www.pcisecuritystandards.org/standards/pci-dss/)
- [ThreatConnect CAL Industry Classification](https://threatconnect.com/blog/enhancing-cybersecurity-with-cal-automated-threat-library-industry-classification/)
- [Cisco NIS2 for Industries](https://www.cisco.com/c/en/us/products/collateral/security/industrial-security/network-info-security-wp.html)

---

## Recommended Architecture for ThreatClaw v2.0 Network Intelligence

Based on all research, here is what I recommend as a practical, lightweight stack for SMBs:

### Tier 1 -- Zero-Cost, Immediate (passive, read existing data)
1. **MAC OUI lookup** -- Embed `mac_oui` Rust crate. Zero external dependency.
2. **ARP table polling** -- Extend existing pfSense connector to also support SNMP, Linux `/proc/net/arp`, MikroTik API.
3. **DNS log ingestion** -- Pi-hole API v6 or AdGuard Home API connector. Parse for client-to-domain mappings.
4. **DHCP log parsing** -- ISC dhcpd syslog or Kea REST API. Get MAC-IP-hostname mappings.
5. **NACE/NAF threat profiles** -- Build a static mapping table (~2 days of work).

### Tier 2 -- Light Integration (deploy optional lightweight tools)
6. **p0f** -- Deploy alongside ThreatClaw for passive OS fingerprinting. Query via socket. <50 MB RAM.
7. **Fingerbank** -- Local SQLite DB for DHCP fingerprint-based device classification. Free API fallback.
8. **JA4 fingerprints** -- If Zeek is present, read JA4 from ssl.log. Build fingerprint database.
9. **User-Agent parsing** -- Rust `woothee` crate for HTTP UA classification.

### Tier 3 -- Network Monitoring (optional, heavier)
10. **Zeek** -- If customer has it or wants it. Read JSON logs for comprehensive metadata.
11. **Suricata** -- If customer has it. Parse eve.json for alerts + flow data.
12. **ntopng** -- Query REST API for real-time network monitoring. Good middle-ground for SMBs who want network visibility without Zeek complexity.
13. **WiFi controller connectors** -- UniFi API, Meraki API for wireless client inventory.

### Tier 4 -- ML/Behavioral (Python skill)
14. **Behavioral baselines** -- Per-device feature vectors (bytes/pkts per hour, top destinations, protocol distribution). Isolation Forest for anomaly detection. Retrain nightly.
15. **DGA detection** -- Random Forest on domain name features. Score every DNS query.
16. **Device classification ML** -- Random Forest on flow features + Fingerbank data. Classify unknown devices.
