# Corvus System Design

This document describes the internal architecture of Corvus: how each component is structured, why it was designed that way, how data flows through the system, and the tradeoffs made at each layer.

---

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [High-Level Architecture](#high-level-architecture)
3. [Component Breakdown](#component-breakdown)
4. [Data Flow](#data-flow)
5. [Temporal Store Design](#temporal-store-design)
6. [Scanner Engine Design](#scanner-engine-design)
7. [OSINT Fusion Layer](#osint-fusion-layer)
8. [Fingerprinting Engine](#fingerprinting-engine)
9. [Anomaly Detection Engine](#anomaly-detection-engine)
10. [Distributed Mesh Design](#distributed-mesh-design)
11. [CVE Correlation Layer](#cve-correlation-layer)
12. [Supply Chain and Dependency Awareness](#supply-chain-and-dependency-awareness)
13. [Cloud API Correlation](#cloud-api-correlation)
14. [LLM Query Interface](#llm-query-interface)
15. [OpenTelemetry Observability](#opentelemetry-observability)
16. [Query Engine](#query-engine)
17. [API Layer](#api-layer)
18. [Technology Choices](#technology-choices)
19. [Concurrency Model](#concurrency-model)
20. [Security Considerations](#security-considerations)

---

## Design Philosophy

Corvus is built around four principles:

**State over snapshots.** Every scan result is a data point in a time series, not a one-off output. The system is always accumulating state, never discarding it.

**Intelligence before noise.** Passive reconnaissance happens before active scanning. The system should know as much as possible about a target before sending a single packet.

**Composability.** Every component is an interface. The scanner engine does not care about the store. The anomaly engine does not care about the scanner. Data flows through well-defined contracts.

**Answers, not data.** Raw port lists and CVE IDs are not useful to most engineers. Every output surface — CLI, API, dashboard — is designed to surface insight and recommended action, not raw data. The LLM layer is not a feature; it is an expression of this principle.

---

## High-Level Architecture

```
 External World
       |
       v
 +-----+----------------------------------------------+
 |               Corvus Process                      |
 |                                                     |
 |  CLI (cobra)          API Server (Fiber)            |
 |       |                      |                      |
 |       +----------+-----------+                      |
 |                  |                                  |
 |          +-------v--------+                         |
 |          |  Job Scheduler |                         |
 |          |  (goroutine    |                         |
 |          |   pool)        |                         |
 |          +---+---+---+----+                         |
 |              |   |   |                              |
 |    +---------+   |   +---------+                   |
 |    |             |             |                   |
 |    v             v             v                   |
 | OSINT         Scanner       Anomaly                |
 | Engine        Engine        Engine                 |
 |    |             |             |                   |
 |    +------+-------+------+-----+                   |
 |           |              |                         |
 |      Fingerprint       Store                       |
 |      Engine         (bbolt)                        |
 |           |              |                         |
 |           +--------------+                         |
 |                  |                                 |
 |           CVE Correlator                           |
 |                  |                                 |
 |           Query Engine                             |
 |                  |                                 |
 |           Mesh (gossip)                            |
 +-----------------------------------------------------+
```

---

## Component Breakdown

### cmd/corvus

The binary entrypoint. Parses CLI flags using cobra, initializes configuration via viper, wires dependencies together, and hands control to either the CLI command executor or the API server. This layer contains no business logic.

### internal/scanner

Responsible for the mechanical act of probing ports. Contains three sub-engines: TCP connect scan, SYN (raw socket) scan, and UDP scan. Each engine implements the same `Scanner` interface so they are interchangeable. The scanner engine does not interpret results, it only produces them.

### internal/osint

The passive intelligence layer. Queries certificate transparency logs (crt.sh), performs reverse DNS and forward DNS lookups, performs ASN and BGP prefix lookups via Team Cymru's whois service, and detects whether a target falls within known cloud provider IP ranges (AWS, GCP, Azure published ranges). Produces a `TargetProfile` that the scanner uses to prioritize ports.

### internal/fingerprint

Takes raw TCP banners (the first bytes a service sends when a connection is established) and identifies the service, its software, and its version. Uses a combination of deterministic regex matching against known banner patterns and heuristic scoring. Does not depend on nmap probe files but implements similar logic independently.

### internal/store

An embedded time-series graph database built on bbolt (BoltDB). The data model is: bucket per host IP, within it a bucket per port number, within it timestamped state records. Provides read and write interfaces for the rest of the system. Handles retention policy enforcement.

### internal/anomaly

Subscribes to a channel that receives new scan results from the scanner. For each result, it queries the store for the previous state of that host:port combination. It diffs the two states and emits an anomaly event if any of the configured conditions are met: new port appeared, port disappeared, banner changed, TLS certificate fingerprint changed, response time delta exceeded threshold, service version changed.

### internal/mesh

Implements a peer-to-peer gossip network using hashicorp/memberlist. Each Corvus instance is a node. Nodes broadcast scan results and anomaly events to the mesh so all nodes maintain a unified view. Also handles distributed CIDR assignment: when scanning a large range, the coordinator node divides the range and assigns sub-ranges to available nodes.

### internal/cve

Queries the NIST National Vulnerability Database (NVD) REST API v2 for CVEs matching a CPE string derived from the fingerprinted service name and version. Results are cached locally in bbolt with a configurable TTL to avoid hammering the API on repeated scans. Returns a slice of CVE records with severity scores.

### internal/query

A lightweight DSL parser and execution engine. Parses natural-language-adjacent query strings into a structured `QueryPlan` (target CIDR, conditions, time range, ordering). Executes the plan against the temporal store and returns results. This is what powers `corvus query "..."`.

### internal/api

A Fiber HTTP server that exposes the full Corvus capability surface over REST and WebSocket. Handlers delegate immediately to the internal engines. Middleware handles API token authentication and per-IP rate limiting.

### pkg/iprange

A utility package for parsing and iterating CIDR ranges, IP lists, and range expressions like `10.0.0.1-10.0.0.254`. Produces an iterator that yields individual `net.IP` values. Shared across the scanner and mesh packages.

### pkg/logger

A structured logger built on `log/slog` (Go standard library, 1.21+). All components receive the logger as a dependency rather than using a global. This makes testing clean and output configurable.

### internal/supplychain

Extends the CVE correlator with two additional data sources: the OSV (Open Source Vulnerabilities) database and the GitHub Advisory Database. Also maintains a detection ruleset for software that should never appear on production hosts: exposed package managers (pip, npm, apt), build tools (gcc, make), debug endpoints (`/debug/pprof`, `/__debug`, Django debug pages), and known malicious package name patterns (typosquatting indicators). Findings are attached to host records in the store and surfaced as anomaly events when first detected.

### internal/llm

Translates natural language questions from the user into structured query plans against the temporal store, then formats the raw results into a plain English summary with recommended actions. Uses the Anthropic Claude API (configurable to OpenAI or a local model via a provider interface). The LLM is never given raw network data directly — the query engine executes the plan and returns structured results, which are then passed to the LLM for summarization. This keeps the LLM out of the critical path and ensures query execution is deterministic.

### internal/otel

Initializes an OpenTelemetry SDK with three signals: metrics (scan throughput, anomaly rate, store write latency, mesh node count), traces (per-scan job spans with child spans per host), and logs (bridged from slog). Exports to a configured OTLP gRPC endpoint. Also exposes a Prometheus-compatible `/metrics` HTTP endpoint on a separate port so teams already running Prometheus do not need an OTEL collector.

### internal/osint (extended)

The original OSINT layer is extended with cloud provider API clients. For targets that fall within AWS IP ranges, Corvus calls the AWS EC2 API to retrieve the security groups attached to the matching instance and their inbound rules. For GCP and Azure, equivalent API calls retrieve firewall rules and NSG rules respectively. The cloud API clients use ambient credentials (instance role, ADC, managed identity) and require no separate credential configuration when Corvus is running inside the cloud environment it is monitoring.

---

## Data Flow

### Active Scan Flow

```
User issues: corvus scan 10.0.0.0/24 --predict

1. CLI parses flags, creates ScanJob{target: "10.0.0.0/24", predict: true}
2. Job Scheduler receives ScanJob, creates goroutine pool
3. OSINT Engine queries CT logs, DNS, BGP for all IPs in range
4. OSINT Engine returns TargetProfile per IP with port probability scores
5. Scanner Engine uses TargetProfile to order port candidates
6. Scanner Engine probes ports, receives results on result channel
7. Fingerprint Engine reads from result channel, grabs banners, identifies services
8. Fingerprint Engine writes enriched results to store
9. Anomaly Engine reads enriched results, diffs against previous store state
10. Anomaly Engine emits alerts on alert channel
11. Mesh Engine broadcasts results to peer nodes
12. CVE Correlator reads fingerprinted services, fetches CVEs, attaches to results
13. API WebSocket handler reads from result channel, streams to connected clients
14. CLI prints table output as results arrive
```

### Watch Flow

```
User issues: corvus watch 10.0.0.0/24 --alert-on new-port

1. CLI creates WatchJob with repeat interval (default 5m)
2. Job Scheduler runs ScanJob on interval
3. After each scan, Anomaly Engine diffs results against stored state
4. If diff matches alert condition (new-port), alert is emitted
5. Alert is written to store, broadcast to mesh, sent to configured sinks
   (stdout, webhook, Slack, PagerDuty)
```

---

## Temporal Store Design

The store is the most important component in Corvus. It is what makes every other capability possible.

### Data Model

```
bbolt database: /var/lib/corvus/data/corvus.db

Bucket layout:

  hosts/
    192.168.1.1/
      ports/
        80/
          2026-05-09T10:00:00Z -> StateRecord{open: true, banner: "nginx/1.24", ...}
          2026-05-08T10:00:00Z -> StateRecord{open: true, banner: "nginx/1.22", ...}
          2026-05-01T10:00:00Z -> StateRecord{open: false}
        443/
          ...
        22/
          ...
    192.168.1.2/
      ...

  alerts/
    2026-05-09T10:05:00Z -> AlertRecord{host: "192.168.1.1", port: 8080, type: "new-port"}
    ...

  meta/
    last_scan -> timestamp
    node_id -> uuid
```

### StateRecord Schema

```go
type StateRecord struct {
    Timestamp   time.Time
    Open        bool
    Banner      string
    ServiceName string
    Version     string
    TLSFingerprint string
    ResponseMs  int64
    CVEs        []string
}
```

### Key Design Decisions

**Why bbolt and not SQLite or Postgres?**
bbolt is a pure Go, embedded, zero-dependency key-value store. It requires no external process, no configuration, and produces a single file. For a CLI tool that needs to work offline on a pentester's laptop or in a container, this is the right tradeoff. The data access patterns (write-heavy per-IP, read-heavy for queries) are well-suited to B-tree key-value storage.

**Why not time-series databases like InfluxDB or Prometheus?**
Corvus should be self-contained. Adding a dependency on a separate database process would prevent it from being used as a CLI tool. bbolt gives 90% of what a time-series DB provides for this use case with zero operational overhead.

**Retention**
A background goroutine runs daily and removes StateRecord entries older than the configured retention period (default 90 days). This bounds disk usage over time.

---

## Scanner Engine Design

### TCP Connect Scan

The simplest scan type. Attempts to complete a full TCP three-way handshake using `net.DialTimeout`. If the connection succeeds, the port is open. This is the only scan type that does not require root privileges. It is the most detectable scan type because it completes connections and appears in server access logs.

### SYN Scan (Half-open)

Sends a raw TCP SYN packet and waits for a SYN-ACK (port open) or RST (port closed) response. Never completes the handshake, so the connection does not appear in most application logs. Requires raw socket access, which requires root or `CAP_NET_RAW`. Uses `golang.org/x/net/ipv4` for raw packet construction.

### UDP Scan

Sends an empty UDP datagram to each target port. If an ICMP "port unreachable" message is returned, the port is closed. No response (within timeout) means open or filtered. UDP scanning is inherently unreliable due to ICMP rate limiting on most operating systems. Corvus applies adaptive timeout logic: if multiple ICMP rate-limit responses are detected, it backs off and spaces UDP probes further apart.

### Concurrency Model

The scanner uses a worker pool pattern. A fixed-size goroutine pool (configurable, default 1000) reads from a work channel. The work channel is populated by the IP range iterator. Results are written to a buffered result channel. This bounds memory usage regardless of how large the target range is.

```
IP Range Iterator -> work channel -> [worker goroutine pool] -> result channel -> consumers
```

### Rate Limiting

A token bucket rate limiter is applied at the worker pool level. This prevents Corvus from accidentally DoS-ing a target or tripping IDS rate-limit detection rules. The rate is configurable via `--rate` flag (packets per second).

---

## OSINT Fusion Layer

### Certificate Transparency Logs

Queries `crt.sh` (a public CT log aggregator) for all certificates ever issued for the target domain. This reveals subdomains, internal hostnames, and historical infrastructure that may not be in DNS. For IP targets, reverse-resolves the IP first.

### DNS Resolution

Performs forward and reverse DNS lookups. Reverse lookups on an IP range often reveal internal hostnames that indicate the service running on a host (e.g., `db-primary.internal`, `jenkins.corp.example.com`). Hostname patterns are scored against known service name patterns to predict likely open ports.

### BGP and ASN Lookup

Uses Team Cymru's whois service (`whois.cymru.com`) to identify the ASN and organization that owns a target IP. This tells Corvus whether the target is a cloud provider, an ISP, a CDN, or an enterprise network, each of which has a characteristic port profile.

### Cloud Provider Range Detection

Compares target IPs against published IP ranges from AWS (ip-ranges.amazonaws.com), GCP (cloud.google.com/compute/docs/faq), and Azure (azureipranges). If a target is in a cloud range, its likely port profile is very different from an on-premise host.

### Port Probability Model

All OSINT signals are combined into a simple scoring model. Each port is assigned a probability score from 0 to 1 based on the signals. The scanner sorts ports by descending score and scans the most likely ports first. This is not machine learning. It is deterministic rule-based scoring, which is transparent, debuggable, and correct by construction.

---

## Fingerprinting Engine

### Banner Grabbing

After a port is confirmed open via connect scan, the fingerprinting engine opens a fresh connection and reads the first 4096 bytes. Many services (SSH, SMTP, FTP, HTTP, Redis, Postgres) immediately send an identifying banner when a connection is established. This banner is stored verbatim in the StateRecord.

### Service Identification

The raw banner is matched against a library of compiled regular expressions, one per known service. The first match wins. If no match is found, the service is recorded as "unknown" with the raw banner preserved for manual inspection.

### Version Extraction

Service-specific version extraction patterns are applied to the matched banner. For example, the nginx HTTP server banner `Server: nginx/1.24.0` has a version extraction pattern `nginx/([0-9.]+)` that captures `1.24.0`. Extracted versions are normalized to `major.minor.patch` format for consistent CVE lookups.

### TLS Certificate Inspection

For ports that respond to a TLS handshake (443, 8443, and any port where a TLS banner is detected), Corvus performs a TLS handshake and extracts the certificate chain. It stores the SHA-256 fingerprint of the leaf certificate, the subject, issuer, and expiry date. Certificate fingerprint changes between scans are a high-signal anomaly event.

---

## Anomaly Detection Engine

The anomaly engine is a pure state-diff function. It takes two StateRecord values (previous and current) for the same host:port and produces zero or more AnomalyEvent values.

### Detection Rules

| Condition | Anomaly Type | Severity |
|---|---|---|
| Port was closed, now open | new-port | High |
| Port was open, now closed | port-closed | Medium |
| Banner changed | banner-drift | Medium |
| TLS fingerprint changed | cert-rotation | High |
| Service version changed | version-drift | Low |
| Response time increased >200% | latency-spike | Low |
| CVE with CVSS >= 9.0 detected | critical-cve | Critical |

### Alert Dispatch

AnomalyEvent values are written to an alert channel. The alert dispatcher reads from this channel and delivers alerts to configured sinks. Built-in sinks: stdout, JSON file, HTTP webhook (generic), Slack incoming webhook. The sink interface is exported so users can implement custom sinks.

---

## Distributed Mesh Design

### Gossip Protocol

Corvus uses hashicorp/memberlist, the same library used by HashiCorp Consul and Serf. Memberlist implements the SWIM gossip protocol, which provides eventual consistency, failure detection, and membership management with O(log N) message complexity.

### Node Roles

In a Corvus mesh, all nodes are equal. There is no dedicated coordinator. When a large scan is initiated from any node, that node temporarily acts as the coordinator for that job: it divides the CIDR range into equal sub-ranges and assigns each sub-range to available nodes via broadcast message. If a node fails mid-scan, its sub-range is detected as unassigned (via heartbeat timeout) and redistributed.

### State Synchronization

Each node maintains its own local bbolt store. Scan results and state changes are broadcast to the mesh as compact binary-encoded messages. Receiving nodes merge incoming state into their local store using a last-write-wins strategy (based on timestamp). This means the mesh is eventually consistent, not strongly consistent. For the use case of network monitoring this is acceptable.

---

## CVE Correlation Layer

### NVD API v2

Corvus uses the NIST NVD REST API v2. Given a service name and version (e.g., `nginx 1.22.0`), it constructs a CPE 2.3 string (`cpe:2.3:a:nginx:nginx:1.22.0:*:*:*:*:*:*:*`) and queries the NVD `/rest/json/cves/2.0` endpoint with the `cpeName` parameter.

### Local Cache

CVE results are cached in a dedicated bbolt bucket keyed by the CPE string. Cache entries expire after the configured TTL (default 24 hours). This prevents repeated API calls for the same service version across multiple scans. If the NVD API is unreachable, the cache serves stale results rather than failing.

### Output

Each CVE record in the output includes: CVE ID, CVSS v3 base score, severity rating, a one-sentence description, and a link to the full NVD entry.

---

## Supply Chain and Dependency Awareness

### Problem

CVE databases like NVD cover known vulnerabilities in released software versions. They do not cover:
- Vulnerabilities disclosed to OSV or GitHub Advisory before NVD ingestion (NVD has significant ingestion lag)
- Software that is insecure by presence alone — a production host exposing a package manager or a debug endpoint is a misconfiguration regardless of CVE status
- Typosquatted or malicious package names that appear in HTTP response headers or service banners

### OSV and GitHub Advisory Database

Corvus queries the OSV REST API (`api.osv.dev/v1/query`) with the detected package ecosystem and version. The GitHub Advisory Database is queried via the GitHub GraphQL API for packages not covered by OSV. Both sources are cached locally in bbolt with the same TTL as NVD results.

The three databases are deduplicated by CVE ID before results are returned. If all three are unavailable, cached results are served with a staleness warning.

### Production Hygiene Detection

A ruleset of regex patterns matches against banners, HTTP response headers, and open port numbers to detect software that should not be running on production hosts:

```
- Port 9229 open: Node.js inspector (remote code execution if exposed)
- Banner contains "Django/*/debug": Django debug mode enabled
- HTTP header "X-Powered-By: PHP/5.*": end-of-life PHP version
- Port 6443 or banner "kubectl": Kubernetes API exposed
- Banner contains "npm/", "pip/", "gem/": package manager accessible
- Port 4444, 5555, 9001: common reverse shell and RAT default ports
```

Each hit produces a `hygiene-violation` anomaly event with severity and remediation advice.

---

## Cloud API Correlation

### Why Port State Alone Is Not Enough

A port being open tells you the current network state. It does not tell you:
- Whether it is intentionally exposed or a misconfiguration
- Which firewall rule permits the traffic
- When that rule was created and by whom
- Whether the rule is overly broad (e.g., `0.0.0.0/0` vs a specific CIDR)

Cloud provider APIs expose all of this. For teams running infrastructure on AWS, GCP, or Azure, this context turns a port scan result into an actionable finding.

### AWS

When a target IP is identified as AWS, Corvus calls `ec2:DescribeInstances` to find the instance, then `ec2:DescribeSecurityGroups` to retrieve the attached security groups and their inbound rules. The rule that permits traffic to the open port is identified and its source CIDR, creation time, and associated IAM principal (if available via CloudTrail lookup) are attached to the scan result.

### GCP

Calls `compute.instances.list` and `compute.firewalls.list` to retrieve the VPC firewall rules applicable to the target instance. Tags and target service accounts are resolved to their associated firewall rule.

### Azure

Calls the Azure Resource Manager API to retrieve the Network Security Group (NSG) associated with the target instance's NIC. Resolves the specific NSG rule permitting the open port.

### Output

Cloud API correlation produces an additional field on each open port result:

```json
{
  "port": 5432,
  "state": "open",
  "service": "postgresql",
  "cloud": {
    "provider": "aws",
    "instance_id": "i-0abc123",
    "security_group": "sg-0def456",
    "rule": {
      "source": "0.0.0.0/0",
      "created": "2026-04-15T09:12:00Z",
      "note": "source is 0.0.0.0/0 — publicly exposed"
    }
  }
}
```

The `note` field is generated by the anomaly engine, not the cloud API. Overly permissive rules (source `0.0.0.0/0`) are flagged as `cloud-exposure` anomaly events with HIGH severity.

---

## LLM Query Interface

### Architecture

The LLM layer is a thin translation and summarization wrapper around the query engine. It never executes queries itself. The flow is:

```
User question (natural language)
        |
        v
  LLM: translate to QueryPlan JSON
        |
        v
  Query Engine: execute QueryPlan against store
        |
        v
  LLM: summarize structured results into plain English + recommended actions
        |
        v
  Output to CLI or API response
```

The LLM is called twice per `ask` request: once to translate, once to summarize. The translation call uses a structured output schema (JSON mode) to produce a valid `QueryPlan`. The summarization call receives the raw results and a system prompt that instructs it to explain findings in plain English and suggest remediation steps.

### Provider Interface

```go
type LLMProvider interface {
    Translate(ctx context.Context, question string) (QueryPlan, error)
    Summarize(ctx context.Context, results []QueryResult) (string, error)
}
```

Three implementations: `AnthropicProvider` (Claude API), `OpenAIProvider`, `LocalProvider` (calls a local OpenAI-compatible API, e.g. Ollama). Provider is selected by config. The interface ensures the rest of the system does not depend on any specific LLM vendor.

### What the LLM Is NOT Used For

- Executing scan jobs
- Making decisions about alerting thresholds
- Writing to the store
- Anything on the critical path of a scan

The LLM is only invoked when the user explicitly asks a question (`corvus ask` CLI command or `POST /api/v1/ask` API endpoint). It is never invoked automatically during a scan.

---

## OpenTelemetry Observability

### Three Signals

**Metrics** — Counters, gauges, and histograms exported via OTLP and Prometheus:

| Metric | Type | Description |
|---|---|---|
| `corvus_ports_scanned_total` | Counter | Total ports probed across all scans |
| `corvus_ports_open_total` | Counter | Total open ports found |
| `corvus_anomalies_total` | Counter | Anomaly events by type and severity |
| `corvus_scan_duration_seconds` | Histogram | Duration of scan jobs |
| `corvus_store_write_duration_seconds` | Histogram | bbolt write latency |
| `corvus_mesh_nodes` | Gauge | Current connected mesh node count |
| `corvus_cve_critical_total` | Counter | Critical CVEs found across all scans |

**Traces** — Each scan job is a root span. Each host is a child span. Each port probe is a child of the host span. This allows trace-based debugging of slow scans or unexpected results.

**Logs** — The slog handler is bridged to the OTLP log signal so structured logs from all components land in the same observability backend as traces and metrics, enabling correlation.

### Export

OTLP gRPC export is configured via `otel.endpoint` in config. If the endpoint is empty, telemetry is collected in-process but not exported (zero overhead for CLI usage). The Prometheus endpoint is always available on `otel.prometheus_port` regardless of OTLP configuration.

---

## Query Engine

### DSL Grammar

The query language is parsed using a hand-written recursive descent parser (no external parser generator dependency). The grammar covers:

```
query     = "find" conditions "in" target [time_clause] [order_clause]
conditions = condition ("," condition)*
condition  = port_cond | service_cond | cve_cond | state_cond
target    = cidr | ip | "all"
time_clause = "in last" duration | "since" datetime | "between" datetime "and" datetime
order_clause = "order by" field ("asc" | "desc")
```

### Execution

A parsed QueryPlan is handed to the query executor, which translates it into a series of bbolt range scans. Results are streamed out as they are found rather than buffering all results in memory first. This allows queries across large stores to return first results quickly.

---

## API Layer

### Fiber

The API is built with gofiber/fiber v3, which is built on top of fasthttp. fasthttp does not use the standard `net/http` interface, which is why Fiber achieves significantly higher throughput than Gin or Echo. For Corvus, this matters because the scan results streaming endpoint can have many concurrent connections, and the lower per-connection overhead of fasthttp compounds at scale.

### WebSocket Streaming

The `/api/v1/scan/:id/stream` endpoint upgrades to WebSocket and sends scan results as JSON messages in real time as they arrive from the scanner worker pool. This is implemented using fiber's built-in WebSocket adapter on top of the fasthttp WebSocket implementation.

### Authentication

API token authentication is middleware-based. The token is a random 32-byte value configured in `configs/default.yaml` or via the `CORVUS_API_AUTH_TOKEN` environment variable. If the token is empty, authentication is disabled (intended for local use only).

### Rate Limiting

Per-IP rate limiting is applied using a sliding window algorithm implemented in memory. The default is 100 requests per minute per IP. For the WebSocket streaming endpoint, the limit applies to the upgrade request only, not to the stream.

---

## Technology Choices

| Component | Technology | Reason |
|---|---|---|
| Language | Go 1.22+ | Native concurrency, low-level socket access, single binary output |
| HTTP framework | gofiber/fiber v3 | fasthttp performance, WebSocket, clean middleware API |
| Embedded store | bbolt | Zero-dependency, single file, embedded, pure Go |
| Gossip protocol | hashicorp/memberlist | Battle-tested, used in production by Consul and Nomad |
| CLI | cobra + viper | Go standard for CLI tools, environment variable support |
| Logging | log/slog | Go standard library, structured, zero external dependency |
| Raw sockets | golang.org/x/net/ipv4 | Low-level packet construction for SYN scan |
| Configuration | yaml + viper | Human-readable, widely understood |
| LLM — primary | Anthropic Claude API | claude-sonnet-4-6, structured output (JSON mode), tool use |
| LLM — alternative | OpenAI API / Ollama | Provider interface allows swap without core changes |
| Observability | OpenTelemetry Go SDK | Vendor-neutral, covers metrics + traces + logs in one SDK |
| Cloud — AWS | aws-sdk-go-v2 | Official SDK, ambient credential chain support |
| Cloud — GCP | google-cloud-go | Official SDK, ADC credential chain |
| Cloud — Azure | azure-sdk-for-go | Official SDK, managed identity support |
| Vuln DB — OSV | OSV REST API | Faster ingestion than NVD, covers more ecosystems |
| Vuln DB — GitHub | GitHub GraphQL API | Advisory Database, covers npm/PyPI/Go/Rust/etc. |

---

## Concurrency Model

Corvus uses Go's goroutine model throughout. The key concurrency primitives used are:

- **Worker pools**: Fixed-size goroutine pools with buffered work channels for the scanner
- **Fan-out channels**: One result channel read by multiple consumers (fingerprint, anomaly, API stream, mesh broadcast)
- **Context cancellation**: All long-running operations accept `context.Context` for clean shutdown
- **sync.WaitGroup**: Used to track when all workers in a pool have finished
- **sync.Mutex and sync.RWMutex**: Used in the store wrapper and mesh node table, never held across I/O operations

No external concurrency libraries are used.

---

## Security Considerations

**SYN scan requires root.** Inform the user at startup if SYN scan is requested without sufficient privileges. Fall back to TCP connect scan rather than failing.

**Rate limiting on the scanner.** Do not allow the scanner to consume the full host network capacity by default. The default 1000 concurrent workers and token bucket rate limiter are conservative enough for most targets.

**API token.** The API server must not start without an auth token if bound to a non-loopback address. Enforce this at startup.

**No data exfiltration.** OSINT queries go to public services (crt.sh, NVD API, Team Cymru whois). No scan results are ever sent to any external service unless the user configures a webhook sink explicitly.

**Mesh encryption.** Gossip messages between mesh nodes are encrypted using a pre-shared key configured via `CORVUS_MESH_SECRET`. hashicorp/memberlist supports AES encryption out of the box.
