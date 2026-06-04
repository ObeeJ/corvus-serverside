# Corvus Use Cases

This document walks through the specific scenarios in which Corvus provides value that no existing tool provides. Each use case includes the problem being solved, how Corvus addresses it, and the exact commands or API calls involved.

---

## Table of Contents

1. [Platform Engineering: Continuous Exposure Monitoring](#1-platform-engineering-continuous-exposure-monitoring)
2. [Platform Engineering: Service Discovery in Dynamic Environments](#2-platform-engineering-service-discovery-in-dynamic-environments)
3. [Backend Engineering: Dependency Port Verification](#3-backend-engineering-dependency-port-verification)
4. [Penetration Testing: Intelligent Reconnaissance](#4-penetration-testing-intelligent-reconnaissance)
5. [Security Operations: Network Anomaly Detection](#5-security-operations-network-anomaly-detection)
6. [Security Research: Distributed Internet Scanning](#6-security-research-distributed-internet-scanning)
7. [Compliance: Continuous Attack Surface Validation](#7-compliance-continuous-attack-surface-validation)
8. [Incident Response: Rapid Network State Comparison](#8-incident-response-rapid-network-state-comparison)

---

## 1. Platform Engineering: Continuous Exposure Monitoring

### The Problem

A platform team manages a production VPC with hundreds of EC2 instances, RDS clusters, and Kubernetes nodes. A developer accidentally opens port 5432 (Postgres) to `0.0.0.0/0` in a security group. By the time a human notices, the database has been crawled by automated scanners.

No existing tool continuously watches for this and alerts the moment it happens. nmap would have to be run on a cron job, the output diffed manually, and alerts built on top. This is fragile, complex, and rarely done correctly in practice.

### How Corvus Solves It

Corvus runs as a persistent daemon watching the production CIDR range. The moment a new port appears on any host, an alert is dispatched.

```bash
# Start Corvus in watch mode, scan every 5 minutes, alert on any new port
corvus watch 10.0.0.0/16 \
  --interval 5m \
  --alert-on new-port \
  --alert-sink webhook \
  --webhook-url https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
```

When port 5432 appears on `10.0.1.47`, the Slack webhook receives:

```json
{
  "type": "new-port",
  "host": "10.0.1.47",
  "port": 5432,
  "service": "postgresql",
  "version": "14.2",
  "first_seen": "2026-05-09T14:23:11Z",
  "cves": [
    {"id": "CVE-2022-1552", "cvss": 8.8, "severity": "HIGH"}
  ]
}
```

The alert includes CVE correlation inline. The team knows immediately that the exposed port is running a vulnerable version.

### What This Replaces

- Manual nmap cron jobs with fragile diff scripts
- Cloud-native tools that only check security group rules (not actual port state)
- Commercial exposure management tools that cost thousands per month

---

## 2. Platform Engineering: Service Discovery in Dynamic Environments

### The Problem

A Kubernetes cluster with 50 nodes runs hundreds of pods. Services expose NodePorts and HostPorts. A platform engineer needs to know exactly what is reachable on the node network at any given time. The cluster state changes constantly as pods are scheduled and rescheduled.

### How Corvus Solves It

Corvus runs as a DaemonSet-adjacent tool (or a sidecar in the monitoring namespace) and continuously scans the node CIDR. The temporal store maintains the full history of what was open when.

```bash
# Continuous discovery, short interval, output to API
corvus watch 10.244.0.0/16 \
  --interval 1m \
  --alert-on new-port,port-closed \
  --output-format json

# Query what is currently exposed on the node network
corvus query "find all open ports in 10.244.0.0/16"

# Query what appeared in the last deployment window
corvus query "find all ports opened in 10.244.0.0/16 in last 30m"
```

### Integration with CI/CD

Corvus can be run as a post-deployment validation step in a pipeline:

```bash
# After deploying, assert that only expected ports are open
corvus assert 10.244.0.0/16 \
  --allowed-ports 80,443,8080 \
  --fail-on unexpected-port
```

This command exits with code 1 if any port outside the allowed list is open, blocking the pipeline.

---

## 3. Backend Engineering: Dependency Port Verification

### The Problem

A backend service depends on Redis on port 6379, Postgres on 5432, and an internal gRPC service on 9090. Before running integration tests, a developer wants to verify that all dependencies are reachable and responding correctly. If any dependency is down, they want to know which one and why.

### How Corvus Solves It

```bash
# Check specific ports on specific hosts, with service verification
corvus check \
  redis.internal:6379 \
  postgres.internal:5432 \
  grpc-service.internal:9090 \
  --verify-service \
  --output table
```

Output:

```
HOST                    PORT    STATE   SERVICE         VERSION   LATENCY
redis.internal          6379    open    redis           7.0.5     1.2ms
postgres.internal       5432    open    postgresql      14.2      2.1ms
grpc-service.internal   9090    closed  -               -         -
```

The exit code is non-zero when any checked port is not in the expected state. This makes it composable in shell scripts and Makefiles.

```makefile
check-deps:
    corvus check redis.internal:6379 postgres.internal:5432 || (echo "dependencies not ready" && exit 1)
```

### Version Drift Detection

```bash
# Alert if a dependency's version changes
corvus watch redis.internal:6379 \
  --alert-on version-drift \
  --expected-version "7.0.*"
```

If Redis is upgraded (or downgraded) without coordination, the alert fires. This catches uncoordinated infrastructure changes before they cause application failures.

---

## 4. Penetration Testing: Intelligent Reconnaissance

### The Problem

A penetration tester is given a scope of `203.0.113.0/24`. A naive approach scans all 65,535 ports on all 256 hosts: 16.7 million probe packets. This is slow, noisy, and likely to trigger IDS. An experienced tester knows to scan common ports first and use OSINT to narrow the scope, but this is a manual multi-tool workflow involving nmap, amass, crt.sh web searches, and manual synthesis.

### How Corvus Solves It

```bash
# Phase 1: Passive OSINT only, no active packets
corvus predict 203.0.113.0/24 --output report

# Output:
# 203.0.113.1  - ASN: AS64496 (ExampleCorp)
#   Predicted ports: 80 (0.97), 443 (0.97), 22 (0.82), 8080 (0.45)
#   CT log subdomains: api.example.com, staging.example.com, jenkins.example.com
#   Cloud provider: AWS us-east-1
#
# 203.0.113.5  - ASN: AS64496 (ExampleCorp)
#   Predicted ports: 5432 (0.71), 6379 (0.68), 22 (0.82)
#   Hostname (rDNS): db-primary.internal.example.com
```

The tester now knows that `203.0.113.5` is almost certainly a database server before sending a single packet. This changes the scan strategy entirely.

```bash
# Phase 2: Active scan, prediction-guided
corvus scan 203.0.113.0/24 \
  --predict \
  --scan-type syn \
  --rate 500 \
  --output json | tee results.json
```

```bash
# Phase 3: Query results for interesting findings
corvus query "find all hosts with CVE severity HIGH or CRITICAL in 203.0.113.0/24"
corvus query "find all hosts with port 22 open running openssh version below 8.0"
```

### Stealth Mode

```bash
# Mimic normal browser traffic patterns, randomize timing
corvus scan 203.0.113.0/24 \
  --scan-type connect \
  --rate 10 \
  --jitter 500ms \
  --randomize-hosts \
  --randomize-ports
```

`--randomize-hosts` and `--randomize-ports` break sequential scanning patterns that IDS systems detect. `--jitter` adds random delay between probes.

---

## 5. Security Operations: Network Anomaly Detection

### The Problem

A SOC team monitors a corporate network with 5,000 hosts across multiple sites. They need to know when:
- A new service appears on any host
- An existing service changes its banner (potential backdoor or software replacement)
- A TLS certificate is rotated (expected) or changes fingerprint mid-validity (suspicious)
- A high-severity CVE is published for software already detected on the network

### How Corvus Solves It

```bash
# Run Corvus as a persistent daemon across corporate range
corvus serve \
  --scan-target 10.0.0.0/8 \
  --scan-interval 15m \
  --alert-on new-port,banner-drift,cert-rotation,critical-cve \
  --alert-sink webhook \
  --webhook-url https://siem.corp.internal/corvus/ingest
```

The SIEM receives structured JSON events for every anomaly. This is not a batch report at end of scan. Each anomaly fires immediately as it is detected during the scan.

### Historical Query for Incident Investigation

When an incident occurs, the SOC analyst queries the temporal store to reconstruct the network state at any point in time:

```bash
# When did this host first expose port 4444?
corvus query "find ports opened on 10.0.14.23 since 2026-05-01"

# What was the service on port 80 of this host 48 hours ago?
corvus query "service on 10.0.14.23:80 at 2026-05-07T14:00:00Z"

# Which hosts changed banners in the last week?
corvus query "find all hosts with banner-drift in 10.0.0.0/8 in last 7d"
```

This reconstructive capability — knowing exactly what the network looked like at any past point — does not exist in any other open-source scanner.

---

## 6. Security Research: Distributed Internet Scanning

### The Problem

A security researcher wants to scan a large public CIDR block (with appropriate permission) to study the distribution of a specific service across the internet. Running this from a single machine is slow and puts all the traffic from one IP, which may be rate-limited or blocked.

### How Corvus Solves It

```bash
# On node 1 (initiating node)
corvus node \
  --bind 10.0.0.1:7946 \
  --advertise 203.0.113.1:7946 \
  --secret "your-mesh-secret"

# On nodes 2, 3, 4 (joining nodes)
corvus node \
  --bind 10.0.0.2:7946 \
  --join 10.0.0.1:7946 \
  --secret "your-mesh-secret"

# From any node: initiate distributed scan
corvus scan 198.51.100.0/22 \
  --distributed \
  --ports 9200 \
  --verify-service elasticsearch
```

Corvus automatically divides `198.51.100.0/22` (1024 hosts) across the 4 nodes. Each node scans its assigned sub-range independently. Results are merged into a unified view accessible from any node:

```bash
corvus query "find all hosts with port 9200 open in 198.51.100.0/22"
```

---

## 7. Compliance: Continuous Attack Surface Validation

### The Problem

A security compliance program requires evidence that no unauthorized services are exposed on the production network. This evidence must be continuous, not point-in-time. Auditors want to see a log showing that the network has been monitored continuously and that deviations were detected and resolved within SLA.

### How Corvus Solves It

```bash
# Define the allowed port policy in configuration
# configs/compliance.yaml:
#   allowed_ports:
#     "10.0.0.0/24": [80, 443, 22]
#     "10.0.1.0/24": [5432, 6379]
#     "10.0.2.0/24": [9090]

corvus serve \
  --config configs/compliance.yaml \
  --scan-interval 30m \
  --alert-on policy-violation \
  --alert-sink file \
  --alert-file /var/log/corvus/violations.jsonl
```

Every policy violation (unexpected port open) is written to an append-only JSONL file. This file is the audit trail. The alert timestamp, host, port, service, and CVE data are all present for every violation.

```bash
# Generate compliance report for a time period
corvus report \
  --from 2026-04-01 \
  --to 2026-04-30 \
  --output pdf \
  > april-compliance-report.pdf
```

---

## 8. Incident Response: Rapid Network State Comparison

### The Problem

A security incident has been detected. The incident response team needs to answer: "What was different about this host's network profile 2 hours before the incident compared to right now?" They need to know if a new port appeared, if a service changed, or if a backdoor was installed and started listening.

### How Corvus Solves It

Because Corvus continuously records state to the temporal store, the IR team can query the exact state at any historical point:

```bash
# What was the network state of the affected host before the incident?
corvus diff 10.0.14.99 \
  --from "2026-05-09T10:00:00Z" \
  --to "2026-05-09T14:00:00Z"

# Output:
# HOST: 10.0.14.99
#
# ADDED PORTS:
#   4444/tcp  open  netcat (nc)  [appeared at 2026-05-09T12:31:07Z]
#
# CHANGED SERVICES:
#   22/tcp  ssh  banner changed:
#     before: "OpenSSH_8.4p1 Ubuntu-6ubuntu2.1"
#     after:  "OpenSSH_7.9p1 Debian-10+deb10u2"
#
# UNCHANGED:
#   80/tcp   open  nginx/1.24.0
#   443/tcp  open  nginx/1.24.0
```

This output tells the IR team exactly what happened: a reverse shell was opened on port 4444, and the SSH banner changed, suggesting the SSH binary was replaced. Both events are timestamped to the minute.

No tool that runs a scan today can answer "what was the state 4 hours ago." Corvus can.
