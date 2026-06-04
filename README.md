# Corvus — Server Side

> **Networks forget. Corvus doesn't.**

A stateful network-intelligence engine written in Go. Most scanners send packets, print results, and forget everything. Corvus *remembers*: it tracks how a network changes over time, fuses passive intelligence before it touches a target, flags behavioural anomalies the moment they appear, and answers questions in plain English.

Where `nmap`, `masscan`, and `rustscan` answer *"what is open right now"*, Corvus answers *"what changed, when, why it matters, and what to do about it."*

This repository is the **backend** — the engine, CLI, API server, and data layer. The web dashboard lives in a separate project.

<p align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white">
  <img alt="API" src="https://img.shields.io/badge/API-Fiber%20%2B%20WebSocket-000000">
  <img alt="Store" src="https://img.shields.io/badge/Store-bbolt%20%2B%20Postgres-336791">
  <img alt="License" src="https://img.shields.io/badge/License-Proprietary-red">
  <img alt="Status" src="https://img.shields.io/badge/Status-Active%20development-f59e0b">
</p>

---

## The Problem

Continuous infrastructure is dynamic — containers spin up, security groups drift, services get patched, ports appear. The dominant tooling is *stateless*: every scan starts from zero, keeps no history, and surfaces a flat list of open ports with no notion of *change*. That leaves real questions unanswered:

- Did a new port appear on my subnet overnight, and exactly when?
- Did a TLS cert rotate or a service banner mutate unexpectedly?
- Which exposed services are running software with known CVEs *right now*?
- Can I ask all of that in English instead of memorising scan flags?

## The Solution

Corvus treats network state as a **time series**. Every host → port → service observation is versioned in an embedded temporal store, so history and drift are first-class. Around that core it layers passive OSINT, behavioural anomaly detection, vulnerability correlation, a distributed mesh, and a natural-language query interface — all reachable from one CLI binary and one streaming API.

---

## Capabilities

| Capability | What it actually does |
|---|---|
| **Temporal state store** | Every observation versioned in an embedded `bbolt` graph (`host → port → service → state history`). Query the full timeline of any endpoint. |
| **Active scanning** | Bounded-concurrency TCP connect scanner, plus half-open **SYN** scanning over raw sockets with automatic fallback to TCP connect when `CAP_NET_RAW`/root is unavailable. |
| **Predictive OSINT** | Passive pre-scan enrichment from Certificate Transparency logs, DNS, and BGP/ASN data — including cloud-provider attribution (AWS / GCP / Azure) by ASN — to prioritise likely-open targets before sending a packet. |
| **Behavioural anomaly detection** | Alerts on *change*, not just "port open": new ports, banner mutation, TLS cert rotation, service-version drift, response-time deltas. Pluggable alert sinks. |
| **CVE correlation** | Fingerprinted services are matched to CPEs and cross-referenced against **NVD** and **OSV**, with response caching and optional NVD API key. |
| **Supply-chain checks** | Heuristic detection of exposed dev tooling, debug endpoints, package managers, and indicators that shouldn't appear on production hosts. |
| **Encrypted mesh** | Peer-to-peer UDP gossip mesh for coordinating multiple nodes; traffic is authenticated-encrypted with a shared cluster key (NaCl). Covered by unit tests. |
| **Natural-language queries** | An LLM layer translates English into query plans against the store and summarises findings. Multi-provider (Groq default, OpenAI, Anthropic). |
| **Streaming API** | Fiber REST API with WebSocket live-streaming of scan progress and events. |
| **Accounts & billing** | JWT auth, API-key issuance/gating, and a billing layer (Paystack + crypto addresses) backed by Postgres with versioned migrations. |
| **Observability** | Structured logging, OpenTelemetry hooks, and Sentry integration. |

> **Honest scope:** cloud-provider correlation is ASN/BGP-based attribution, not live security-group/IAM inspection. The mesh is a custom NaCl-encrypted gossip implementation. Outbound email and response-action webhooks are currently logged/mocked rather than delivered. See `docs/` for the full design intent.

---

## Architecture

```
                              Corvus Engine
  +-----------------------------------------------------------------------+
  |  Passive OSINT        Active Scanner        Anomaly Engine            |
  |  CT logs / DNS        TCP connect / SYN      State diff / drift        |
  |  BGP / ASN attrib.    Banner + fingerprint   Alert sinks              |
  |        |                    |                     |                    |
  |  +-----v--------------------v---------------------v-----------+       |
  |  |        Temporal Graph Store (bbolt)                        |       |
  |  |        host -> port -> service -> [state history]          |       |
  |  +-------------------------------+----------------------------+       |
  |                                  |                                    |
  |  +-----------+   +---------------v-----------+   +---------------+    |
  |  | CVE / OSV |   | Encrypted Gossip Mesh     |   | LLM NL Query  |    |
  |  | Supply    |   | (UDP + NaCl shared key)   |   | (Groq/OpenAI) |    |
  |  | chain     |   +---------------------------+   +---------------+    |
  |  +-----------+                                                        |
  |                                                                       |
  |  Fiber REST + WebSocket   |   CLI (cobra)   |   Bubble Tea TUI         |
  |  JWT / API keys / billing |   Postgres + migrations  |   OTEL/Sentry  |
  +-----------------------------------------------------------------------+
```

---

## Tech Stack

**Language** Go 1.25 · **API** Fiber v2 + WebSocket · **CLI** Cobra · **TUI** Bubble Tea / Lip Gloss · **Temporal store** bbolt · **Relational store** PostgreSQL via `pgx` + `golang-migrate` · **Auth** JWT (`golang-jwt`) · **Config** Viper · **Observability** OpenTelemetry + Sentry · **Crypto** `golang.org/x/crypto` (NaCl).

---

## Quick Start

Requires **Go 1.25+**.

```bash
git clone https://github.com/ObeeJ/corvus-serverside.git
cd corvus-serverside
cp .env.example .env        # fill in optional keys (LLM, NVD, Postgres, billing)
make build                  # → ./bin/corvus

# Scan a host or CIDR and record state
./bin/corvus scan 192.168.1.0/24

# Continuously watch and alert on change
./bin/corvus watch 192.168.1.0/24 --alert-on new-port,cert-change,banner-drift

# Passive OSINT pre-scan, no active packets
./bin/corvus predict 203.0.113.0/24

# Query history
./bin/corvus query "services with version drift in the last 7 days"

# Run the API server (+ web dashboard if present)
./bin/corvus serve
```

### CLI surface

```
scan      Scan a host, range, or CIDR and detect changes
watch     Continuously monitor a target and alert on any change
predict   OSINT pre-scan / intelligence profile without active scanning
query     Query historical scan data
serve     Start the API server and web dashboard
node      Start a Corvus mesh node
tui       Launch the interactive dashboard
login     Authenticate the CLI for centralized/remote scans
import    Import an nmap XML scan (nmap -oX)
seed      Populate the store with sample data
```

### Selected API endpoints (`/api/v1`)

```
POST /scan            POST /query           GET  /hosts          GET /hosts/:ip
GET  /scan/:id        GET  /scan/:id/stream (WS)                 GET /alerts
POST /ask             GET  /supplychain/:ip GET  /mesh/nodes     GET /stats
POST /auth/login      POST /auth/signup     GET  /auth/me        ... /keys, /billing
GET  /healthz         GET  /readyz
```

---

## Project Layout

```
corvus-serverside/
├── cmd/corvus/        # Binary entrypoint (cobra CLI)
├── internal/
│   ├── scanner/         # TCP connect + SYN scan engines
│   ├── osint/           # CT logs, DNS, BGP/ASN, prediction model
│   ├── fingerprint/     # Banner grabbing, service identification
│   ├── store/           # Temporal graph store (bbolt)
│   ├── anomaly/         # Diff engine + alert sinks
│   ├── cve/             # NVD + OSV correlation with caching
│   ├── supplychain/     # Dev-tool / debug-endpoint detection
│   ├── mesh/            # Encrypted UDP gossip mesh (tested)
│   ├── llm/             # NL → query translation & summarisation
│   ├── query/           # Query execution engine
│   ├── api/             # Fiber server, handlers, middleware, WebSocket
│   ├── auth/            # JWT auth, sessions
│   ├── apikey/          # API-key issuance & gating
│   ├── billing/         # Paystack + crypto billing
│   ├── db/ users/       # Postgres access layer
│   ├── tui/             # Bubble Tea dashboard
│   └── otel/            # OpenTelemetry wiring
├── pkg/                 # iprange, logger, config (reusable)
├── migrations/          # Versioned SQL migrations
├── configs/  docs/  scripts/
```

---

## Status & Disclaimer

Corvus is a **personal engineering project under active development** — a demonstration of systems design in Go, not a certified security product. It compiles cleanly (`go build ./...`), passes `go vet`, and ships unit tests across the core packages (iprange, query parser, fingerprinting, OSINT attribution, supply-chain checks, anomaly diffing, auth, API keys, the temporal store, and the encrypted mesh), run on every push via GitHub Actions CI. Coverage elsewhere is still growing, and some integrations (email delivery, response webhooks, deep cloud-API correlation) are intentionally stubbed pending future work.

**Authorized use only.** Active scanning may be illegal or against policy on networks you do not own or lack written permission to assess. You are solely responsible for how you use this tool. The author accepts no liability for misuse or for any damage arising from its use. Provided **as-is**, without warranty of any kind.

## License & Usage

**© 2026 ObeeJ. All rights reserved.** This project is **proprietary and source-available** — see [LICENSE](LICENSE).

This code is published publicly for **portfolio and evaluation purposes only**. You are welcome to read it and assess the engineering. You may **not** copy, reuse, modify, redistribute, deploy, or build upon it — in whole or in part — without prior written permission from the author.

If you'd like to use, license, or collaborate on Corvus, please reach out. Please don't replicate or repackage it as your own.
