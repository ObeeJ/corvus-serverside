# Corvus — Full Product & Build Plan

## Context

Corvus is a stateful network intelligence engine built in Go. It goes beyond traditional port scanners by tracking how networks change over time, fusing passive OSINT before scanning, correlating CVEs and cloud security context, and answering plain-English questions via an LLM interface.

The product will be shipped as:
1. **Open source CLI** — core scanner, fingerprinting, anomaly detection, CVE lookup. Free forever.
2. **Cloud SaaS** — hosted on Railway, adds auth, billing, LLM, cloud API correlation, and the web dashboard.

Working name: **Corvus** (brand/domain not finalised — avoid hardcoding in user-facing strings, use a config constant).

---

## Business Model

### Pricing (rolling 30-day limits)

| Tier | Price | LLM Provider | Scans/day | Asks/30d | Alerts/day |
|---|---|---|---|---|---|
| Free | $0 | Groq (Llama 3.3 70B) | 3 | 20 | 5 |
| Starter | $3/mo | Claude Haiku | 20 | 200 | 50 |
| Pro | $19/mo | Claude Sonnet | Unlimited | 1,000 | Unlimited |
| Enterprise | Custom | Claude Opus | Unlimited | Unlimited | Unlimited |

**Philosophy:** Free tier is genuinely useful — powered by Groq so LLM cost is zero. $3 Starter is priced to remove any hesitation. Revenue comes from volume of Starter users + upsell to Pro for teams. Keep the free tier generous enough that users recommend it.

### Open Source Boundary
- **Free / open source:** Scanner engine, fingerprinting, anomaly detection, OSINT, CVE lookup, CLI, self-hosted store
- **Cloud SaaS only:** Web dashboard, auth/accounts, LLM `ask` interface, cloud API correlation (AWS), Stripe billing, multi-tenant data isolation, OpenTelemetry managed export

Self-hosters get a powerful CLI tool. Cloud users get the full product. This is the standard open-core model.

### Billing Implementation
- **Stripe** — Checkout (hosted payment page), Webhooks (subscription lifecycle), Customer Portal (self-serve management)
- Limits reset on rolling 30-day window (not calendar month)
- Usage tracked in PostgreSQL `usage_logs` table, checked via quota middleware on every API call
- LLM provider routed by plan at runtime

---

## Tech Stack

| Layer | Technology | Reason |
|---|---|---|
| Language | Go 1.22+ | Single binary, native concurrency, raw socket access |
| HTTP | gofiber/fiber v3 | fasthttp performance, WebSocket, clean middleware |
| Scan store | bbolt (embedded) | Zero-dependency, single file, works offline |
| User/billing DB | PostgreSQL (Railway addon) | Relational, multi-tenant, Stripe state |
| Migrations | golang-migrate | SQL migrations, version-controlled schema |
| Auth | JWT (golang-jwt/jwt v5) | Stateless, works with Railway |
| Payments | Stripe Go SDK | Checkout + webhooks + portal |
| Frontend | React + Vite + Tailwind CSS + shadcn/ui | Google/Claude aesthetic, professional minimal |
| LLM — Free | Groq (Llama 3.3 70B) | Free tier, fast inference |
| LLM — Starter | Claude Haiku | Cheap, fast structured output |
| LLM — Pro | Claude Sonnet 4.6 | Best quality answers |
| LLM — Enterprise | Claude Opus | Maximum capability |
| Cloud API | aws-sdk-go-v2 | AWS security group correlation |
| Cloud dev | LocalStack | Fake AWS locally, no real account needed |
| Observability | OpenTelemetry Go SDK | Metrics + traces + Prometheus endpoint |
| Deploy | Railway | Backend binary + PostgreSQL + persistent volume |
| CI/CD | GitHub Actions | Build, test, lint, Docker push |

---

## Project Structure (Final)

```
corvus/
├── cmd/corvus/           # Binary entrypoint (cobra CLI)
├── internal/
│   ├── scanner/            # TCP connect, SYN (raw), UDP engines
│   ├── osint/              # CT logs, DNS, BGP, AWS IP range detection
│   ├── fingerprint/        # Banner grab, service + version ID
│   ├── store/              # bbolt temporal graph (scan data)
│   ├── anomaly/            # State diff, alert dispatch, sinks
│   ├── cve/                # NVD + OSV + GitHub Advisory + local cache
│   ├── supplychain/        # Dev tool detection, hygiene ruleset
│   ├── cloud/              # AWS security group correlation
│   ├── llm/                # Provider interface + Groq/Haiku/Sonnet/Opus routing
│   ├── query/              # Query plan execution against store
│   ├── mesh/               # Gossip protocol (hashicorp/memberlist)
│   ├── api/                # Fiber HTTP server, routes, WebSocket
│   ├── auth/               # JWT middleware, signup/login handlers
│   ├── billing/            # Stripe checkout, webhook, portal, quota middleware
│   ├── otel/               # OpenTelemetry SDK init, metrics, traces
│   └── db/                 # PostgreSQL client, migrations
├── web/                    # React + Vite dashboard (built into binary via embed.FS)
├── pkg/
│   ├── iprange/            # CIDR parsing and iteration
│   └── logger/             # slog structured logger
├── migrations/             # SQL migration files
├── configs/
│   └── default.yaml        # Default config (all integrations off by default)
├── scripts/                # Install, LocalStack setup
├── docs/                   # SYSTEM_DESIGN, USE_CASES, BUILD_GUIDE, PRODUCT_PLAN
└── .github/workflows/      # CI, release, Docker
```

---

## Database Schema (PostgreSQL)

```sql
-- Users and auth
users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT 'free',  -- free | starter | pro | enterprise
  created_at TIMESTAMPTZ
)

-- Stripe billing state
subscriptions (
  user_id UUID REFERENCES users(id),
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  status TEXT,  -- active | cancelled | past_due
  current_period_end TIMESTAMPTZ
)

-- Rolling 30-day usage tracking
usage_logs (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  feature TEXT NOT NULL,  -- scan | ask | alert
  created_at TIMESTAMPTZ NOT NULL
)
-- Quota check: SELECT COUNT(*) FROM usage_logs
--   WHERE user_id=$1 AND feature=$2 AND created_at > NOW() - INTERVAL '30 days'
```

---

## Build Phases

### Phase 1 — Working Core (Weeks 1–4)
Goal: `corvus scan 192.168.1.0/24` works end-to-end.

- `go mod init github.com/ObeeJ/corvus`
- Install all dependencies
- `pkg/logger` — slog structured logger
- `pkg/iprange` — CIDR parser and iterator
- `internal/store` — bbolt temporal graph store
- `internal/scanner` — TCP connect scan engine (worker pool, rate limiter)
- `internal/fingerprint` — banner grab, regex service/version ID
- `internal/anomaly` — state diff, stdout alert sink
- `cmd/corvus` — cobra CLI: `scan`, `watch` commands

Deliverable: binary that scans, stores results, detects changes, prints output.

---

### Phase 2 — Intelligence Layer (Weeks 5–7)
Goal: smarter than nmap before sending packets.

- `internal/osint` — crt.sh CT logs, DNS forward/reverse, Team Cymru BGP/ASN
- `internal/cve` — NVD + OSV + GitHub Advisory, bbolt cache, deduplication
- `internal/supplychain` — hygiene ruleset (debug ports, dev tools, reverse shell ports)
- `internal/scanner` extended — SYN scan (raw sockets, requires CAP_NET_RAW), UDP scan with ICMP backoff
- CLI extended — `predict`, `query` commands

Deliverable: `corvus scan --predict` works with CVEs and hygiene flags inline.

---

### Phase 3 — API + Dashboard (Weeks 8–11)
Goal: full web interface, professional and minimal (Google/Claude aesthetic).

- `internal/query` — query plan execution engine
- `internal/api` — Fiber REST API, WebSocket streaming, embed React build
- `web/` — React + Vite + Tailwind + shadcn/ui dashboard

Dashboard screens (all required for MVP):
1. **Live scan view** — streaming ports appear as discovered, service + CVE inline
2. **Host list** — IP, port count, risk score, last seen
3. **Host detail** — port history timeline, CVEs, cloud context, anomaly log
4. **Alert feed** — live anomaly stream, filterable by type/severity
5. **Ask page** — clean text input, LLM answer rendered in markdown
6. **Settings** — scan targets, alert sinks, integrations toggle

Design direction: `#FAFAFA` background, `#111` text, slate accent, Inter font body,
JetBrains Mono for IPs/ports/banners, shadcn Card/Table/Badge components throughout.

Deliverable: full working UI served from the Go binary.

---

### Phase 3b — Auth + Billing + Multi-tenancy (Weeks 12–13)
Goal: users can sign up, pay, and have fully isolated data.

- PostgreSQL setup on Railway with golang-migrate
- `internal/auth` — signup, login, JWT issue/verify middleware
- Multi-tenancy — every bbolt store keyed by `user_id`, every Postgres query scoped by `user_id`
- `internal/billing` — Stripe checkout, webhook handler, customer portal redirect
- Quota middleware — checks rolling 30-day usage before every scan/ask/alert, returns 429 with upgrade URL on limit hit
- LLM routing — provider selected by `user.Plan` at request time
- Dashboard screens: login, signup, pricing page, billing management

Deliverable: full SaaS with working payments and isolated user data.

---

### Phase 4 — Integrations & Active Response (Weeks 14–17)
Goal: modern integrations and automated remediation all live.

- `internal/llm` — provider interface, Groq/Haiku/Sonnet/Opus clients, `ask` CLI + `/api/v1/ask` endpoint
- `internal/cloud` — AWS SDK v2, EC2 DescribeInstances + DescribeSecurityGroups, LocalStack for dev
- `internal/otel` — OTLP metrics + traces + Prometheus `/metrics` endpoint
- Alert sinks — Slack webhook, generic HTTP webhook, PagerDuty
- `internal/response` — Active Response framework to automatically remediate critical threats (e.g. modify AWS Security Groups or local iptables rules)

Deliverable: LLM queries work tier-routed, AWS correlation works against LocalStack locally and real AWS in prod, and critical alerts can trigger automated remediation.

---

### Phase 5 — Distributed Mesh (Weeks 18–19)
Goal: multiple Corvus nodes coordinate scans.

- `internal/mesh` — hashicorp/memberlist gossip, node join/leave, CIDR division, result broadcast, AES mesh encryption
- CLI: `node` command
- API: `/api/v1/mesh/nodes` endpoint

---

### Phase 6 — Deploy + Polish (Week 20)
Goal: production-ready on Railway.

- `railway.toml` config, persistent volume mount at `/var/lib/corvus/`
- Docker multi-stage build (builder + minimal runtime image)
- GitHub Actions: build + test + lint on PR, Docker push + Railway deploy on main
- README install instructions, quick start guide

---

## Critical Implementation Notes

1. **bbolt is per-user in cloud mode.** Each user gets their own bbolt file at `/var/lib/corvus/{user_id}.db`. In CLI/self-hosted mode, single file at configured path.

2. **SYN scan requires root.** At startup, if SYN scan is requested without `CAP_NET_RAW`, fall back to TCP connect with a warning — never hard fail.

3. **LLM is never on the critical path.** If API key is missing or provider is down, `ask` returns an error. Every other feature keeps working.

4. **Railway persistent volume.** Must be mounted at `/var/lib/corvus/`. Without it, all bbolt data is lost on redeploy. Document this prominently.

5. **Stripe webhook secret.** Must be verified on every incoming webhook using `stripe.ConstructEvent`. Never trust webhook payloads without signature verification.

6. **Product name constant.** Use `const ProductName = "Corvus"` in `pkg/config/brand.go` so it can be changed before launch without a find-replace across the codebase.

---

## Immediate Next Step

Start Phase 1. First command:

```bash
cd /home/obeej/Desktop/corvus
go mod init github.com/ObeeJ/corvus
```

Then install dependencies and write `pkg/logger/logger.go` as the first Go file.
