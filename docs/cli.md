# Corvus CLI

> Networks forget. Corvus doesn't.

The `corvus` binary works standalone — local scans need no account. An API key
is only required for **centralized/remote** scans that count against your plan
and feed the dashboard, history, and alerts.

## Commands

| Command | What it does |
|---------|--------------|
| `corvus scan <target>` | Local scan of a host/range/CIDR (free, unlimited). |
| `corvus scan <target> --remote` | Run the scan through the API — plan-gated, stored centrally. |
| `corvus watch <target>` | Continuously monitor a target and alert on changes. |
| `corvus predict <target>` | OSINT pre-scan (DNS/BGP/cloud ranges) — no active probing. |
| `corvus query "<expr>"` | Query historical scan state (`open ports on 10.0.0.0/24`). |
| `corvus tui` | Interactive terminal dashboard (hosts + query). Needs a TTY. |
| `corvus import <nmap.xml>` | Import an `nmap -oX` scan into Corvus. |
| `corvus seed` | Populate sample data for demos / empty dashboards. |
| `corvus login` | Store CLI credentials for `--remote` scans. |
| `corvus serve` / `node` | Run the API server / a mesh node. |

## Local vs remote scanning

Local scans run entirely on your machine and are never gated:

```bash
corvus scan 192.168.1.0/24
corvus scan 10.0.0.1 --ports 1-65535 --scan-type syn
```

Remote scans go through the Corvus API, enforce your plan quota
(free: 5 scans / 30 days; pro: unlimited), and persist to the dashboard:

```bash
corvus login                       # prompts for email + password, mints an API key
corvus scan 192.168.1.0/24 --remote
```

Credentials are stored at `~/.config/corvus/config.json` (mode `0600`). You can
also supply a key per-invocation:

```bash
corvus scan 10.0.0.0/24 --remote --api-key corvus_sk_... --api-url https://api.corvus.sh
# or
export CORVUS_API_KEY=corvus_sk_...
```

Already have a key? Store it without logging in:

```bash
corvus login --api-key corvus_sk_... --api-url https://api.corvus.sh
```

## Importing nmap scans

The bridge for existing nmap users — pull your scans into Corvus for history,
anomaly detection, and CVE correlation:

```bash
nmap -oX scan.xml 192.168.1.0/24
corvus import scan.xml
corvus query "open ports on 192.168.1.0/24"
```

## Output & color

All output uses the Industrial Precision palette (amber `#F97316`, monospace).
Color is automatically disabled when output is piped or `NO_COLOR` is set, so
logs and pipes stay clean.

## Managing API keys

Keys are created/listed/revoked from the dashboard (or directly):

```
POST   /api/v1/keys        { "label": "ci-runner" }   → returns the key once
GET    /api/v1/keys                                    → metadata only
DELETE /api/v1/keys/:id                                → revoke
```
