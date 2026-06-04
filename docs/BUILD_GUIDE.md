# Corvus Build Guide

This guide walks through building Corvus from nothing to a working binary, one layer at a time. Every function is explained in plain English before the code is shown. Every block of code is translated into what it actually does, why it exists, and what would break if it were removed.

Read this guide in order. Each layer depends on the one before it. Do not skip layers.

---

## Table of Contents

1. [Layer 0: Project Initialization](#layer-0-project-initialization)
2. [Layer 1: Logger (pkg/logger)](#layer-1-logger)
3. [Layer 2: IP Range Parser (pkg/iprange)](#layer-2-ip-range-parser)
4. [Layer 3: Store (internal/store)](#layer-3-store)
5. [Layer 4: Scanner Core (internal/scanner)](#layer-4-scanner-core)
6. [Layer 5: OSINT Engine (internal/osint)](#layer-5-osint-engine)
7. [Layer 6: Fingerprint Engine (internal/fingerprint)](#layer-6-fingerprint-engine)
8. [Layer 7: Anomaly Engine (internal/anomaly)](#layer-7-anomaly-engine)
9. [Layer 8: CVE Correlator (internal/cve)](#layer-8-cve-correlator)
10. [Layer 9: Query Engine (internal/query)](#layer-9-query-engine)
11. [Layer 10: Mesh (internal/mesh)](#layer-10-mesh)
12. [Layer 11: API Server (internal/api)](#layer-11-api-server)
13. [Layer 12: CLI Entrypoint (cmd/corvus)](#layer-12-cli-entrypoint)

---

## Layer 0: Project Initialization

### What we are doing

Before any code, we need a Go module. A Go module is a named, versioned unit of code. The module name is how Go identifies this project and how internal packages import each other.

### Commands

```bash
cd /home/obeej/prjcts/corvus
go mod init github.com/ObeeJ/corvus
```

**In plain English:** This tells Go "this directory is a project called github.com/ObeeJ/corvus." Every package inside this project will import each other using paths that start with that name. For example, the scanner package will be imported as `github.com/ObeeJ/corvus/internal/scanner`.

### Install dependencies

```bash
go get github.com/gofiber/fiber/v3
go get github.com/gofiber/websocket/v2
go get go.etcd.io/bbolt
go get github.com/hashicorp/memberlist
go get github.com/spf13/cobra
go get github.com/spf13/viper
go get golang.org/x/net
```

**In plain English:** These are the external libraries Corvus depends on. Go downloads them and records their exact versions in `go.sum` so that every developer building this project gets identical versions.

---

## Layer 1: Logger

**File:** `pkg/logger/logger.go`

### What this layer does

Every component in Corvus needs to write log messages. Rather than using `fmt.Println` scattered everywhere (which produces unstructured output), we use a structured logger. Structured logs are JSON lines where every field (timestamp, level, message, component name) is a named key-value pair. This makes logs machine-parseable by log aggregators like Loki, Datadog, or CloudWatch.

We use Go's standard library `log/slog` (added in Go 1.21). We do not import a third-party logging library. Zero extra dependency.

### Why every component receives the logger rather than using a global

If the logger were global, tests would produce log output to stdout during testing (noisy), and you could not configure different log levels for different components. Passing the logger as a parameter gives each component its own named instance and makes tests clean.

### The code, block by block

```go
package logger

import (
    "log/slog"
    "os"
)
```

**What this does:** Declares this file belongs to the `logger` package. Imports `log/slog` (the structured logger) and `os` (to write to stdout).

```go
type Config struct {
    Level  string // "debug", "info", "warn", "error"
    Format string // "json" or "text"
}
```

**What this does:** Defines a configuration struct. Instead of accepting five separate parameters in a function call, we accept one Config struct. This makes it easy to add new options later without changing every call site.

**In plain English:** Config is a small form that says "what kind of logger do you want?" The caller fills it in and hands it to `New`.

```go
func New(component string, cfg Config) *slog.Logger {
    level := slog.LevelInfo
    switch cfg.Level {
    case "debug":
        level = slog.LevelDebug
    case "warn":
        level = slog.LevelWarn
    case "error":
        level = slog.LevelError
    }
```

**What this does:** Creates a new logger. The `component` string will appear in every log line as `"component": "scanner"` or `"component": "osint"` so you can filter logs by which part of the system produced them.

The switch statement converts the string level ("debug") to the internal constant (`slog.LevelDebug`). Switch defaults to `slog.LevelInfo` so if the config says something invalid, the logger still works.

**In plain English:** This function takes a name and a config and produces a logger. Think of it as "give me a logger for the scanner" — then every log line from the scanner will be tagged with that name.

```go
    var handler slog.Handler
    opts := &slog.HandlerOptions{Level: level}

    if cfg.Format == "json" {
        handler = slog.NewJSONHandler(os.Stdout, opts)
    } else {
        handler = slog.NewTextHandler(os.Stdout, opts)
    }

    return slog.New(handler).With("component", component)
}
```

**What this does:** Creates either a JSON handler (outputs `{"time":"...","level":"INFO","component":"scanner","msg":"..."}`) or a text handler (outputs `time=... level=INFO component=scanner msg=...`). Then creates the logger with `slog.New` and permanently attaches the component name using `.With`.

`.With("component", component)` means: "add this key-value pair to every single log line this logger ever produces, without the caller having to remember to include it."

**In plain English:** This is the part that actually builds the logger and stamps every message with the component's name.

---

## Layer 2: IP Range Parser

**File:** `pkg/iprange/parser.go`

### What this layer does

The scanner needs to iterate over IP addresses. A user might specify a single IP (`192.168.1.1`), a CIDR range (`192.168.1.0/24`), or a range expression (`192.168.1.1-192.168.1.50`). This package parses all three formats and produces an iterator — a function you call repeatedly to get the next IP address.

### Why an iterator instead of a slice

If the user specifies `10.0.0.0/8`, that is 16 million IP addresses. Storing all 16 million as a slice would use ~384MB of memory just for the IP list. An iterator produces one IP at a time, using constant memory regardless of the range size.

### The code, block by block

```go
package iprange

import (
    "encoding/binary"
    "fmt"
    "net"
)
```

**What this does:** `encoding/binary` lets us convert between IP addresses (which are 4-byte sequences) and integers. We need integer arithmetic to increment through a range. `net` provides `net.IP` and `net.ParseCIDR`.

```go
type Iterator struct {
    current uint32
    end     uint32
}
```

**What this does:** Represents a range of IPs as two integers. `current` is the IP we are about to yield. `end` is the last IP in the range. Both are stored as 32-bit unsigned integers because IPv4 addresses are 32 bits. This makes increment and comparison simple integer operations.

**In plain English:** Instead of a list of all IPs, we just remember "where we are" and "where we stop." Like a for-loop counter.

```go
func (it *Iterator) Next() (net.IP, bool) {
    if it.current > it.end {
        return nil, false
    }
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, it.current)
    it.current++
    return ip, true
}
```

**What this does:** `Next` is the core of the iterator. If we have passed the end, return `nil, false` (the caller knows we are done). Otherwise, convert the current integer back into a 4-byte IP using big-endian byte order (standard network byte order), increment the counter, and return the IP.

**In plain English:** Every time you call Next, it gives you the next IP address in the range, like turning a page. When there are no more pages, it tells you by returning false.

**Why `binary.BigEndian`:** Network protocols store integers with the most significant byte first (big-endian). `192.168.1.1` is stored as bytes `[192, 168, 1, 1]`. If we used little-endian, the bytes would be reversed and the IP would be wrong.

```go
func ParseCIDR(cidr string) (*Iterator, error) {
    _, network, err := net.ParseCIDR(cidr)
    if err != nil {
        return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
    }

    start := binary.BigEndian.Uint32(network.IP)
    mask := binary.BigEndian.Uint32(network.Mask)
    end := (start & mask) | (^mask)

    return &Iterator{current: start, end: end}, nil
}
```

**What this does:** Parses a CIDR string. `net.ParseCIDR("192.168.1.0/24")` returns the network address and mask. We convert both to integers, then compute the broadcast address (the last IP in the range) using bitwise NOT on the mask.

**The math in plain English:** If the network is `192.168.1.0` and the mask is `255.255.255.0`, then NOT-mask is `0.0.0.255`. The broadcast is `192.168.1.0 | 0.0.0.255 = 192.168.1.255`. That is the last address in the /24 range.

```go
func ParseSingle(ip string) (*Iterator, error) {
    parsed := net.ParseIP(ip).To4()
    if parsed == nil {
        return nil, fmt.Errorf("invalid IPv4 address: %q", ip)
    }
    addr := binary.BigEndian.Uint32(parsed)
    return &Iterator{current: addr, end: addr}, nil
}
```

**What this does:** Parses a single IP address. Sets `current` and `end` to the same value so `Next` returns exactly one IP.

**In plain English:** A single IP is a "range" of exactly one address. By making it an Iterator like everything else, the rest of the code does not need to know whether it is iterating over one IP or a million.

```go
func Parse(input string) (*Iterator, error) {
    if strings.Contains(input, "/") {
        return ParseCIDR(input)
    }
    if strings.Contains(input, "-") {
        return parseRange(input)
    }
    return ParseSingle(input)
}
```

**What this does:** The public entry point. Dispatches to the right parser based on what the input looks like. Contains `/`? It is a CIDR. Contains `-`? It is a range expression. Otherwise, it is a single IP.

**In plain English:** This is the front door. You hand it whatever the user typed, and it figures out what kind of thing it is and returns an iterator.

---

## Layer 3: Store

**File:** `internal/store/store.go`

### What this layer does

The store is Corvus's memory. Every scan result is written here. Every query reads from here. Every anomaly check compares against what is here. Without the store, Corvus is just another snapshot scanner.

The store uses bbolt, an embedded key-value database. The entire database is a single file on disk. No server process, no configuration, no external dependency.

### Data model in plain English

Think of the store as a set of nested folders:

```
hosts/
  192.168.1.1/
    ports/
      80/
        "2026-05-09T10:00:00Z" -> {open: true, banner: "nginx", ...}
        "2026-05-08T10:00:00Z" -> {open: true, banner: "nginx", ...}
      443/
        ...
```

Each IP address is a folder. Inside it, each port number is a folder. Inside that, each timestamp is a file containing the scan result for that port at that moment in time.

### The code, block by block

```go
package store

import (
    "encoding/json"
    "fmt"
    "time"

    bolt "go.etcd.io/bbolt"
)
```

**What this does:** Imports the bbolt package (aliased as `bolt` to match its historical name) and standard libraries for JSON encoding and time handling.

```go
var (
    bucketHosts  = []byte("hosts")
    bucketAlerts = []byte("alerts")
    bucketMeta   = []byte("meta")
)
```

**What this does:** Defines the top-level bucket names as byte slices. In bbolt, bucket names are raw bytes. These constants are declared here once so that every part of the code uses the same spelling. A typo in a bucket name would silently create a new empty bucket instead of reading from the right one.

**In plain English:** These are the names of the top-level folders in the database. By declaring them as constants, we make it impossible to accidentally misspell them.

```go
type StateRecord struct {
    Timestamp      time.Time `json:"timestamp"`
    Open           bool      `json:"open"`
    Banner         string    `json:"banner"`
    ServiceName    string    `json:"service_name"`
    Version        string    `json:"version"`
    TLSFingerprint string    `json:"tls_fingerprint"`
    ResponseMs     int64     `json:"response_ms"`
    CVEs           []string  `json:"cves"`
}
```

**What this does:** Defines the shape of one scan result record. Every field has a JSON tag so it serializes predictably regardless of how the struct is named or reordered in the future.

**In plain English:** This is one row in the database. It answers: "At this timestamp, was this port open? What service was running? What version? Were there CVEs?"

```go
type Store struct {
    db *bolt.DB
}

func Open(path string) (*Store, error) {
    db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
    if err != nil {
        return nil, fmt.Errorf("open store at %q: %w", path, err)
    }

    err = db.Update(func(tx *bolt.Tx) error {
        for _, name := range [][]byte{bucketHosts, bucketAlerts, bucketMeta} {
            if _, err := tx.CreateBucketIfNotExists(name); err != nil {
                return err
            }
        }
        return nil
    })
    if err != nil {
        return nil, fmt.Errorf("initialize buckets: %w", err)
    }

    return &Store{db: db}, nil
}
```

**What this does:** Opens the bbolt database file at `path`. File permissions `0600` mean only the owner can read and write (important for a file containing network intelligence data). The `Timeout: 1s` means if another process has the database locked, we fail fast rather than waiting forever.

After opening, we run a write transaction that creates the three top-level buckets if they do not already exist. `CreateBucketIfNotExists` is idempotent — safe to call every time the store opens.

**In plain English:** This is like opening a binder and making sure the right divider tabs are already in it. If they are not there yet, we add them. If they are already there, we leave them alone.

```go
func (s *Store) WriteState(ip string, port uint16, record StateRecord) error {
    return s.db.Update(func(tx *bolt.Tx) error {
        // Navigate to: hosts -> ip -> ports -> port number
        hosts := tx.Bucket(bucketHosts)

        hostBucket, err := hosts.CreateBucketIfNotExists([]byte(ip))
        if err != nil {
            return err
        }

        portsBucket, err := hostBucket.CreateBucketIfNotExists([]byte("ports"))
        if err != nil {
            return err
        }

        portKey := fmt.Sprintf("%d", port)
        portBucket, err := portsBucket.CreateBucketIfNotExists([]byte(portKey))
        if err != nil {
            return err
        }

        // Key is the timestamp, value is the JSON-encoded record
        key := record.Timestamp.UTC().Format(time.RFC3339Nano)
        value, err := json.Marshal(record)
        if err != nil {
            return err
        }

        return portBucket.Put([]byte(key), value)
    })
}
```

**What this does:** Writes one StateRecord to the nested bucket structure. The write happens inside a bbolt transaction (`db.Update`). If any step fails, the entire transaction is rolled back automatically.

The key is the RFC3339Nano timestamp string (e.g., `2026-05-09T10:00:00.000000000Z`). RFC3339 timestamps sort lexicographically in chronological order — the earliest timestamp comes first alphabetically. This is a crucial property: it means we can iterate through a port bucket in time order without sorting.

**In plain English:** This function drills down through the nested folders (hosts → this IP → ports → this port number) and writes the scan result as a JSON file. The filename is the timestamp.

```go
func (s *Store) ReadLatestState(ip string, port uint16) (*StateRecord, error) {
    var record *StateRecord

    err := s.db.View(func(tx *bolt.Tx) error {
        hosts := tx.Bucket(bucketHosts)
        hostBucket := hosts.Bucket([]byte(ip))
        if hostBucket == nil {
            return nil // no data for this host yet
        }

        portsBucket := hostBucket.Bucket([]byte("ports"))
        if portsBucket == nil {
            return nil
        }

        portBucket := portsBucket.Bucket([]byte(fmt.Sprintf("%d", port)))
        if portBucket == nil {
            return nil
        }

        // Cursor.Last() gives us the lexicographically last key,
        // which is the most recent timestamp
        cursor := portBucket.Cursor()
        _, value := cursor.Last()
        if value == nil {
            return nil
        }

        var r StateRecord
        if err := json.Unmarshal(value, &r); err != nil {
            return err
        }
        record = &r
        return nil
    })

    return record, err
}
```

**What this does:** Reads the most recent StateRecord for a given host and port. Uses `db.View` (read-only transaction). Navigates to the port bucket and calls `cursor.Last()` to get the lexicographically last key — which, because our keys are RFC3339 timestamps, is the most recent one.

**In plain English:** This function opens the folder for this IP and port, finds the most recent file (by alphabetical order, which equals chronological order for RFC3339 timestamps), reads it, and returns it.

```go
func (s *Store) Close() error {
    return s.db.Close()
}
```

**What this does:** Closes the database file. Always called on shutdown to flush any pending writes and release the file lock. In Go, this is typically called with `defer store.Close()` immediately after `Open`.

---

## Layer 4: Scanner Core

**File:** `internal/scanner/scanner.go`, `tcp.go`, `syn.go`, `udp.go`, `result.go`

### What this layer does

The scanner performs the actual network probing. It takes a list of IP addresses and port numbers, sends packets, observes responses, and produces results. The rest of the system does not care which scan type was used — it only sees a stream of results.

### The Result type (result.go)

```go
package scanner

import (
    "net"
    "time"
)

type Result struct {
    IP        net.IP
    Port      uint16
    Open      bool
    Banner    []byte    // raw bytes received from the service
    Latency   time.Duration
    Error     error     // nil if probe succeeded (open or cleanly refused)
    Timestamp time.Time
}
```

**What this does:** Defines what one scan probe produces. Open means the port responded positively. Banner is the raw bytes the service sent (may be empty). Error captures network-level failures distinct from closed ports.

**In plain English:** After probing one port on one host, the scanner produces a Result that says "here is what I found."

### The Scanner interface (scanner.go)

```go
package scanner

import (
    "context"
    "log/slog"
)

type Scanner interface {
    Scan(ctx context.Context, targets <-chan Target, results chan<- Result)
}

type Target struct {
    IP   net.IP
    Port uint16
}
```

**What this does:** Declares the `Scanner` interface. Any type that has a `Scan` method with this signature is a Scanner. This means `TCPScanner`, `SYNScanner`, and `UDPScanner` are all interchangeable. The rest of the system only talks to this interface, never to a concrete type.

**The channel-based design in plain English:** `targets` is a channel that someone pushes IP:port pairs into. The scanner reads from it and writes results into `results`. The scanner does not know where the targets came from or who is reading the results. This separation means we can plug any producer and any consumer together without changing the scanner.

`context.Context` carries a cancellation signal. When the user presses Ctrl+C, the context is cancelled and the scanner stops cleanly.

### TCP Connect Scanner (tcp.go)

```go
package scanner

import (
    "context"
    "fmt"
    "log/slog"
    "net"
    "time"
)

type TCPScanner struct {
    Timeout     time.Duration
    Concurrency int
    log         *slog.Logger
}
```

**What this does:** Defines the TCP scanner struct. `Timeout` is how long to wait for a connection before deciding the port is closed or filtered. `Concurrency` is how many simultaneous connection attempts to make.

```go
func (s *TCPScanner) Scan(ctx context.Context, targets <-chan Target, results chan<- Result) {
    sem := make(chan struct{}, s.Concurrency)

    for {
        select {
        case <-ctx.Done():
            return
        case target, ok := <-targets:
            if !ok {
                return // targets channel closed, we are done
            }

            sem <- struct{}{} // acquire slot (blocks if at concurrency limit)
            go func(t Target) {
                defer func() { <-sem }() // release slot when done
                results <- s.probe(ctx, t)
            }(target)
        }
    }
}
```

**What this does:** The core scan loop. Reads targets from the channel one at a time. For each target, acquires a slot in the semaphore (a buffered channel used as a counting semaphore), launches a goroutine to probe the target, and releases the slot when done. The `select` on `ctx.Done()` means cancellation is responsive — the loop stops immediately when cancelled, not at the next target.

**The semaphore in plain English:** Imagine a parking lot with 1000 spaces. Each goroutine needs a parking space to run. When all 1000 spaces are taken, new goroutines wait at the entrance. When a goroutine finishes, it leaves and a waiting goroutine takes its space. This prevents us from launching 16 million goroutines for a /8 scan.

**Why `target` is captured as a parameter to the goroutine:** In Go, goroutines capture variables from the enclosing scope by reference. If we wrote `go func() { s.probe(target) }()` without the parameter, all goroutines might probe the same (last) target due to the loop variable being shared. Passing it as a parameter creates a copy per goroutine.

```go
func (s *TCPScanner) probe(ctx context.Context, t Target) Result {
    address := fmt.Sprintf("%s:%d", t.IP, t.Port)
    start := time.Now()

    conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)

    result := Result{
        IP:        t.IP,
        Port:      t.Port,
        Timestamp: start,
        Latency:   time.Since(start),
    }

    if err != nil {
        result.Open = false
        result.Error = err
        return result
    }

    defer conn.Close()
    result.Open = true

    // Read banner: give the service 2 seconds to send something
    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    buf := make([]byte, 4096)
    n, _ := conn.Read(buf)
    result.Banner = buf[:n]

    return result
}
```

**What this does:** The actual probe. Attempts a TCP connection using `DialContext` (which respects context cancellation). If it fails, records the port as closed. If it succeeds, reads up to 4096 bytes from the connection within a 2-second deadline (the banner), then closes the connection.

**Why `conn.SetReadDeadline`:** Some services (like raw TCP ports with no application layer) will accept a connection but never send anything. Without a read deadline, the goroutine would hang forever waiting for a banner that never comes.

**In plain English:** Try to shake hands with the service. If it refuses, the port is closed. If it accepts, steal a look at the first thing it says (the banner), then hang up.

### Worker Pool (scanner.go)

```go
type Pool struct {
    scanner  Scanner
    targets  chan Target
    Results  chan Result
}

func NewPool(s Scanner, bufSize int) *Pool {
    return &Pool{
        scanner: s,
        targets: make(chan Target, bufSize),
        Results: make(chan Result, bufSize),
    }
}

func (p *Pool) Submit(ip net.IP, port uint16) {
    p.targets <- Target{IP: ip, Port: port}
}

func (p *Pool) Run(ctx context.Context) {
    go func() {
        p.scanner.Scan(ctx, p.targets, p.Results)
        close(p.Results)
    }()
}

func (p *Pool) Done() {
    close(p.targets)
}
```

**What this does:** Wraps the scanner in a pool that manages the channels. The caller submits targets via `Submit`, starts scanning with `Run`, signals all targets are submitted with `Done`, and reads results from `Results`.

**In plain English:** The Pool is the interface between "here is what I want scanned" and "here are the results." Submit feeds the machine. Done tells the machine you are finished feeding it. Results is where you pick up what the machine produced.

---

## Layer 5: OSINT Engine

**File:** `internal/osint/predict.go`, `ctlogs.go`, `dns.go`, `bgp.go`

### What this layer does

Before active scanning starts, the OSINT engine gathers passive intelligence about each target. It builds a `TargetProfile` that the scanner uses to order its probes.

### TargetProfile (predict.go)

```go
package osint

import "net"

type TargetProfile struct {
    IP              net.IP
    Hostnames       []string
    Organization    string
    ASN             uint32
    CloudProvider   string   // "aws", "gcp", "azure", or ""
    PortScores      map[uint16]float64 // port -> probability 0..1
}
```

**What this does:** The output of the OSINT phase for one IP address. `PortScores` is the key field: a map from port number to probability that the port is open. The scanner sorts ports by descending score.

**In plain English:** Before scanning, we know: who owns this IP, what it is probably named, what cloud it is in, and which ports are most likely open. The scanner uses this knowledge to be efficient.

### DNS Lookup (dns.go)

```go
func ReverseLookup(ip net.IP) ([]string, error) {
    names, err := net.LookupAddr(ip.String())
    if err != nil {
        return nil, err
    }
    return names, nil
}
```

**What this does:** Performs a PTR (reverse DNS) lookup. Given an IP address, returns the hostnames associated with it. Many organizations set PTR records that reveal what a machine is (`db-primary.prod.example.com`, `jenkins.ci.example.com`).

**In plain English:** Ask DNS "what is the name of this IP?" The name often tells you what the machine does, which tells you which ports to expect.

```go
func scoreFromHostname(hostname string, scores map[uint16]float64) {
    lower := strings.ToLower(hostname)
    rules := map[string]map[uint16]float64{
        "db":       {5432: 0.85, 3306: 0.80, 27017: 0.70},
        "postgres": {5432: 0.95},
        "mysql":    {3306: 0.95},
        "redis":    {6379: 0.95},
        "jenkins":  {8080: 0.90, 443: 0.80},
        "web":      {80: 0.90, 443: 0.90},
        "api":      {443: 0.90, 8080: 0.75},
        "ssh":      {22: 0.95},
        "mail":     {25: 0.90, 587: 0.85, 993: 0.80},
        "ldap":     {389: 0.90, 636: 0.80},
    }

    for keyword, portMap := range rules {
        if strings.Contains(lower, keyword) {
            for port, score := range portMap {
                if existing, ok := scores[port]; !ok || score > existing {
                    scores[port] = score
                }
            }
        }
    }
}
```

**What this does:** Pattern-matches the hostname against known keywords and assigns probability scores to ports. A host named `db-primary.example.com` gets a 0.95 score for port 5432 (Postgres) and 0.80 for port 3306 (MySQL).

**In plain English:** If the hostname contains "db", there is a high chance the host is a database server. Database servers tend to run on specific ports. So we increase the scan priority for those ports.

### Certificate Transparency Lookup (ctlogs.go)

```go
func QueryCTLogs(domain string) ([]string, error) {
    url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var entries []struct {
        NameValue string `json:"name_value"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
        return nil, err
    }

    seen := map[string]bool{}
    var names []string
    for _, e := range entries {
        for _, name := range strings.Split(e.NameValue, "\n") {
            name = strings.TrimSpace(name)
            if name != "" && !seen[name] {
                seen[name] = true
                names = append(names, name)
            }
        }
    }
    return names, nil
}
```

**What this does:** Queries crt.sh, a public CT log search engine. Certificate transparency logs record every TLS certificate ever issued. Querying for a domain returns all subdomains that have ever had a certificate issued — including internal subdomains that are not in public DNS.

**In plain English:** Every time someone issues an HTTPS certificate, it is recorded in a public log. We query that log to find all the subdomains and internal hostnames associated with a target's domain. This reveals infrastructure that is invisible to normal DNS queries.

---

## Layer 6: Fingerprint Engine

**File:** `internal/fingerprint/banner.go`, `service.go`

### What this layer does

Takes the raw banner bytes from the scanner and produces a human-readable service identification with version.

### Service identification (service.go)

```go
package fingerprint

import (
    "regexp"
    "strings"
)

type Match struct {
    ServiceName string
    Version     string
    Confidence  float64 // 0..1
}

type rule struct {
    pattern    *regexp.Regexp
    service    string
    versionSub int // capture group index for version
}
```

**What this does:** Defines the data structures for fingerprinting. A `Match` is the output: we identified the service as X, version Y, with confidence Z. A `rule` is one entry in the pattern library.

```go
var rules = []rule{
    {
        pattern:    regexp.MustCompile(`(?i)SSH-(\d+\.\d+)-OpenSSH_(\S+)`),
        service:    "openssh",
        versionSub: 2,
    },
    {
        pattern:    regexp.MustCompile(`(?i)Server:\s*nginx/(\S+)`),
        service:    "nginx",
        versionSub: 1,
    },
    {
        pattern:    regexp.MustCompile(`(?i)Server:\s*Apache/(\S+)`),
        service:    "apache",
        versionSub: 1,
    },
    {
        pattern:    regexp.MustCompile(`^\+OK`),
        service:    "pop3",
        versionSub: 0,
    },
    {
        pattern:    regexp.MustCompile(`^\*\s+OK`),
        service:    "imap",
        versionSub: 0,
    },
    {
        pattern:    regexp.MustCompile(`^220.*ESMTP`),
        service:    "smtp",
        versionSub: 0,
    },
    {
        pattern:    regexp.MustCompile(`^\-ERR`),
        service:    "redis",
        versionSub: 0,
    },
    {
        pattern:    regexp.MustCompile(`PostgreSQL`),
        service:    "postgresql",
        versionSub: 0,
    },
}
```

**What this does:** The rule library. Each entry is a regular expression that matches a known service banner, the service name, and which capture group contains the version string.

**In plain English:** This is a lookup table. Each row says "if the banner matches this pattern, it is this service, and the version is in this part of the match."

```go
func Identify(banner []byte) Match {
    text := string(banner)

    for _, r := range rules {
        matches := r.pattern.FindStringSubmatch(text)
        if matches == nil {
            continue
        }

        version := ""
        if r.versionSub > 0 && r.versionSub < len(matches) {
            version = matches[r.versionSub]
        }

        return Match{
            ServiceName: r.service,
            Version:     version,
            Confidence:  0.9,
        }
    }

    return Match{
        ServiceName: "unknown",
        Version:     "",
        Confidence:  0.0,
    }
}
```

**What this does:** Runs the banner against each rule in order. Returns the first match. If nothing matches, returns "unknown". Rules are ordered by specificity (more specific patterns first) so that the most precise identification wins.

**In plain English:** Look at the banner. Try each pattern in the library. The first one that fits tells you what service is running. If nothing fits, give up and say "unknown."

---

## Layer 7: Anomaly Engine

**File:** `internal/anomaly/detector.go`

### What this layer does

Compares new scan results against the previous known state and emits events when something meaningful changed.

```go
package anomaly

import (
    "time"
    "github.com/ObeeJ/corvus/internal/store"
)

type EventType string

const (
    EventNewPort       EventType = "new-port"
    EventPortClosed    EventType = "port-closed"
    EventBannerDrift   EventType = "banner-drift"
    EventCertRotation  EventType = "cert-rotation"
    EventVersionDrift  EventType = "version-drift"
    EventLatencySpike  EventType = "latency-spike"
    EventCriticalCVE   EventType = "critical-cve"
)

type Event struct {
    Type      EventType
    IP        string
    Port      uint16
    Timestamp time.Time
    Before    *store.StateRecord
    After     *store.StateRecord
    Detail    string
}
```

**What this does:** Defines the vocabulary of anomalies. Each `EventType` is a named string constant so they can be compared, logged, and filtered without magic strings.

**In plain English:** These are the names of the things Corvus can notice. When something changes, the change is described by one of these types.

```go
type Detector struct {
    store  *store.Store
    events chan<- Event
}

func (d *Detector) Analyze(ip string, port uint16, current *store.StateRecord) {
    previous, err := d.store.ReadLatestState(ip, port)
    if err != nil || previous == nil {
        // First time we have seen this host:port — if open, it is a new port
        if current.Open {
            d.events <- Event{
                Type:      EventNewPort,
                IP:        ip,
                Port:      port,
                Timestamp: current.Timestamp,
                After:     current,
            }
        }
        return
    }
```

**What this does:** The core analysis function. First, it reads the previous state from the store. If there is no previous state, this is a new host:port combination — if it is open, emit a `new-port` event.

**In plain English:** Look up what we knew about this port before. If we have never seen it before and it is open, that is automatically a "new port" event.

```go
    // Port state changed
    if !previous.Open && current.Open {
        d.events <- Event{Type: EventNewPort, IP: ip, Port: port,
            Timestamp: current.Timestamp, Before: previous, After: current}
    }
    if previous.Open && !current.Open {
        d.events <- Event{Type: EventPortClosed, IP: ip, Port: port,
            Timestamp: current.Timestamp, Before: previous, After: current}
    }

    // Banner changed
    if previous.Open && current.Open && previous.Banner != current.Banner {
        d.events <- Event{Type: EventBannerDrift, IP: ip, Port: port,
            Timestamp: current.Timestamp, Before: previous, After: current,
            Detail: fmt.Sprintf("was %q, now %q", previous.Banner, current.Banner)}
    }

    // TLS certificate changed
    if previous.TLSFingerprint != "" && current.TLSFingerprint != "" &&
        previous.TLSFingerprint != current.TLSFingerprint {
        d.events <- Event{Type: EventCertRotation, IP: ip, Port: port,
            Timestamp: current.Timestamp, Before: previous, After: current}
    }

    // Response time spiked more than 200%
    if previous.ResponseMs > 0 && current.ResponseMs > previous.ResponseMs*3 {
        d.events <- Event{Type: EventLatencySpike, IP: ip, Port: port,
            Timestamp: current.Timestamp, Before: previous, After: current,
            Detail: fmt.Sprintf("was %dms, now %dms", previous.ResponseMs, current.ResponseMs)}
    }
}
```

**What this does:** Performs the state diff. Compares every meaningful field between the previous and current records and emits an event for each meaningful change.

**In plain English:** Like a diff tool for network state. If a port changed state, emit an event. If the banner changed, emit an event. If the TLS certificate fingerprint changed, emit an event. If the response time tripled, emit an event.

**Why `current.ResponseMs > previous.ResponseMs*3` and not just `> previous.ResponseMs + 100`:** A threshold based on ratio (3x) is meaningful regardless of baseline latency. A host with 2ms baseline is anomalous at 6ms. A host with 100ms baseline is not anomalous at 106ms. Ratio-based thresholds adapt to the natural latency of each host.

---

## Layer 8: CVE Correlator

**File:** `internal/cve/correlator.go`

### What this layer does

After a service is fingerprinted, the CVE correlator queries the NVD (National Vulnerability Database) for known vulnerabilities in that service version.

```go
package cve

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "time"
)

type CVE struct {
    ID          string
    Description string
    CVSSv3      float64
    Severity    string // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    NVDURL      string
}
```

**What this does:** Defines one CVE record. These are attached to fingerprinted services in the scan results.

```go
func buildCPE(service, version string) string {
    // CPE 2.3 format: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*
    // For common services we use known vendor strings
    vendors := map[string]string{
        "nginx":      "nginx",
        "apache":     "apache",
        "openssh":    "openbsd",
        "postgresql": "postgresql",
        "redis":      "redis",
        "mysql":      "mysql",
    }
    vendor, ok := vendors[service]
    if !ok {
        vendor = service
    }
    return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, service, version)
}
```

**What this does:** Converts a service name and version into a CPE (Common Platform Enumeration) string, which is the identifier the NVD uses to match vulnerabilities to software.

**In plain English:** The NVD does not know what "nginx 1.22.0" means unless we format it as a CPE string. This function does that translation.

```go
func (c *Correlator) Lookup(service, version string) ([]CVE, error) {
    if version == "" {
        return nil, nil
    }

    cpe := buildCPE(service, version)

    // Check cache first
    if cached, ok := c.cache.Get(cpe); ok {
        return cached, nil
    }

    endpoint := "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params := url.Values{"cpeName": {cpe}, "resultsPerPage": {"20"}}
    req, _ := http.NewRequest("GET", endpoint+"?"+params.Encode(), nil)

    if c.apiKey != "" {
        req.Header.Set("apiKey", c.apiKey)
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, fmt.Errorf("NVD request: %w", err)
    }
    defer resp.Body.Close()

    // ... parse response, cache result, return CVEs
}
```

**What this does:** Checks the local cache first. If the result is not cached, queries the NVD API with the CPE string. Sets the API key header if one is configured (authenticated requests get higher rate limits from NVD).

**In plain English:** First check if we already asked this question recently. If yes, use the cached answer. If no, ask the NVD and save the answer for next time.

---

## Layer 9: Query Engine

**File:** `internal/query/parser.go`, `engine.go`

### What this layer does

Parses the intent-aware query DSL and executes it against the temporal store.

### Parser (parser.go)

```go
package query

import (
    "strings"
    "time"
)

type QueryPlan struct {
    Conditions  []Condition
    TargetCIDR  string
    Since       time.Time
    Until       time.Time
    OrderBy     string
    OrderDesc   bool
}

type Condition struct {
    Type  string // "open-port", "service", "cve-severity", "banner-contains"
    Value string
}
```

**What this does:** Defines the parsed query as a structured plan. `QueryPlan` is the output of parsing. The executor runs the plan against the store.

**In plain English:** The parser converts words into a data structure the executor can act on. "find all hosts with port 22 open" becomes `QueryPlan{Conditions: [{Type: "open-port", Value: "22"}]}`.

```go
func Parse(input string) (*QueryPlan, error) {
    input = strings.TrimSpace(strings.ToLower(input))
    plan := &QueryPlan{}

    // Extract time clause
    if idx := strings.Index(input, "in last"); idx != -1 {
        durationStr := strings.TrimSpace(input[idx+7:])
        d, err := time.ParseDuration(durationStr)
        if err == nil {
            plan.Since = time.Now().Add(-d)
            input = input[:idx]
        }
    }

    // Extract target
    if idx := strings.Index(input, "in "); idx != -1 {
        rest := strings.TrimSpace(input[idx+3:])
        fields := strings.Fields(rest)
        if len(fields) > 0 {
            plan.TargetCIDR = fields[0]
            input = input[:idx]
        }
    }

    // Extract conditions from remaining text
    plan.Conditions = parseConditions(input)

    return plan, nil
}
```

**What this does:** A hand-written parser that strips clauses from the query string from right to left. First extracts the time clause, then the target, then parses the remaining text as conditions.

**Why hand-written and not a parser generator:** This parser does not need to be a full grammar. The query language is intentionally simple. A hand-written parser is easier to debug, produces better error messages, and has zero external dependencies.

**In plain English:** Read the query from right to left: pull off the time part, pull off the target part, what is left must be the conditions. It is like disassembling a sentence word by word from the end.

---

## Layer 10: Mesh

**File:** `internal/mesh/node.go`, `gossip.go`

### What this layer does

Connects multiple Corvus instances so they share scan results and coordinate distributed scanning.

```go
package mesh

import (
    "encoding/json"
    "log/slog"

    "github.com/hashicorp/memberlist"
)

type Node struct {
    list      *memberlist.Memberlist
    broadcasts *memberlist.TransmitLimitedQueue
    log       *slog.Logger
}
```

**What this does:** Wraps hashicorp/memberlist. `list` is the gossip network. `broadcasts` is the queue of messages to send to all peers.

```go
func NewNode(cfg Config, log *slog.Logger) (*Node, error) {
    mlCfg := memberlist.DefaultWANConfig()
    mlCfg.Name = cfg.NodeID
    mlCfg.BindAddr = cfg.BindAddr
    mlCfg.BindPort = cfg.BindPort

    if cfg.Secret != "" {
        key, _ := hex.DecodeString(cfg.Secret)
        mlCfg.SecretKey = key
    }

    n := &Node{log: log}
    mlCfg.Delegate = n

    list, err := memberlist.Create(mlCfg)
    if err != nil {
        return nil, err
    }
    n.list = list
    n.broadcasts = &memberlist.TransmitLimitedQueue{
        NumNodes:       func() int { return list.NumMembers() },
        RetransmitMult: 3,
    }
    return n, nil
}
```

**What this does:** Creates a memberlist instance. `DefaultWANConfig` sets up the gossip protocol parameters for nodes that may be across the internet (as opposed to a LAN). The `Delegate` is this `Node` — memberlist calls methods on the delegate when it has messages to deliver.

**In plain English:** Set up the gossip network. Tell memberlist "I am this node, encrypt traffic with this key, and call me when messages arrive."

```go
func (n *Node) BroadcastResult(result ScanResult) {
    data, _ := json.Marshal(result)
    n.broadcasts.QueueBroadcast(&broadcast{data: data})
}

// Implements memberlist.Delegate
func (n *Node) NotifyMsg(data []byte) {
    var result ScanResult
    if err := json.Unmarshal(data, &result); err != nil {
        return
    }
    // Write the received result to local store
    n.onResult(result)
}
```

**What this does:** `BroadcastResult` sends a scan result to all peers via gossip. `NotifyMsg` is called by memberlist when a message from a peer arrives. We decode it and write it to the local store.

**In plain English:** When we find something, broadcast it. When a peer broadcasts something, receive it and save it locally. Every node ends up with the same data.

---

## Layer 11: API Server

**File:** `internal/api/server.go`, `routes.go`, `handlers/scan.go`

### What this layer does

Exposes Corvus over HTTP and WebSocket so other systems can trigger scans, query results, and receive real-time streams.

```go
package api

import (
    "github.com/gofiber/fiber/v3"
    "github.com/gofiber/fiber/v3/middleware/limiter"
    "log/slog"
)

type Server struct {
    app    *fiber.App
    engine *engine.Engine // the core Corvus engine
    log    *slog.Logger
}

func New(eng *engine.Engine, cfg Config, log *slog.Logger) *Server {
    app := fiber.New(fiber.Config{
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        ErrorHandler: errorHandler,
    })

    s := &Server{app: app, engine: eng, log: log}
    s.registerMiddleware()
    s.registerRoutes()
    return s
}
```

**What this does:** Creates the Fiber application with sensible timeouts. `ReadTimeout` prevents slow-loris attacks (clients that send requests very slowly to hold connections). `WriteTimeout` ensures streaming responses do not hang indefinitely.

```go
func (s *Server) registerMiddleware() {
    s.app.Use(limiter.New(limiter.Config{
        Max:        100,
        Expiration: time.Minute,
        KeyGenerator: func(c fiber.Ctx) string {
            return c.IP()
        },
    }))

    s.app.Use(func(c fiber.Ctx) error {
        token := c.Get("Authorization")
        if s.cfg.AuthToken != "" && token != "Bearer "+s.cfg.AuthToken {
            return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
                "error": "unauthorized",
            })
        }
        return c.Next()
    })
}
```

**What this does:** Registers two middleware functions that run before every request handler. The limiter rejects requests from any IP that exceeds 100 requests per minute. The auth middleware checks the `Authorization` header against the configured token.

**In plain English:** Every request passes through these filters before reaching the handler. The rate limiter says "no more than 100 requests per minute from any one address." The auth filter says "prove you have the token or get rejected."

```go
func (s *Server) registerRoutes() {
    v1 := s.app.Group("/api/v1")
    v1.Post("/scan", s.handlers.StartScan)
    v1.Get("/scan/:id", s.handlers.GetScan)
    v1.Get("/scan/:id/stream", websocket.New(s.handlers.StreamScan))
    v1.Post("/query", s.handlers.ExecuteQuery)
    v1.Get("/hosts", s.handlers.ListHosts)
    v1.Get("/hosts/:ip", s.handlers.GetHost)
    v1.Get("/alerts", s.handlers.ListAlerts)
    v1.Get("/mesh/nodes", s.handlers.ListMeshNodes)
}
```

**What this does:** Declares the URL routing table. Each route maps an HTTP method and path to a handler function. The `/scan/:id/stream` route upgrades to WebSocket for live result streaming.

```go
func (h *Handlers) StartScan(c fiber.Ctx) error {
    var req struct {
        Target  string `json:"target"`
        Predict bool   `json:"predict"`
        Ports   string `json:"ports"`
    }
    if err := c.BodyParser(&req); err != nil {
        return fiber.ErrBadRequest
    }

    job, err := h.engine.StartScan(c.Context(), engine.ScanConfig{
        Target:  req.Target,
        Predict: req.Predict,
        Ports:   req.Ports,
    })
    if err != nil {
        return err
    }

    return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
        "id":     job.ID,
        "status": "running",
    })
}
```

**What this does:** Parses the request body, starts a scan job on the engine (which runs asynchronously), and immediately returns a job ID with status "running." The client can poll `GET /api/v1/scan/:id` or subscribe to `GET /api/v1/scan/:id/stream` for live updates.

**Why return 202 Accepted instead of 200 OK:** A scan takes time. Returning 202 Accepted tells the client "I received your request and I am working on it, but I am not done yet." If we returned 200 OK and a result immediately, the client would not know whether to wait for more.

---

## Layer 12: CLI Entrypoint

**File:** `cmd/corvus/main.go`

### What this layer does

The `main` function is the entry point. It wires every component together, reads configuration, and dispatches to the right command. No business logic lives here.

```go
package main

import (
    "os"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
    "github.com/ObeeJ/corvus/internal/scanner"
    "github.com/ObeeJ/corvus/internal/store"
    "github.com/ObeeJ/corvus/internal/api"
    "github.com/ObeeJ/corvus/pkg/logger"
)

func main() {
    root := buildRootCommand()
    if err := root.Execute(); err != nil {
        os.Exit(1)
    }
}
```

**What this does:** Builds the root cobra command tree and executes it. Cobra parses `os.Args`, finds the right subcommand, and calls its `Run` function. If anything returns an error, `os.Exit(1)` signals failure to the shell.

**In plain English:** This is the front door of the whole program. Cobra reads what the user typed, figures out which command it is, and calls the right function.

```go
func buildRootCommand() *cobra.Command {
    root := &cobra.Command{
        Use:   "corvus",
        Short: "A living network intelligence engine",
        PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
            return viper.BindPFlags(cmd.Flags())
        },
    }

    root.AddCommand(
        buildScanCommand(),
        buildWatchCommand(),
        buildQueryCommand(),
        buildServeCommand(),
        buildNodeCommand(),
        buildDiffCommand(),
    )

    return root
}
```

**What this does:** Assembles the full command tree. `PersistentPreRunE` runs before every subcommand and binds command-line flags to viper so that `viper.GetString("target")` works anywhere, whether the value came from a flag, an environment variable, or the config file.

**In plain English:** Think of this as the main menu. Every option the user can type after `corvus` is listed here as a subcommand.

```go
func buildScanCommand() *cobra.Command {
    cmd := &cobra.Command{
        Use:   "scan [target]",
        Short: "Scan a host or CIDR range",
        Args:  cobra.ExactArgs(1),
        RunE: func(cmd *cobra.Command, args []string) error {
            log := logger.New("scan", logger.Config{
                Level:  viper.GetString("log-level"),
                Format: viper.GetString("log-format"),
            })

            st, err := store.Open(viper.GetString("store-path"))
            if err != nil {
                return err
            }
            defer st.Close()

            sc := scanner.NewTCPScanner(scanner.Config{
                Timeout:     viper.GetDuration("timeout"),
                Concurrency: viper.GetInt("concurrency"),
            }, log)

            // ... run scan, print results
            return nil
        },
    }

    cmd.Flags().Bool("predict", false, "Run OSINT pre-scan before active scanning")
    cmd.Flags().String("ports", "1-1024", "Port range to scan")
    cmd.Flags().Duration("timeout", 3*time.Second, "Connection timeout per port")
    cmd.Flags().Int("concurrency", 1000, "Number of concurrent probes")

    return cmd
}
```

**What this does:** Defines the `scan` subcommand. `Args: cobra.ExactArgs(1)` makes cobra enforce that exactly one positional argument (the target) is provided and produce a helpful error if it is missing.

`RunE` is the function that runs when the user types `corvus scan <target>`. It creates the logger, opens the store, creates the scanner, runs the scan, and prints results. Each call to `viper.GetString` reads from flags, environment variables (`CORVUS_LOG_LEVEL`), or the config file, in that order of precedence.

**In plain English:** This is everything that happens when you type `corvus scan 192.168.1.0/24`. Set up logging, open the database, create the scanner, fire, print what comes back.

---

## Build Order Summary

| Layer | Files | Depends On |
|---|---|---|
| 0 | go.mod | nothing |
| 1 | pkg/logger | nothing |
| 2 | pkg/iprange | nothing |
| 3 | internal/store | logger |
| 4 | internal/scanner | logger, iprange |
| 5 | internal/osint | logger |
| 6 | internal/fingerprint | nothing |
| 7 | internal/anomaly | store, logger |
| 8 | internal/cve | logger |
| 9 | internal/query | store |
| 10 | internal/mesh | store, logger |
| 11 | internal/api | scanner, store, anomaly, cve, query, mesh, logger |
| 12 | cmd/corvus | all of the above |

Build one layer at a time. After each layer, write a test that confirms the layer's public interface works. Only move to the next layer when the current one compiles and passes its tests.
