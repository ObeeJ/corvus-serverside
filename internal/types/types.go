package types

import (
	"net"
	"time"
)

// ScanResult is the raw output from the scanner — port state only, no service info.
type ScanResult struct {
	IP         net.IP
	Port       uint16
	Protocol   string // "tcp" | "udp"
	Open       bool
	ResponseMs int64
	ScannedAt  time.Time
}

// EnrichedResult is a ScanResult after the fingerprinting stage.
type EnrichedResult struct {
	ScanResult
	ServiceName    string
	Version        string
	Banner         string
	TLSFingerprint string
	TLSSubject     string
	TLSExpiry      time.Time

	// Phase 2: intelligence enrichments
	CVEs                []CVERef             `json:"cves,omitempty"`
	SupplyChainFindings []SupplyChainFinding `json:"supply_chain,omitempty"`
	OSINTProfile        *OSINTProfile        `json:"osint,omitempty"`
}

// CVERef is a vulnerability reference attached to a fingerprinted service.
type CVERef struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	CVSSv3      float64 `json:"cvss_v3"`
	Severity    string  `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	URL         string  `json:"url"`
}

// SupplyChainFinding flags a security hygiene issue detected on a host.
type SupplyChainFinding struct {
	Type        string `json:"type"`        // "debug-port", "dev-tool", "reverse-shell", "exposed-pkg-mgr"
	Severity    string `json:"severity"`    // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Port        uint16 `json:"port"`
	Service     string `json:"service"`
	Description string `json:"description"`
}

// OSINTProfile is the passive intelligence gathered about a target before active scanning.
type OSINTProfile struct {
	IP            net.IP             `json:"ip"`
	Hostnames     []string           `json:"hostnames,omitempty"`
	Organization  string             `json:"organization,omitempty"`
	ASN           uint32             `json:"asn,omitempty"`
	CloudProvider string             `json:"cloud_provider,omitempty"` // "aws", "gcp", "azure", or ""
	PortScores    map[uint16]float64 `json:"port_scores,omitempty"`   // port → probability 0..1
}

// StateRecord is persisted to the temporal store for a host:port at a point in time.
type StateRecord struct {
	Timestamp      time.Time `json:"ts"`
	Open           bool      `json:"open"`
	Banner         string    `json:"banner,omitempty"`
	ServiceName    string    `json:"service,omitempty"`
	Version        string    `json:"version,omitempty"`
	TLSFingerprint string    `json:"tls_fp,omitempty"`
	TLSSubject     string    `json:"tls_sub,omitempty"`
	TLSExpiry      time.Time `json:"tls_exp,omitempty"`
	ResponseMs     int64     `json:"resp_ms"`
}

// AnomalyType identifies the kind of state change detected.
type AnomalyType string

const (
	AnomalyNewPort      AnomalyType = "new-port"
	AnomalyPortClosed   AnomalyType = "port-closed"
	AnomalyBannerDrift  AnomalyType = "banner-drift"
	AnomalyCertRotation AnomalyType = "cert-rotation"
	AnomalyVersionDrift AnomalyType = "version-drift"
	AnomalyLatencySpike AnomalyType = "latency-spike"
)

// Severity describes how critical an anomaly is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// AnomalyEvent is emitted when a meaningful network state change is detected.
type AnomalyEvent struct {
	Timestamp time.Time    `json:"ts"`
	Host      net.IP       `json:"host"`
	Port      uint16       `json:"port"`
	Protocol  string       `json:"proto"`
	Type      AnomalyType  `json:"type"`
	Severity  Severity     `json:"severity"`
	Before    *StateRecord `json:"before,omitempty"`
	After     *StateRecord `json:"after,omitempty"`
	Message   string       `json:"message"`
}

// ScanConfig holds runtime parameters for a scan job.
type ScanConfig struct {
	Timeout     time.Duration
	Concurrency int
	Rate        int // probes per second; 0 = unlimited
}
