package handlers

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"sort"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/gofiber/fiber/v2"
)

// HostHandlers implements host-related API routes.
type HostHandlers struct {
	storeMgr *store.Manager
	log      *slog.Logger
}

// NewHostHandlers creates a new HostHandlers instance.
func NewHostHandlers(storeMgr *store.Manager, log *slog.Logger) *HostHandlers {
	return &HostHandlers{storeMgr: storeMgr, log: log}
}

// HostSummary is the response shape for the host list endpoint.
type HostSummary struct {
	IP        string  `json:"ip"`
	PortCount int     `json:"port_count"`
	RiskScore float64 `json:"risk_score"`
	LastSeen  string  `json:"last_seen"`
	TopService string `json:"top_service,omitempty"`
}

// PortDetail describes a single open port with its latest state.
type PortDetail struct {
	Port        uint16                   `json:"port"`
	Protocol    string                   `json:"protocol"`
	Service     string                   `json:"service"`
	Version     string                   `json:"version"`
	Banner      string                   `json:"banner,omitempty"`
	ResponseMs  int64                    `json:"response_ms"`
	LastSeen    string                   `json:"last_seen"`
	CVEs        []types.CVERef           `json:"cves,omitempty"`
	SupplyChain []types.SupplyChainFinding `json:"supply_chain,omitempty"`
	History     []types.StateRecord      `json:"history,omitempty"`
}

// HostDetail is the response shape for the host detail endpoint.
type HostDetail struct {
	IP        string              `json:"ip"`
	PortCount int                 `json:"port_count"`
	RiskScore float64             `json:"risk_score"`
	LastSeen  string              `json:"last_seen"`
	Ports     []PortDetail        `json:"ports"`
	Alerts    []types.AnomalyEvent `json:"alerts"`
	OSINT     *types.OSINTProfile `json:"osint,omitempty"`
}

// ListHosts returns a summary of all discovered hosts.
// GET /api/v1/hosts
func (h *HostHandlers) ListHosts(c *fiber.Ctx) error {
	// Multi-tenant: get user ID
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	st, err := h.storeMgr.GetStore(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load user store"})
	}

	hostIPs, err := st.ListHosts()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	summaries := make([]HostSummary, 0, len(hostIPs))

	for _, ipStr := range hostIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		openPorts, err := st.ReadOpenPorts(ip)
		if err != nil {
			h.log.Debug("reading open ports for host", "ip", ipStr, "err", err)
			continue
		}

		var lastSeen time.Time
		var riskScore float64
		var topService string

		for _, portProto := range openPorts {
			var port uint16
			var proto string
			fmt.Sscanf(portProto, "%d/%s", &port, &proto) //nolint:errcheck

			latest, err := st.ReadLatestState(ip, port, proto)
			if err != nil || latest == nil {
				continue
			}

			if latest.Timestamp.After(lastSeen) {
				lastSeen = latest.Timestamp
			}

			if latest.ServiceName != "" && topService == "" {
				topService = latest.ServiceName
			}

			// Simple risk: high-risk ports contribute more.
			riskScore += portRiskWeight(port, latest.ServiceName)
		}

		// Clamp risk score to 0–100.
		riskScore = math.Min(riskScore, 100)

		lastSeenStr := ""
		if !lastSeen.IsZero() {
			lastSeenStr = lastSeen.UTC().Format(time.RFC3339)
		}

		summaries = append(summaries, HostSummary{
			IP:         ipStr,
			PortCount:  len(openPorts),
			RiskScore:  math.Round(riskScore*10) / 10,
			LastSeen:   lastSeenStr,
			TopService: topService,
		})
	}

	// Sort by risk score descending.
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].RiskScore > summaries[j].RiskScore
	})

	return c.JSON(fiber.Map{
		"hosts": summaries,
		"total": len(summaries),
	})
}

// GetHost returns detailed information about a single host.
// GET /api/v1/hosts/:ip
func (h *HostHandlers) GetHost(c *fiber.Ctx) error {
	// Multi-tenant: get user ID
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		userID = "default"
	}

	st, err := h.storeMgr.GetStore(userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to load user store"})
	}

	ipStr := c.Params("ip")
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid IP address"})
	}

	openPorts, err := st.ReadOpenPorts(ip)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	if len(openPorts) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "host not found"})
	}

	// Parse optional history window.
	sinceStr := c.Query("since", "168h") // Default: last 7 days
	sinceDur, err := time.ParseDuration(sinceStr)
	if err != nil {
		sinceDur = 168 * time.Hour
	}
	since := time.Now().Add(-sinceDur)

	var lastSeen time.Time
	var riskScore float64
	ports := make([]PortDetail, 0, len(openPorts))

	for _, portProto := range openPorts {
		var port uint16
		var proto string
		fmt.Sscanf(portProto, "%d/%s", &port, &proto) //nolint:errcheck

		latest, err := st.ReadLatestState(ip, port, proto)
		if err != nil || latest == nil {
			continue
		}

		if latest.Timestamp.After(lastSeen) {
			lastSeen = latest.Timestamp
		}

		riskScore += portRiskWeight(port, latest.ServiceName)

		// Get history for this port.
		history, _ := st.ReadHistory(ip, port, proto, since, time.Time{})

		pd := PortDetail{
			Port:       port,
			Protocol:   proto,
			Service:    latest.ServiceName,
			Version:    latest.Version,
			Banner:     latest.Banner,
			ResponseMs: latest.ResponseMs,
			LastSeen:   latest.Timestamp.UTC().Format(time.RFC3339),
			History:    history,
		}

		ports = append(ports, pd)
	}

	// Fetch alerts for this host.
	allAlerts, _ := st.ReadAlerts(since, time.Time{})
	var hostAlerts []types.AnomalyEvent
	for _, alert := range allAlerts {
		if alert.Host.String() == ipStr {
			hostAlerts = append(hostAlerts, alert)
		}
	}

	riskScore = math.Min(riskScore, 100)

	lastSeenStr := ""
	if !lastSeen.IsZero() {
		lastSeenStr = lastSeen.UTC().Format(time.RFC3339)
	}

	detail := HostDetail{
		IP:        ipStr,
		PortCount: len(ports),
		RiskScore: math.Round(riskScore*10) / 10,
		LastSeen:  lastSeenStr,
		Ports:     ports,
		Alerts:    hostAlerts,
	}

	return c.JSON(detail)
}

// portRiskWeight assigns a risk weight based on port number and service name.
func portRiskWeight(port uint16, service string) float64 {
	// Critical services
	switch service {
	case "ssh":
		return 5
	case "rdp":
		return 15
	case "telnet":
		return 25
	case "ftp":
		return 10
	case "mysql", "postgresql", "mongodb", "redis":
		return 20
	case "smb":
		return 15
	}

	// Known risky ports
	switch {
	case port == 23:
		return 20 // telnet
	case port == 445:
		return 15 // SMB
	case port == 3389:
		return 15 // RDP
	case port == 6379:
		return 20 // Redis
	case port == 27017:
		return 20 // MongoDB
	case port == 9200:
		return 15 // Elasticsearch
	case port < 1024:
		return 3 // Well-known port
	default:
		return 1 // Ephemeral
	}
}
