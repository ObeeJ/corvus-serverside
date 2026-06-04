package anomaly

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// AlertSink receives anomaly events for delivery to a destination (stdout, webhook, Slack, etc.).
type AlertSink interface {
	Send(event types.AnomalyEvent) error
}

// Engine diffs incoming scan results against stored state and dispatches anomaly events.
type Engine struct {
	store     *store.Store
	sinks     []AlertSink
	log       *slog.Logger
	seenPorts map[string]struct{} // keys: "ip:port/proto", populated during a scan run
}

func New(st *store.Store, sinks []AlertSink, log *slog.Logger) *Engine {
	return &Engine{
		store:     st,
		sinks:     sinks,
		log:       log,
		seenPorts: make(map[string]struct{}),
	}
}

// Reset clears the seen-ports tracker. Call before starting each new scan.
func (e *Engine) Reset() {
	e.seenPorts = make(map[string]struct{})
}

// Process handles a single enriched result: reads previous state, writes new state, diffs, dispatches.
func (e *Engine) Process(result types.EnrichedResult) error {
	key := seenKey(result.IP, result.Port, result.Protocol)
	e.seenPorts[key] = struct{}{}

	prev, err := e.store.ReadLatestState(result.IP, result.Port, result.Protocol)
	if err != nil {
		e.log.Warn("reading previous state", "err", err, "host", result.IP, "port", result.Port)
	}

	curr := types.StateRecord{
		Timestamp:      result.ScannedAt,
		Open:           result.Open,
		Banner:         result.Banner,
		ServiceName:    result.ServiceName,
		Version:        result.Version,
		TLSFingerprint: result.TLSFingerprint,
		TLSSubject:     result.TLSSubject,
		TLSExpiry:      result.TLSExpiry,
		ResponseMs:     result.ResponseMs,
	}

	if err := e.store.WriteState(result.IP, result.Port, result.Protocol, curr); err != nil {
		e.log.Warn("writing state", "err", err, "host", result.IP, "port", result.Port)
	}

	for _, ev := range diff(result.IP, result.Port, result.Protocol, prev, &curr) {
		e.dispatch(ev)
	}

	return nil
}

// Flush emits port-closed events for ports that were open in the store but not seen in the current scan.
// Call after all results have been processed.
func (e *Engine) Flush(scannedHosts []net.IP) {
	for _, ip := range scannedHosts {
		prevOpen, err := e.store.ReadOpenPorts(ip)
		if err != nil {
			e.log.Warn("reading open ports from store", "err", err, "host", ip)
			continue
		}

		for _, portProto := range prevOpen {
			key := ip.String() + ":" + portProto
			if _, seen := e.seenPorts[key]; seen {
				continue
			}

			var port uint16
			var proto string
			fmt.Sscanf(portProto, "%d/%s", &port, &proto) //nolint:errcheck

			prev, _ := e.store.ReadLatestState(ip, port, proto)
			if prev == nil || !prev.Open {
				continue
			}

			closedRec := types.StateRecord{
				Timestamp: time.Now(),
				Open:      false,
			}
			e.store.WriteState(ip, port, proto, closedRec) //nolint:errcheck

			svc := prev.ServiceName
			if svc == "" {
				svc = "unknown"
			}

			e.dispatch(types.AnomalyEvent{
				Timestamp: time.Now(),
				Host:      ip,
				Port:      port,
				Protocol:  proto,
				Type:      types.AnomalyPortClosed,
				Severity:  types.SeverityMedium,
				Before:    prev,
				After:     &closedRec,
				Message:   fmt.Sprintf("%s on %s:%d/%s is no longer responding", svc, ip, port, proto),
			})
		}
	}
}

func (e *Engine) dispatch(ev types.AnomalyEvent) {
	if err := e.store.WriteAlert(ev); err != nil {
		e.log.Warn("persisting alert", "err", err)
	}
	for _, sink := range e.sinks {
		if err := sink.Send(ev); err != nil {
			e.log.Warn("alert sink error", "err", err)
		}
	}
}

// diff compares previous and current state and returns any anomaly events.
func diff(ip net.IP, port uint16, proto string, prev, curr *types.StateRecord) []types.AnomalyEvent {
	var events []types.AnomalyEvent

	// New port: was absent or closed, now open.
	if curr.Open && (prev == nil || !prev.Open) {
		svc := curr.ServiceName
		if svc == "" {
			svc = "unknown"
		}
		ver := ""
		if curr.Version != "" {
			ver = " " + curr.Version
		}
		events = append(events, types.AnomalyEvent{
			Timestamp: curr.Timestamp,
			Host:      ip,
			Port:      port,
			Protocol:  proto,
			Type:      types.AnomalyNewPort,
			Severity:  types.SeverityHigh,
			Before:    prev,
			After:     curr,
			Message:   fmt.Sprintf("new port %d/%s open on %s — %s%s", port, proto, ip, svc, ver),
		})
		return events
	}

	if !curr.Open || prev == nil {
		return events
	}

	// Banner drift.
	if prev.Banner != "" && curr.Banner != "" && prev.Banner != curr.Banner {
		events = append(events, types.AnomalyEvent{
			Timestamp: curr.Timestamp,
			Host:      ip,
			Port:      port,
			Protocol:  proto,
			Type:      types.AnomalyBannerDrift,
			Severity:  types.SeverityMedium,
			Before:    prev,
			After:     curr,
			Message:   fmt.Sprintf("banner changed on %s:%d/%s", ip, port, proto),
		})
	}

	// Version drift.
	if prev.Version != "" && curr.Version != "" && prev.Version != curr.Version {
		events = append(events, types.AnomalyEvent{
			Timestamp: curr.Timestamp,
			Host:      ip,
			Port:      port,
			Protocol:  proto,
			Type:      types.AnomalyVersionDrift,
			Severity:  types.SeverityLow,
			Before:    prev,
			After:     curr,
			Message:   fmt.Sprintf("version changed on %s:%d/%s: %s → %s", ip, port, proto, prev.Version, curr.Version),
		})
	}

	// TLS certificate rotation.
	if prev.TLSFingerprint != "" && curr.TLSFingerprint != "" && prev.TLSFingerprint != curr.TLSFingerprint {
		events = append(events, types.AnomalyEvent{
			Timestamp: curr.Timestamp,
			Host:      ip,
			Port:      port,
			Protocol:  proto,
			Type:      types.AnomalyCertRotation,
			Severity:  types.SeverityHigh,
			Before:    prev,
			After:     curr,
			Message:   fmt.Sprintf("TLS certificate changed on %s:%d/%s (subject: %s)", ip, port, proto, curr.TLSSubject),
		})
	}

	// Latency spike: response time more than tripled.
	if prev.ResponseMs > 0 && curr.ResponseMs > prev.ResponseMs*3 {
		events = append(events, types.AnomalyEvent{
			Timestamp: curr.Timestamp,
			Host:      ip,
			Port:      port,
			Protocol:  proto,
			Type:      types.AnomalyLatencySpike,
			Severity:  types.SeverityLow,
			Before:    prev,
			After:     curr,
			Message:   fmt.Sprintf("latency spike on %s:%d/%s: %dms → %dms", ip, port, proto, prev.ResponseMs, curr.ResponseMs),
		})
	}

	return events
}

func seenKey(ip net.IP, port uint16, proto string) string {
	return fmt.Sprintf("%s:%d/%s", ip.String(), port, strings.ToLower(proto))
}
