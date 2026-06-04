package response

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// Action defines what automated response to take for a given anomaly.
type Action struct {
	Type    string // "block-ip", "notify-webhook", "run-script"
	Target  string // IP, URL, or script path
	Enabled bool
}

// Rule maps an anomaly type + severity to a response action.
type Rule struct {
	AnomalyType types.AnomalyType
	MinSeverity types.Severity
	Action      Action
}

// Engine evaluates anomaly events against rules and executes configured responses.
type Engine struct {
	rules []Rule
	log   *slog.Logger
}

// New creates a response engine with the given rules.
func New(rules []Rule, log *slog.Logger) *Engine {
	return &Engine{rules: rules, log: log}
}

// Evaluate checks an anomaly event against all rules and executes matching actions.
func (e *Engine) Evaluate(ctx context.Context, event types.AnomalyEvent) {
	for _, rule := range e.rules {
		if !rule.Action.Enabled {
			continue
		}
		if rule.AnomalyType != "" && rule.AnomalyType != event.Type {
			continue
		}
		if !severityMeets(event.Severity, rule.MinSeverity) {
			continue
		}
		e.execute(ctx, rule.Action, event)
	}
}

func (e *Engine) execute(ctx context.Context, action Action, event types.AnomalyEvent) {
	switch action.Type {
	case "block-ip":
		e.blockIP(ctx, event.Host.String())
	case "run-script":
		e.runScript(ctx, action.Target, event)
	case "notify-webhook":
		e.log.Info("response: webhook notification (not implemented)", "url", action.Target, "event", event.Type)
	default:
		e.log.Warn("unknown response action type", "type", action.Type)
	}
}

func (e *Engine) blockIP(ctx context.Context, ip string) {
	// Use iptables to drop traffic from the offending IP.
	cmd := exec.CommandContext(ctx, "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
	if out, err := cmd.CombinedOutput(); err != nil {
		e.log.Error("failed to block IP", "ip", ip, "err", err, "output", string(out))
		return
	}
	e.log.Info("response: blocked IP via iptables", "ip", ip)
}

func (e *Engine) runScript(ctx context.Context, scriptPath string, event types.AnomalyEvent) {
	args := []string{
		fmt.Sprintf("--host=%s", event.Host),
		fmt.Sprintf("--port=%d", event.Port),
		fmt.Sprintf("--type=%s", event.Type),
		fmt.Sprintf("--severity=%s", event.Severity),
	}
	cmd := exec.CommandContext(ctx, scriptPath, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		e.log.Error("response script failed", "script", scriptPath, "err", err, "output", string(out))
		return
	}
	e.log.Info("response: script executed", "script", scriptPath, "host", event.Host)
}

// severityMeets returns true if actual severity is >= minimum required.
func severityMeets(actual, minimum types.Severity) bool {
	order := map[types.Severity]int{
		types.SeverityLow:      1,
		types.SeverityMedium:   2,
		types.SeverityHigh:     3,
		types.SeverityCritical: 4,
	}
	return order[actual] >= order[minimum]
}

// ParseRules parses a simple rule spec string into Rule slices.
// Format: "new-port:HIGH:block-ip", "cert-rotation:CRITICAL:run-script:/path/to/script"
func ParseRules(specs []string) []Rule {
	var rules []Rule
	for _, spec := range specs {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) < 3 {
			continue
		}
		actionParts := strings.SplitN(parts[2], ":", 2)
		target := ""
		if len(actionParts) > 1 {
			target = actionParts[1]
		}
		rules = append(rules, Rule{
			AnomalyType: types.AnomalyType(parts[0]),
			MinSeverity: types.Severity(parts[1]),
			Action: Action{
				Type:    actionParts[0],
				Target:  target,
				Enabled: true,
			},
		})
	}
	return rules
}
