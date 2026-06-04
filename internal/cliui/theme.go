// Package cliui provides branded lipgloss styles for all Corvus CLI output.
// It enforces the Industrial Precision design system: amber #F97316 accent,
// monospace, sharp/minimal, single accent colour. Styles are disabled
// automatically when output is not a TTY or the NO_COLOR env is set.
package cliui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
	"github.com/muesli/termenv"

	"github.com/ObeeJ/corvus-serverside/pkg/config"
)

// ── Colours ─────────────────────────────────────────────────────────────────

var (
	Accent   = lipgloss.Color("#F97316")
	Dim      = lipgloss.Color("#777E8C")
	Faint    = lipgloss.Color("#444B58")
	White    = lipgloss.Color("#E8E9EC")
	Red      = lipgloss.Color("#EF4444")
	Amber    = lipgloss.Color("#F59E0B")
	Yellow   = lipgloss.Color("#EAB308")
	Green    = lipgloss.Color("#22C55E")
	BgPanel  = lipgloss.Color("#181B22")
)

// ── Base Styles ─────────────────────────────────────────────────────────────

var (
	// Bold accent for headings and highlights.
	AccentBold = lipgloss.NewStyle().Bold(true).Foreground(Accent)

	// Muted text for secondary information.
	Muted = lipgloss.NewStyle().Foreground(Dim)

	// Very faint text for decorative elements.
	Faded = lipgloss.NewStyle().Foreground(Faint)

	// White body text.
	Body = lipgloss.NewStyle().Foreground(White)

	// Table column header style.
	ColHeader = lipgloss.NewStyle().
			Foreground(Faint).
			Bold(true).
			PaddingRight(2)

	// Table cell style.
	Cell = lipgloss.NewStyle().
		Foreground(Dim).
		PaddingRight(2)

	// Accent cell (e.g. host IP).
	AccentCell = lipgloss.NewStyle().
			Foreground(Accent).
			PaddingRight(2)

	// Separator line.
	Rule = lipgloss.NewStyle().Foreground(Faint)
)

// ── Severity ────────────────────────────────────────────────────────────────

// SeverityStyle returns a lipgloss style coloured by severity level.
func SeverityStyle(sev string) lipgloss.Style {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return lipgloss.NewStyle().Bold(true).Foreground(Red)
	case "HIGH":
		return lipgloss.NewStyle().Bold(true).Foreground(Accent)
	case "MEDIUM":
		return lipgloss.NewStyle().Foreground(Amber)
	case "LOW":
		return lipgloss.NewStyle().Foreground(Dim)
	default:
		return lipgloss.NewStyle().Foreground(Dim)
	}
}

// SevBadge returns a bracketed severity label like "[CRITICAL]".
func SevBadge(sev string) string {
	return SeverityStyle(sev).Render("[" + strings.ToUpper(sev) + "]")
}

// SevSymbol returns a coloured symbol for a severity level.
func SevSymbol(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return SeverityStyle("CRITICAL").Render("✖")
	case "HIGH":
		return SeverityStyle("HIGH").Render("⚠")
	case "MEDIUM":
		return SeverityStyle("MEDIUM").Render("●")
	default:
		return SeverityStyle("LOW").Render("○")
	}
}

// ── Banner ──────────────────────────────────────────────────────────────────

// Banner returns the branded CLI header line.
func Banner() string {
	bar := AccentBold.Render("▌")
	name := AccentBold.Render(config.ProductName)
	ver := Muted.Render("v" + config.ProductVersion)
	dash := Faded.Render("—")
	tag := Muted.Render(config.ProductTagline)
	return fmt.Sprintf("\n  %s %s %s %s %s\n", bar, name, ver, dash, tag)
}

// ScanHeader returns a formatted scan header block.
func ScanHeader(target string, hosts, ports int) string {
	var b strings.Builder
	b.WriteString(Banner())
	b.WriteString(fmt.Sprintf("  %s %s  %s  %s %d hosts  %s  %s %d ports/host\n\n",
		Faded.Render("target:"),
		AccentBold.Render(target),
		Faded.Render("|"),
		Faded.Render(""),
		hosts,
		Faded.Render("|"),
		Faded.Render(""),
		ports,
	))
	return b.String()
}

// ScanFooter returns a formatted scan summary line.
func ScanFooter(hosts, open int, elapsed float64) string {
	rule := Faded.Render("  ─────────────────────────────────────────────────────")
	stats := fmt.Sprintf("  %s  ·  %s  ·  %s",
		Body.Render(fmt.Sprintf("%d hosts", hosts)),
		AccentBold.Render(fmt.Sprintf("%d open ports", open)),
		Muted.Render(fmt.Sprintf("%.1fs", elapsed)),
	)
	return fmt.Sprintf("\n%s\n%s\n\n", rule, stats)
}

// CVEWarning renders a coloured CVE + supply chain summary.
func CVEWarning(cveCount, scCount int) string {
	return fmt.Sprintf("  %s  %s  ·  %s\n\n",
		SeverityStyle("HIGH").Render("⚠"),
		SeverityStyle("HIGH").Render(fmt.Sprintf("%d CVE(s) found", cveCount)),
		SeverityStyle("MEDIUM").Render(fmt.Sprintf("%d supply chain flag(s)", scCount)),
	)
}

// ── Box drawing ─────────────────────────────────────────────────────────────

// BoxTop renders a box top with a label.
func BoxTop(label string) string {
	return fmt.Sprintf("  %s %s %s",
		AccentBold.Render("┌─"),
		AccentBold.Render(label),
		Faded.Render("─────────────────────────────────"),
	)
}

// BoxRow renders a row inside a box.
func BoxRow(key, value string) string {
	return fmt.Sprintf("  %s  %-16s %s",
		Faded.Render("│"),
		Muted.Render(key+":"),
		Body.Render(value),
	)
}

// BoxSep renders a separator inside a box.
func BoxSep() string {
	return fmt.Sprintf("  %s", Faded.Render("│"))
}

// BoxBottom renders a box bottom.
func BoxBottom() string {
	return fmt.Sprintf("  %s\n",
		Faded.Render("└──────────────────────────────────────"),
	)
}

// ── Utilities ───────────────────────────────────────────────────────────────

// ColorEnabled returns true if colour output should be used.
// Returns false when stdout is not a TTY or NO_COLOR is set.
func ColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return term.IsTerminal(os.Stdout.Fd())
}

// init disables lipgloss colour when output is piped or NO_COLOR is set.
func init() {
	if !ColorEnabled() {
		lipgloss.DefaultRenderer().SetColorProfile(termenv.Ascii)
	}
}
