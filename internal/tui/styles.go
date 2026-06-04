package tui

import (
	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/charmbracelet/lipgloss"
)

var (
	// Tab Styles
	TabActive = lipgloss.NewStyle().
			Bold(true).
			Foreground(cliui.Accent).
			Padding(0, 2).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(cliui.Accent)

	TabInactive = lipgloss.NewStyle().
			Foreground(cliui.Dim).
			Padding(0, 2)

	TabBar = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, true, false).
		BorderForeground(cliui.Faint).
		PaddingLeft(1)

	// Panel Styles
	PanelStyle = lipgloss.NewStyle().
			Padding(1, 2)

	DetailPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder(), false, false, false, true).
				BorderForeground(cliui.Faint).
				PaddingLeft(2).
				PaddingRight(1)

	HelpStyle = lipgloss.NewStyle().
			Foreground(cliui.Faint).
			Padding(0, 1)

	// Severity Badges for Alerts
	BadgeCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0c0d10")).Background(cliui.Red).Padding(0, 1)
	BadgeHigh     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0c0d10")).Background(cliui.Accent).Padding(0, 1)
	BadgeMedium   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0c0d10")).Background(cliui.Amber).Padding(0, 1)
	BadgeLow      = lipgloss.NewStyle().Bold(true).Foreground(cliui.Dim).Background(cliui.Faint).Padding(0, 1)

	// Form / Inputs styling
	InputPrompt = lipgloss.NewStyle().Foreground(cliui.Accent).Bold(true)

	// Option Select styling
	OptionSelected = lipgloss.NewStyle().Foreground(lipgloss.Color("#0c0d10")).Background(cliui.Accent).Padding(0, 1).Bold(true)
	OptionUnselected = lipgloss.NewStyle().Foreground(cliui.Dim).Padding(0, 1)
)

// BadgeForSeverity returns styled badge for given severity
func BadgeForSeverity(sev string) string {
	switch sev {
	case "CRITICAL":
		return BadgeCritical.Render(" CRIT ")
	case "HIGH":
		return BadgeHigh.Render(" HIGH ")
	case "MEDIUM":
		return BadgeMedium.Render(" MED  ")
	case "LOW":
		return BadgeLow.Render(" LOW  ")
	default:
		return BadgeLow.Render(" INFO ")
	}
}
