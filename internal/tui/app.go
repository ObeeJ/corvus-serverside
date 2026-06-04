package tui

import (
	"log/slog"
	"strings"

	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/ObeeJ/corvus-serverside/internal/engine"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tabIndex int

const (
	tabHosts tabIndex = iota
	tabAlerts
	tabScan
	tabQuery
)

type rootModel struct {
	st     *store.Store
	mgr    *store.Manager
	eng    *engine.Engine
	log    *slog.Logger
	active tabIndex
	width  int
	height int

	hosts  *hostsView
	alerts *alertsView
	scan   *scanView
	query  *queryView
}

func newRootModel(mgr *store.Manager, st *store.Store, eng *engine.Engine, log *slog.Logger) *rootModel {
	return &rootModel{
		st:     st,
		mgr:    mgr,
		eng:    eng,
		log:    log,
		active: tabHosts,
		hosts:  newHostsView(st),
		alerts: newAlertsView(st),
		scan:   newScanView(mgr, eng),
		query:  newQueryView(st, log),
	}
}

func (m *rootModel) Init() tea.Cmd {
	return nil
}

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

		// Subtract header, tabs, and footer rows
		childMsg := tea.WindowSizeMsg{Width: msg.Width, Height: msg.Height}
		_, cmd = m.hosts.Update(childMsg)
		cmds = append(cmds, cmd)
		_, cmd = m.alerts.Update(childMsg)
		cmds = append(cmds, cmd)
		_, cmd = m.scan.Update(childMsg)
		cmds = append(cmds, cmd)
		_, cmd = m.query.Update(childMsg)
		cmds = append(cmds, cmd)

		return m, tea.Batch(cmds...)

	case tea.KeyMsg:
		// Global shortcut: ctrl+c always quits.
		if msg.String() == "ctrl+c" {
			if m.scan.running && m.scan.cancelScan != nil {
				m.scan.cancelScan()
			}
			return m, tea.Quit
		}

		isDetailShowing := (m.active == tabHosts && m.hosts.showingDetail) ||
			(m.active == tabAlerts && m.alerts.showingDetail)

		isInputFocused := (m.active == tabHosts && m.hosts.filtering) ||
			(m.active == tabAlerts && m.alerts.filtering) ||
			(m.active == tabScan && (m.scan.focusIndex == 0 || m.scan.focusIndex == 1)) ||
			(m.active == tabQuery && m.query.queryInput.Focused())

		if !isDetailShowing {
			if msg.String() == "tab" {
				m.active = (m.active + 1) % 4
				m.refreshActiveTab()
				return m, nil
			}
			if msg.String() == "shift+tab" {
				m.active = (m.active - 1 + 4) % 4
				m.refreshActiveTab()
				return m, nil
			}

			if !isInputFocused {
				switch msg.String() {
				case "q":
					return m, tea.Quit
				case "1":
					m.active = tabHosts
					m.refreshActiveTab()
					return m, nil
				case "2":
					m.active = tabAlerts
					m.refreshActiveTab()
					return m, nil
				case "3":
					m.active = tabScan
					m.refreshActiveTab()
					return m, nil
				case "4":
					m.active = tabQuery
					m.refreshActiveTab()
					return m, nil
				}
			}
		}
	}

	// Delegate update to active tab view
	switch m.active {
	case tabHosts:
		var model tea.Model
		model, cmd = m.hosts.Update(msg)
		m.hosts = model.(*hostsView)
	case tabAlerts:
		var model tea.Model
		model, cmd = m.alerts.Update(msg)
		m.alerts = model.(*alertsView)
	case tabScan:
		var model tea.Model
		model, cmd = m.scan.Update(msg)
		m.scan = model.(*scanView)
	case tabQuery:
		var model tea.Model
		model, cmd = m.query.Update(msg)
		m.query = model.(*queryView)
	}

	return m, cmd
}

func (m *rootModel) refreshActiveTab() {
	switch m.active {
	case tabHosts:
		m.hosts.loadHosts()
		m.hosts.table.Focus()
	case tabAlerts:
		m.alerts.loadAlerts()
		m.alerts.table.Focus()
	case tabScan:
		m.scan.focusIndex = 0
		m.scan.targetInput.Focus()
		m.scan.portsInput.Blur()
	case tabQuery:
		m.query.queryInput.Focus()
	}
}

func (m *rootModel) View() string {
	if m.width == 0 {
		return "\n  loading…"
	}

	// 1. Header Banner
	header := cliui.Banner()

	// 2. Tab Bar
	tabs := []string{"HOSTS (1)", "ALERTS (2)", "SCAN (3)", "QUERY (4)"}
	var renderedTabs []string
	for i, t := range tabs {
		if tabIndex(i) == m.active {
			renderedTabs = append(renderedTabs, TabActive.Render(t))
		} else {
			renderedTabs = append(renderedTabs, TabInactive.Render(t))
		}
	}
	tabRow := "  " + lipgloss.JoinHorizontal(lipgloss.Bottom, renderedTabs...)
	tabRow = TabBar.Render(tabRow)

	// 3. Body View
	var body string
	switch m.active {
	case tabHosts:
		body = PanelStyle.Render(m.hosts.View())
	case tabAlerts:
		body = PanelStyle.Render(m.alerts.View())
	case tabScan:
		body = PanelStyle.Render(m.scan.View())
	case tabQuery:
		body = PanelStyle.Render(m.query.View())
	}

	// 4. Footer Help Line
	var helpKeys string
	switch m.active {
	case tabHosts:
		if m.hosts.showingDetail {
			helpKeys = "↑/↓ scroll   esc/enter back   q quit"
		} else if m.hosts.filtering {
			helpKeys = "type filter   enter/esc done"
		} else {
			helpKeys = "↑/↓ navigate   enter details   / filter   tab next tab   q quit"
		}
	case tabAlerts:
		if m.alerts.showingDetail {
			helpKeys = "↑/↓ scroll   esc/enter back   q quit"
		} else if m.alerts.filtering {
			helpKeys = "type filter   enter/esc done"
		} else {
			helpKeys = "↑/↓ navigate   enter details   / filter   tab next tab   q quit"
		}
	case tabScan:
		if m.scan.running {
			helpKeys = "esc cancel scan"
		} else {
			helpKeys = "↑/↓ move focus   space select/toggle   enter start   tab next tab   q quit"
		}
	case tabQuery:
		helpKeys = "type query   enter run   tab next tab   q quit"
	}
	footer := HelpStyle.Render("  " + helpKeys)

	return header + tabRow + "\n" + body + "\n" + footer
}

// ── Shared Package-Level Helpers ──

func newTable(cols []table.Column) table.Model {
	t := table.New(table.WithColumns(cols), table.WithFocused(true), table.WithHeight(12))
	s := table.DefaultStyles()
	s.Header = s.Header.Foreground(cliui.Faint).Bold(true).BorderForeground(cliui.Faint).BorderBottom(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("#0c0d10")).Background(cliui.Accent).Bold(false)
	s.Cell = s.Cell.Foreground(cliui.Dim)
	t.SetStyles(s)
	return t
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func truncate(s string, n int) string {
	if n < 8 {
		n = 8
	}
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
