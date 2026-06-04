package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type alertsView struct {
	st            *store.Store
	table         table.Model
	detail        viewport.Model
	filterInput   textinput.Model
	showingDetail bool
	filtering     bool
	width, height int
	alerts        []types.AnomalyEvent
}

func newAlertsView(st *store.Store) *alertsView {
	ti := textinput.New()
	ti.Placeholder = "Filter by Host or Message..."
	ti.Prompt = " / "
	ti.CharLimit = 45
	ti.Width = 30

	cols := []table.Column{
		{Title: "TIMESTAMP", Width: 20},
		{Title: "SEVERITY", Width: 10},
		{Title: "HOST", Width: 16},
		{Title: "TYPE", Width: 18},
		{Title: "MESSAGE", Width: 50},
	}

	t := newTable(cols)

	v := &alertsView{
		st:          st,
		table:       t,
		filterInput: ti,
	}
	v.loadAlerts()
	v.table.Focus()
	return v
}

func (v *alertsView) Init() tea.Cmd {
	return nil
}

func (v *alertsView) loadAlerts() {
	alerts, err := v.st.ReadAlerts(time.Time{}, time.Time{})
	if err != nil {
		return
	}
	// Reverse alerts to show newest first
	for i, j := 0, len(alerts)-1; i < j; i, j = i+1, j-1 {
		alerts[i], alerts[j] = alerts[j], alerts[i]
	}
	v.alerts = alerts
	v.updateTableRows()
}

func (v *alertsView) updateTableRows() {
	filter := strings.ToLower(strings.TrimSpace(v.filterInput.Value()))
	var rows []table.Row
	for _, ev := range v.alerts {
		hostStr := ev.Host.String()
		msgStr := ev.Message
		typeStr := string(ev.Type)

		if filter != "" && !strings.Contains(strings.ToLower(hostStr), filter) && !strings.Contains(strings.ToLower(msgStr), filter) {
			continue
		}

		rows = append(rows, table.Row{
			ev.Timestamp.Format("2006-01-02 15:04:05"),
			string(ev.Severity),
			hostStr,
			typeStr,
			msgStr,
		})
	}
	v.table.SetRows(rows)
}

func (v *alertsView) renderAlertDetail(idx int) string {
	if idx < 0 || idx >= len(v.alerts) {
		return "No alert selected."
	}
	ev := v.alerts[idx]

	var b strings.Builder
	b.WriteString(cliui.AccentBold.Render("▌ ANOMALY ALERT DETAILS") + "\n\n")
	b.WriteString(fmt.Sprintf("%-12s %s\n", cliui.Muted.Render("Timestamp:"), ev.Timestamp.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("%-12s %s\n", cliui.Muted.Render("Host:"), ev.Host.String()))
	b.WriteString(fmt.Sprintf("%-12s %d/%s\n", cliui.Muted.Render("Port:"), ev.Port, ev.Protocol))
	b.WriteString(fmt.Sprintf("%-12s %s\n", cliui.Muted.Render("Severity:"), BadgeForSeverity(string(ev.Severity))))
	b.WriteString(fmt.Sprintf("%-12s %s\n", cliui.Muted.Render("Type:"), string(ev.Type)))
	b.WriteString(fmt.Sprintf("%-12s %s\n\n", cliui.Muted.Render("Message:"), ev.Message))

	if ev.Before != nil {
		b.WriteString(cliui.AccentBold.Render("┌── Previous State ─────────────────────────────") + "\n")
		b.WriteString(formatStateRecord(ev.Before))
		b.WriteString(cliui.Faded.Render("└───────────────────────────────────────────────") + "\n\n")
	}
	if ev.After != nil {
		b.WriteString(cliui.AccentBold.Render("┌── Current State ──────────────────────────────") + "\n")
		b.WriteString(formatStateRecord(ev.After))
		b.WriteString(cliui.Faded.Render("└───────────────────────────────────────────────") + "\n\n")
	}
	return b.String()
}

func formatStateRecord(rec *types.StateRecord) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  %s %v\n", cliui.Muted.Render("Open:"), rec.Open))
	if rec.ServiceName != "" {
		b.WriteString(fmt.Sprintf("  %s %s\n", cliui.Muted.Render("Service:"), rec.ServiceName))
	}
	if rec.Version != "" {
		b.WriteString(fmt.Sprintf("  %s %s\n", cliui.Muted.Render("Version:"), rec.Version))
	}
	if rec.Banner != "" {
		b.WriteString(fmt.Sprintf("  %s %s\n", cliui.Muted.Render("Banner:"), rec.Banner))
	}
	if rec.TLSFingerprint != "" {
		b.WriteString(fmt.Sprintf("  %s %s\n", cliui.Muted.Render("TLS Subj:"), rec.TLSSubject))
		b.WriteString(fmt.Sprintf("  %s %s\n", cliui.Muted.Render("TLS Exp:"), rec.TLSExpiry.Format("2006-01-02")))
	}
	b.WriteString(fmt.Sprintf("  %s %dms\n", cliui.Muted.Render("Latency:"), rec.ResponseMs))
	return b.String()
}

func (v *alertsView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		v.width, v.height = msg.Width, msg.Height
		tableH := msg.Height - 10
		if tableH < 4 {
			tableH = 4
		}
		v.table.SetHeight(tableH)
		v.detail = viewport.New(msg.Width-4, tableH)
		return v, nil

	case tea.KeyMsg:
		if v.filtering {
			switch msg.String() {
			case "enter", "esc":
				v.filtering = false
				v.filterInput.Blur()
				v.table.Focus()
				return v, nil
			default:
				v.filterInput, cmd = v.filterInput.Update(msg)
				v.updateTableRows()
				return v, cmd
			}
		}

		if v.showingDetail {
			switch msg.String() {
			case "esc", "q", "backspace", "enter":
				v.showingDetail = false
				v.table.Focus()
				return v, nil
			}
			v.detail, cmd = v.detail.Update(msg)
			return v, cmd
		}

		switch msg.String() {
		case "/":
			v.filtering = true
			v.filterInput.Focus()
			v.table.Blur()
			return v, nil
		case "enter":
			row := v.table.SelectedRow()
			if len(row) > 0 {
				// Find the index of the selected alert in the filtered list
				// Simple mapping: table selected cursor index
				cursor := v.table.Cursor()
				// Find actual alert
				filter := strings.ToLower(strings.TrimSpace(v.filterInput.Value()))
				count := 0
				for idx, ev := range v.alerts {
					hostStr := ev.Host.String()
					msgStr := ev.Message
					if filter != "" && !strings.Contains(strings.ToLower(hostStr), filter) && !strings.Contains(strings.ToLower(msgStr), filter) {
						continue
					}
					if count == cursor {
						v.detail.SetContent(v.renderAlertDetail(idx))
						v.showingDetail = true
						v.table.Blur()
						break
					}
					count++
				}
			}
			return v, nil
		}

		v.table, cmd = v.table.Update(msg)
	}

	return v, nil
}

func (v *alertsView) View() string {
	var b strings.Builder

	if v.filtering || v.filterInput.Value() != "" {
		b.WriteString(v.filterInput.View() + "\n\n")
	}

	if v.showingDetail {
		b.WriteString(v.detail.View())
	} else {
		b.WriteString(v.table.View())
	}

	return b.String()
}
