package tui

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/ObeeJ/corvus-serverside/internal/query"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type queryView struct {
	st            *store.Store
	log           *slog.Logger
	queryInput    textinput.Model
	queryTable    table.Model
	queryMsg      string
	width, height int
}

func newQueryView(st *store.Store, log *slog.Logger) *queryView {
	qi := textinput.New()
	qi.Placeholder = "e.g. open ports on 10.0.0.0/24 or services with version 2.4"
	qi.Prompt = " Query Expression › "
	qi.CharLimit = 200
	qi.Focus()

	cols := []table.Column{
		{Title: "HOST", Width: 18},
		{Title: "PORT", Width: 8},
		{Title: "PROTO", Width: 7},
		{Title: "SERVICE", Width: 14},
		{Title: "VERSION", Width: 16},
		{Title: "STATUS", Width: 10},
	}
	t := newTable(cols)

	return &queryView{
		st:         st,
		log:        log,
		queryInput: qi,
		queryTable: t,
	}
}

func (v *queryView) Init() tea.Cmd {
	return nil
}

func (v *queryView) runQuery() {
	expr := strings.TrimSpace(v.queryInput.Value())
	if expr == "" {
		return
	}
	plan, err := query.Parse(expr)
	if err != nil {
		v.queryMsg = cliui.SeverityStyle("HIGH").Render("Parse error: " + err.Error())
		v.queryTable.SetRows(nil)
		return
	}
	results, err := query.NewEngine(v.st, v.log).Execute(plan)
	if err != nil {
		v.queryMsg = cliui.SeverityStyle("HIGH").Render("Execution error: " + err.Error())
		v.queryTable.SetRows(nil)
		return
	}
	rows := make([]table.Row, 0, len(results))
	for _, r := range results {
		status := "closed"
		if r.State.Open {
			status = "open"
		}
		rows = append(rows, table.Row{
			r.IP, fmt.Sprintf("%d", r.Port), r.Protocol,
			orDash(r.State.ServiceName), orDash(r.State.Version), status,
		})
	}
	v.queryTable.SetRows(rows)
	v.queryMsg = cliui.Muted.Render(fmt.Sprintf("%d result(s) found", len(results)))
}

func (v *queryView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		v.width, v.height = msg.Width, msg.Height
		tableH := msg.Height - 12
		if tableH < 4 {
			tableH = 4
		}
		v.queryTable.SetHeight(tableH)
		v.queryInput.Width = msg.Width - 8
		return v, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			v.runQuery()
			return v, nil
		}

		v.queryInput, cmd = v.queryInput.Update(msg)
	}

	return v, cmd
}

func (v *queryView) View() string {
	var b strings.Builder

	b.WriteString(cliui.AccentBold.Render("▌ QUERY HISTORICAL SCAN DATA") + "\n\n")
	b.WriteString(v.queryInput.View() + "\n")
	if v.queryMsg != "" {
		b.WriteString("  " + v.queryMsg + "\n")
	}
	b.WriteString("\n" + v.queryTable.View())

	return b.String()
}
