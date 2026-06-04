package tui

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type hostInfo struct {
	IP        string
	OpenCount int
	Services  string
	LastSeen  time.Time
}

type hostsView struct {
	st            *store.Store
	table         table.Model
	detail        viewport.Model
	filterInput   textinput.Model
	showingDetail bool
	filtering     bool
	width, height int
	hosts         []hostInfo
}

func newHostsView(st *store.Store) *hostsView {
	ti := textinput.New()
	ti.Placeholder = "Filter by IP..."
	ti.Prompt = " / "
	ti.CharLimit = 45
	ti.Width = 30

	cols := []table.Column{
		{Title: "HOST IP", Width: 18},
		{Title: "PORTS", Width: 8},
		{Title: "SERVICES", Width: 32},
		{Title: "LAST SEEN", Width: 20},
	}

	t := newTable(cols)

	v := &hostsView{
		st:          st,
		table:       t,
		filterInput: ti,
	}
	v.loadHosts()
	v.table.Focus()
	return v
}

func (v *hostsView) Init() tea.Cmd {
	return nil
}

func (v *hostsView) loadHosts() {
	ips, err := v.st.ListHosts()
	if err != nil {
		return
	}

	v.hosts = nil
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}

		ports, err := v.st.ReadOpenPorts(ip)
		if err != nil {
			continue
		}

		var lastSeen time.Time
		var svcs []string
		for _, portProto := range ports {
			var port uint16
			var proto string
			fmt.Sscanf(portProto, "%d/%s", &port, &proto)
			rec, err := v.st.ReadLatestState(ip, port, proto)
			if err == nil && rec != nil {
				if rec.Timestamp.After(lastSeen) {
					lastSeen = rec.Timestamp
				}
				if rec.ServiceName != "" {
					svcs = append(svcs, rec.ServiceName)
				}
			}
		}

		svcs = uniqueStrings(svcs)
		svcStr := "—"
		if len(svcs) > 0 {
			svcStr = strings.Join(svcs, ", ")
		}

		v.hosts = append(v.hosts, hostInfo{
			IP:        ipStr,
			OpenCount: len(ports),
			Services:  svcStr,
			LastSeen:  lastSeen,
		})
	}
	v.updateTableRows()
}

func (v *hostsView) updateTableRows() {
	filter := strings.TrimSpace(v.filterInput.Value())
	var rows []table.Row
	for _, h := range v.hosts {
		if filter != "" && !strings.Contains(h.IP, filter) {
			continue
		}
		seenStr := "—"
		if !h.LastSeen.IsZero() {
			seenStr = h.LastSeen.Format("2006-01-02 15:04:05")
		}
		rows = append(rows, table.Row{
			h.IP,
			fmt.Sprintf("%d", h.OpenCount),
			h.Services,
			seenStr,
		})
	}
	v.table.SetRows(rows)
}

func (v *hostsView) renderHostDetail(ipStr string) string {
	var b strings.Builder
	b.WriteString(cliui.AccentBold.Render("▌ HOST DETAILS: "+ipStr) + "\n\n")

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return b.String() + cliui.Muted.Render("Invalid address")
	}

	ports, err := v.st.ReadOpenPorts(ip)
	if err != nil || len(ports) == 0 {
		return b.String() + cliui.Muted.Render("No open ports found in state.")
	}

	b.WriteString(cliui.Faded.Render("PORT/PROTO") + "\t" + cliui.Faded.Render("SERVICE") + "\t" + cliui.Faded.Render("VERSION") + "\t" + cliui.Faded.Render("LATENCY") + "\n")
	b.WriteString(cliui.Faded.Render("──────────") + "\t" + cliui.Faded.Render("───────") + "\t" + cliui.Faded.Render("───────") + "\t" + cliui.Faded.Render("───────") + "\n")

	for _, pp := range ports {
		var port uint16
		var proto string
		fmt.Sscanf(pp, "%d/%s", &port, &proto)
		rec, err := v.st.ReadLatestState(ip, port, proto)
		if err != nil || rec == nil {
			continue
		}

		svc := "unknown"
		if rec.ServiceName != "" {
			svc = rec.ServiceName
		}
		ver := "—"
		if rec.Version != "" {
			ver = rec.Version
		}
		lat := fmt.Sprintf("%dms", rec.ResponseMs)

		b.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\n",
			cliui.AccentCell.Render(fmt.Sprintf("%d/%s", port, proto)),
			cliui.Body.Render(svc),
			cliui.Muted.Render(ver),
			cliui.Muted.Render(lat),
		))

		if rec.Banner != "" {
			b.WriteString("  " + cliui.Faded.Render("Banner: "+truncate(rec.Banner, v.width-20)) + "\n")
		}

		if rec.TLSFingerprint != "" {
			b.WriteString("  " + cliui.Faded.Render(fmt.Sprintf("TLS Subject: %s", rec.TLSSubject)) + "\n")
			b.WriteString("  " + cliui.Faded.Render(fmt.Sprintf("TLS Expiry:  %s", rec.TLSExpiry.Format("2006-01-02"))) + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (v *hostsView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
				v.detail.SetContent(v.renderHostDetail(row[0]))
				v.showingDetail = true
				v.table.Blur()
			}
			return v, nil
		}

		v.table, cmd = v.table.Update(msg)
	}

	return v, nil
}

func (v *hostsView) View() string {
	var b strings.Builder

	// Render filter input if active/filled
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

func uniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
