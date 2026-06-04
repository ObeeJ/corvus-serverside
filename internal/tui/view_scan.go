package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/ObeeJ/corvus-serverside/internal/engine"
	"github.com/ObeeJ/corvus-serverside/internal/store"
	"github.com/ObeeJ/corvus-serverside/internal/types"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type scanResultMsg types.EnrichedResult
type scanFinishedMsg struct {
	err error
}

type tuiAlertSink struct{}

func (tuiAlertSink) Send(event types.AnomalyEvent) error { return nil }

type scanView struct {
	mgr           *store.Manager
	eng           *engine.Engine
	targetInput   textinput.Model
	portsInput    textinput.Model
	predict       bool
	scanType      string // tcp, syn, udp
	focusIndex    int    // 0: target, 1: ports, 2: predict, 3: scanType, 4: button
	running       bool
	spinner       spinner.Model
	resultsTable  table.Model
	results       []types.EnrichedResult
	errMsg        string
	cancelScan    context.CancelFunc
	startedTime   time.Time
	elapsedTime   time.Duration
	hostsCount    int
	portsCount    int
	width, height int
	scanChan      chan types.EnrichedResult
}

func newScanView(mgr *store.Manager, eng *engine.Engine) *scanView {
	tInput := textinput.New()
	tInput.Placeholder = "127.0.0.1"
	tInput.SetValue("127.0.0.1")
	tInput.Prompt = " Target Range: "
	tInput.Focus()

	pInput := textinput.New()
	pInput.Placeholder = "1-1024,80,443"
	pInput.SetValue("1-1024")
	pInput.Prompt = " Target Ports: "

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(cliui.Accent)

	cols := []table.Column{
		{Title: "HOST", Width: 18},
		{Title: "PORT", Width: 8},
		{Title: "PROTO", Width: 7},
		{Title: "SERVICE", Width: 14},
		{Title: "VERSION", Width: 16},
		{Title: "LATENCY", Width: 10},
	}
	t := newTable(cols)

	return &scanView{
		mgr:          mgr,
		eng:          eng,
		targetInput:  tInput,
		portsInput:   pInput,
		predict:      false,
		scanType:     "tcp",
		focusIndex:   0,
		spinner:      s,
		resultsTable: t,
	}
}

func (v *scanView) Init() tea.Cmd {
	return nil
}

func nextScanResult(ch chan types.EnrichedResult) tea.Cmd {
	return func() tea.Msg {
		res, ok := <-ch
		if !ok {
			return scanFinishedMsg{}
		}
		return scanResultMsg(res)
	}
}

func (v *scanView) updateTableRows() {
	var rows []table.Row
	for _, r := range v.results {
		svc := "—"
		if r.ServiceName != "" {
			svc = r.ServiceName
		}
		ver := "—"
		if r.Version != "" {
			ver = r.Version
		}
		rows = append(rows, table.Row{
			r.IP.String(),
			fmt.Sprintf("%d", r.Port),
			r.Protocol,
			svc,
			ver,
			fmt.Sprintf("%dms", r.ResponseMs),
		})
	}
	v.resultsTable.SetRows(rows)
}

func (v *scanView) startScanJob() tea.Cmd {
	v.running = true
	v.errMsg = ""
	v.results = nil
	v.resultsTable.SetRows(nil)
	v.startedTime = time.Now()

	ctx, cancel := context.WithCancel(context.Background())
	v.cancelScan = cancel

	cfg := engine.ScanConfig{
		UserID:      "default",
		Target:      strings.TrimSpace(v.targetInput.Value()),
		Predict:     v.predict,
		Ports:       strings.TrimSpace(v.portsInput.Value()),
		ScanType:    v.scanType,
		Timeout:     750 * time.Millisecond,
		Concurrency: 2000,
		Rate:        0,
	}

	job, err := v.eng.StartScan(ctx, cfg)
	if err != nil {
		v.running = false
		v.errMsg = err.Error()
		return nil
	}

	v.hostsCount = job.Hosts
	v.portsCount = job.Ports

	ch := v.eng.Subscribe(job.ID)
	v.scanChan = ch

	return tea.Batch(
		v.spinner.Tick,
		nextScanResult(ch),
	)
}

func (v *scanView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	if v.running {
		v.elapsedTime = time.Since(v.startedTime)
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		v.width, v.height = msg.Width, msg.Height
		tableH := msg.Height - 12
		if tableH < 4 {
			tableH = 4
		}
		v.resultsTable.SetHeight(tableH)
		return v, nil

	case spinner.TickMsg:
		v.spinner, cmd = v.spinner.Update(msg)
		return v, cmd

	case scanResultMsg:
		v.results = append(v.results, types.EnrichedResult(msg))
		v.updateTableRows()
		return v, nextScanResult(v.scanChan)

	case scanFinishedMsg:
		v.running = false
		if v.cancelScan != nil {
			v.cancelScan()
		}
		return v, nil

	case tea.KeyMsg:
		if v.running {
			switch msg.String() {
			case "esc", "ctrl+c":
				if v.cancelScan != nil {
					v.cancelScan()
				}
				v.running = false
				v.errMsg = "Scan cancelled by user."
			}
			return v, nil
		}

		switch msg.String() {
		case "up", "k":
			v.focusIndex--
			if v.focusIndex < 0 {
				v.focusIndex = 4
			}
		case "down", "j":
			v.focusIndex++
			if v.focusIndex > 4 {
				v.focusIndex = 0
			}
		case "enter":
			if v.focusIndex == 4 {
				return v, v.startScanJob()
			}
		case " ":
			if v.focusIndex == 2 {
				v.predict = !v.predict
			} else if v.focusIndex == 3 {
				switch v.scanType {
				case "tcp":
					v.scanType = "syn"
				case "syn":
					v.scanType = "udp"
				default:
					v.scanType = "tcp"
				}
			}
		}

		if v.focusIndex == 0 {
			v.targetInput.Focus()
			v.portsInput.Blur()
			v.targetInput, cmd = v.targetInput.Update(msg)
			return v, cmd
		} else if v.focusIndex == 1 {
			v.targetInput.Blur()
			v.portsInput.Focus()
			v.portsInput, cmd = v.portsInput.Update(msg)
			return v, cmd
		} else {
			v.targetInput.Blur()
			v.portsInput.Blur()
		}
	}

	return v, nil
}

func (v *scanView) View() string {
	var b strings.Builder

	if v.running {
		b.WriteString(fmt.Sprintf("\n  %s %s Running Scan on %s (%d hosts, %d ports/host)...\n",
			v.spinner.View(),
			cliui.AccentBold.Render("SCANNING:"),
			v.targetInput.Value(),
			v.hostsCount,
			v.portsCount,
		))
		b.WriteString(fmt.Sprintf("  %s %s  ·  %s %d\n\n",
			cliui.Muted.Render("Elapsed:"),
			cliui.Body.Render(fmt.Sprintf("%.1fs", v.elapsedTime.Seconds())),
			cliui.Muted.Render("Discovered open ports:"),
			len(v.results),
		))
		b.WriteString(v.resultsTable.View())
		return b.String()
	}

	b.WriteString(cliui.AccentBold.Render("▌ START SCAN JOB") + "\n\n")

	targetPrompt := "  Target Range: "
	portsPrompt := "  Target Ports: "
	predictPrompt := "  OSINT Predict:"
	typePrompt := "  Scan Protocol:"

	if v.focusIndex == 0 {
		b.WriteString(lipgloss.NewStyle().Foreground(cliui.Accent).Render("›") + targetPrompt[1:] + v.targetInput.View() + "\n")
	} else {
		b.WriteString(" " + targetPrompt[1:] + v.targetInput.View() + "\n")
	}

	if v.focusIndex == 1 {
		b.WriteString(lipgloss.NewStyle().Foreground(cliui.Accent).Render("›") + portsPrompt[1:] + v.portsInput.View() + "\n")
	} else {
		b.WriteString(" " + portsPrompt[1:] + v.portsInput.View() + "\n")
	}

	predictVal := "[ ] No"
	if v.predict {
		predictVal = "[x] Yes"
	}
	if v.focusIndex == 2 {
		b.WriteString(fmt.Sprintf("%s %s %s %s\n",
			lipgloss.NewStyle().Foreground(cliui.Accent).Render("›"),
			predictPrompt[1:],
			OptionSelected.Render(predictVal),
			cliui.Faded.Render("(Space to toggle)"),
		))
	} else {
		b.WriteString(fmt.Sprintf("  %s %s\n", predictPrompt[1:], OptionUnselected.Render(predictVal)))
	}

	typeVal := strings.ToUpper(v.scanType)
	if v.focusIndex == 3 {
		b.WriteString(fmt.Sprintf("%s %s %s %s\n",
			lipgloss.NewStyle().Foreground(cliui.Accent).Render("›"),
			typePrompt[1:],
			OptionSelected.Render(typeVal),
			cliui.Faded.Render("(Space to cycle TCP/SYN/UDP)"),
		))
	} else {
		b.WriteString(fmt.Sprintf("  %s %s\n", typePrompt[1:], OptionUnselected.Render(typeVal)))
	}

	b.WriteString("\n")

	buttonStyle := lipgloss.NewStyle().Padding(0, 3).Border(lipgloss.NormalBorder()).BorderForeground(cliui.Faint)
	if v.focusIndex == 4 {
		buttonStyle = lipgloss.NewStyle().Padding(0, 3).Foreground(lipgloss.Color("#0c0d10")).Background(cliui.Accent).Bold(true)
	}
	b.WriteString("  " + buttonStyle.Render("START SCAN") + "\n")

	if v.errMsg != "" {
		b.WriteString("\n  " + cliui.SeverityStyle("HIGH").Render("Error: "+v.errMsg) + "\n")
	}

	return b.String()
}
