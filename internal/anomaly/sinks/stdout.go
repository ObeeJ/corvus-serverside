package sinks

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/cliui"
	"github.com/ObeeJ/corvus-serverside/internal/types"
)

// StdoutSink writes anomaly events to stdout in a branded, human-readable format.
type StdoutSink struct {
	w io.Writer
}

func NewStdout() *StdoutSink {
	return &StdoutSink{w: os.Stdout}
}

func (s *StdoutSink) Send(event types.AnomalyEvent) error {
	symbol := cliui.SevSymbol(string(event.Severity))
	badge := cliui.SevBadge(string(event.Severity))
	ts := event.Timestamp.Format(time.RFC3339)

	_, _ = fmt.Fprintf(s.w, "\n  %s  %s %s\n",
		symbol,
		cliui.AccentBold.Render(string(event.Type)),
		badge,
	)
	_, _ = fmt.Fprintf(s.w, "     %s    %s\n",
		cliui.Muted.Render("host"),
		cliui.Body.Render(fmt.Sprintf("%s:%d/%s", event.Host, event.Port, event.Protocol)),
	)
	_, _ = fmt.Fprintf(s.w, "     %s %s\n",
		cliui.Muted.Render("message"),
		cliui.Body.Render(event.Message),
	)
	_, _ = fmt.Fprintf(s.w, "     %s    %s\n",
		cliui.Muted.Render("time"),
		cliui.Faded.Render(ts),
	)

	return nil
}
