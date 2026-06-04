package tui

import (
	"github.com/charmbracelet/bubbles/key"
)

type keyMap struct {
	Up         key.Binding
	Down       key.Binding
	Enter      key.Binding
	Esc        key.Binding
	Tab        key.Binding
	ShiftTab   key.Binding
	Quit       key.Binding
	Filter     key.Binding
	StartScan  key.Binding
	CancelScan key.Binding
}

var keys = keyMap{
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "move up"),
	),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "move down"),
	),
	Enter: key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("enter", "select/action"),
	),
	Esc: key.NewBinding(
		key.WithKeys("esc"),
		key.WithHelp("esc", "back/clear"),
	),
	Tab: key.NewBinding(
		key.WithKeys("tab"),
		key.WithHelp("tab", "next tab"),
	),
	ShiftTab: key.NewBinding(
		key.WithKeys("shift+tab"),
		key.WithHelp("shift+tab", "prev tab"),
	),
	Quit: key.NewBinding(
		key.WithKeys("ctrl+c", "q"),
		key.WithHelp("q/ctrl+c", "quit"),
	),
	Filter: key.NewBinding(
		key.WithKeys("/"),
		key.WithHelp("/", "filter"),
	),
	StartScan: key.NewBinding(
		key.WithKeys("s"),
		key.WithHelp("s", "start scan"),
	),
	CancelScan: key.NewBinding(
		key.WithKeys("ctrl+c", "esc"),
		key.WithHelp("esc/ctrl+c", "cancel"),
	),
}
