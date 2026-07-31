// Package tui renders cadrega's static-analysis and LLM-analysis results as
// an interactive terminal UI built with Bubble Tea.
package tui

import (
	"fmt"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/utox39/cadrega/pkg/findings"
)

const (
	tabBarHeight  = 1
	helpBarHeight = 1
)

var (
	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 2).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62"))

	inactiveTabStyle = lipgloss.NewStyle().
				Padding(0, 2).
				Foreground(lipgloss.Color("245"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("245"))

	verdictStyle = lipgloss.NewStyle().Bold(true)
)

// TuiData carries the analysis results shown by the TUI.
type TuiData struct {
	StaticFindings []findings.Finding
	LLMFindings    []findings.Finding
	StaticVerdict  string
	LLMVerdict     string
	LLMOutput      string
	Verbose        bool
}

type tuiSection struct {
	title    string
	viewport viewport.Model
}

type tuiModel struct {
	sections []tuiSection
	active   int
	ready    bool
}

func severityStyle(sev findings.Severity) lipgloss.Style {
	switch sev {
	case findings.Low:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true) // yellow
	case findings.Medium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true) // orange
	case findings.High:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true) // red
	default:
		return lipgloss.NewStyle()
	}
}

func formatFinding(source string, f findings.Finding) string {
	sevTag := severityStyle(f.Severity).Render("[" + f.Severity.String() + "]")
	prefix := ""
	if source != "" {
		prefix = "(" + source + ") "
	}
	return fmt.Sprintf(
		"%s%s  %s\n  Message:  %s\n  Evidence: %s",
		prefix, sevTag, f.Name, f.Message, f.Evidence,
	)
}

func buildFindingsSection(verdictLabel, verdict string, finds []findings.Finding) string {
	var b strings.Builder

	b.WriteString(verdictStyle.Render(verdictLabel + ": " + verdict))
	b.WriteString("\n\n")

	if len(finds) == 0 {
		b.WriteString("No findings.")
		return b.String()
	}

	for i, f := range finds {
		if i > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString(formatFinding("", f))
	}

	return b.String()
}

func buildFinalVerdictSection(data TuiData) string {
	var b strings.Builder

	b.WriteString(verdictStyle.Render("Static Analysis: " + data.StaticVerdict))
	b.WriteString("\n")
	b.WriteString(verdictStyle.Render("LLM Analysis:    " + data.LLMVerdict))
	b.WriteString("\n\n")

	if len(data.StaticFindings) == 0 && len(data.LLMFindings) == 0 {
		b.WriteString("No findings.")
		return b.String()
	}

	first := true
	for _, f := range data.StaticFindings {
		if !first {
			b.WriteString("\n\n")
		}
		first = false
		b.WriteString(formatFinding("static", f))
	}
	for _, f := range data.LLMFindings {
		if !first {
			b.WriteString("\n\n")
		}
		first = false
		b.WriteString(formatFinding("llm", f))
	}

	return b.String()
}

func newTUIModel(data TuiData) tuiModel {
	sections := []tuiSection{
		{title: "Final Verdict", viewport: viewport.New()},
		{title: "Static Analysis", viewport: viewport.New()},
		{title: "LLM Analysis", viewport: viewport.New()},
	}

	sections[0].viewport.SetContent(buildFinalVerdictSection(data))
	sections[1].viewport.SetContent(buildFindingsSection("Verdict", data.StaticVerdict, data.StaticFindings))
	sections[2].viewport.SetContent(buildFindingsSection("Verdict", data.LLMVerdict, data.LLMFindings))

	if data.Verbose {
		llmOutputVP := viewport.New()
		llmOutputVP.SetContent(data.LLMOutput)
		sections = append(sections, tuiSection{title: "LLM Output", viewport: llmOutputVP})
	}

	return tuiModel{sections: sections, active: 0}
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) renderTabBar() (string, [][2]int) {
	var rendered []string
	var bounds [][2]int
	col := 0

	for i, s := range m.sections {
		style := inactiveTabStyle
		if i == m.active {
			style = activeTabStyle
		}
		tab := style.Render(s.title)
		rendered = append(rendered, tab)

		width := lipgloss.Width(tab)
		bounds = append(bounds, [2]int{col, col + width})
		col += width
	}

	return lipgloss.JoinHorizontal(lipgloss.Top, rendered...), bounds
}

func (m *tuiModel) setSize(width, height int) {
	contentHeight := max(height-tabBarHeight-helpBarHeight, 0)

	for i := range m.sections {
		m.sections[i].viewport.SetWidth(width)
		m.sections[i].viewport.SetHeight(contentHeight)
	}
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.setSize(msg.Width, msg.Height)
		m.ready = true
		return m, nil

	case tea.KeyPressMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "left", "h":
			m.active = (m.active - 1 + len(m.sections)) % len(m.sections)
			return m, nil
		case "right", "l":
			m.active = (m.active + 1) % len(m.sections)
			return m, nil
		}

	case tea.MouseClickMsg:
		mouse := msg.Mouse()
		if mouse.Button == tea.MouseLeft && mouse.Y == 0 {
			_, bounds := m.renderTabBar()
			for i, b := range bounds {
				if mouse.X >= b[0] && mouse.X < b[1] {
					m.active = i
					return m, nil
				}
			}
		}
	}

	var cmd tea.Cmd
	m.sections[m.active].viewport, cmd = m.sections[m.active].viewport.Update(msg)
	return m, cmd
}

func (m tuiModel) View() tea.View {
	if !m.ready {
		return tea.NewView("Loading...")
	}

	tabBar, _ := m.renderTabBar()

	help := helpStyle.Render("h/l ←/→ switch section · j/k ↑/↓ scroll · q quit")

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		tabBar,
		m.sections[m.active].viewport.View(),
		help,
	)

	v := tea.NewView(content)
	v.AltScreen = true
	v.MouseMode = tea.MouseModeCellMotion

	return v
}

// RunTUI launches the interactive Bubble Tea TUI showing the analysis results
// in data. It blocks until the user quits.
func RunTUI(data TuiData) error {
	p := tea.NewProgram(newTUIModel(data))
	_, err := p.Run()
	return err
}
