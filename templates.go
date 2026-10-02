package main

import (
	"embed"
	"html"
	htemplate "html/template"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/*.gotpl
var templates embed.FS

type SeverityGroup struct {
	Name            string
	Vulnerabilities []SourcedVulnerability
}

func renderTemplates(targetDir string, vulns []SourcedVulnerability) error {
	var vulnsBySev = make(map[string][]SourcedVulnerability)
	for i := range vulns {
		vulnsBySev[vulns[i].Severity] = append(vulnsBySev[vulns[i].Severity], vulns[i])
	}

	severities := make([]SeverityGroup, 0, 5)
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		slices.SortFunc(
			vulnsBySev[sev],
			func(a, b SourcedVulnerability) int {
				return strings.Compare(a.Title, b.Title)
			},
		)

		severities = append(
			severities,
			SeverityGroup{
				Name:            sev,
				Vulnerabilities: vulnsBySev[sev],
			},
		)
	}

	if err := renderHtml(targetDir, severities); err != nil {
		return err
	}

	return renderFeeds(targetDir, severities)
}

func renderHtml(targetDir string, severities []SeverityGroup) error {
	path := filepath.Join(targetDir, "index.html")
	slog.Info("Writing HTML report", "path", path)
	t, err := htemplate.New("index.html.gotpl").
		ParseFS(templates, "templates/index.html.gotpl")
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if err := t.Execute(
		f,
		struct {
			Severities []SeverityGroup
			Version    string
			Time       time.Time
		}{
			Severities: severities,
			Version:    purserVersion(),
			Time:       time.Now(),
		},
	); err != nil {
		return err
	}
	return f.Close()
}

func renderFeeds(targetDir string, severities []SeverityGroup) error {
	t, err := template.New("atom.xml.gotpl").
		Funcs(template.FuncMap{"escape": html.EscapeString}).
		ParseFS(templates, "templates/atom.xml.gotpl")
	if err != nil {
		return err
	}

	for _, sev := range severities {
		err = renderFeed(t, targetDir, sev)

		if err != nil {
			return err
		}
	}
	return nil
}

func renderFeed(t *template.Template, targetDir string, sev SeverityGroup) error {
	path := filepath.Join(targetDir, strings.ToLower(sev.Name)+".xml")
	slog.Info("Writing feed", "path", path)

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	if err := t.Execute(
		f,
		struct {
			Severity        string
			Vulnerabilities []SourcedVulnerability
			Time            time.Time
		}{
			Severity:        sev.Name,
			Vulnerabilities: sev.Vulnerabilities,
			Time:            time.Now(),
		},
	); err != nil {
		return err
	}
	return f.Close()
}

func purserVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	return info.Main.Version
}
