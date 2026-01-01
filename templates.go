package main

import (
	"embed"
	"html/template"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"time"
)

//go:embed templates/*.gotpl
var templates embed.FS

func renderTemplates(targetDir string, vulns []SourcedVulnerability) error {
	var vulsBySev = make(map[string][]SourcedVulnerability)
	for i := range vulns {
		vulsBySev[vulns[i].Severity] = append(vulsBySev[vulns[i].Severity], vulns[i])
	}

	type SeverityGroup struct {
		Name            string
		Vulnerabilities []SourcedVulnerability
	}

	var severities []SeverityGroup
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		slices.SortFunc(vulsBySev[sev], func(a, b SourcedVulnerability) int {
			return strings.Compare(a.Title, b.Title)
		})

		severities = append(severities, SeverityGroup{
			Name:            sev,
			Vulnerabilities: vulsBySev[sev],
		})
	}

	path := filepath.Join(targetDir, "index.html")
	slog.Info("Writing HTML report", "path", path)
	t, err := template.ParseFS(templates, "templates/*.gotpl")
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return t.ExecuteTemplate(f, "index.html.gotpl", struct {
		Severities []SeverityGroup
		Version    string
		Time       time.Time
	}{
		Severities: severities,
		Version:    purserVersion(),
		Time:       time.Now(),
	})
}

func purserVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	return info.Main.Version
}
