package main

import (
	"cmp"
	"embed"
	"encoding/json"
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
	"unicode"
)

//go:embed templates/*.gotpl
var templates embed.FS

var severityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

func renderTemplates(targetDir string, res *ScanResult) error {
	sortVulnerabilities(res.Vulnerabilities)
	slices.SortFunc(
		res.ScanErrors,
		func(a, b ScanError) int {
			return strings.Compare(a.Image, b.Image)
		},
	)

	if err := renderJSON(targetDir, res); err != nil {
		return err
	}

	all := slices.Concat(res.Vulnerabilities, scanErrorVulnerabilities(res.ScanErrors))
	sortVulnerabilities(all)
	severities := groupBySeverity(all)

	if err := renderHtml(targetDir, severities, res.Time); err != nil {
		return err
	}

	return renderFeeds(targetDir, severities, res.Time)
}

func sortVulnerabilities(vulns []SourcedVulnerability) {
	slices.SortFunc(
		vulns,
		func(a, b SourcedVulnerability) int {
			return cmp.Or(
				cmp.Compare(slices.Index(severityOrder, a.Severity), slices.Index(severityOrder, b.Severity)),
				strings.Compare(a.Title, b.Title),
				strings.Compare(a.Fingerprint, b.Fingerprint),
			)
		},
	)
}

func renderJSON(targetDir string, res *ScanResult) error {
	path := filepath.Join(targetDir, "report.json")
	slog.Info("Writing JSON report", "path", path)

	type report struct {
		Time            time.Time              `json:"time"`
		PurserVersion   string                 `json:"purser_version"`
		Vulnerabilities []SourcedVulnerability `json:"vulnerabilities"`
		ScanErrors      []ScanError            `json:"scan_errors"`
	}

	r := report{
		Time:            res.Time,
		PurserVersion:   purserVersion(),
		Vulnerabilities: res.Vulnerabilities,
		ScanErrors:      res.ScanErrors,
	}
	if r.Vulnerabilities == nil {
		r.Vulnerabilities = []SourcedVulnerability{}
	}
	if r.ScanErrors == nil {
		r.ScanErrors = []ScanError{}
	}

	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, b, 0o644)
}

// scanErrorVulnerabilities presents images that couldn't be scanned as
// critical vulnerabilities, so they stand out in the HTML report and feeds.
func scanErrorVulnerabilities(errs []ScanError) []SourcedVulnerability {
	vulns := make([]SourcedVulnerability, 0, len(errs))
	for _, e := range errs {
		vulns = append(vulns, SourcedVulnerability{
			Title:       "Unable to scan image",
			Description: "Purser was unable to scan the image: " + e.Error,
			Fingerprint: "purser-scan-error-" + e.Image,
			Severity:    "CRITICAL",
			Images:      []string{e.Image},
			Containers:  e.Containers,
		})
	}
	return vulns
}

type SeverityGroup struct {
	Name            string
	Vulnerabilities []SourcedVulnerability
}

func groupBySeverity(vulns []SourcedVulnerability) []SeverityGroup {
	vulnsBySev := make(map[string][]SourcedVulnerability)
	for i := range vulns {
		vulnsBySev[vulns[i].Severity] = append(vulnsBySev[vulns[i].Severity], vulns[i])
	}

	severities := make([]SeverityGroup, 0, len(severityOrder))
	for _, sev := range severityOrder {
		severities = append(severities, SeverityGroup{Name: sev, Vulnerabilities: vulnsBySev[sev]})
	}
	return severities
}

func renderHtml(targetDir string, severities []SeverityGroup, generated time.Time) error {
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
			Time:       generated,
		},
	); err != nil {
		return err
	}
	return f.Close()
}

func renderFeeds(targetDir string, severities []SeverityGroup, generated time.Time) error {
	t, err := template.New("atom.xml.gotpl").
		Funcs(template.FuncMap{"escape": escapeXML}).
		ParseFS(templates, "templates/atom.xml.gotpl")
	if err != nil {
		return err
	}

	for _, sev := range severities {
		err = renderFeed(t, targetDir, sev, generated)

		if err != nil {
			return err
		}
	}
	return nil
}

// escapeXML escapes markup and replaces characters that XML 1.0 doesn't
// allow (including invalid UTF-8) with U+FFFD.
func escapeXML(s string) string {
	return html.EscapeString(
		strings.Map(
			func(r rune) rune {
				switch {
				case r == '\t', r == '\n', r == '\r',
					r >= 0x20 && r <= 0xD7FF,
					r >= 0xE000 && r <= 0xFFFD,
					r >= 0x10000 && r <= unicode.MaxRune:
					return r
				default:
					return unicode.ReplacementChar
				}
			},
			s,
		),
	)
}

func renderFeed(t *template.Template, targetDir string, sev SeverityGroup, generated time.Time) error {
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
			Time:            generated,
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
