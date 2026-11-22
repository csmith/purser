package main

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFeedsAreValidXMLWithForbiddenCharacters(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	vulns := []SourcedVulnerability{
		{
			Title:       "Bad <title>\x01",
			ID:          "CVE-2026-0001",
			Description: "Contains \uFFFF, \uFFFE, \x00, \x1b, \xed\xa0\x80 and \xff but keeps\ttabs & newlines\n",
			Severity:    "MEDIUM",
			Fingerprint: "fp-1",
			Packages:    []AffectedPackage{{Name: "pkg\x02", InstalledVersion: "1.0", FixedVersion: "1.1"}},
			Images:      []string{"image\x7f:latest"},
			Containers:  []Container{{ID: "abc", Name: "container\x03"}},
		},
	}

	require.NoError(t, renderTemplates(dir, &ScanResult{Time: time.Now(), Vulnerabilities: vulns}))

	b, err := os.ReadFile(filepath.Join(dir, "medium.xml"))
	require.NoError(t, err)

	var feed struct {
		Entries []struct {
			Title   string `xml:"title"`
			Content string `xml:"content"`
		} `xml:"entry"`
	}
	require.NoError(t, xml.Unmarshal(b, &feed))
	require.Len(t, feed.Entries, 1)
	assert.Equal(t, "CVE-2026-0001: Bad <title>\uFFFD", feed.Entries[0].Title)
	assert.Contains(
		t,
		feed.Entries[0].Content,
		"Contains \uFFFD, \uFFFD, \uFFFD, \uFFFD, \uFFFD\uFFFD\uFFFD and \uFFFD but keeps\ttabs & newlines\n",
	)
}

func TestJSONReport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	scanned := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	res := &ScanResult{
		Time: scanned,
		Vulnerabilities: []SourcedVulnerability{
			{
				Title:       "Low thing",
				ID:          "CVE-2026-0002",
				Description: "Something minor",
				Severity:    "LOW",
				Fingerprint: "fp-2",
				Packages:    []AffectedPackage{{Name: "libbar", InstalledVersion: "2.0", FixedVersion: ""}},
				Images:      []string{"bar:1"},
				Containers:  []Container{{ID: "c2", Name: "bar"}},
			},
			{
				Title:       "Critical thing",
				ID:          "CVE-2026-0001",
				Description: "Something bad",
				Severity:    "CRITICAL",
				Fingerprint: "fp-1",
				Packages: []AffectedPackage{
					{Name: "libfoo", InstalledVersion: "1.0", FixedVersion: "1.1"},
					{Name: "libfoo-dev", InstalledVersion: "1.0", FixedVersion: "1.1"},
				},
				Images:     []string{"foo:1", "foo:2"},
				Containers: []Container{{ID: "c1", Name: "foo"}, {ID: "c3", Name: "foo2"}},
			},
		},
		ScanErrors: []ScanError{
			{Image: "broken:1", Error: "image scan failed: boom", Containers: []Container{{ID: "c4", Name: "broken"}}},
		},
	}

	require.NoError(t, renderTemplates(dir, res))

	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	require.NoError(t, err)

	var report struct {
		Time            time.Time `json:"time"`
		Vulnerabilities []struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
			Fingerprint string `json:"fingerprint"`
			Packages    []struct {
				Name             string `json:"name"`
				InstalledVersion string `json:"installed_version"`
				FixedVersion     string `json:"fixed_version"`
			} `json:"packages"`
			Images     []string `json:"images"`
			Containers []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"vulnerabilities"`
		ScanErrors []struct {
			Image      string `json:"image"`
			Error      string `json:"error"`
			Containers []struct {
				Name string `json:"name"`
			} `json:"containers"`
		} `json:"scan_errors"`
	}
	require.NoError(t, json.Unmarshal(b, &report))

	assert.True(t, scanned.Equal(report.Time))

	require.Len(t, report.Vulnerabilities, 2, "scan errors shouldn't be reported as vulnerabilities")
	crit := report.Vulnerabilities[0]
	assert.Equal(t, "CVE-2026-0001", crit.ID)
	assert.Equal(t, "Critical thing", crit.Title)
	assert.Equal(t, "Something bad", crit.Description)
	assert.Equal(t, "CRITICAL", crit.Severity)
	assert.Equal(t, "fp-1", crit.Fingerprint)
	require.Len(t, crit.Packages, 2)
	assert.Equal(t, "libfoo", crit.Packages[0].Name)
	assert.Equal(t, "1.0", crit.Packages[0].InstalledVersion)
	assert.Equal(t, "1.1", crit.Packages[0].FixedVersion)
	assert.Equal(t, []string{"foo:1", "foo:2"}, crit.Images)
	require.Len(t, crit.Containers, 2)
	assert.Equal(t, "c1", crit.Containers[0].ID)
	assert.Equal(t, "foo", crit.Containers[0].Name)
	assert.Equal(t, "CVE-2026-0002", report.Vulnerabilities[1].ID)

	require.Len(t, report.ScanErrors, 1)
	assert.Equal(t, "broken:1", report.ScanErrors[0].Image)
	assert.Equal(t, "image scan failed: boom", report.ScanErrors[0].Error)
	require.Len(t, report.ScanErrors[0].Containers, 1)
	assert.Equal(t, "broken", report.ScanErrors[0].Containers[0].Name)

	html, err := os.ReadFile(filepath.Join(dir, "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(html), "Unable to scan image")
	assert.Contains(t, string(html), "image scan failed: boom")
}

func TestJSONReportEmptyScan(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, renderTemplates(dir, &ScanResult{Time: time.Now()}))

	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	require.NoError(t, err)

	var report map[string]any
	require.NoError(t, json.Unmarshal(b, &report))
	assert.Equal(t, []any{}, report["vulnerabilities"])
	assert.Equal(t, []any{}, report["scan_errors"])
}
