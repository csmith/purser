package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

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

	require.NoError(t, renderTemplates(dir, vulns))

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
