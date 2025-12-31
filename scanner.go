package main

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/javadb"
	ttypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"

	_ "modernc.org/sqlite" // Required to read the Java vulnerability DB
)

// Scanner handles scanning a container image using Trivy. Scanner is NOT
// thread safe: Scan() must NOT be called from multiple goroutines at the
// same time.
type Scanner struct {
	runner  artifact.Runner
	options flag.Options
}

func NewScanner(context context.Context, cacheDir string) *Scanner {
	opts := trivyOptions(cacheDir)

	return &Scanner{
		options: opts,
		runner:  lo.Must(artifact.NewRunner(context, opts, artifact.TargetContainerImage)),
	}
}

func (t *Scanner) Close(ctx context.Context) error {
	return t.runner.Close(ctx)
}

func (t *Scanner) Scan(ctx context.Context, imageRef string) ([]Vulnerability, error) {
	t.options.ScanOptions.Target = imageRef
	report, err := t.runner.ScanImage(ctx, t.options)
	if err != nil {
		return nil, fmt.Errorf("image scan failed: %w", err)
	}

	var vulns []Vulnerability
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			v := report.Results[i].Vulnerabilities[j]
			vulns = append(vulns, Vulnerability{
				Title:            v.Title,
				ID:               v.VulnerabilityID,
				Description:      v.Description,
				Severity:         v.Severity,
				Fingerprint:      v.Fingerprint,
				Package:          v.PkgName,
				FixedVersion:     v.FixedVersion,
				InstalledVersion: v.InstalledVersion,
			})
		}
	}

	return vulns, nil
}

func trivyOptions(cacheDir string) flag.Options {
	// Despite everything being exported nicely, Trivy is highly coupled to
	// Cobra and doesn't have a good way for us to get default options. Instead,
	// we just have to specify everything we care about here.
	return flag.Options{
		GlobalOptions: flag.GlobalOptions{
			Quiet:    true,
			CacheDir: cacheDir,
			Timeout:  5 * time.Minute,
		},

		CacheOptions: flag.CacheOptions{
			CacheBackend: "fs",
		},

		DBOptions: flag.DBOptions{
			NoProgress: true,
			DBRepositories: []name.Reference{
				lo.Must(name.NewTag(db.DefaultGCRRepository)),
				lo.Must(name.NewTag(db.DefaultGHCRRepository)),
			},
			JavaDBRepositories: []name.Reference{
				lo.Must(name.NewTag(javadb.DefaultGCRRepository)),
				lo.Must(name.NewTag(javadb.DefaultGHCRRepository)),
			},
		},

		ImageOptions: flag.ImageOptions{
			ImageSources: ftypes.ImageSources{ftypes.DockerImageSource},
		},

		PackageOptions: flag.PackageOptions{
			PkgTypes:         ttypes.PkgTypes,
			PkgRelationships: ftypes.Relationships,
		},

		ReportOptions: flag.ReportOptions{
			Format: ttypes.FormatJSON,
		},

		ScanOptions: flag.ScanOptions{
			Scanners:          ttypes.Scanners{ttypes.VulnerabilityScanner},
			Parallel:          0,
			DetectionPriority: ftypes.PriorityPrecise,
			DisableTelemetry:  true,
		},

		VulnerabilityOptions: flag.VulnerabilityOptions{
			VulnSeveritySources: []dbtypes.SourceID{"auto"},
		},

		AppVersion: lo.Must(trivyVersion()),
	}
}

func trivyVersion() (string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", fmt.Errorf("could not read build info")
	}

	for _, d := range info.Deps {
		if d.Path == "github.com/aquasecurity/trivy" {
			return strings.TrimPrefix(d.Version, "v"), nil
		}
	}

	return "", fmt.Errorf("could not find Scanner version")
}
