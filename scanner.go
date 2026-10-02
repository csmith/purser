package main

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"runtime/debug"
	"slices"
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
	"github.com/moby/moby/client"
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
	t.options.Target = imageRef
	report, err := t.runner.ScanImage(ctx, t.options)
	if incompleteArchiveErr(err) {
		// The daemon has the image's metadata but not its content, so its
		// archive of the image references blobs it doesn't contain. Re-fetch
		// the exact content the container runs (pull by digest, not tag, so
		// the scanned version can't drift) and try once more.
		if repairErr := t.repairImage(ctx, imageRef); repairErr != nil {
			return nil, fmt.Errorf("image scan failed: %w (re-fetch of image content failed: %w)", err, repairErr)
		}
		report, err = t.runner.ScanImage(ctx, t.options)
	}
	if err != nil {
		return nil, fmt.Errorf("image scan failed: %w", err)
	}

	vulns := make(map[string]Vulnerability)
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			v := report.Results[i].Vulnerabilities[j]
			key := v.Fingerprint
			if v.VulnerabilityID != "" {
				key = v.VulnerabilityID
			}

			if existing, ok := vulns[key]; ok {
				existing.Packages = append(
					vulns[key].Packages,
					AffectedPackage{
						Name:             v.PkgName,
						FixedVersion:     v.FixedVersion,
						InstalledVersion: v.InstalledVersion,
					},
				)
				vulns[key] = existing
			} else {
				vulns[key] = Vulnerability{
					Title:       v.Title,
					ID:          v.VulnerabilityID,
					Description: v.Description,
					Severity:    v.Severity, //nolint:staticcheck // Keep Trivy's selected severity, including its source fallback.
					Fingerprint: v.Fingerprint,
					Packages: []AffectedPackage{
						{
							Name:             v.PkgName,
							FixedVersion:     v.FixedVersion,
							InstalledVersion: v.InstalledVersion,
						},
					},
				}
			}
		}
	}

	return slices.Collect(maps.Values(vulns)), nil
}

// incompleteArchiveErr matches missing blobs, not tag mismatches.
func incompleteArchiveErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found in tar") && !strings.Contains(msg, "not found in tarball")
}

// digestFor returns the repo digest from repoDigests pointing at the same
// repository as imageRef. Pulling by that digest re-fetches the
// content of the image the container is running, even if the tag has since
// moved to a newer build.
func digestFor(imageRef string, repoDigests []string) (string, bool) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return "", false
	}
	repo := ref.Context().Name()
	for _, repoDigest := range repoDigests {
		// Normalise both sides, since daemon records may use short names like
		// "adze@sha256:..." where the reference parses to "docker.io/library/adze".
		if d, err := name.NewDigest(repoDigest); err == nil && d.Context().Name() == repo {
			return repoDigest, true
		}
	}
	return "", false
}

// repairImage re-downloads the image's content from the registry it came
// from, using the repo digest recorded on the daemon, so the image's archive
// becomes complete again.
//
// The pull is unauthenticated: the Docker API does not expose daemon-stored
// credentials to API clients, and purser has no credential handling. This
// works for registries that allow anonymous pulls (such as the mirror this
// was written for); otherwise the re-fetch fails and the original scan error
// is reported.
func (t *Scanner) repairImage(ctx context.Context, imageRef string) error {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	inspect, err := c.ImageInspect(ctx, imageRef)
	if err != nil {
		return err
	}
	digest, ok := digestFor(imageRef, inspect.RepoDigests)
	if !ok {
		return fmt.Errorf("no repo digest recorded for %s, cannot re-fetch its content", imageRef)
	}

	slog.Warn("Daemon's copy of the image is missing content, re-fetching it by digest", "image", imageRef, "digest", digest)
	resp, err := c.ImagePull(ctx, digest, client.ImagePullOptions{})
	if err != nil {
		return err
	}
	return resp.Wait(ctx)
}

func trivyOptions(cacheDir string) flag.Options {
	// Despite everything being exported nicely, Trivy is highly coupled to
	// Cobra and doesn't have a good way for us to get default options. Instead,
	// we just have to specify everything we care about here.
	return flag.Options{
		Quiet:    true,
		CacheDir: cacheDir,
		Timeout:  5 * time.Minute,

		CacheBackend: "fs",

		NoProgress: true,
		DBRepositories: []name.Reference{
			lo.Must(name.NewTag(db.DefaultGCRRepository)),
			lo.Must(name.NewTag(db.DefaultGHCRRepository)),
		},
		JavaDBRepositories: []name.Reference{
			lo.Must(name.NewTag(javadb.DefaultGCRRepository)),
			lo.Must(name.NewTag(javadb.DefaultGHCRRepository)),
		},

		ImageSources: ftypes.ImageSources{ftypes.DockerImageSource},

		PkgTypes:         ttypes.PkgTypes,
		PkgRelationships: ftypes.Relationships,

		Format: ttypes.FormatJSON,

		Scanners:          ttypes.Scanners{ttypes.VulnerabilityScanner},
		Parallel:          0,
		DetectionPriority: ftypes.PriorityPrecise,
		DisableTelemetry:  true,

		VulnSeveritySources: []dbtypes.SourceID{"auto"},

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
