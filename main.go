package main

import (
	"context"
	"flag"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"slices"
	"syscall"
	"time"

	"github.com/csmith/envflag/v2"
	"github.com/csmith/slogflags"
	"github.com/moby/moby/client"
)

var (
	cacheDir   = flag.String("cache-dir", ".data/cache", "Directory to store cached vulnerability information")
	outputDir  = flag.String("output-dir", ".data/output", "Directory to write reports to")
	scanPeriod = flag.Duration("scan-period", time.Hour*12, "How often to scan for vulnerabilities")
)

func main() {
	envflag.Parse()
	_ = slogflags.Logger(slogflags.WithSetDefault(true))

	ctx, cancel := context.WithCancel(context.Background())
	scanner := NewScanner(context.Background(), *cacheDir)
	ticker := time.NewTicker(*scanPeriod)

	slog.Info("Purser is running", "scan-period", *scanPeriod, "cache-dir", *cacheDir)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	slog.Info("Performing initial scan")
	performScan(ctx, scanner)

	select {
	case <-ticker.C:
		slog.Info("Starting scan")
		performScan(ctx, scanner)
	case <-c:
		slog.Info("Signal received, shutting down")
		cancel()
	}
}

func performScan(ctx context.Context, scanner *Scanner) {
	res, err := scanContainers(ctx, scanner)
	if err != nil {
		slog.Error("Failed to scan containers", "error", err)
		os.Exit(1)
	}

	slog.Info("Scan complete", "vulnerabilities", len(res))

	err = renderTemplates(*outputDir, res)
	if err != nil {
		slog.Error("Failed to render templates", "error", err)
		os.Exit(1)
	}
}

func scanContainers(ctx context.Context, scanner *Scanner) ([]SourcedVulnerability, error) {
	containers, err := listContainers(ctx)
	if err != nil {
		return nil, err
	}

	vulns := make(map[string]SourcedVulnerability)
	done := 0

	for image := range containers {
		slog.Info("Scanning image", "image", image, "remaining", len(containers)-done)
		res, err := scanner.Scan(ctx, image)
		if err != nil {
			return nil, err
		}

		for j := range res {
			if s, ok := vulns[res[j].Fingerprint]; ok {
				s.Images = append(s.Images, image)
				s.Containers = append(s.Containers, containers[image]...)
			} else {
				vulns[res[j].Fingerprint] = SourcedVulnerability{
					Vulnerability: res[j],
					Images:        []string{image},
					Containers:    containers[image],
				}
			}
		}

		done++
	}

	return slices.Collect(maps.Values(vulns)), nil
}

func listContainers(ctx context.Context) (map[string][]Container, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	containers, err := c.ContainerList(ctx, client.ContainerListOptions{
		Filters: client.Filters{
			"status": {"running": true},
		},
	})
	if err != nil {
		return nil, err
	}

	images := make(map[string][]Container)
	for i := range containers.Items {
		container := containers.Items[i]
		images[container.Image] = append(images[container.Image], Container{
			ID:   container.ID,
			Name: container.Names[0][1:],
		})
	}

	return images, nil
}
