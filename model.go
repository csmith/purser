package main

import "time"

type Container struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Vulnerability struct {
	Title       string            `json:"title"`
	ID          string            `json:"id"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Fingerprint string            `json:"fingerprint"`
	Packages    []AffectedPackage `json:"packages"`
}

type AffectedPackage struct {
	Name             string `json:"name"`
	FixedVersion     string `json:"fixed_version"`
	InstalledVersion string `json:"installed_version"`
}

type SourcedVulnerability struct {
	Vulnerability
	Images     []string    `json:"images"`
	Containers []Container `json:"containers"`
}

type ScanError struct {
	Image      string      `json:"image"`
	Error      string      `json:"error"`
	Containers []Container `json:"containers"`
}

type ScanResult struct {
	Time            time.Time
	Vulnerabilities []SourcedVulnerability
	ScanErrors      []ScanError
}
