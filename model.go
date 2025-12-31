package main

type Container struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Vulnerability struct {
	Title       string
	ID          string
	Description string
	Severity    string
	Fingerprint string
	Packages    []AffectedPackage
}

type AffectedPackage struct {
	Name             string
	FixedVersion     string
	InstalledVersion string
}

type SourcedVulnerability struct {
	Vulnerability
	Images     []string
	Containers []Container
}
