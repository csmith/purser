# Purser

Purser runs periodic vulnerability scans on all container images that are in
use on a host. It lists running containers via the Docker API, then scans
each distinct image using [Trivy](https://trivy.dev/). Aggregated details
are then written to a HTML report.

## Usage

Purser is designed to run as a container itself. It requires a directory
in which to cache vulnerability database files, access to the host's docker
socket (for listing containers and reading images), and a directory to output
the reports.

A simple docker compose file is below.

```yaml
services:
  purser:
    image: ghcr.io/csmith/purser
    restart: unless-stopped
    user: '0' # or some other uid with access to the docker socket
    volumes:
      - cache:/data/cache
      - output:/data/output
      - /var/run/docker.sock:/var/run/docker.sock

volumes:
  cache:
  output:
```

In production enviroments you may want to use a proxy like
[dsp](https://github.com/greboid/dsp) to limit purser to
read-only requests, and allow it to run as a regular user.

## Options

Purser options should be specified as environment vars. The following options
are available:

| Option      | Description                                             | Default                                              |
|-------------|---------------------------------------------------------|------------------------------------------------------|
| SCAN_PERIOD | How often to scan containers for vulnerabilities        | `12h`                                                |
| OUTPUT_DIR  | Directory to write reports to                           | `/data/output/` (docker) `.data/output/` (otherwise) |
| CACHE_DIR   | Directory to cache vulnerability databases in           | `/data/cache/` (docker) `.data/cache/` (otherwise)   |
| SWARM       | Whether to try and scan all images used in Docker Swarm | `false`                                              |
| LOG_LEVEL   | Minimum log level to output                             | `INFO`                                               |
| LOG_FORMAT  | Format of log output (`TEXT` or `JSON`)                 | `TEXT`                                               |
| DOCKER_HOST | URL to access the Docker API                            | `-`                                                  |
