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
read-only requests and pulls, and allow it to run as a regular user.

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

## Docker pruning and missing images 

If Purser runs against a docker daemon that prunes its images, the original
image may no longer be available. In this case, Purser will show critical
"Unable to scan image" errors with a message along the lines of:

> Purser was unable to scan the image: image scan failed: scan error: scan failed: failed analysis: unable to get the image's config file: unable to populate: unable to open: failed to initialize the struct from the temporary file: file blobs/sha256/b57acab7ab2fad3c7d8271f95477c8a57461cdb210d1b521ec7b879094bfbb5b not found in tar

As of v1.2.0, Purser will attempt to pull these images (with the exact digest
that is running) and retry the scan. Purser currently has no way to
authenticate to private registries, so this will only work for public images.
