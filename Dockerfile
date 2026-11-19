FROM golang:1.27.4 AS build

WORKDIR /go/src/app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    set -eux; \
    CGO_ENABLED=0 go build -o /purser .; \
    mkdir -p /data/cache /data/output /notices; \
    go tool gocredits -skip-missing . > /notices/CREDITS;

FROM ghcr.io/greboid/dockerbase/nonroot:1.20261022.0
COPY --from=build /purser /purser
COPY --from=build --chown=65532:65532 /data /
COPY --from=build /notices /notices
VOLUME /data/cache
VOLUME /data/output
ENTRYPOINT ["/purser"]
ENV CACHE_DIR=/data/cache OUTPUT_DIR=/data/output
