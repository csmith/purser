FROM golang:1.25 AS build
ENV GOEXPERIMENT=jsonv2

WORKDIR /go/src/app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    set -eux; \
    CGO_ENABLED=0 go build -o /purser .; \
    mkdir -p /data/cache /data/output; \
    go run github.com/google/go-licenses@latest save ./... --save_path=/notices \
        --ignore github.com/xi2/xz \
        --ignore modernc.org/mathutil \
        ;

FROM ghcr.io/greboid/dockerbase/nonroot:1.20250803.0
COPY --from=build /purser /purser
COPY --from=build --chown=65532:65532 /data /
COPY --from=build /notices /notices
VOLUME /data/cache
VOLUME /data/output
ENTRYPOINT ["/purser"]
CMD ["--cache-dir", "/data/cache", "--outputdir", "/data/output"]