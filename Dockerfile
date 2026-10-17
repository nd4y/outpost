# syntax=docker/dockerfile:1
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS rsync-build
RUN apk add --no-cache build-base openssl-dev zstd-dev lz4-dev xxhash-dev popt-dev acl-dev attr-dev ca-certificates python3
COPY vendor/rsync-3.5.1.tar.gz /tmp/rsync.tar.gz
RUN echo "c55f9c9dc10fb8bec397b399a0fdded53cc9a2d8e30891bb0d63724d25c37bef  /tmp/rsync.tar.gz" | sha256sum -c - \
 && mkdir /src && tar -xzf /tmp/rsync.tar.gz -C /src --strip-components=1
WORKDIR /src
RUN ./configure --prefix=/usr --disable-md2man --disable-roll-simd --disable-idn \
 && make -j2 \
 && strip rsync \
 && mkdir -p /runtime/usr/bin /runtime/lib /runtime/usr/lib /runtime/etc/ssl/certs /runtime/data /runtime/state /runtime/run/outpost /runtime/tmp \
 && cp rsync /runtime/usr/bin/rsync \
 && ldd rsync | awk '{ for (i=1;i<=NF;i++) if (substr($i,1,1)=="/") print $i }' | sort -u | xargs -r -I '{}' cp --parents '{}' /runtime \
 && cp /lib/ld-musl-*.so.1 /runtime/lib/ \
 && cp /etc/ssl/certs/ca-certificates.crt /runtime/etc/ssl/certs/ \
 && printf 'outpost:x:65532:65532:Outpost:/state:/nonexistent\n' > /runtime/etc/passwd \
 && printf 'outpost:x:65532:\n' > /runtime/etc/group \
 && chown 65532:65532 /runtime/data /runtime/state /runtime/run/outpost /runtime/tmp \
 && chmod 0700 /runtime/state /runtime/run/outpost

FROM --platform=$BUILDPLATFORM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS netbird
ARG TARGETARCH
COPY vendor/netbird_0.81.2_linux_${TARGETARCH}.tar.gz /tmp/netbird.tar.gz
RUN case "$TARGETARCH" in amd64) HASH=a3a5f97d67c8854b33aa562c0bf2244430f07c724cde5ab522f211b49c75c354 ;; arm64) HASH=8152afcc5b5609463d304f8c5ce835fa0d645cc745b0b689c19b1cc4acd1197c ;; *) exit 1 ;; esac && echo "$HASH  /tmp/netbird.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/netbird.tar.gz -C /tmp netbird

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:3082400e369fa24d5fc60bca20edab3f6d604e0c5a690ec66b295eff4dd87ade AS supervisor
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
ARG TARGETARCH
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -buildid=" -o /outpost ./cmd/outpost

FROM victoriametrics/vmagent:v1.154.0@sha256:2a939a9df9c8591aa5447efcd21af8c4f2ecc60ca6a8e742ffd46b9c76ef7f17 AS vmagent
FROM victoriametrics/vlagent:v1.53.0@sha256:a82f93ffecc153fb068606903e512368b070272739d823abe99fad0eff6e1849 AS vlagent

FROM scratch
LABEL org.opencontainers.image.title="Outpost Hyper Backup receiver" \
 org.opencontainers.image.description="Shellless non-root rsync with NetBird userspace networking" \
 org.opencontainers.image.source="https://github.com/nd4y/outpost"
COPY --from=rsync-build /runtime/ /
COPY --from=netbird /tmp/netbird /usr/bin/netbird
COPY --from=supervisor /outpost /usr/bin/outpost
COPY --from=vmagent /vmagent-prod /usr/bin/vmagent
COPY --from=vlagent /vlagent-prod /usr/bin/vlagent
USER 65532:65532
WORKDIR /data
ENV PATH=/usr/bin HOME=/state NB_DAEMON_ADDR=unix:///state/netbird.sock NB_CONFIG=/state/config.json NB_STATE_DIR=/state NB_LOG_FILE=console
HEALTHCHECK --interval=30s --timeout=8s --start-period=150s --retries=3 CMD ["/usr/bin/outpost","health"]
ENTRYPOINT ["/usr/bin/outpost"]
