# Build context is a verified scripts/build-release.py output, not the checkout.
FROM scratch
ARG TARGETARCH
ARG REVISION
LABEL org.opencontainers.image.source="https://github.com/nd4y/outpost" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.licenses="MIT"
COPY --chmod=0555 linux_${TARGETARCH}/outpost /outpost
COPY --chmod=0555 linux_${TARGETARCH}/outpost-kit /outpost-kit
COPY licenses/ /licenses/
USER 65532:65532
WORKDIR /
ENTRYPOINT ["/outpost"]
CMD ["help"]
