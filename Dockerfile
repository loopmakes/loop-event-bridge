FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY *.go ./
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -trimpath -ldflags="-s -w -X main.buildVersion=${VERSION} -X main.buildRevision=${REVISION}" -o /out/loop-event-bridge . && mkdir -p /out/data && chown 65532:65532 /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/loop-event-bridge /loop-event-bridge
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/loop-event-bridge", "healthcheck"]
ENTRYPOINT ["/loop-event-bridge"]
