# Build the manager binary
FROM golang:1.22 as builder

ARG GOARCH

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY controllers/ controllers/

# Build
RUN --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg \
  CGO_ENABLED=0 GOOS=linux GOARCH=${GOARCH} go build -a -o manager main.go

FROM alpine:edge
ARG USER=root
RUN apk -U upgrade && apk add --no-cache \
    nmap \
    libcap \
    sudo \
    bash \
    nmap-scripts && \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip  /usr/bin/nmap \
    && rm -rf /var/cache/apk/*
WORKDIR /
COPY --from=builder /workspace/manager .
COPY nmap-ipv6-multicast-echo.nse nmap-ipv6-multicast-echo.nse
USER $USER:$USER
ENTRYPOINT ["/manager"]
