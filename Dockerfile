# Build the manager binary
FROM golang:1.18 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
ARG GOPRIVATE
ARG GIT_USER
ARG GIT_PASSWORD
RUN if [ ! -z "$GIT_USER" ] && [ ! -z "$GIT_PASSWORD" ]; then \
        printf "machine github.com\n \
            login ${GIT_USER}\n \
            password ${GIT_PASSWORD}\n \
            \nmachine api.github.com\n \
            login ${GIT_USER}\n \
            password ${GIT_PASSWORD}\n" \
            >> ${HOME}/.netrc;\
    fi


RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY controllers/ controllers/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go
# RUN CGO_ENABLED=1 GOOS=linux go build -o manager -a -ldflags '-linkmode external -extldflags "-static"' main.go

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
USER $USER:$USER
ENTRYPOINT ["/manager"]
