
# Image URL to use all building/pushing image targets
IMG ?= netdata-ipam:1
# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
CRD_OPTIONS ?= "crd:trivialVersions=true"

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

all: manager

# Run tests
test: generate fmt vet manifests
	#golangci-lint run ./...
	USE_EXISTING_CLUSTER=true go test ./... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -gcflags='-m -N -l' -o bin/manager main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go
	sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip  /usr/bin/nmap
	sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet install
	/usr/local/go/bin/go run ./main.go

# Install CRDs into a cluster
install: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests kustomize
	cd config/manager && kustomize edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests: controller-gen
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook paths="./..." output:crd:artifacts:config=config/crd/bases

# Run go fmt against code
fmt:
	go fmt ./...

# Run go vet against code
vet:
	go vet ./...

# Generate code
generate: controller-gen
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

# Build the podman image
podman-build:
	podman -r build . -t ${IMG} --build-arg GOPRIVATE=${GOPRIVATE} --build-arg GIT_USER=${GIT_USER} --build-arg GIT_PASSWORD=${GIT_PASSWORD}
	minikube ssh "sudo sh -c 'podman save localhost/${IMG} | podman load'"

# Push the podman image
podman-push:
	podman -r push  ${IMG}

# Build the podman image
docker-build: test
	podman build . -t ${IMG} --build-arg GOPRIVATE=${GOPRIVATE} --build-arg GIT_USER=${GIT_USER} --build-arg GIT_PASSWORD=${GIT_PASSWORD}

# Push the podman image
docker-push:
	podman push ${IMG}

KUSTOMIZE = /usr/local/bin/kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v3@v3.8.7)

# find or download controller-gen
# download controller-gen if necessary
CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.5.0)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

run-delve: generate fmt vet manifests
	go build -gcflags "all=-trimpath=$(shell go env GOPATH)" -o bin/manager main.go
	sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./bin/manager
	dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./bin/manager

