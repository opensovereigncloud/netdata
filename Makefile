
# Image URL to use all building/pushing image targets
IMG ?= netdata:1
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
	golangci-lint run ./...
	go test ./... -coverprofile cover.out

# Build manager binary
manager: generate fmt vet
	go build -gcflags='-m -N -l' -o bin/manager main.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go
	sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	/usr/local/go/bin/go run ./main.go

# Install CRDs into a cluster
install: manifests
	kustomize build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests
	kustomize build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	cd config/manager && kustomize edit set image controller=${IMG}
	kustomize build config/default | kubectl apply -f -

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
	podman -r build . -t ${IMG}
	minikube ssh "sudo sh -c 'podman save localhost/${IMG} | docker load'"

# Push the docker image
podman-push:
	podman -r push  ${IMG}

# Build the docker image
docker-build: test
	docker build . -t ${IMG}

# Push the docker image
docker-push:
	docker push ${IMG}

# find or download controller-gen
# download controller-gen if necessary
controller-gen:
ifeq (, $(shell which controller-gen))
	@{ \
	set -e ;\
	CONTROLLER_GEN_TMP_DIR=$$(mktemp -d) ;\
	cd $$CONTROLLER_GEN_TMP_DIR ;\
	go mod init tmp ;\
	go get sigs.k8s.io/controller-tools/cmd/controller-gen@v0.5.0 ;\
	rm -rf $$CONTROLLER_GEN_TMP_DIR ;\
	}
CONTROLLER_GEN=$(GOBIN)/controller-gen
else
CONTROLLER_GEN=$(shell which controller-gen)
endif


run-delve: generate fmt vet manifests
	go build -gcflags "all=-trimpath=$(shell go env GOPATH)" -o bin/manager main.go
	sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./bin/manager
	dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec ./bin/manager

