### Install by helm

```
kubectl create ns onmetal
helm install netdata ./chart -n onmetal  --set image.repository=localhost/netdata
```

for autoreload require (stakater/reloader)[https://github.com/stakater/Reloader]


### Build image

```
USE_EXISTING_CLUSTER=true make test
eval $(minikube -p minikube podman-env)
make podman-build
make podman-push
```


### Logs

```
kubectl logs -f -lcontrol-plane=controller-manager --all-containers=true
```

### Build local execution file with [capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go
setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./manager
export NETSOURCE=ndp
export KUBECONFIG=~/.kube/config
./manager


```

### debug
```
export DEBUG=TRUE
```
