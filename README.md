### Build

```
eval $(minikube -p minikube podman-env)
make podman-build
make podman-push
```


### Logs

```
kubectl logs -f -lcontrol-plane=controller-manager --all-containers=true
```

### Test local
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o manager main.go
setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip ./manager
./manager

```
