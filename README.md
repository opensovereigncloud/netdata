# netdata
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) 
[![GitHub License](https://img.shields.io/static/v1?label=License&message=Apache-2.0&color=blue&style=flat-square)](LICENSE)

## Overview
The Netdata operator keeps a watch over subnets and scans or discovers the servers from the network by using two different ways NMAP and Netlink.

NMAP - Netdata operator scans for IPv4 addresses and creates the ip objects in the Kubernetes cluster.

Netlink - Netdata operator subscribes to Netlink for all the IPv6 updates. When the Netdata receives an update for the IPv6 address it creates or updates the IP object in the Kubernetes cluster.

Netada operator creates ip objects with two important labels ip address and mac of the server. The IP and MAC info is further consumed by oob-operator.


#### Workflow

![Netdata Workflow](netdata_workflow.jpg)

## Contributing

We'd love to get feedback from you. Please report bugs, suggestions or post questions by opening a GitHub issue.

### How it works
This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/)

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/) 
which provides a reconcile function responsible for synchronizing resources untile the desired state is reached on the cluster 

## License

Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

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
