#!/bin/bash
make docker-build
rm -rf netdata-ipam.tar
docker save localhost/netdata-ipam:1 > netdata-ipam.tar
rm -rf netdata-ipam.tar.gz
gzip netdata-ipam.tar
scp netdata-ipam.tar.gz pronix@45.86.152.3:/tmp/
