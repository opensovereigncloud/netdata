#!/bin/bash
set -e
set -x
unset ALL_PROXY
unset all_proxy

function genJson() {
  jq -c -r -n --arg ipvar "192.168.10.1$i" --arg macvar "1a:1b:1c:1d:1e:$i"  --arg hostname "hostname$i" '{ "service": [ "dhcp4" ], "command": "lease4-add", "arguments": { "ip-address": $ipvar, "hw-address": $macvar, hostname: $hostname }}'
}

for i in 11 21 31 41 51 61
do
  echo $(genJson)
  curl -X POST -H "Content-Type: application/json" -d "$(genJson)" http://192.168.49.2:31549/
done

