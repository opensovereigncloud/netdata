/*


Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-logr/logr"
	ndp "github.com/mdlayher/ndp"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/runtime"
	"log"
	"os"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"strings"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"net"
	"net/http"
	"net/url"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	dev1 "netdata/api/v1"
)

type KeaJson []struct {
	Arguments Arguments `json:"arguments"`
	Result    int       `json:"result"`
	Text      string    `json:"text"`
}
type Lease struct {
	Cltt      int    `json:"cltt"`
	FqdnFwd   bool   `json:"fqdn-fwd"`
	FqdnRev   bool   `json:"fqdn-rev"`
	Hostname  string `json:"hostname"`
	HwAddress string `json:"hw-address"`
	IPAddress string `json:"ip-address"`
	State     int    `json:"state"`
	SubnetID  int    `json:"subnet-id"`
	ValidLft  int    `json:"valid-lft"`
}
type Arguments struct {
	Leases []Lease `json:"leases"`
}

type PostData struct {
	Command string   `json:"command"`
	Service []string `json:"service"`
}

func postData(ipv int) string {
	res := &PostData{
		Command: fmt.Sprintf("lease%d-get-all", ipv),
		Service: []string{fmt.Sprintf("dhcp%d", ipv)},
	}
	res1, _ := json.Marshal(res)
	//'{ "command": "lease4-get-all", "service": [ "dhcp4" ] }'
	//'{ "command": "lease6-get-all", "service": [ "dhcp6" ] }'
	return string(res1)
}

/*
 if [ "$1" == "-6" ]; then
  output=$(curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "lease6-get-all", "service": [ "dhcp6" ] }' http://192.168.10.3:8000/)
else
  output=$(curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "lease4-get-all", "service": [ "dhcp4" ] }' http://192.168.10.3:8000/)
fi

*/

func kealease(apiUrl string, ipv int) []Lease {
	postData := postData(ipv)
	log.Printf("Kea post data  is #%s ", postData)
	resp, err := http.Post(apiUrl, "application/json", strings.NewReader(postData))
	if err != nil {
		log.Fatalf("Fail request kea api: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	log.Printf("Kea result is #%s ", body)
	keajson := KeaJson{}
	json.Unmarshal(body, &keajson)
	return keajson[0].Arguments.Leases
}

type netdataconf struct {
	Subnets  []string `yaml:"subnets"`
	Interval int      `yaml:"interval"`
	TTL      int      `yaml:"ttl"`
	KeaApi   string   `yaml:"keaapi"`
}

func (c *netdataconf) getConf() *netdataconf {

	yamlFile, err := ioutil.ReadFile("/etc/manager/netdata-config.yaml")
	if err != nil {
		log.Fatalf("yamlFile.Get err   #%v ", err)
		os.Exit(21)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	log.Printf("Config is #%v ", c)

	return c
}

func (c *netdataconf) validate() {
	c.validateSubnets()
	c.validateInterval()
	c.validateKeaApi()
}

// c.Subnets not empty
// c.Subnets each subnet is real subnet
func (c *netdataconf) validateSubnets() {
	if len(c.Subnets) > 0 {
		log.Printf("at least 1 subnet")
	} else {
		log.Fatalf("require at least one subnet")
		os.Exit(20)
	}
	for idx := range c.Subnets {
		k := &c.Subnets[idx]
		ipaddr, ipnet, err := net.ParseCIDR(*k)
		if err != nil && ipaddr.String() == ipnet.IP.String() {
			log.Fatal(err)
			os.Exit(20)
		}
	}
}

// c.Interval > 50
// TTL > Interval
func (c *netdataconf) validateInterval() {
	if c.TTL > c.Interval {
		log.Printf("valid ttl > interval")
	} else {
		log.Fatalf("wrong ttl < interval")
		os.Exit(20)
	}

	if c.TTL > c.Interval {
		log.Printf("valid ttl > interval")
	} else {
		log.Fatalf("wrong ttl < interval")
		os.Exit(20)
	}
}

// KeaApi correct url
func (c *netdataconf) validateKeaApi() {
	u, err := url.Parse(c.KeaApi)
	if err == nil && u.Scheme != "" && u.Host != "" {
		log.Printf("valid kea url")
	} else {
		log.Fatalf("wrong kea url")
		os.Exit(20)
	}
}

// NetdataReconciler reconciles a Netdata object
type NetdataReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func nmapScan(targetSubnet string, ctx context.Context) []nmap.Host {
	//  setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip  /usr/bin/nmap
	// nmap --privileged -sn -oX - 192.168.178.0/24
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targetSubnet),
		nmap.WithPingScan(),
		nmap.WithPrivileged(),
		nmap.WithContext(ctx),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	return result.Hosts
}
func createNetCRD(ipv4 string, ipv6 string, mac string, subnet string, conf *netdataconf, ctx context.Context, r *NetdataReconciler, req ctrl.Request) {
	var expTime metav1.Time = metav1.Time{Time: time.Now().Add(time.Duration(conf.TTL) * time.Second)}
	netSpec := dev1.NetdataSpec{
		IPAddress:   ipv4,
		IPV6Address: ipv6,
		MACAddress:  mac,
		Expiration:  expTime,
		Subnet:      subnet,
	}

	crdname := strings.ToLower(strings.Replace(mac, ":", "", -1))
	netcrd := &dev1.Netdata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdname,
			Namespace: req.Namespace,
		},
		Spec: netSpec,
	}
	_, err := ctrl.CreateOrUpdate(ctx, r, netcrd, func() error {
		r.Log.V(0).Info("Create netdata crd ", "metadata.name", netcrd.ObjectMeta.Name, " IPAddress", netcrd.Spec.IPAddress)
		return nil
	})
	if err != nil {
		log.Fatalf("Fail crd creation : %v", err)
	}
}

func checkttl(r *NetdataReconciler, ctx context.Context, req ctrl.Request, now metav1.Time) {
	var crds dev1.NetdataList
	if err := r.List(ctx, &crds, client.InNamespace(req.Namespace)); err != nil {
		r.Log.Error(err, "unable to list netdata crd")
	}
	for idx := range crds.Items {
		k := &crds.Items[idx]
		expirationTime := &k.Spec.Expiration
		if expirationTime != nil {
			if expirationTime.Before(&now) {
				if err := r.Delete(ctx, k, client.PropagationPolicy(metav1.DeletePropagationBackground)); client.IgnoreNotFound(err) != nil {
					r.Log.Error(err, "unable to delete expired netdata crd", "key", k)
				} else {
					r.Log.V(0).Info("deleted expired netdata crd", "key", k)
				}
			}
		}
	}
}

// +kubebuilder:rbac:groups=machine.onmetal.de.onmetal.de,resources=netdata,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=machine.onmetal.de.onmetal.de,resources=netdata/status,verbs=get;update;patch
func (r *NetdataReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	_ = r.Log.WithValues("netdata", req.NamespacedName)
	mergeRes := make(map[string]dev1.NetdataSpec)

	// ttl
	var now metav1.Time = metav1.Time{Time: time.Now()}
	checkttl(r, ctx, req, now)

	// ipv6 neighbour
	// Select a network interface by its name to use for NDP communications.
	ifi, err := net.InterfaceByName("wlp2s0")
	if err != nil {
		log.Fatalf("failed to get interface: %v", err)
	}

	// Set up an *ndp.Conn, bound to this interface's link-local IPv6 address.
	ndpconn, ip, err := ndp.Dial(ifi, ndp.LinkLocal)
	if err != nil {
		log.Fatalf("failed to dial NDP connection: %v", err)
	}
	// Clean up after the connection is no longer needed.
	defer ndpconn.Close()

	fmt.Println("ndp: bound to address:", ip)
	// Choose a target with a known IPv6 link-local address.
	target := net.ParseIP("fe80::")

	// Use target's solicited-node multicast address to request that the target
	// respond with a neighbor advertisement.
	snm, err := ndp.SolicitedNodeMulticast(target)
	if err != nil {
		log.Fatalf("failed to determine solicited-node multicast address: %v", err)
	}

	// Build a neighbor solicitation message, indicate the target's link-local
	// address, and also specify our source link-layer address.
	m := &ndp.NeighborSolicitation{
		TargetAddress: target,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      ifi.HardwareAddr,
			},
		},
	}

	// Send the multicast message and wait for a response.
	if err := ndpconn.WriteTo(m, nil, snm); err != nil {
		log.Fatalf("failed to write neighbor solicitation: %v", err)
	}

	msg, _, from, err := ndpconn.ReadFrom()
	if err != nil {
		log.Fatalf("failed to read NDP message: %v", err)
	}

	// Expect a neighbor advertisement message with a target link-layer
	// address option.
	na, ok := msg.(*ndp.NeighborAdvertisement)
	if !ok {
		log.Fatalf("message is not a neighbor advertisement: %T", msg)
	}
	if len(na.Options) != 1 {
		log.Fatal("expected one option in neighbor advertisement")
	}
	tll, ok := na.Options[0].(*ndp.LinkLayerAddress)
	if !ok {
		log.Fatalf("option is not a link-layer address: %T", msg)
	}

	fmt.Printf("ndp: neighbor advertisement from %s:\n", from)
	fmt.Printf("  - solicited: %t\n", na.Solicited)
	fmt.Printf("  - link-layer address: %s\n", tll.Addr)
	mergeRes[string(tll.Addr)] = dev1.NetdataSpec{
		IPAddress:  string(from),
		MACAddress: string(tll.Addr),
	}

	// get configmap data
	var c netdataconf
	c.getConf()

	// kea api
	res1 := kealease(c.KeaApi, 4)
	res2 := kealease(c.KeaApi, 6)
	for idx := range res1 {
		k := &res1[idx]
		mergeRes[k.HwAddress] = dev1.NetdataSpec{
			IPAddress:  k.IPAddress,
			MACAddress: k.HwAddress,
		}
	}

	for idx := range res2 {
		k := &res1[idx]
		mergeRes[k.HwAddress] = dev1.NetdataSpec{
			IPV6Address: k.IPAddress,
			MACAddress:  k.HwAddress,
		}
	}

	// nmap
	for idx := range c.Subnets {
		subnet := &c.Subnets[idx]
		res := nmapScan(*subnet, ctx)
		for hostidx := range res {
			host := &res[hostidx]
			nmapIp := host.Addresses[0].Addr
			var nmapMac string
			if len(host.Addresses) == 2 {
				nmapMac = host.Addresses[1].Addr
			} else {
				break
			}
			fmt.Printf("Host ipv4 is %s mac is %s\n", host.Addresses[0], host.Addresses[1])
			mergeRes[nmapMac] = dev1.NetdataSpec{
				IPAddress:  nmapIp,
				MACAddress: nmapMac,
			}
		}
	}

	fmt.Printf("Merge is %+v\n", mergeRes)

	// filter nets
	// save new crd
	for mk, mv := range mergeRes {
		fit := false
		for idx := range c.Subnets {
			subnet := &c.Subnets[idx]
			_, ipnetA, _ := net.ParseCIDR(*subnet)
			ipB := net.ParseIP(mv.IPAddress)
			if ipnetA.Contains(ipB) {
				fmt.Printf("fit ip %s to subnet %s", mv.IPAddress, *subnet)
				fit = true
				createNetCRD(mv.IPAddress, mv.IPV6Address, mv.MACAddress, *subnet, &c, ctx, r, req)
				break
			}
		}
		if fit {
			fmt.Printf("fit to subnet")
		} else {
			fmt.Printf("NOT fit to subnet, DELETE %s", mk)
			delete(mergeRes, mk)
			fmt.Printf("Merge is %+v\n", mergeRes)
		}
	}

	return ctrl.Result{}, nil
}

func (r *NetdataReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dev1.Netdata{}).
		Complete(r)
}
