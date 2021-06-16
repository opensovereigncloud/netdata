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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-logr/logr"
	ndp "github.com/mdlayher/ndp"
	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"net/http"
	"net/url"

	"github.com/Ullaakut/nmap/v2"

	dev1 "github.com/onmetal/netdata/api/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var errRetry = errors.New("retry")

const (
	naFormat = `neighbor advertisement from %s:
  - router:         %t
  - solicited:      %t
  - override:       %t
  - target address: %s
`
	nsFormat = `neighbor solicitation from %s:
  - target address: %s
`
)

// NetdataMap is resulted map of discovered hosts
type NetdataMap map[string]dev1.NetdataSpec

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

// '{ "command": "lease4-get-all", "service": [ "dhcp4" ] }'
// '{ "command": "lease6-get-all", "service": [ "dhcp6" ] }'
func postData(ipv int) string {
	res := &PostData{
		Command: fmt.Sprintf("lease%d-get-all", ipv),
		Service: []string{fmt.Sprintf("dhcp%d", ipv)},
	}
	res1, _ := json.Marshal(res)
	return string(res1)
}

/*
  output=$(curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "lease6-get-all", "service": [ "dhcp6" ] }' http://192.168.10.3:8000/)
  output=$(curl -s -X POST -H "Content-Type: application/json" -d '{ "command": "lease4-get-all", "service": [ "dhcp4" ] }' http://192.168.10.3:8000/)
*/

func (r *NetdataReconciler) kealease(apiUrl string, ipv int) []Lease {
	postData := postData(ipv)
	log.Printf("Kea post data  is #%s ", postData)
	resp, err := http.Post(apiUrl, "application/json", strings.NewReader(postData))
	if err != nil {
		r.Log.Error(err, "Fail request kea api")
		return []Lease{}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.Log.Error(err, "Fail read kea api answer")
	}

	log.Printf("Kea result is #%s ", body)
	keajson := KeaJson{}
	if err = json.Unmarshal(body, &keajson); err != nil {
		log.Printf("Kea result is not parsed. Error is #%s ", err)
		return []Lease{}
	}
	return keajson[0].Arguments.Leases
}

type netdataconf struct {
	Subnets   []string `yaml:"subnets"`
	Interval  int      `yaml:"interval"`
	TTL       int      `yaml:"ttl"`
	KeaApi    string   `yaml:"keaapi"`
	Interface string   `yaml:"interface"`
	IPPrio    []string `yaml:"ippriority"`
	NamePrio  []string `yaml:"hostnamepriority"`
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
	c.validate()

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
	for ihx := range result.Hosts {
		host := &result.Hosts[ihx]
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for idx := range host.Ports {
			port := &host.Ports[idx]
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

	crdname := strings.ToLower(strings.ReplaceAll(mac, ":", ""))
	labels := map[string]string{"ipv4": ipv4, "ipv6": strings.ReplaceAll(ipv6, ":", "_")}
	netcrd := &dev1.Netdata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      crdname,
			Namespace: req.Namespace,
			Labels:    labels,
		},
		Spec: netSpec,
	}
	_, err := ctrl.CreateOrUpdate(ctx, r, netcrd, func() error {
		r.Log.V(0).Info("Create netdata crd ", "metadata.name", netcrd.ObjectMeta.Name, " IPAddress", netcrd.Spec.IPAddress)
		return nil
	})
	if err != nil {
		r.Log.Error(err, "Fail crd creation")
	}
}

func optStr(o ndp.Option) string {
	switch o := o.(type) {
	case *ndp.LinkLayerAddress:
		dir := "source"
		if o.Direction == ndp.Target {
			dir = "target"
		}

		return fmt.Sprintf("%s link-layer address: %s", dir, o.Addr.String())
	case *ndp.MTU:
		return fmt.Sprintf("MTU: %d", *o)
	case *ndp.PrefixInformation:
		var flags []string
		if o.OnLink {
			flags = append(flags, "on-link")
		}
		if o.AutonomousAddressConfiguration {
			flags = append(flags, "autonomous")
		}

		return fmt.Sprintf("prefix information: %s/%d, flags: [%s], valid: %s, preferred: %s",
			o.Prefix.String(),
			o.PrefixLength,
			strings.Join(flags, ", "),
			o.ValidLifetime,
			o.PreferredLifetime,
		)
	case *ndp.RawOption:
		return fmt.Sprintf("type: %03d, value: %v", o.Type, o.Value)
	case *ndp.RouteInformation:
		return fmt.Sprintf("route information: %s/%d, preference: %s, lifetime: %s",
			o.Prefix.String(),
			o.PrefixLength,
			o.Preference.String(),
			o.RouteLifetime,
		)
	case *ndp.RecursiveDNSServer:
		var ss []string
		for _, s := range o.Servers {
			ss = append(ss, s.String())
		}
		servers := strings.Join(ss, ", ")

		return fmt.Sprintf("recursive DNS servers: lifetime: %s, servers: %s", o.Lifetime, servers)
	case *ndp.DNSSearchList:
		return fmt.Sprintf("DNS search list: lifetime: %s, domain names: %s", o.Lifetime, strings.Join(o.DomainNames, ", "))
	default:
		panic(fmt.Sprintf("unrecognized option: %v", o))
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

func (mergeRes NetdataMap) processNDP(msg ndp.Message, from net.IP) {
	// Expect a neighbor advertisement message with a target link-layer
	// address option.
	na, ok := msg.(*ndp.NeighborAdvertisement)
	if !ok {
		log.Printf("message is not a neighbor advertisement: %T", msg)
		return
	}
	if len(na.Options) != 1 {
		log.Printf("expected one option in neighbor advertisement")
		return
	}
	tll, ok := na.Options[0].(*ndp.LinkLayerAddress)
	if !ok {
		log.Printf("option is not a link-layer address: %T", msg)
		return
	}

	fmt.Printf("ndp: neighbor advertisement from %s:\n", from)
	fmt.Printf("  - solicited: %t\n", na.Solicited)
	fmt.Printf("  - link-layer address: %s\n", tll.Addr)
	mergeRes[tll.Addr.String()] = dev1.NetdataSpec{
		IPV6Address: from.String(),
		MACAddress:  tll.Addr.String(),
	}
}

func (mergeRes NetdataMap) kealeaseProcess(c *netdataconf, r *NetdataReconciler) {
	res1 := r.kealease(c.KeaApi, 4)
	for idx := range res1 {
		k := &res1[idx]
		mergeRes[k.HwAddress] = dev1.NetdataSpec{
			IPAddress:  k.IPAddress,
			MACAddress: k.HwAddress,
			Hostname:   k.Hostname,
		}
	}

	res2 := r.kealease(c.KeaApi, 6)
	for idx := range res2 {
		k := &res1[idx]
		ipv6 := k.IPAddress
		if mergeRes[k.HwAddress].IPV6Address != "" {
			if indexOf("hdp", c.IPPrio) > indexOf("kea", c.IPPrio) {
				ipv6 = mergeRes[k.HwAddress].IPV6Address
			}
		}

		mergeRes[k.HwAddress] = dev1.NetdataSpec{
			IPV6Address: ipv6,
			MACAddress:  k.HwAddress,
			Hostname:    k.Hostname,
		}
	}
}

func (mergeRes NetdataMap) filterAndCreateCRD(c *netdataconf, r *NetdataReconciler, ctx context.Context, req ctrl.Request) {
	for mk, mv := range mergeRes {
		fit := false
		for idx := range c.Subnets {
			subnet := &c.Subnets[idx]
			_, ipnetA, _ := net.ParseCIDR(*subnet)
			if len(mv.IPAddress) > 0 {
				ipB := net.ParseIP(mv.IPAddress)
				if ipnetA.Contains(ipB) {
					r.Log.Info("fit", "ip", mv.IPAddress, "  to subnet ", *subnet)
					fit = true
					createNetCRD(mv.IPAddress, mv.IPV6Address, mv.MACAddress, *subnet, c, ctx, r, req)
					break
				}
			}
			if len(mv.IPV6Address) > 0 {
				r.Log.Info("ipv6 address for check ", "ipv6", mv.IPV6Address)
				ipB6 := net.ParseIP(mv.IPV6Address)
				if ipnetA.Contains(ipB6) {
					r.Log.Info("fit", "ip", ipB6, "  to subnet ", *subnet)
					fit = true
					createNetCRD(mv.IPAddress, mv.IPV6Address, mv.MACAddress, *subnet, c, ctx, r, req)
					break
				}
			}
		}
		if fit {
			r.Log.Info("fit to subnet")
		} else {
			r.Log.Info("NOT fit to subnet", "DELETE", mk)
			delete(mergeRes, mk)
			fmt.Printf("Merge is %+v\n", mergeRes)
		}
	}
}

func (mergeRes NetdataMap) ndpProcess(c *netdataconf, r *NetdataReconciler, ctx context.Context) {
	// Select a network interface by its name to use for NDP communications.
	ifi, err := net.InterfaceByName(c.Interface)
	if err != nil {
		r.Log.Error(err, " .failed to get interface.")
	}

	// Set up an *ndp.Conn, bound to this interface's link-local IPv6 address.
	ndpconn, ip, err := ndp.Dial(ifi, ndp.LinkLocal)
	if err != nil {
		r.Log.Error(err, ".failed to dial NDP connection.")
		return
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
		r.Log.Error(err, " .failed to determine solicited-node multicast address.")
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
		r.Log.Error(err, " .failed to write neighbor solicitation.")
	}

	ll := log.New(os.Stderr, "ndp ns> ", 0)
	if err := mergeRes.receiveLoop(ctx, ndpconn, ll); err != nil {
		r.Log.Error(err, " failed to read message:")
	}

}

func ipVersion(s string) string {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return "ipv4"
		case ':':
			return "ipv6"
		}
	}
	return ""
}

func (mergeRes NetdataMap) nmapProcess(c *netdataconf, r *NetdataReconciler, ctx context.Context) {
	for idx := range c.Subnets {
		subnet := &c.Subnets[idx]
		r.Log.Info("Nmap scan ", "subnet", *subnet)
		if ipVersion(*subnet) == "ipv4" {
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
				r.Log.Info("Host", "ipv4 is", host.Addresses[0], " mac is ", host.Addresses[1])
				hostname := ""
				if len(host.Hostnames) > 0 {
					hostname = host.Hostnames[0].Name
				}
				if mergeRes[nmapMac].Hostname != "" {
					if indexOf("kea", c.IPPrio) > indexOf("nmap", c.IPPrio) {
						hostname = mergeRes[nmapMac].Hostname
					}
				}
				if mergeRes[nmapMac].IPAddress != "" {
					if indexOf("kea", c.IPPrio) > indexOf("nmap", c.IPPrio) {
						nmapIp = mergeRes[nmapMac].IPAddress
					}
				}
				mergeRes[nmapMac] = dev1.NetdataSpec{
					IPAddress:  nmapIp,
					MACAddress: nmapMac,
					Hostname:   hostname,
				}
			}
		} else {
			r.Log.Info("Skip nmap scanning for ipv6", "subnet", *subnet)
		}
	}
}

func (mergeRes NetdataMap) receiveLoop(ctx context.Context, c *ndp.Conn, ll *log.Logger) error {
	var count int
	for i := 0; i < 10; i++ {
		ll.Printf("loop %d", i)

		msg, from, err := receive(ctx, c, nil)
		switch err {
		case context.Canceled:
			ll.Printf("received %d message(s)", count)
			return nil
		case errRetry:
			continue
		case nil:
			count++
			mergeRes.printMessage(ll, msg, from)
		default:
			return err
		}
	}
	return nil
}

func receive(ctx context.Context, c *ndp.Conn, check func(m ndp.Message) bool) (ndp.Message, net.IP, error) {
	if err := c.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, nil, fmt.Errorf("failed to set deadline: %v", err)
	}

	msg, _, from, err := c.ReadFrom()
	if err == nil {
		if check != nil && !check(msg) {
			// Read a message, but it isn't the one we want.  Keep trying.
			return nil, nil, errRetry
		}

		// Got a message that passed the check, if check was not nil.
		return msg, from, nil
	}

	// Was the context canceled already?
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
	}

	// Was the error caused by a read timeout, and should the loop continue?
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return nil, nil, errRetry
	}

	return nil, nil, fmt.Errorf("failed to read message: %v", err)
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 //not found.
}

func (mergeRes NetdataMap) printMessage(ll *log.Logger, m ndp.Message, from net.IP) {
	switch m := m.(type) {
	case *ndp.NeighborAdvertisement:
		mergeRes.processNDP(m, from)
		printNA(ll, m, from)
	case *ndp.NeighborSolicitation:
		printNS(ll, m, from)
	default:
		ll.Printf("%s %#v", from, m)
	}
}

func printNA(ll *log.Logger, na *ndp.NeighborAdvertisement, from net.IP) {
	s := fmt.Sprintf(
		naFormat,
		from.String(),
		na.Router,
		na.Solicited,
		na.Override,
		na.TargetAddress.String(),
	)

	ll.Print(s + optionsString(na.Options))
}

func printNS(ll *log.Logger, ns *ndp.NeighborSolicitation, from net.IP) {
	s := fmt.Sprintf(
		nsFormat,
		from.String(),
		ns.TargetAddress.String(),
	)

	ll.Print(s + optionsString(ns.Options))
}

func optionsString(options []ndp.Option) string {
	if len(options) == 0 {
		return ""
	}

	var s strings.Builder
	s.WriteString("  - options:\n")

	for _, o := range options {
		writef(&s, "    - %s\n", optStr(o))
	}

	return s.String()
}

func writef(sw io.StringWriter, format string, a ...interface{}) {
	_, _ = sw.WriteString(fmt.Sprintf(format, a...))
}

// +kubebuilder:rbac:groups=machine.onmetal.de,resources=netdata,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=machine.onmetal.de,resources=netdata/status,verbs=get;update;patch
func (r *NetdataReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	_ = r.Log.WithValues("netdata", req.NamespacedName)
	mergeRes := make(NetdataMap)

	// get configmap data
	var c netdataconf
	c.getConf()

	// ttl
	var now metav1.Time = metav1.Time{Time: time.Now()}
	checkttl(r, ctx, req, now)
	// kea api
	mergeRes.kealeaseProcess(&c, r)
	// ipv6 neighbour
	mergeRes.ndpProcess(&c, r, ctx)
	// nmap
	mergeRes.nmapProcess(&c, r, ctx)

	// filter nets
	// save new crd
	mergeRes.filterAndCreateCRD(&c, r, ctx, req)

	return ctrl.Result{}, nil
}

func (r *NetdataReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&dev1.Netdata{}).
		Complete(r)
}
