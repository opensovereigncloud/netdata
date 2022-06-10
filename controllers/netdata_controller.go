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
	"bytes"
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/go-logr/logr"
	ndp "github.com/mdlayher/ndp"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"net/http"
	"net/netip"
	"net/url"

	nmap "github.com/Ullaakut/nmap/v2"

	"github.com/onmetal/ipam/api/v1alpha1"
	"github.com/onmetal/ipam/clientset"
	clienta1 "github.com/onmetal/ipam/clientset/v1alpha1"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
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
type NetdataSpec struct {
	Addresses  []IPsubnet
	MACAddress string
	Hostname   []string
}

type IPsubnet struct {
	IPS    []string
	Subnet string
	IPType string
}

type NetdataMap map[string]NetdataSpec

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
	r.Log.V(1).Info("Kea post data  is", "postData", postData)
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

	r.Log.V(1).Info("Kea result is #%s ", body)
	keajson := KeaJson{}
	if err = json.Unmarshal(body, &keajson); err != nil {
		r.Log.V(1).Info("Kea result is not parsed. Error is #%s ", err)
		return []Lease{}
	}
	return keajson[0].Arguments.Leases
}

type netdataconf struct {
	Interval    int               `yaml:"interval"`
	TTL         int               `yaml:"ttl"`
	KeaApi      []string          `yaml:"dhcp"`
	Interface   string            `yaml:"doNotDefinendp"`
	IPNamespace string            `default:"default" yaml:"ipnamespace"`
	SubnetLabel map[string]string `yaml:"subnetLabelSelector"`
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
	c.getNDPInterface()
	c.validate()
	log.Printf("Config is #%v ", c)

	return c
}

func (c *netdataconf) getNMAPInterface() string {
	if os.Getenv("NETSOURCE") == "nmap" {
		subnetList := c.getSubnets()
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			log.Printf("interface name %s", i.Name)
			for _, subi := range subnetList.Items {
				subnet := subi.Spec.CIDR.String()
				if IpVersion(subnet) == "ipv4" {
					addrs, _ := i.Addrs()
					for _, addri := range addrs {
						_, ipnetSub, _ := net.ParseCIDR(subnet)
						ipIf, _, _ := net.ParseCIDR(addri.String())
						if ipnetSub.Contains(ipIf) {
							return i.Name
						}
					}
				} else {
					// skiped network, require only ipv4
				}
			}
		}
	}
	return ""
}

func (c *netdataconf) getNDPInterface() {
	if os.Getenv("NETSOURCE") == "ndp" {
		subnetList := c.getSubnets()
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			log.Printf("interface name %s", i.Name)
			for _, subi := range subnetList.Items {
				subnet := subi.Spec.CIDR.String()
				if IpVersion(subnet) == "ipv4" {
					// skiped network, require only ipv6
				} else {
					addrs, _ := i.Addrs()
					for _, addri := range addrs {
						_, ipnetSub, _ := net.ParseCIDR(subnet)
						ipIf, _, _ := net.ParseCIDR(addri.String())
						if ipnetSub.Contains(ipIf) {
							c.Interface = i.Name
							return
						}
					}
				}
			}
		}
	}
}

// get subnets by label
func (c *netdataconf) getSubnets() *v1alpha1.SubnetList {
	kubeconfig := kubeconfigCreate()

	cs, _ := clientset.NewForConfig(kubeconfig)
	clientSubnet := cs.IpamV1Alpha1().Subnets(c.IPNamespace)
	labelSelector := metav1.LabelSelector{MatchLabels: c.SubnetLabel}

	subnetListOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
		Limit:         100,
	}
	subnetList, _ := clientSubnet.List(context.Background(), subnetListOptions)
	return subnetList
}

func (c *netdataconf) validate() {
	c.validateInterval()
	c.validateKeaApi()
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
	for idx := range c.KeaApi {
		keaendpoint := c.KeaApi[idx]
		u, err := url.Parse(keaendpoint)
		if err == nil && u.Scheme != "" && u.Host != "" {
			log.Printf("valid kea url %s", keaendpoint)
		} else {
			log.Fatalf("wrong kea url %s", keaendpoint)
			os.Exit(20)
		}
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

func kubeconfigCreate() *rest.Config {
	var kubeconfig *rest.Config
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			log.Printf("unable to load kubeconfig from %s: %v", kubeconfigPath, err)
		}
		kubeconfig = config
	} else {
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Printf("unable to load in-cluster config: %v", err)
		}
		kubeconfig = config
	}
	if err := v1alpha1.AddToScheme(scheme.Scheme); err != nil {
		errors.Wrap(err, "unable to add registered types to client scheme")
	}
	return kubeconfig
}

func contains(s []v1alpha1.IP, elem v1alpha1.IP) bool {
	for _, v := range s {
		if v.ObjectMeta.Name == elem.ObjectMeta.Name {
			return true
		}
	}

	return false
}

func createIPAM(c *netdataconf, ctx context.Context, ip v1alpha1.IP) {
	kubeconfig := kubeconfigCreate()

	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(c.IPNamespace)

	subnetList := c.getSubnets()
	// select subnet by ip and ip mask
	var subnet v1alpha1.Subnet
	for _, k := range subnetList.Items {
		log.Printf("               CHECK subnet from subnetlist: %s\n", k.ObjectMeta.Name)
		if k.Spec.CIDR != nil {
			subnetAddr := k.Spec.CIDR.String()
			_, subnetnetA, _ := net.ParseCIDR(subnetAddr)
			ipcur := net.ParseIP(ip.Spec.IP.String())
			log.Printf("ip.Spec.IP.String() ip: %+v\n", ip.Spec.IP.String())
			log.Printf("COMPARE ip: %+v\nsubnet: %+v", ipcur, subnetnetA)
			if subnetnetA.Contains(ipcur) {
				subnet = k
				break
			} else {
				log.Printf("not fit \nip: %+v\nsubnet: %+v\n\n\n", ipcur, subnetnetA)
			}
		}
	}
	//log.Printf("\n\n\nSelected subnets: %+v\n", subnetList)
	log.Printf("Selected subnet with ip: %+v\n\n\n", subnet.ObjectMeta.Name)
	if subnet.ObjectMeta.Name == "" {
		log.Printf("\nNOT FOUND proper subnet. skipped.: %+v\n", ip)
		return
	}
	ip.Spec.Subnet.Name = subnet.ObjectMeta.Name

	// list of ip for delete
	var deleteIPS []v1alpha1.IP
	var notDeleteIPS []v1alpha1.IP
	var updateLabelsIPS []v1alpha1.IP

	log.Printf("\n\n!!!!!!!!!!!!!!!!!!!!!!\n1 deleteIPS %v", deleteIPS)
	deleteIPS, notDeleteIPS, updateLabelsIPS = checkDuplicateMac(ctx, ip, client, deleteIPS, notDeleteIPS, updateLabelsIPS)
	log.Printf("\n\n!!!!!!!!!!!!!!!!!!!!!!\n2 deleteIPS %v", deleteIPS)
	// remove ip duplication
	deleteIPS = checkDuplicateIP(ctx, ip, client, deleteIPS)
	log.Printf("\n\n!!!!!!!!!!!!!!!!!!!!!!\n3 deleteIPS %v", deleteIPS)

	// delete objects
	for delindex := range deleteIPS {
		existedIP := deleteIPS[delindex]
		if contains(notDeleteIPS, existedIP) {
			log.Printf("not deleted  %+s because it is in not_delete_array \n\n", existedIP.ObjectMeta.Name)
		} else {
			err := client.Delete(ctx, existedIP.ObjectMeta.Name, v1.DeleteOptions{})
			if err != nil {
				log.Printf("ERROR!!  delete ips %+v error +%v \n\n", existedIP, err.Error())
			}
			log.Printf("DELETED ips %s \n\n", existedIP.ObjectMeta.Name)
		}
	}

	// update labels
	for upindex := range updateLabelsIPS {
		existedIP := updateLabelsIPS[upindex]
		existedIP.ObjectMeta.Labels["origin"] = os.Getenv("NETSOURCE")
		updatedIP := &v1alpha1.IP{}
		updatedIP, err := client.Update(ctx, &existedIP, v1.UpdateOptions{})
		if err != nil {
			log.Printf("update error +%v ", err.Error())
		}
		log.Printf("Updated LABELs IP. +%v ", updatedIP)
	}

	// create ip with subnet
	if len(notDeleteIPS) == 0 {
		getk8sObject, err := client.Get(ctx, ip.ObjectMeta.Name, v1.GetOptions{})
		if err != nil {
			log.Printf("get error +%v ", err.Error())
		}
		if err != nil && getk8sObject.ObjectMeta.Name != "" {
			updatedIP := &v1alpha1.IP{}
			updatedIP, err = client.Update(ctx, &ip, v1.UpdateOptions{})
			if err != nil {
				log.Printf("update error +%v ", err.Error())
			}
			log.Printf("Updated IP. +%v ", updatedIP)

		} else {
			createdIP := &v1alpha1.IP{}
			createdIP, err = client.Create(ctx, &ip, v1.CreateOptions{})
			if err != nil {
				log.Printf("create error +%v ", err.Error())
			}
			log.Printf("Created IP. +%s ", createdIP.ObjectMeta.Name)
		}
	}

}

func checkDuplicateMac(ctx context.Context, ip v1alpha1.IP, client clienta1.IPInterface, deleteIPS []v1alpha1.IP, notDeleteIPS []v1alpha1.IP, updateLabelsIPS []v1alpha1.IP) ([]v1alpha1.IP, []v1alpha1.IP, []v1alpha1.IP) {
	// if (do we have object with different IP address and same origin)
	//    ->  delete object
	labelsIPS := make(map[string]string)
	labelsIPS["mac"] = strings.Split(ip.ObjectMeta.GenerateName, "-")[0]

	labelSelectorIPS := metav1.LabelSelector{MatchLabels: labelsIPS}
	ipsListOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelectorIPS.MatchLabels).String(),
		Limit:         100,
	}
	ipsList, _ := client.List(ctx, ipsListOptions)
	for ipindex := range ipsList.Items {
		existedIP := ipsList.Items[ipindex]
		if existedIP.Spec.IP.Equal(ip.Spec.IP) {
			notDeleteIPS = append(notDeleteIPS, existedIP)
			if existedIP.ObjectMeta.Labels["origin"] == os.Getenv("NETSOURCE") {
				log.Printf("labels for current %s  existed Labels:  %+v \n\n", existedIP.ObjectMeta.Name, existedIP.ObjectMeta.Labels)
			} else {
				// update- add label origin-os.Getenv("NETSOURCE")
				if existedIP.ObjectMeta.Labels["origin"] != "kea" {
					log.Printf("add to update labels to current origin %+v \n\n", existedIP.ObjectMeta.Name)
					updateLabelsIPS = append(updateLabelsIPS, existedIP)
				}
			}
		} else {
			log.Printf("existedIP.Spec.IP != ip.Spec.IP\n  %+v != %+v \n\n", existedIP.Spec.IP, ip.Spec.IP)
			// ndp do not mix with nmap and kea
			if existedIP.Spec.IP.Net.Is6() == ip.Spec.IP.Net.Is6() {
				// mac and origin are same, but ip is different - delete
				if existedIP.ObjectMeta.Labels["origin"] == os.Getenv("NETSOURCE") {
					log.Printf("add to delete list %+v \n\n", existedIP.ObjectMeta.Name)
					deleteIPS = append(deleteIPS, existedIP)
				}
			}
		}
	}
	return deleteIPS, notDeleteIPS, updateLabelsIPS
}

func checkDuplicateIP(ctx context.Context, ip v1alpha1.IP, client clienta1.IPInterface, deleteIPS []v1alpha1.IP) []v1alpha1.IP {
	labelsIPS := make(map[string]string)
	labelsIPS["ip"] = ip.Spec.IP.String()

	labelSelectorIPS := metav1.LabelSelector{MatchLabels: labelsIPS}
	ipsListOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelectorIPS.MatchLabels).String(),
		Limit:         100,
	}
	ipsList, _ := client.List(ctx, ipsListOptions)
	mac := strings.Split(ip.ObjectMeta.GenerateName, "-")[0]
	for ipindex := range ipsList.Items {
		existedIP := ipsList.Items[ipindex]
		if existedIP.Spec.IP.Equal(ip.Spec.IP) && existedIP.ObjectMeta.Labels["mac"] != mac {

			if existedIP.ObjectMeta.Labels["origin"] == os.Getenv("NETSOURCE") {
				log.Printf("found ipam ip object with same ip %v and diferent mac %v . DELETE", ip.Spec.IP, mac)
				deleteIPS = append(deleteIPS, existedIP)
			}
		}
	}
	return deleteIPS
}

func createNetCRD(mv NetdataSpec, conf *netdataconf, ctx context.Context, r *NetdataReconciler, req ctrl.Request) {
	macLow := strings.ToLower(mv.MACAddress)
	mv.MACAddress = macLow

	crdname := strings.ReplaceAll(macLow, ":", "")
	labels := make(map[string]string)
	for idx := range mv.Addresses {
		ipsubnet := &mv.Addresses[idx]
		ips := ipsubnet.IPS
		ipsubnet.IPType = IpVersion(ips[0])
		for jdx := range ips {
			labels["ip"] = strings.ReplaceAll(ips[jdx], ":", "_")
		}
	}
	labels["origin"] = os.Getenv("NETSOURCE")
	labels["mac"] = crdname

	ipaddr, _ := v1alpha1.IPAddrFromString(mv.Addresses[0].IPS[0])

	ipIPAM := &v1alpha1.IP{
		ObjectMeta: v1.ObjectMeta{
			GenerateName: crdname + "-" + os.Getenv("NETSOURCE") + "-",
			Namespace:    req.Namespace,
			Labels:       labels,
		},
		Spec: v1alpha1.IPSpec{
			Subnet: corev1.LocalObjectReference{
				Name: "emptynameshouldnotexist",
			},
			IP: ipaddr,
		},
	}

	createIPAM(conf, ctx, *ipIPAM)
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
		return fmt.Sprintf("unrecognized option: %v", o)
	}
}

func processNDPNS(msg ndp.Message, from netip.Addr, c *netdataconf, ch chan NetdataMap) {
	// Expect a neighbor advertisement message with a target link-layer
	// address option.

	na, ok := msg.(*ndp.NeighborSolicitation)
	if !ok {
		log.Printf("message is not a neighbor solicitation: %T", msg)
		return
	}
	if len(na.Options) != 1 {
		log.Printf("expected one option in neighbor solicitation")
		return
	}
	tll, ok := na.Options[0].(*ndp.LinkLayerAddress)
	if !ok {
		log.Printf("option is not a link-layer address: %T", msg)
		return
	}

	fmt.Printf("ndp: neighbor solicitation from %s:\n", from)
	fmt.Printf("  - link-layer address: %s\n", tll.Addr)

	res := make(NetdataMap)
	res[tll.Addr.String()] = newNetdataSpec(tll.Addr.String(), strings.Split(from.String(), "%")[0], "", "ipv6")
	ch <- res
}
func processNDPRS(msg ndp.Message, from netip.Addr, c *netdataconf, ch chan NetdataMap) {
	// Expect a route solicitation message with a target link-layer
	// address option.

	na, ok := msg.(*ndp.RouterSolicitation)
	if !ok {
		log.Printf("message is not a router solicitation: %T", msg)
		return
	}
	if len(na.Options) != 1 {
		log.Printf("expected one option in router solicitation")
		return
	}
	tll, ok := na.Options[0].(*ndp.LinkLayerAddress)
	if !ok {
		log.Printf("option is not a link-layer address: %T", msg)
		return
	}

	fmt.Printf("ndp: router solicitation from %s:\n", from)
	fmt.Printf("  - link-layer address: %s\n", tll.Addr)

	res := make(NetdataMap)
	res[tll.Addr.String()] = newNetdataSpec(tll.Addr.String(), strings.Split(from.String(), "%")[0], "", "ipv6")
	ch <- res
}
func processNDPRA(msg ndp.Message, from netip.Addr, c *netdataconf, ch chan NetdataMap) {
	// Expect a router advertisement message with a target link-layer
	// address option.

	na, ok := msg.(*ndp.RouterAdvertisement)
	if !ok {
		log.Printf("message is not a router advertisement: %T", msg)
		return
	}
	if len(na.Options) != 1 {
		log.Printf("expected one option in router advertisement")
		return
	}
	tll, ok := na.Options[0].(*ndp.LinkLayerAddress)
	if !ok {
		log.Printf("option is not a link-layer address: %T", msg)
		return
	}

	fmt.Printf("ndp: router advertisement from %s:\n", from)
	fmt.Printf("  - link-layer address: %s\n", tll.Addr)

	res := make(NetdataMap)
	res[tll.Addr.String()] = newNetdataSpec(tll.Addr.String(), strings.Split(from.String(), "%")[0], "", "ipv6")
	ch <- res
}
func processNDPNA(msg ndp.Message, from netip.Addr, c *netdataconf, ch chan NetdataMap) {
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

	res := make(NetdataMap)
	res[tll.Addr.String()] = newNetdataSpec(tll.Addr.String(), strings.Split(from.String(), "%")[0], "", "ipv6")
	ch <- res
}

func newRes(subnet string, k *Lease) NetdataSpec {
	return newNetdataSpec(k.HwAddress, k.IPAddress, k.Hostname, "ipv4")
}

func newNetdataSpec(mac string, ip string, hostname string, iptype string) NetdataSpec {
	ips := []string{ip}
	ipsubnet := IPsubnet{
		IPS:    ips,
		Subnet: "deleteThisField",
		IPType: iptype,
	}
	return NetdataSpec{
		Addresses:  []IPsubnet{ipsubnet},
		MACAddress: mac,
		Hostname:   []string{hostname},
	}
}

func unique(arr []string) []string {
	occurred := map[string]bool{}
	result := []string{}
	for e := range arr {
		if !occurred[arr[e]] {
			occurred[arr[e]] = true
			result = append(result, arr[e])
		}
	}
	return result
}

func (mergeRes NetdataMap) addIP2Res(k string, v NetdataSpec) {
	newHostname := append(mergeRes[k].Hostname, v.Hostname...)
	if thisMac, ok := mergeRes[k]; ok {
		thisMac.Hostname = unique(newHostname)
		mergeRes[k] = thisMac
	}

	for idx := range mergeRes[k].Addresses {
		ipsubnet := &mergeRes[k].Addresses[idx]
		// v always contain only 1 subnet
		if ipsubnet.Subnet == v.Addresses[0].Subnet {
			ipsubnet.IPS = append(ipsubnet.IPS, v.Addresses[0].IPS...)
			return
		}
	}
	if thisMac, ok := mergeRes[k]; ok {
		thisMac.Addresses = append(thisMac.Addresses, v.Addresses[0])
		mergeRes[k] = thisMac
	}
}

func processKeaRes(res []Lease, c *netdataconf, ch chan NetdataMap) {
	for idx := range res {
		k := &res[idx]
		dhcprecord := make(NetdataMap)
		dhcprecord[k.HwAddress] = newRes("deleteFieldSubnet", k)
		ch <- dhcprecord
	}
}

func kealeaseProcess(c *netdataconf, r *NetdataReconciler, ch chan NetdataMap, wg *sync.WaitGroup) {
	defer wg.Done()
	for kidx := range c.KeaApi {
		keaendpoint := &c.KeaApi[kidx]
		// fetch data from kea for ipv4
		res1 := r.kealease(*keaendpoint, 4)
		processKeaRes(res1, c, ch)

		// fetch data from kea for ipv6
		res2 := r.kealease(*keaendpoint, 6)
		processKeaRes(res2, c, ch)
	}
	fmt.Print("Kea done\n")
}

func (mergeRes NetdataMap) filterAndCreateCRD(c *netdataconf, r *NetdataReconciler, ctx context.Context, req ctrl.Request) {
	for _, mv := range mergeRes {
		createNetCRD(mv, c, ctx, r, req)
	}
}

type (
	// ICMPPayload is capable of generating a signed ICMP payload.
	ICMPPayload struct {
		Helo      string    `json:"h"`
		Timestamp time.Time `json:"t"`
	}
)

var (
	secret = make([]byte, 16)

	helo = "netdata-ipam ping-agent"
)

// NewICMPPayload returns a new ICMPPayload set to current time.
func NewICMPPayload() *ICMPPayload {
	return &ICMPPayload{
		Helo:      helo,
		Timestamp: time.Now(),
	}
}

// Bytes returns a signed payload.
func (p *ICMPPayload) Bytes() []byte {
	// THis should never fail.
	msg, _ := json.Marshal(p)

	h := md5.New()
	h.Write(secret)
	h.Write(msg)
	digest := h.Sum(nil)

	return append(digest, msg...)
}

func (p *ICMPPayload) Read(payload []byte) error {
	if len(payload) < 16 {
		return errors.New("payload too short")
	}

	h := md5.New()
	h.Write(secret)
	h.Write(payload[16:])
	digest := h.Sum(nil)

	if !bytes.Equal(digest, payload[:16]) {
		return errors.New("checksum error")
	}

	return json.Unmarshal(payload[16:], p)
}

func newICMPPacket6(id uint16, seq int) []byte {
	b, _ := (&icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Seq:  seq,
			Data: NewICMPPayload().Bytes(),
		},
	}).Marshal(nil)

	return b
}

func ndpProcess(c *netdataconf, r *NetdataReconciler, ctx context.Context, ch chan NetdataMap, wg *sync.WaitGroup) {
	defer wg.Done()
	ndpif := c.Interface
	r.Log.Info("Bind to interface ", ndpif, " for ndp")
	// Select a network interface by its name to use for NDP communications.
	ifi, err := net.InterfaceByName(ndpif)
	if err != nil {
		ifaces, err := net.Interfaces()
		for _, i := range ifaces {
			r.Log.Info("interface", "name", i.Name)
		}
		r.Log.Error(err, " .failed to get interface.")
	}

	// Set up an *ndp.Conn, bound to this interface's link-local IPv6 address.
	ndpconn, ip, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		r.Log.Error(err, ".failed to dial NDP connection.")
		return
	}
	// Clean up after the connection is no longer needed.
	defer ndpconn.Close()

	r.Log.Info("ndp:", " bound to address:", ip)
	// Choose a target with a known IPv6 link-local address.
	target, err := netip.ParseAddr("fe80::")
	if err != nil {
		r.Log.Error(err, ".failed to parse ip fe80::.")
		return
	}

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

	// send ping6 multicast
	// ping -I mgmt0 -6 ff02::1
	ff02Addr, _ := netip.ParseAddr("ff02::1")

	var previousID int32
	pingid := uint16(atomic.AddInt32(&previousID, 1) & 0xffff)
	for seq := 0; seq < 3; seq++ {

		b := newICMPPacket6(pingid, seq)

		err := ndpconn.WriteRaw(b, nil, ff02Addr)
		if err != nil {
			r.Log.Error(err, " .failed to sent ping ff02::1 address.")
		}
		fmt.Printf("ping to address ff02::1 , seq = %d\n", seq)
		time.Sleep(1 * time.Second)
	}

	// Send the multicast message and wait for a response.
	if err := ndpconn.WriteTo(m, nil, snm); err != nil {
		r.Log.Error(err, " .failed to write neighbor solicitation.")
	}

	ll := log.New(os.Stderr, "ndp ns> ", 0)
	if err := receiveLoop(ctx, ndpconn, ll, c, ch); err != nil {
		r.Log.Error(err, " failed to read message:")
	}
}

func IpVersion(s string) string {
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

func toNetdataMap(host *nmap.Host, subnet string) (NetdataMap, error) {
	var nmapMac string
	if len(host.Addresses) == 2 {
		nmapMac = host.Addresses[1].Addr
	} else {
		return nil, errors.New("No data for new crd")
	}
	nmapIp := host.Addresses[0].Addr

	hostname := ""
	if len(host.Hostnames) > 0 {
		hostname = host.Hostnames[0].Name
	}
	res := make(NetdataMap)
	res[nmapMac] = newNetdataSpec(nmapMac, nmapIp, hostname, "ipv4")
	return res, nil
}

func nmapProcess(c *netdataconf, r *NetdataReconciler, ctx context.Context, ch chan NetdataMap, wg *sync.WaitGroup) {
	defer wg.Done()
	subnetList := c.getSubnets()
	for _, subi := range subnetList.Items {
		// check if at least 1 interface belong to subnet
		if len(c.getNMAPInterface()) > 0 {

			subnet := subi.Spec.CIDR.String()
			r.Log.V(1).Info("Nmap scan ", "subnet", subnet)

			if IpVersion(subnet) == "ipv4" {
				res := nmapScan(subnet, ctx)

				for hostidx := range res {
					host := &res[hostidx]
					res, err := toNetdataMap(host, subnet)
					if err == nil {
						r.Log.V(1).Info("Host", "ipv4 is", host.Addresses[0], " mac is ", host.Addresses[1])
						ch <- res
						r.Log.V(1).Info("added to channel Host", "ipv4 is", host.Addresses[0], " mac is ", host.Addresses[1])
					}
				}
			} else {
				r.Log.V(1).Info("Skip nmap scanning for ipv6", "subnet", subnet)
			}
		}
	}
}

func receiveLoop(ctx context.Context, conn *ndp.Conn, ll *log.Logger, conf *netdataconf, ch chan NetdataMap) error {
	var count int
	for i := 0; i < 100; i++ {
		ll.Printf("loop %d", i)

		msg, from, err := receive(ctx, conn, nil)
		switch err {
		case context.Canceled:
			ll.Printf("received %d message(s)", count)
			return nil
		case errRetry:
			continue
		case nil:
			count++
			printMessage(ll, msg, from, conf, ch)
		default:
			return err
		}
	}
	return nil
}

func receive(ctx context.Context, c *ndp.Conn, check func(m ndp.Message) bool) (ndp.Message, netip.Addr, error) {
	if err := c.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, netip.Addr{}, fmt.Errorf("failed to set deadline: %v", err)
	}

	msg, _, from, err := c.ReadFrom()
	if err == nil {
		if check != nil && !check(msg) {
			// Read a message, but it isn't the one we want.  Keep trying.
			return nil, netip.Addr{}, errRetry
		}

		// Got a message that passed the check, if check was not nil.
		return msg, from, nil
	}

	// Was the context canceled already?
	select {
	case <-ctx.Done():
		return nil, netip.Addr{}, ctx.Err()
	default:
	}

	// Was the error caused by a read timeout, and should the loop continue?
	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		return nil, netip.Addr{}, errRetry
	}

	return nil, netip.Addr{}, fmt.Errorf("failed to read message: %v", err)
}

func printMessage(ll *log.Logger, m ndp.Message, from netip.Addr, c *netdataconf, ch chan NetdataMap) {
	switch m := m.(type) {
	case *ndp.NeighborAdvertisement:
		processNDPNA(m, from, c, ch)
		printNA(ll, m, from)
	case *ndp.NeighborSolicitation:
		processNDPNS(m, from, c, ch)
		printNS(ll, m, from)
	case *ndp.RouterAdvertisement:
		processNDPRA(m, from, c, ch)
	case *ndp.RouterSolicitation:
		processNDPRS(m, from, c, ch)
	default:
		ll.Printf("%s %#v", from, m)
	}
}

func printNA(ll *log.Logger, na *ndp.NeighborAdvertisement, from netip.Addr) {
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

func printNS(ll *log.Logger, ns *ndp.NeighborSolicitation, from netip.Addr) {
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
func (r *NetdataReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("netdata", req.NamespacedName)
	mergeRes := make(NetdataMap)

	// get configmap data
	var c netdataconf
	c.getConf()

	//	fmt.Printf("runtime.GOMAXPROC() = %+v \n", runtime.GOMAXPROC)
	r.Log.V(1).Info("\nMergeRes init state.", "mergeRes", mergeRes)
	ch := make(chan NetdataMap, 1000)

	wg := sync.WaitGroup{}
	netSource := os.Getenv("NETSOURCE")
	switch netSource {
	case "kea":
		wg.Add(1)
		go kealeaseProcess(&c, r, ch, &wg)
		fmt.Printf("\nStarted kea \n")
	case "ndp":
		wg.Add(1)
		go ndpProcess(&c, r, ctx, ch, &wg)
		fmt.Printf("\nStarted ndp \n")
	case "nmap":
		wg.Add(1)
		go nmapProcess(&c, r, ctx, ch, &wg)
		fmt.Printf("\nStarted nmap \n")
	default:
		fmt.Printf("\nRequire define proper NETSOURCE environment variable. current NETSOURCE is +%v \n", netSource)
		os.Exit(11)
	}

	wg.Wait()
	r.Log.V(1).Info("\nWg ended \n")
	close(ch)
	r.Log.V(1).Info("\nch closed \n")

	for entity := range ch {
		for k, v := range entity {
			r.Log.V(1).Info("\ntest 1  mergeRes = %+v \n", mergeRes)
			r.Log.V(1).Info("\ntest 1  k = %+v \n", k)
			r.Log.V(1).Info("\ntest 1  v = %+v \n", v)
			mergeRes.add2map(k, v)
			r.Log.V(1).Info("\ntest 2 should change  mergeRes = %+v \n", mergeRes)
		}
	}

	// filter nets
	// save new crd
	mergeRes.filterAndCreateCRD(&c, r, ctx, req)

	return ctrl.Result{}, nil
}

func (mergeRes NetdataMap) add2map(k string, v NetdataSpec) {
	indexArr := len(mergeRes[k].Addresses)
	if indexArr == 0 {
		mergeRes[k] = v
	} else {
		mergeRes.addIP2Res(k, v)
	}
}

func (r *NetdataReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.Subnet{}).
		Complete(r)
}
