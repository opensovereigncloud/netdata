// Copyright 2023 OnMetal authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/go-logr/logr"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"net/http"
	"net/url"

	nmap "github.com/Ullaakut/nmap/v2"

	"github.com/onmetal/ipam/api/v1alpha1"
	"github.com/onmetal/ipam/clientset"
	clienta1 "github.com/onmetal/ipam/clientset/v1alpha1"

	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var SubnetNetlinkListener = make(map[string]chan struct{})

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

	r.Log.V(1).Info("Kea result is", "body", body)
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
	IPNamespace string            `default:"default" yaml:"ipnamespace"`
	SubnetLabel map[string]string `yaml:"subnetLabelSelector"`
}

func (c *netdataconf) getConf() *netdataconf {
	yamlFile, err := os.ReadFile("/etc/manager/netdata-config.yaml")

	if err != nil {
		log.Fatalf("yamlFile.Get err   #%v ", err)
		os.Exit(21)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
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
				// only IPv4 networks are supported for now
				if IpVersion(subnet) == "ipv4" {
					addrs, _ := i.Addrs()
					for _, addri := range addrs {
						_, ipnetSub, _ := net.ParseCIDR(subnet)
						ipIf, _, _ := net.ParseCIDR(addri.String())
						if ipnetSub.Contains(ipIf) {
							return i.Name
						}
					}
				}
			}
		}
	}
	return ""
}

// get subnets by label clusterwide
func (c *netdataconf) getSubnets() *v1alpha1.SubnetList {
	kubeconfig := kubeconfigCreate()

	cs, _ := clientset.NewForConfig(kubeconfig)
	clientSubnet := cs.IpamV1Alpha1().Subnets(metav1.NamespaceAll)
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
		_ = errors.Wrap(err, "unable to add registered types to client scheme")
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

func createIPAMNetlink(c *netdataconf, ctx context.Context, ip v1alpha1.IP, subnet *ipamv1alpha1.Subnet) {
	kubeconfig := kubeconfigCreate()
	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(subnet.ObjectMeta.Namespace)

	ip.Spec.Subnet.Name = subnet.ObjectMeta.Name
	ip.ObjectMeta.Namespace = subnet.ObjectMeta.Namespace

	createNewIP := true

	//If MACs  are the same and IP is different - delete the existing object
	handleDuplicateMacs(ctx, ip, client, &createNewIP)

	// If IPs are the same but MAC is different delete the existing object
	handleDuplicateIPs(ctx, ip, client, &createNewIP)

	// Create new IP
	if createNewIP {
		ref := v1.OwnerReference{Name: "netdata.onmetal.de/ip", APIVersion: "v1", Kind: "ip", UID: "ip"}
		ip.OwnerReferences = append(ip.OwnerReferences, ref)
		createdIP, err := client.Create(ctx, &ip, v1.CreateOptions{})
		if err != nil {
			log.Printf("Create IP error +%v ", err.Error())
		}
		log.Printf("Created IP object : %s \n", createdIP.ObjectMeta.Name)

	}
}

func CheckIPFromNetlinkAndKea(ips *ipamv1alpha1.IPList, ctx context.Context, ip v1alpha1.IP) string {
	// If two IP objects exist one from kea and another from netlink, this function will return netlink IP for deletion

	m := make(map[string]string)

	for _, existedIP := range ips.Items {
		if existedIP.Spec.IP.Equal(ip.Spec.IP) {
			if existedIP.ObjectMeta.Labels["origin"] == "kea" {
				m["kea"] = existedIP.ObjectMeta.Name
			}
			if existedIP.ObjectMeta.Labels["origin"] == "netlink" {
				m["netlink"] = existedIP.ObjectMeta.Name
			}
		}
	}

	if val, ok := m["netlink"]; ok {
		if _, ok := m["kea"]; ok {
			return val
		}
	}
	return ""
}

func handleDuplicateMacs(ctx context.Context, ip v1alpha1.IP, client clienta1.IPInterface, createNewIP *bool) {
	mac := strings.Split(ip.ObjectMeta.GenerateName, "-")[0]
	labelsIPS := make(map[string]string)
	labelsIPS["mac"] = mac
	labelSelectorIPS := metav1.LabelSelector{MatchLabels: labelsIPS}
	ipsListOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelectorIPS.MatchLabels).String(),
		Limit:         100,
	}
	ipsList, _ := client.List(ctx, ipsListOptions)

	// Special case: If an IP object exists from both kea and Netlink then delete Netlink IP
	deleteIP := CheckIPFromNetlinkAndKea(ipsList, ctx, ip)
	if deleteIP != "" {
		*createNewIP = false // do not create new IP from Netlink
		err := client.Delete(ctx, deleteIP, v1.DeleteOptions{})
		if err != nil {
			log.Printf("ERROR!!  delete ips %+v error +%v \n", deleteIP, err.Error())
		} else {
			log.Printf("Same IP object exists from kea and Netlink, Deleted IP object : %s \n", deleteIP)
		}
		// Refresh the list, since we have deleted an item
		ipsList, _ = client.List(ctx, ipsListOptions)
	}

	for _, existedIP := range ipsList.Items {
		if existedIP.Spec.IP.Equal(ip.Spec.IP) {
			*createNewIP = false
			// If an IP object with the same IP and same MAC already exists from Netlink and you own it, update the lifetime
			if existedIP.ObjectMeta.Labels["origin"] == os.Getenv("NETSOURCE") {
				for _, v := range existedIP.OwnerReferences {
					if v.Name == "netdata.onmetal.de/ip" {
						existedIP.Labels["timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
						updatedIP, err := client.Update(ctx, &existedIP, v1.UpdateOptions{})
						if err != nil {
							log.Printf("Update error : +%v ", err.Error())
						}
						log.Printf("Updated timestamp of IP object: %s \n", updatedIP.ObjectMeta.Name)
					}
				}
			}
		}
	}
}

func handleDuplicateIPs(ctx context.Context, ip v1alpha1.IP, client clienta1.IPInterface, createNewIP *bool) {
	// If IPS is same but MAC is different delete the existing object
	mac := strings.Split(ip.ObjectMeta.GenerateName, "-")[0]
	labelsIPS_ip := make(map[string]string)
	labelsIPS_ip["ip"] = ip.Spec.IP.String()

	labelSelectorIPS_ip := metav1.LabelSelector{MatchLabels: labelsIPS_ip}
	ipsListOptions_ip := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelectorIPS_ip.MatchLabels).String(),
		Limit:         100,
	}
	ipsList_ip, _ := client.List(ctx, ipsListOptions_ip)
	for _, existedIP := range ipsList_ip.Items {
		if existedIP.ObjectMeta.Labels["mac"] != mac {
			log.Printf("**************************************************************")
			log.Printf("ERROR : Duplicate ip found, existing object : %v, new mac = %v", existedIP.ObjectMeta.Name, mac)
			log.Printf("**************************************************************")
			*createNewIP = false
		}
	}
}

func createIPAM(c *netdataconf, ctx context.Context, ip v1alpha1.IP) {
	kubeconfig := kubeconfigCreate()

	cs, _ := clientset.NewForConfig(kubeconfig)

	// TODO cache result and speedup
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
	ip.ObjectMeta.Namespace = subnet.ObjectMeta.Namespace

	// list of ip for delete
	var deleteIPS []v1alpha1.IP
	var notDeleteIPS []v1alpha1.IP
	var updateLabelsIPS []v1alpha1.IP

	client := cs.IpamV1Alpha1().IPs(subnet.ObjectMeta.Namespace)
	deleteIPS, notDeleteIPS, updateLabelsIPS = checkDuplicateMac(ctx, ip, client, deleteIPS, notDeleteIPS, updateLabelsIPS)
	// remove ip duplication
	deleteIPS = checkDuplicateIP(ctx, ip, client, deleteIPS)

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
			updatedIP, err := client.Update(ctx, &ip, v1.UpdateOptions{})
			if err != nil {
				log.Printf("update error +%v ", err.Error())
			}
			log.Printf("Updated IP. +%v ", updatedIP)

		} else {
			createdIP, err := client.Create(ctx, &ip, v1.CreateOptions{})
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

func FullIPv6(ip net.IP) string {
	dst := make([]byte, hex.EncodedLen(len(ip)))
	_ = hex.Encode(dst, ip)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
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

func createNetCRDNetlink(mv NetdataSpec, conf *netdataconf, ctx context.Context, subnet *ipamv1alpha1.Subnet) {
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
	labels["timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	labels["labelsubnet"] = conf.SubnetLabel["labelsubnet"]
	ipaddr, _ := v1alpha1.IPAddrFromString(mv.Addresses[0].IPS[0])

	ipIPAM := &v1alpha1.IP{
		ObjectMeta: v1.ObjectMeta{
			GenerateName: crdname + "-" + os.Getenv("NETSOURCE") + "-",
			Namespace:    conf.IPNamespace,
			Labels:       labels,
		},
		Spec: v1alpha1.IPSpec{
			Subnet: corev1.LocalObjectReference{
				Name: "emptynameshouldnotexist",
			},
			IP: ipaddr,
		},
	}

	createIPAMNetlink(conf, ctx, *ipIPAM, subnet)
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

func cleanupIps(ctx context.Context, c *netdataconf, origin string) {
	subnetList := c.getSubnets()
	ips := getIps(origin)

	for idx := range ips {
		var deleteFlag bool
		deleteFlag = true
		ip := &ips[idx]
		// check subnet existens with proper labels
		for subnetx := range subnetList.Items {
			sub := &subnetList.Items[subnetx]
			if ip.Spec.Subnet.Name == sub.ObjectMeta.Name {
				deleteFlag = false
				break
			}
		}
		// check time of creation
		if deleteFlag {
			deleteIP(ctx, ip)
		}
	}
}

func deleteIP(ctx context.Context, ip *v1alpha1.IP) {
	kubeconfig := kubeconfigCreate()
	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(ip.ObjectMeta.Namespace)
	err := client.Delete(ctx, ip.ObjectMeta.Name, v1.DeleteOptions{})
	if err != nil {
		fmt.Printf("deleteIP ERROR!!  %+v error +%v \n\n", ip, err.Error())
	} else {
		fmt.Printf("deleted IP  %s \n", ip.ObjectMeta.Name)
	}
}

func getIps(origin string) []v1alpha1.IP {
	kubeconfig := kubeconfigCreate()
	cs, _ := clientset.NewForConfig(kubeconfig)
	clientip := cs.IpamV1Alpha1().IPs(metav1.NamespaceAll)

	labelsorigin := map[string]string{"origin": origin}
	labelSelector := metav1.LabelSelector{MatchLabels: labelsorigin}
	labelListOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelector.MatchLabels).String(),
		Limit:         1000,
	}
	ipList, _ := clientip.List(context.Background(), labelListOptions)
	return ipList.Items
}

func NetlinkProcessor(ctx context.Context, ch chan NetdataMap, conf *netdataconf, subnet *ipamv1alpha1.Subnet) {
	log.Printf("starting netlink processor for subnet %s", subnet.Name)

	for entity := range ch {
		for _, v := range entity {
			createNetCRDNetlink(v, conf, ctx, subnet)
		}
	}
	log.Printf("netlink processor ended")

}

func NetlinkListener(ctx context.Context, ch chan NetdataMap, conf *netdataconf, subnet *ipamv1alpha1.Subnet) {
	log.Printf("starting netlink listener for subnet %s", subnet.Name)

	chNetlink := make(chan netlink.NeighUpdate)
	done := make(chan struct{})
	if err := netlink.NeighSubscribe(chNetlink, done); err != nil {
		log.Printf("Netlink listener subscription failed, %v", err)
		return
	}

	// If we already have a netlink listener running for a subnet, do not create new listener
	val, ok := SubnetNetlinkListener[subnet.ObjectMeta.Name]
	if ok && (val != nil) {
		close(done)
		close(ch)
		return
	}

	// Store netlink listner subnet name and closing channel
	SubnetNetlinkListener[subnet.Name] = done

	for data := range chNetlink {

		// Ignore IPs from different subnet
		ip := data.Neigh.IP.String()
		mac := data.Neigh.HardwareAddr.String()

		if subnet.Spec.CIDR != nil {
			subnetAddr := subnet.Spec.CIDR.String()
			_, subnetnetA, _ := net.ParseCIDR(subnetAddr)
			ipcur := net.ParseIP(ip)
			if !subnetnetA.Contains(ipcur) {
				continue
			}
		}
		// Ignore empty IP || empty MAC || IPv4 || link local address
		if ip == "::" || mac == "" || (IpVersion(ip) == "ipv4") || strings.HasPrefix(ip, "fe80") {
			continue
		}

		// Ignore RTM_NEWNEIGH entries with States PROBE, STALE, INCOMPLETE, FAILED stc.
		if (data.Type == unix.RTM_NEWNEIGH) && (data.Neigh.State != netlink.NUD_REACHABLE) {
			continue
		}

		// Prepare netDataMap and send on the channel
		m := make(NetdataMap)

		m[mac] = newNetdataSpec(mac, ip, "", "ipv6")
		ch <- m
	}
	close(ch)
	log.Printf("Netlink listener ended")
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

// +kubebuilder:rbac:groups=ipam.onmetal.de/v1alpha1,resources=subnet,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.onmetal.de/v1alpha1,resources=subnet/status,verbs=get
func (r *NetdataReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = r.Log.WithValues("netdata", req.NamespacedName)
	var subnet ipamv1alpha1.Subnet
	err := r.Get(ctx, req.NamespacedName, &subnet)
	if err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Subnet: %w", err))
	}
	if subnet.ObjectMeta.Name == "" {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get subnet.ObjectMeta.Name: %w", err))
	}

	log.Printf("Started reconciling for subnet : %v", subnet.ObjectMeta.Name)
	mergeRes := make(NetdataMap)

	// get configmap data
	var c netdataconf
	c.getConf()

	//	fmt.Printf("runtime.GOMAXPROC() = %+v \n", runtime.GOMAXPROC)
	r.Log.V(1).Info("\nMergeRes init state.", "mergeRes", mergeRes)
	ch := make(chan NetdataMap, 1000)

	chNetlink := make(chan NetdataMap, 1000)

	wg := sync.WaitGroup{}
	netSource := os.Getenv("NETSOURCE")
	switch netSource {
	case "kea":
		cleanupIps(ctx, &c, netSource)
		wg.Add(1)
		go kealeaseProcess(&c, r, ch, &wg)
		fmt.Printf("\nStarted kea \n")
	case "nmap":
		cleanupIps(ctx, &c, netSource)
		wg.Add(1)
		go nmapProcess(&c, r, ctx, ch, &wg)
		fmt.Printf("\nStarted nmap \n")
	case "netlink":
		// Skip subnets which do not have required label. e.g labelsubnet = oob
		val, ok := subnet.Labels["labelsubnet"]
		if !ok || val != c.SubnetLabel["labelsubnet"] {
			errString := fmt.Sprintf("Not reconciling as Labelsubnet do not match for subnet : %v", subnet.ObjectMeta.Name)
			log.Print(errString)
			return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf(errString))
		}

		// We only create netlink listener per subnet, so ignore multiple reconcile for a subnet
		ch, ok := SubnetNetlinkListener[subnet.ObjectMeta.Name]
		if !ok {
			// Apply lock to avoid race condition as you may get multiple requests for a subnet
			var mu sync.Mutex
			mu.Lock()
			SubnetNetlinkListener[subnet.ObjectMeta.Name] = nil
			mu.Unlock()
			go NetlinkListener(context.Background(), chNetlink, &c, &subnet)
			go NetlinkProcessor(context.Background(), chNetlink, &c, &subnet)
		} else {
			// Netlink listener is already created and you are here again for subnet deletion, stop the listener.
			if subnet.GetDeletionTimestamp() != nil && ch != nil {
				log.Printf("got a delete subnet request")
				close(ch)
				delete(SubnetNetlinkListener, subnet.ObjectMeta.Name)
			}
		}

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
