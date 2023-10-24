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
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/go-logr/logr"
	yaml "gopkg.in/yaml.v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	nmap "github.com/Ullaakut/nmap/v2"

	"github.com/onmetal/ipam/api/v1alpha1"
	"github.com/onmetal/ipam/clientset"
	clienta1 "github.com/onmetal/ipam/clientset/v1alpha1"

	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	ping "github.com/prometheus-community/pro-bing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var doOnce sync.Once

var ipLocalCache = make(map[string]time.Time)
var mu sync.Mutex
var delMu sync.Mutex

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

type netdataconf struct {
	Interval    int               `yaml:"interval"`
	TTL         int               `yaml:"ttl"`
	IPNamespace string            `default:"default" yaml:"ipnamespace"`
	SubnetLabel map[string]string `yaml:"subnetLabelSelector"`
}

func (c *netdataconf) getConf(r *NetdataReconciler, log logr.Logger) *netdataconf {

	yamlFile, err := os.ReadFile(r.Config)
	if err != nil {
		log.Error(err, "yamlFile.Get error")
		os.Exit(21)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Error(err, "Unmarshal error")
	}
	c.validate(log)

	log.Info(fmt.Sprintf("Config is %v ", c))

	return c
}

func (c *netdataconf) getNMAPInterface(log logr.Logger) string {
	if os.Getenv("NETSOURCE") == "nmap" {
		subnetList := c.getSubnets(log)
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			log.Info(fmt.Sprintf("interface name %s", i.Name))
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
func (c *netdataconf) getSubnets(log logr.Logger) *v1alpha1.SubnetList {
	kubeconfig := kubeconfigCreate(log)

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

func (c *netdataconf) validate(log logr.Logger) {
	c.validateInterval(log)
}

// TTL > Interval
func (c *netdataconf) validateInterval(log logr.Logger) {
	if c.TTL > c.Interval {
		log.Info("valid ttl > interval")
	} else {
		log.Error(fmt.Errorf("wrong ttl < interval"), "error")
		os.Exit(20)
	}
}

// NetdataReconciler reconciles a Netdata object
type NetdataReconciler struct {
	client.Client
	Log         logr.Logger
	Scheme      *runtime.Scheme
	Config      string
	disabled    bool
	disabledMtx sync.RWMutex
}

func (r *NetdataReconciler) enable() {
	r.disabledMtx.Lock()
	defer r.disabledMtx.Unlock()
	r.disabled = false
}

func (r *NetdataReconciler) disable() {
	r.disabledMtx.Lock()
	defer r.disabledMtx.Unlock()
	r.disabled = true
}

func (r *NetdataReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.disabledMtx.RLock()
	defer r.disabledMtx.RUnlock()
	if r.disabled {
		return ctrl.Result{}, nil
	}

	return r.reconcile(ctx, req)
}

func nmapScan(targetSubnet string, ctx context.Context, log logr.Logger) []nmap.Host {
	//  setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip  /usr/bin/nmap
	// nmap --privileged -sn -oX - 192.168.178.0/24
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targetSubnet),
		nmap.WithPingScan(),
		nmap.WithPrivileged(),
		nmap.WithContext(ctx),
	)
	if err != nil {
		log.Error(err, "unable to create nmap scanner")
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Error(err, "unable to run nmap scan")
	}

	if warnings != nil {
		log.Info(fmt.Sprintf("Warnings: \n %v", warnings))
	}

	// Use the results to print an example output
	for ihx := range result.Hosts {
		host := &result.Hosts[ihx]
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		log.Info(fmt.Sprintf("Host %q:", host.Addresses[0]))

		for idx := range host.Ports {
			port := &host.Ports[idx]
			log.Info(fmt.Sprintf("\tPort %d/%s %s %s", port.ID, port.Protocol, port.State, port.Service.Name))
		}
	}

	log.Info(fmt.Sprintf("Nmap done: %d hosts up scanned in %3f seconds", len(result.Hosts), result.Stats.Finished.Elapsed))
	return result.Hosts
}

func kubeconfigCreate(log logr.Logger) *rest.Config {
	var kubeconfig *rest.Config
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath != "" {
		config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			log.Error(err, fmt.Sprintf("unable to load kubeconfig from %s: ", kubeconfigPath))
		}
		kubeconfig = config
	} else {
		config, err := rest.InClusterConfig()
		if err != nil {
			log.Error(err, "unable to load in-cluster config")
		}
		kubeconfig = config
	}
	if err := v1alpha1.AddToScheme(scheme.Scheme); err != nil {
		_ = errors.Wrap(err, "unable to add registered types to client scheme")
	}
	return kubeconfig
}

func IPCleaner(ctx context.Context, c *netdataconf, origin string, log logr.Logger) {

	// Initially fill the cache with expired time, this will ensure to ping all IPs in first run
	ips := getIps(origin, log)
	expiredTime := time.Now().Add(-(time.Second * time.Duration(c.TTL) * 2))
	for _, ip := range ips {
		ipLocalCache[ip.Spec.IP.String()] = expiredTime
	}

	for {
		ips := getIps(origin, log)
		for _, ip := range ips {
			ipAddress := ip.Spec.IP.String()

			// If the IP is seen 90% TTL then do not ping it
			lastSeen := time.Since(ipLocalCache[ipAddress]).Seconds()
			if lastSeen < float64(c.TTL)*0.9 {
				continue
			}

			pinger, err := ping.NewPinger(ipAddress)
			if err != nil {
				log.Info(fmt.Sprintf("IP Cleaner Address could not be resolved, IP object: %s", ip.Name)) // no such host, the address cant be resolved
				continue
			}

			pinger.Count = 3
			pinger.Timeout = time.Second * 5
			err = pinger.Run()

			// If ping fails, try one more time after 5 sec if it still fails delete the ip object
			if err != nil || pinger.PacketsRecv == 0 {
				log.Info(fmt.Sprintf("IP Cleaner ping failed, redialing in 5 sec for IP object: %s, ", ip.Name)) // no such host, the address cant be resolved
				time.Sleep(time.Second * 5)
				err = pinger.Run()
				if err != nil || pinger.PacketsRecv == 0 {
					log.Info(fmt.Sprintf("IP Cleaner ping failed, deleting IP object: %s", ip.ObjectMeta.Name))
					err := deleteIP(ctx, &ip, log)
					if err == nil {
						delMu.Lock()
						delete(ipLocalCache, ipAddress)
						delMu.Unlock()
					}
				}
			}
		}
		time.Sleep(time.Second * time.Duration(c.TTL))
	}
}

func createIPAM(c *netdataconf, ctx context.Context, ip v1alpha1.IP, subnet *ipamv1alpha1.Subnet, log logr.Logger) {
	kubeconfig := kubeconfigCreate(log)
	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(subnet.ObjectMeta.Namespace)

	ip.Spec.Subnet.Name = subnet.ObjectMeta.Name
	ip.ObjectMeta.Namespace = subnet.ObjectMeta.Namespace

	createNewIP := true

	handleDuplicateMacs(ctx, ip, client, &createNewIP, log)

	handleDuplicateIPs(ctx, ip, client, &createNewIP, log)

	// Create new IP
	if createNewIP {
		ref := v1.OwnerReference{Name: "netdata.onmetal.de/ip", APIVersion: "v1", Kind: "ip", UID: "ip"}
		ip.OwnerReferences = append(ip.OwnerReferences, ref)
		createdIP, err := client.Create(ctx, &ip, v1.CreateOptions{})
		if err != nil {
			log.Error(err, "Create IP error")
		}
		log.Info(fmt.Sprintf("Created IP object: %s \n", createdIP.ObjectMeta.Name))

	}
	// update timestamp in the local cache
	mu.Lock()
	ipLocalCache[ip.Spec.IP.String()] = time.Now()
	mu.Unlock()
}

func handleDuplicateMacs(ctx context.Context, ip v1alpha1.IP, client clienta1.IPInterface, createNewIP *bool, log logr.Logger) {
	mac := strings.Split(ip.ObjectMeta.GenerateName, "-")[0]
	labelsIPS := make(map[string]string)
	labelsIPS["mac"] = mac
	labelSelectorIPS := metav1.LabelSelector{MatchLabels: labelsIPS}
	ipsListOptions := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelectorIPS.MatchLabels).String(),
		Limit:         100,
	}
	ipsList, _ := client.List(ctx, ipsListOptions)

	for _, existedIP := range ipsList.Items {
		if existedIP.Spec.IP.Equal(ip.Spec.IP) {
			*createNewIP = false
		}
	}
}

func handleDuplicateIPs(ctx context.Context, ip v1alpha1.IP, client clienta1.IPInterface, createNewIP *bool, log logr.Logger) {
	mac := strings.Split(ip.ObjectMeta.GenerateName, "-")[0]
	labelsIPS_ip := make(map[string]string)
	labelsIPS_ip["ip"] = strings.ReplaceAll(ip.Spec.IP.String(), ":", "-")

	labelSelectorIPS_ip := metav1.LabelSelector{MatchLabels: labelsIPS_ip}
	ipsListOptions_ip := metav1.ListOptions{
		LabelSelector: labels.Set(labelSelectorIPS_ip.MatchLabels).String(),
		Limit:         100,
	}
	ipsList_ip, _ := client.List(ctx, ipsListOptions_ip)
	for _, existedIP := range ipsList_ip.Items {
		if existedIP.ObjectMeta.Labels["mac"] != mac {
			log.Error(fmt.Errorf("ERROR : Duplicate ip found, existing object : %v, new mac = %v", existedIP.ObjectMeta.Name, mac), "ERROR")
			*createNewIP = false
		}
	}
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

func createNetCRD(mv NetdataSpec, conf *netdataconf, ctx context.Context, subnet *ipamv1alpha1.Subnet, log logr.Logger) {
	macLow := strings.ToLower(mv.MACAddress)
	mv.MACAddress = macLow

	crdname := strings.ReplaceAll(macLow, ":", "")
	labels := make(map[string]string)
	for idx := range mv.Addresses {
		ipsubnet := &mv.Addresses[idx]
		ips := ipsubnet.IPS
		ipsubnet.IPType = IpVersion(ips[0])
		for jdx := range ips {
			labels["ip"] = strings.ReplaceAll(ips[jdx], ":", "-")
		}
	}
	labels["origin"] = os.Getenv("NETSOURCE")
	labels["mac"] = crdname
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

	createIPAM(conf, ctx, *ipIPAM, subnet, log)
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

func deleteIP(ctx context.Context, ip *v1alpha1.IP, log logr.Logger) error {
	kubeconfig := kubeconfigCreate(log)
	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(ip.ObjectMeta.Namespace)
	err := client.Delete(ctx, ip.ObjectMeta.Name, v1.DeleteOptions{})
	if err != nil {
		log.Error(err, "delete IP error")
	} else {
		log.Info(fmt.Sprintf("deleted IP  %s", ip.ObjectMeta.Name))
	}
	return err
}

func getIps(origin string, log logr.Logger) []v1alpha1.IP {
	kubeconfig := kubeconfigCreate(log)
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

func nmapProcess(c *netdataconf, r *NetdataReconciler, ctx context.Context, ch chan NetdataMap, wg *sync.WaitGroup, log logr.Logger) {
	defer wg.Done()
	subnetList := c.getSubnets(log)
	for _, subi := range subnetList.Items {
		// check if at least 1 interface belong to subnet
		if len(c.getNMAPInterface(log)) > 0 {

			subnet := subi.Spec.CIDR.String()
			log.Info("Nmap scan ", "subnet", subnet)

			if IpVersion(subnet) == "ipv4" {
				res := nmapScan(subnet, ctx, log)

				for hostidx := range res {
					host := &res[hostidx]
					res, err := toNetdataMap(host, subnet)
					if err == nil {
						log.Info("Host", "ipv4 is", host.Addresses[0], " mac is ", host.Addresses[1])
						ch <- res
						log.Info("added to channel Host", "ipv4 is", host.Addresses[0], " mac is ", host.Addresses[1])
					}
				}
			} else {
				log.Info("Skip nmap scanning for ipv6", "subnet", subnet)
			}
		}
	}
}

// +kubebuilder:rbac:groups=ipam.onmetal.de/v1alpha1,resources=subnet,verbs=get;list;watch
// +kubebuilder:rbac:groups=ipam.onmetal.de/v1alpha1,resources=subnet/status,verbs=get
func (r *NetdataReconciler) reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("netdata", req.NamespacedName)
	var subnet ipamv1alpha1.Subnet
	err := r.Get(ctx, req.NamespacedName, &subnet)
	if err != nil {
		log.Error(err, "requested subnet resource not found")
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get Subnet: %v", err))
	}
	if subnet.ObjectMeta.Name == "" {
		return ctrl.Result{}, client.IgnoreNotFound(fmt.Errorf("cannot get subnet.ObjectMeta.Name: %v", err))
	}

	// get configmap data
	var c netdataconf
	c.getConf(r, log)

	// Skip subnets which do not have required label. e.g labelsubnet = oob
	val, ok := subnet.Labels["labelsubnet"]
	if !ok || val != c.SubnetLabel["labelsubnet"] {
		errString := fmt.Sprintf("Not reconciling as Labelsubnet do not match for subnet : %v", subnet.ObjectMeta.Name)
		log.Info(errString)
		return ctrl.Result{}, fmt.Errorf(errString)
	}

	log.Info("Started reconciling for subnet", "subnet", subnet.ObjectMeta.Name)

	netSource := os.Getenv("NETSOURCE")
	switch netSource {
	case "nmap":
		ch := make(chan NetdataMap, 1000)
		mergeRes := make(NetdataMap)
		log.Info("\nMergeRes init state.", "mergeRes", mergeRes)
		// Start IP Cleaner go routine, this will be executed only once and it will run forever.
		doOnce.Do(func() {
			log.Info("Starting IP Cleaner...")
			go IPCleaner(ctx, &c, "nmap", log)
		})

		wg := sync.WaitGroup{}

		wg.Add(1)
		go nmapProcess(&c, r, ctx, ch, &wg, log)
		log.Info("\nStarted nmap \n")

		wg.Wait()
		log.Info("\nWg ended \n")
		close(ch)
		log.Info("\nch closed \n")

		for entity := range ch {
			for k, v := range entity {
				log.Info("\ntest 1  mergeRes = %+v \n", mergeRes)
				log.Info("\ntest 1  k = %+v \n", k)
				log.Info("\ntest 1  v = %+v \n", v)
				mergeRes.add2map(k, v)
				log.Info("\ntest 2 should change  mergeRes = %+v \n", mergeRes)
			}
		}

		for _, mv := range mergeRes {
			createNetCRD(mv, &c, ctx, &subnet, log)
		}
	default:
		log.Error(fmt.Errorf("Require define proper NETSOURCE environment variable. current NETSOURCE is +%v", netSource), "error", "env")
		os.Exit(11)
	}
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
