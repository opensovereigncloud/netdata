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

	nmap "github.com/Ullaakut/nmap/v2"

	"github.com/onmetal/ipam/api/v1alpha1"
	"github.com/onmetal/ipam/clientset"
	clienta1 "github.com/onmetal/ipam/clientset/v1alpha1"

	ping "github.com/prometheus-community/pro-bing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

var ipLocalCache = make(map[string]time.Time)
var mu sync.Mutex
var delMu sync.Mutex

var (
	Log        = ctrl.Log.WithName("netdata")
	kubeconfig = kubeconfigCreate(Log)
)

type hostData struct {
	ip         string
	mac        string
	subnetName string
}

type netdataconf struct {
	TTL         int               `yaml:"ttl"`
	IPNamespace string            `default:"default" yaml:"ipnamespace"`
	SubnetLabel map[string]string `yaml:"subnetLabelSelector"`
}

func (c *netdataconf) getConf(log logr.Logger) *netdataconf {

	yamlFile, err := os.ReadFile("/etc/manager/netdata-config.yaml")
	if err != nil {
		log.Error(err, "yamlFile.Get error")
		os.Exit(21)
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		log.Error(err, "Unmarshal error")
	}
	return c
}

// get subnets by label clusterwide
func (c *netdataconf) getSubnets(log logr.Logger) *v1alpha1.SubnetList {
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

func nmapScan(ch chan hostData, subnetName string, wg *sync.WaitGroup, ctx context.Context, log logr.Logger) {
	defer wg.Done()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(subnetName),
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
		log.Info(fmt.Sprintf("Warnings: %v", warnings))
	}

	for _, host := range result.Hosts {
		hostdata := hostData{}
		if len(host.Addresses) == 2 {
			hostdata.mac = host.Addresses[1].Addr
			hostdata.ip = host.Addresses[0].Addr
			hostdata.subnetName = subnetName
			ch <- hostdata
		} else {
			log.Info("mac not found", "host", host.Addresses)
		}
	}
}

func nmapScanIPv6(ch chan hostData, subnetName string, wg *sync.WaitGroup, interfaceName string, interfaceAddress string, ctx context.Context, log logr.Logger) {

	defer wg.Done()

	args := map[string]string{"newtargets": "", "interface": interfaceName, "srcip": interfaceAddress}

	// TODO: find better way of specifying/skipping the target
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(interfaceAddress),
		nmap.WithPingScan(),
		nmap.WithPrivileged(),
		nmap.WithContext(ctx),
		nmap.WithIPv6Scanning(),
		nmap.WithScripts("/nmap-ipv6-multicast-echo.nse"),
		nmap.WithScriptArguments(args),
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

	for _, host := range result.Hosts {
		hostdata := hostData{}
		if len(host.Addresses) == 2 {
			hostdata.mac = host.Addresses[1].Addr
			hostdata.ip = host.Addresses[0].Addr

			//inflate short IP addresses
			if strings.Contains(host.Addresses[0].Addr, "::") {
				i := net.ParseIP(host.Addresses[0].Addr)
				hostdata.ip = FullIPv6(i)
			}

			hostdata.subnetName = subnetName
			ch <- hostdata
		} else {
			log.Info("mac not found", "host", host.Addresses)
		}
	}
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

func ipCleanerCronJob(c *netdataconf, ctx context.Context, origin string, log logr.Logger) {
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

func createIP(hostdata hostData, conf *netdataconf, ctx context.Context, log logr.Logger) {
	macLow := strings.ToLower(hostdata.mac)
	hostdata.mac = macLow

	crdname := strings.ReplaceAll(macLow, ":", "")
	labels := make(map[string]string)
	labels["ip"] = strings.ReplaceAll(hostdata.ip, ":", "-")
	labels["origin"] = "nmap"
	labels["mac"] = crdname
	labels["labelsubnet"] = conf.SubnetLabel["labelsubnet"]
	ipaddr, _ := v1alpha1.IPAddrFromString(hostdata.ip)

	ip := &v1alpha1.IP{
		ObjectMeta: v1.ObjectMeta{
			GenerateName: crdname + "-" + "nmap" + "-",
			Namespace:    conf.IPNamespace,
			Labels:       labels,
		},
		Spec: v1alpha1.IPSpec{
			Subnet: corev1.LocalObjectReference{
				Name: hostdata.subnetName,
			},
			IP: ipaddr,
		},
	}

	createNewIP := true
	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(conf.IPNamespace)
	handleDuplicateMacs(ctx, *ip, client, &createNewIP, log)
	handleDuplicateIPs(ctx, *ip, client, &createNewIP, log)

	if createNewIP {
		ref := v1.OwnerReference{Name: "netdata.onmetal.de/ip", APIVersion: "v1", Kind: "ip", UID: "ip"}
		ip.OwnerReferences = append(ip.OwnerReferences, ref)
		createdIP, err := client.Create(ctx, ip, v1.CreateOptions{})
		if err != nil {
			log.Error(err, "Create IP error")
		}
		log.Info(fmt.Sprintf("Created IP : %s", createdIP.ObjectMeta.Name))

	}
	// update timestamp in the local cache
	mu.Lock()
	ipLocalCache[ip.Spec.IP.String()] = time.Now()
	mu.Unlock()
}

func deleteIP(ctx context.Context, ip *v1alpha1.IP, log logr.Logger) error {
	cs, _ := clientset.NewForConfig(kubeconfig)
	client := cs.IpamV1Alpha1().IPs(ip.ObjectMeta.Namespace)
	err := client.Delete(ctx, ip.ObjectMeta.Name, v1.DeleteOptions{})
	if err != nil {
		log.Error(err, "delete IP error")
	} else {
		log.Info(fmt.Sprintf("Deleted IP  %s", ip.ObjectMeta.Name))
	}
	return err
}

func getIps(origin string, log logr.Logger) []v1alpha1.IP {
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

func subnetScanCronjob(c *netdataconf, ctx context.Context, ch chan hostData, log logr.Logger) {
	wg := sync.WaitGroup{}
	for {
		subnetList := c.getSubnets(log)
		for _, subi := range subnetList.Items {
			subnet := subi.Spec.CIDR.String()

			val, ok := subi.Labels["labelsubnet"]
			if !ok || val != c.SubnetLabel["labelsubnet"] {
				log.Info("Skip the Subnet as it does not have a label labelsubnet", "subnet", subnet)
				continue
			}

			interfaceName, ipAddress := c.getNetworkInterface(subnet, log)
			if interfaceName == "" {
				log.Info("Skip the Subnet as it does not have a network interface", "subnet", subnet)
				continue
			}

			log.Info("scanning subnet", "subnet", subnet, "interface", interfaceName)

			if IpVersion(subnet) == "ipv4" {
				wg.Add(1)
				go nmapScan(ch, subnet, &wg, ctx, log)
			} else {
				wg.Add(1)
				go nmapScanIPv6(ch, subnet, &wg, interfaceName, ipAddress, ctx, log)
			}
		}
		wg.Wait()
		time.Sleep(time.Second * time.Duration(c.TTL))
	}
}

func (c *netdataconf) getNetworkInterface(subnet string, log logr.Logger) (interfaceName string, ipAddress string) {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, addri := range addrs {
			_, ipnetSub, _ := net.ParseCIDR(subnet)
			ipIf, _, _ := net.ParseCIDR(addri.String())
			if ipnetSub.Contains(ipIf) {
				return i.Name, ipIf.String()
			}
		}
	}
	return "", ""
}

func Start() {
	log := Log.WithValues("netdata", "oob")
	var c netdataconf
	c.getConf(log)
	log.Info("config", "config", c)
	ctx := context.TODO()

	log.Info("Start IP Cleaner cron job")
	go ipCleanerCronJob(&c, ctx, "nmap", log)

	ch := make(chan hostData, 5)
	log.Info("Start Subnet scan cron job")
	go subnetScanCronjob(&c, ctx, ch, log)

	for hostdata := range ch {
		createIP(hostdata, &c, ctx, log)
	}
	log.Info("Exit Netdata")
}
