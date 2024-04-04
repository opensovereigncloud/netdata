// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/ironcore-dev/ipam/api/ipam/v1alpha1"
	ipaminformer "github.com/ironcore-dev/ipam/clientgo/informers"
	ipam "github.com/ironcore-dev/ipam/clientgo/ipam"
	"github.com/ironcore-dev/ipam/clientset"
	clienta1 "github.com/ironcore-dev/ipam/clientset/v1alpha1"

	ping "github.com/prometheus-community/pro-bing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
)

// IP local cache via informer events
var ipMap = map[string](*v1alpha1.IP){}

var (
	Log        = ctrl.Log.WithName("netdata")
	kubeconfig = kubeconfigCreate(Log)
)

type hostData struct {
	ip     string
	mac    string
	subnet *v1alpha1.Subnet
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

func nmapScan(ch chan hostData, subnet v1alpha1.Subnet, wg *sync.WaitGroup, ctx context.Context, log logr.Logger) {
	defer wg.Done()
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(subnet.Spec.CIDR.String()),
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
			hostdata.subnet = subnet.DeepCopy()
			ch <- hostdata
		} else {
			log.Info("mac not found", "host", host.Addresses)
		}
	}
}

func nmapScanIPv6(ch chan hostData, subnet v1alpha1.Subnet, wg *sync.WaitGroup, interfaceName string, interfaceAddress string, ctx context.Context, log logr.Logger) {

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

			hostdata.subnet = subnet.DeepCopy()
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

func ipCleanerCronJob(c *netdataconf, ctx context.Context, log logr.Logger) {
	CacheInit := make(chan bool)

	go getIpsViaInformer(CacheInit)
	<-CacheInit // Wait till cache initialised for the first time

	for {
		for _, ip := range ipMap {
			ipAddress := ip.Spec.IP.String()
			pinger, err := ping.NewPinger(ipAddress)
			if err != nil {
				log.Info(fmt.Sprintf("IP Cleaner Address could not be resolved, IP object: %s", ip.Name)) // no such host, the address cant be resolved
				continue
			}

			pinger.SetPrivileged(true)
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
					if err != nil {
						log.Info(err.Error())
					}
					err := deleteIP(ctx, ip, log)
					if err != nil {
						log.Info(err.Error())
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
				Name: hostdata.subnet.Name,
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
		ip.SetOwnerReferences([]metav1.OwnerReference{
			*metav1.NewControllerRef(hostdata.subnet, hostdata.subnet.GroupVersionKind()),
		})

		createdIP, err := client.Create(ctx, ip, v1.CreateOptions{})
		if err != nil {
			log.Error(err, "Create IP error")
		}
		log.Info(fmt.Sprintf("Created IP : %s", createdIP.ObjectMeta.Name))

	}
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
				go nmapScan(ch, subi, &wg, ctx, log)
			} else {
				wg.Add(1)
				go nmapScanIPv6(ch, subi, &wg, interfaceName, ipAddress, ctx, log)
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

func getIpsViaInformer(cacheInit chan bool) {
	cs, _ := ipam.NewForConfig(kubeconfig)
	informerFactory := ipaminformer.NewSharedInformerFactory(cs, time.Second*30)

	ipInformer := informerFactory.Ipam().V1alpha1().IPs()

	_, err := ipInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			IP := obj.(*v1alpha1.IP)
			origin, ok := IP.Labels["origin"]
			if ok && origin == "nmap" {
				ipMap[IP.Name] = IP
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// compare the resource version, if they are different then object is actually updated otherwise its a cache update event and
			// it can be ignored
			oldIP := oldObj.(*v1alpha1.IP)
			newIP := newObj.(*v1alpha1.IP)
			origin, ok := newIP.Labels["origin"]
			if ok && origin == "nmap" {
				if oldIP.ResourceVersion != newIP.ResourceVersion {
					ipMap[newIP.Name] = newIP
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			IP := obj.(*v1alpha1.IP)
			origin, ok := IP.Labels["origin"]
			if ok && origin == "nmap" {
				delete(ipMap, IP.Name)
			}
		},
	})
	if err != nil {
		fmt.Println(err)
	}

	// Start the informer
	stopCh := make(chan struct{})
	defer close(stopCh)

	go ipInformer.Informer().Run(stopCh)

	for {
		if ipInformer.Informer().HasSynced() {
			cacheInit <- true
			break
		}
		time.Sleep(time.Second * 5)
	}
	// Run until interrupted
	select {}
}

func Start() {
	log := Log.WithValues("netdata", "oob")
	var c netdataconf
	c.getConf(log)
	log.Info("config", "config", c)
	ctx := context.TODO()

	log.Info("Start IP Cleaner cron job")
	go ipCleanerCronJob(&c, ctx, log)

	ch := make(chan hostData, 5)
	log.Info("Start Subnet scan cron job")
	go subnetScanCronjob(&c, ctx, ch, log)

	for hostdata := range ch {
		createIP(hostdata, &c, ctx, log)
	}
	log.Info("Exit Netdata")
}
