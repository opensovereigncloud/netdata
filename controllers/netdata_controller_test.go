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
	"fmt"
	"time"

	nmap "github.com/Ullaakut/nmap/v2"
	dev1 "github.com/onmetal/netdata/api/v1"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const timeout = time.Second * 60
const interval = time.Second * 2

var _ = ginkgo.Describe("Netdata Controller", func() {

	var (
		name      = "key"
		namespace = "ns-tests"
		nsSpecs   = &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	)

	ginkgo.BeforeEach(func() {
	})

	ginkgo.AfterEach(func() {
		gomega.Expect(k8sClient.Delete(context.Background(), nsSpecs)).Should(gomega.Succeed())
	})

	ginkgo.Context("Netdata Controller Test", func() {

		ginkgo.It("Should create successfully", func() {
			gomega.Expect(k8sClient.Create(context.Background(), nsSpecs)).Should(gomega.Succeed())

			var later metav1.Time = metav1.Time{Time: time.Now().Add(120 * time.Minute)}

			keySpec := dev1.NetdataSpec{
				Expiration: later,
			}

			createKey(name, namespace, keySpec)

		})

		ginkgo.It("Should Delete Key successfully", func() {
			deleteKey(name, namespace)
		})

	})
})

var _ = ginkgo.Describe("Netdata Controller delete expired", func() {

	var (
		name                  = "key-expired"
		namespace             = "ns-tests-expired"
		nsSpecs               = &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
		early     metav1.Time = metav1.Time{Time: time.Now().Add(-120 * time.Minute)}
	)

	ginkgo.BeforeEach(func() {
	})

	ginkgo.AfterEach(func() {
	})

	ginkgo.Context("Test toNetdataMap(host *nmap.Host, subnet string) (NetdataMap, error)", func() {
		ginkgo.It("toNetdataMap", func() {
			host := nmap.Host{}
			subnet := "1.2.3.0/24"
			var expectedVal NetdataMap
			res, err := toNetdataMap(&host, subnet)
			gomega.Expect(res).To(gomega.Equal(expectedVal))
			gomega.Expect(err).To(gomega.HaveOccurred())
			gomega.Expect(err.Error()).To(gomega.Equal("No data for new crd"))
		})
	})

	ginkgo.Context("Test NetdataMap.add2map() function", func() {
		ginkgo.It("Add NetdataSpec one by one", func() {

			mergeRes := make(NetdataMap)

			mac := "11:11:11:11:11:11"
			ipsubnet := dev1.IPsubnet{
				IPS:    []string{"10.20.30.40"},
				Subnet: "10.20.30.0/24",
			}
			keySpec := dev1.NetdataSpec{
				Addresses:  []dev1.IPsubnet{ipsubnet},
				MACAddress: mac,
				Hostname:   []string{"test1"},
			}

			mergeRes.add2map(mac, keySpec)
			// added first
			gomega.Expect(mergeRes[mac]).To(gomega.Equal(keySpec))
			fmt.Printf(" \n\n in test mergeRes = %+v \n\n", mergeRes)

			mac2 := "55:55:55:55:55:55"
			ipsubnet2 := dev1.IPsubnet{
				IPS:    []string{"10.55.55.55"},
				Subnet: "10.55.55.0/24",
			}
			keySpec2 := dev1.NetdataSpec{
				Addresses:  []dev1.IPsubnet{ipsubnet2},
				MACAddress: mac2,
				Hostname:   []string{"test2"},
			}

			mergeRes.add2map(mac2, keySpec2)
			fmt.Printf("\n\n in test2 mergeRes = %+v \n\n", mergeRes)
			// added second
			gomega.Expect(mergeRes[mac]).To(gomega.Equal(keySpec))
			gomega.Expect(mergeRes[mac2]).To(gomega.Equal(keySpec2))

			ipsubnet3 := dev1.IPsubnet{
				IPS:    []string{"192.168.77.77"},
				Subnet: "192.168.77.0/24",
			}
			keySpec3 := dev1.NetdataSpec{
				Addresses:  []dev1.IPsubnet{ipsubnet3},
				MACAddress: mac2,
				Hostname:   []string{"test3"},
			}

			mergeRes.add2map(mac2, keySpec3)
			fmt.Printf("\n\n in test 3 mergeRes = %+v \n\n", mergeRes)
			// added third
			gomega.Expect(mergeRes[mac]).To(gomega.Equal(keySpec))
			gomega.Expect(mergeRes[mac2]).NotTo(gomega.Equal(keySpec2))
			gomega.Expect(len(mergeRes[mac2].Addresses)).To(gomega.Equal(2))
			gomega.Expect(len(mergeRes[mac2].Hostname)).To(gomega.Equal(2))

			ipsubnet4 := dev1.IPsubnet{
				IPS:    []string{"192.168.77.11"},
				Subnet: "192.168.77.0/24",
			}

			keySpec4 := dev1.NetdataSpec{
				Addresses:  []dev1.IPsubnet{ipsubnet4},
				MACAddress: mac2,
				Hostname:   []string{"test3"},
			}

			mergeRes.add2map(mac2, keySpec4)
			gomega.Expect(len(mergeRes[mac2].Addresses)).To(gomega.Equal(2))
			gomega.Expect(len(mergeRes[mac2].Addresses[1].IPS)).To(gomega.Equal(2))
			gomega.Expect(len(mergeRes[mac2].Hostname)).To(gomega.Equal(2))
		})
	})

	ginkgo.Context("Controller Test deletion expired", func() {
		ginkgo.It("Should create successfully expired", func() {
			gomega.Expect(k8sClient.Create(context.Background(), nsSpecs)).Should(gomega.Succeed())

			ipsubnet := dev1.IPsubnet{
				IPS:    []string{"10.20.30.40"},
				Subnet: "10.20.30.0/24",
			}
			keySpec := dev1.NetdataSpec{
				Addresses:  []dev1.IPsubnet{ipsubnet},
				MACAddress: "52:54:00:b4:c2:63",
				Expiration: early,
			}

			createKey(name, namespace, keySpec)
			gomega.Expect(k8sClient.Delete(context.Background(), nsSpecs)).Should(gomega.Succeed())
		})
	})
})

var _ = ginkgo.Describe("Netdata Controller wrong data", func() {

	var (
		name      = "key-wrong"
		namespace = "ns-tests-wrong"
		nsSpecs   = &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
	)

	ginkgo.BeforeEach(func() {
	})

	ginkgo.AfterEach(func() {
		gomega.Expect(k8sClient.Delete(context.Background(), nsSpecs)).Should(gomega.Succeed())
	})
	ginkgo.Context("Netdata Controller bad data", func() {
		ginkgo.It("Should create successfully and wrong parsing", func() {

			gomega.Expect(k8sClient.Create(context.Background(), nsSpecs)).Should(gomega.Succeed())

			var later metav1.Time = metav1.Time{Time: time.Now().Add(120 * time.Minute)}

			ips := []string{"10.20.130.140"}
			ipsubnet := dev1.IPsubnet{
				IPS:    ips,
				Subnet: "10.20.130.0/24",
			}

			keySpec := dev1.NetdataSpec{
				Addresses:  []dev1.IPsubnet{ipsubnet},
				MACAddress: "AAA52:54:11:b4:c2:63",
				Expiration: later,
			}

			created := &dev1.Netdata{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: keySpec,
			}

			gomega.Expect(k8sClient.Create(context.Background(), created)).ShouldNot(gomega.Succeed())

		})
	})
})

func createKey(name, namespace string, netdata dev1.NetdataSpec) {
	key := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	created := &dev1.Netdata{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: netdata,
	}

	gomega.Expect(k8sClient.Create(context.Background(), created)).Should(gomega.Succeed())
	ginkgo.By("gomega.Expecting Create Successful")
	gomega.Eventually(func() bool {
		keyObj := &dev1.Netdata{}
		_ = k8sClient.Get(context.Background(), key, keyObj)
		fmt.Printf("!!! Name = %s", keyObj.ObjectMeta.Name)
		return true
	}, timeout, interval).Should(gomega.BeTrue())
}

func deleteKey(name, namespace string) {
	key := types.NamespacedName{
		Name:      name,
		Namespace: namespace,
	}
	// Delete Key
	ginkgo.By("Expecting Delete successful")
	gomega.Eventually(func() error {
		pubcrd := &dev1.Netdata{}
		_ = k8sClient.Get(context.Background(), key, pubcrd)
		err := k8sClient.Delete(context.Background(), pubcrd)
		return err
	}, timeout, interval).Should(gomega.Succeed())
}
