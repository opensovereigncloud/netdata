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
	"fmt"

	nmap "github.com/Ullaakut/nmap/v2"
	ipamv1alpha1 "github.com/onmetal/ipam/api/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	controllerruntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Netdata Controller delete expired", func() {
	var ns string
	BeforeEach(func(ctx SpecContext) {
		namespace := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "testns-"},
		}
		Expect(k8sClient.Create(ctx, namespace)).To(Succeed())
		ns = namespace.Name
		DeferCleanup(func(ctx SpecContext) {
			Expect(k8sClient.Delete(ctx, namespace)).To(Succeed())
		})
	})

	var subnet *ipamv1alpha1.Subnet
	var res reconcile.Result
	var err error
	BeforeEach(func() {
		subnet = &ipamv1alpha1.Subnet{
			TypeMeta: metav1.TypeMeta{
				APIVersion: ipamv1alpha1.GroupVersion.String(),
				Kind:       "Subnet",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ns,
				Name:      "subnettest",
				Labels: map[string]string{
					"labelsubnet": "oob",
				},
			},
			Spec: ipamv1alpha1.SubnetSpec{
				Network: v1.LocalObjectReference{Name: "test"},
			},
		}
		res = reconcile.Result{}
		err = nil
	})

	When("Subnet has no label labelsubnet", func() {

		JustBeforeEach(func(ctx SpecContext) {
			delete(subnet.Labels, "labelsubnet")
			netdataReconciler.disable()

			// Create a subnet and test if it is created successfully
			Expect(k8sClient.Create(ctx, subnet)).To(Succeed())
			Eventually(func(g Gomega, ctx SpecContext) {
				var obj ipamv1alpha1.Subnet
				g.Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "subnettest"}, &obj)).To(Succeed())
			}, ctx, "3s").Should(Succeed())

			netdataReconciler.enable()
			res, err = netdataReconciler.Reconcile(ctx, controllerruntime.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "subnettest"}})

		})

		It("Test valid subnet label ", func(ctx SpecContext) {
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError("Not reconciling as Labelsubnet do not match for subnet : subnettest"))
			Expect(res).To(Equal(reconcile.Result{}))
		})
	})

	When("No valid subnet found", func() {
		JustBeforeEach(func(ctx SpecContext) {
			res, err = netdataReconciler.Reconcile(ctx, controllerruntime.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: "subnettest"}})
			fmt.Println(res, err)
		})

		It("Test valid subnet", func(ctx SpecContext) {
			Expect(err).To(MatchError("cannot get Subnet: Subnet.ipam.onmetal.de \"subnettest\" not found"))
			Expect(res).To(Equal(reconcile.Result{}))
		})
	})

	Context("Test toNetdataMap(host *nmap.Host, subnet string) (NetdataMap, error)", func() {
		It("toNetdataMap", func() {
			host := nmap.Host{}
			subnet := "1.2.3.0/24"
			var expectedVal NetdataMap
			res, err := toNetdataMap(&host, subnet)
			Expect(res).To(Equal(expectedVal))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("No data for new crd"))
		})
	})

	Context("Test NetdataMap.add2map() function", func() {
		It("Add NetdataSpec one by one", func() {

			mergeRes := make(NetdataMap)

			mac := "11:11:11:11:11:11"
			ipsubnet := IPsubnet{
				IPS:    []string{"10.20.30.40"},
				Subnet: "10.20.30.0/24",
			}
			keySpec := NetdataSpec{
				Addresses:  []IPsubnet{ipsubnet},
				MACAddress: mac,
				Hostname:   []string{"test1"},
			}

			mergeRes.add2map(mac, keySpec)
			// added first
			Expect(mergeRes[mac]).To(Equal(keySpec))
			fmt.Printf(" \n\n in test mergeRes = %+v \n\n", mergeRes)

			mac2 := "55:55:55:55:55:55"
			ipsubnet2 := IPsubnet{
				IPS:    []string{"10.55.55.55"},
				Subnet: "10.55.55.0/24",
			}
			keySpec2 := NetdataSpec{
				Addresses:  []IPsubnet{ipsubnet2},
				MACAddress: mac2,
				Hostname:   []string{"test2"},
			}

			mergeRes.add2map(mac2, keySpec2)
			fmt.Printf("\n\n in test2 mergeRes = %+v \n\n", mergeRes)
			// added second
			Expect(mergeRes[mac]).To(Equal(keySpec))
			Expect(mergeRes[mac2]).To(Equal(keySpec2))

			ipsubnet3 := IPsubnet{
				IPS:    []string{"192.168.77.77"},
				Subnet: "192.168.77.0/24",
			}
			keySpec3 := NetdataSpec{
				Addresses:  []IPsubnet{ipsubnet3},
				MACAddress: mac2,
				Hostname:   []string{"test3"},
			}

			mergeRes.add2map(mac2, keySpec3)
			fmt.Printf("\n\n in test 3 mergeRes = %+v \n\n", mergeRes)
			// added third
			Expect(mergeRes[mac]).To(Equal(keySpec))
			Expect(mergeRes[mac2]).NotTo(Equal(keySpec2))
			Expect(len(mergeRes[mac2].Addresses)).To(Equal(2))
			Expect(len(mergeRes[mac2].Hostname)).To(Equal(2))

			ipsubnet4 := IPsubnet{
				IPS:    []string{"192.168.77.11"},
				Subnet: "192.168.77.0/24",
			}

			keySpec4 := NetdataSpec{
				Addresses:  []IPsubnet{ipsubnet4},
				MACAddress: mac2,
				Hostname:   []string{"test3"},
			}

			mergeRes.add2map(mac2, keySpec4)
			Expect(len(mergeRes[mac2].Addresses)).To(Equal(2))
			Expect(len(mergeRes[mac2].Addresses[1].IPS)).To(Equal(2))
			Expect(len(mergeRes[mac2].Hostname)).To(Equal(2))
		})
	})

})
