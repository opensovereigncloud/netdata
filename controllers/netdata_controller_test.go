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

	dev1 "netdata/api/v1"

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
	)

	ginkgo.BeforeEach(func() {
	})

	ginkgo.AfterEach(func() {
	})

	ginkgo.Context("Netdata Controller Test", func() {

		ginkgo.It("Should create successfully", func() {
			nsSpecs := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
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

var _ = ginkgo.Describe("Sshpublickey Controller delete expired", func() {

	var (
		name      = "key-expired"
		namespace = "ns-tests-expired"
	)

	ginkgo.BeforeEach(func() {
	})

	ginkgo.AfterEach(func() {
	})
	ginkgo.Context("Controller Test deletion expired", func() {
		ginkgo.It("Should create successfully expired", func() {
			nsSpecs := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
			gomega.Expect(k8sClient.Create(context.Background(), nsSpecs)).Should(gomega.Succeed())

			var early metav1.Time = metav1.Time{Time: time.Now().Add(-120 * time.Minute)}

			keySpec := dev1.NetdataSpec{
				IPAddress:  "10.20.30.40",
				MACAddress: "52:54:00:b4:c2:63",
				Expiration: early,
				Subnet:     "10.20.30.0/24",
			}

			createKey(name, namespace, keySpec)
		})
	})
})

var _ = ginkgo.Describe("Sshpublickey Controller wrong data", func() {

	var (
		name      = "key-wrong"
		namespace = "ns-tests-wrong"
	)

	ginkgo.BeforeEach(func() {
	})

	ginkgo.AfterEach(func() {
	})
	ginkgo.Context("Sshpublickey Controller bad data", func() {
		ginkgo.It("Should create successfully and wrong parsing", func() {
			nsSpecs := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
			gomega.Expect(k8sClient.Create(context.Background(), nsSpecs)).Should(gomega.Succeed())

			var later metav1.Time = metav1.Time{Time: time.Now().Add(120 * time.Minute)}

			keySpec := dev1.NetdataSpec{
				IPAddress:  "A.20.130.140",
				MACAddress: "52:54:11:b4:c2:63",
				Expiration: later,
				Subnet:     "10.20.130.0/24",
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
	ginkgo.By("Expecting Create Successful")
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
