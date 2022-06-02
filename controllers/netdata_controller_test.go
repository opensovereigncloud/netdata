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
	"time"

	nmap "github.com/Ullaakut/nmap/v2"
	ginkgo "github.com/onsi/ginkgo"
	gomega "github.com/onsi/gomega"
)

const timeout = time.Second * 60
const interval = time.Second * 2

var _ = ginkgo.Describe("Netdata Controller delete expired", func() {
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
			gomega.Expect(mergeRes[mac]).To(gomega.Equal(keySpec))
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
			gomega.Expect(mergeRes[mac]).To(gomega.Equal(keySpec))
			gomega.Expect(mergeRes[mac2]).To(gomega.Equal(keySpec2))

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
			gomega.Expect(mergeRes[mac]).To(gomega.Equal(keySpec))
			gomega.Expect(mergeRes[mac2]).NotTo(gomega.Equal(keySpec2))
			gomega.Expect(len(mergeRes[mac2].Addresses)).To(gomega.Equal(2))
			gomega.Expect(len(mergeRes[mac2].Hostname)).To(gomega.Equal(2))

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
			gomega.Expect(len(mergeRes[mac2].Addresses)).To(gomega.Equal(2))
			gomega.Expect(len(mergeRes[mac2].Addresses[1].IPS)).To(gomega.Equal(2))
			gomega.Expect(len(mergeRes[mac2].Hostname)).To(gomega.Equal(2))
		})
	})

})
