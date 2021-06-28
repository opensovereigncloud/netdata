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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// NetdataSpec defines the desired state of Netdata
type NetdataSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Addresses []IPsubnet `json:"addresses,omitempty"`

	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Pattern=`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`
	MACAddress string `json:"macAddress,omitempty"`

	// +kubebuilder:validation:Required
	Expiration metav1.Time `json:"expiration,omitempty"`

	Hostname []string `json:"hostname,omitempty"`
}

type IPsubnet struct {
	// +kubebuilder:validation:Required
	IPS []string `json:"ips"`

	// +kubebuilder:validation:Required
	Subnet string `json:"subnet"`
}

// NetdataStatus defines the observed state of Netdata
type NetdataStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

// +kubebuilder:object:root=true

// Netdata is the Schema for the netdata API
type Netdata struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NetdataSpec   `json:"spec,omitempty"`
	Status NetdataStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// NetdataList contains a list of Netdata
type NetdataList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Netdata `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Netdata{}, &NetdataList{})
}
