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
	"net"
	"testing"
)

func TestIPv6(t *testing.T) {
	testIP := net.ParseIP("FE82::1A12:1234:1A12")
	want := "fe82:0000:0000:0000:0000:1a12:1234:1a12"
	got := FullIPv6(testIP)
	if got != want {
		t.Fail()
	}
}

func TestIP6Version(t *testing.T) {
	testIP := "FE82:0:0:0:0:1A12:1234:1A12"
	want := "ipv6"
	got := IpVersion(testIP)
	if got != want {
		t.Fail()
	}
}

func TestIP4Version(t *testing.T) {
	testIP := "192.0.2.146"
	want := "ipv4"
	got := IpVersion(testIP)
	if got != want {
		t.Fail()
	}
}
