// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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
