package target

import (
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.50"} {
		if _, err := Parse(value); err != nil {
			t.Errorf("Parse(%q): %v", value, err)
		}
	}
	for _, value := range []string{"8.8.8.8", "100.64.0.1", "127.0.0.1", "169.254.1.1", "::1", "192.168.001.1", "bad"} {
		if _, err := Parse(value); err == nil {
			t.Errorf("Parse(%q) unexpectedly succeeded", value)
		}
	}
}

func TestDiscover(t *testing.T) {
	t.Parallel()
	candidates := discover([]interfaceInfo{
		{name: "down0", addresses: []net.Addr{ipNet("192.168.1.10/24")}},
		{name: "en0", up: true, addresses: []net.Addr{ipNet("fe80::1/64"), ipNet("192.168.1.50/24"), ipNet("8.8.8.8/24")}},
		{name: "vpn0", up: true, addresses: []net.Addr{ipNet("10.8.0.12/24"), ipNet("192.168.1.50/24")}},
	})
	want := []Candidate{
		{Address: netip.MustParseAddr("10.8.0.12"), Interface: "vpn0"},
		{Address: netip.MustParseAddr("192.168.1.50"), Interface: "en0"},
	}
	if !reflect.DeepEqual(candidates, want) {
		t.Fatalf("discover() = %#v, want %#v", candidates, want)
	}
}

func ipNet(value string) *net.IPNet {
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		panic(err)
	}
	network.IP = ip
	return network
}
