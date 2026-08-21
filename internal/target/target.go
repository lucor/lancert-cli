// Package target validates the private IPv4 addresses supported by Lancert.
package target

import (
	"fmt"
	"net/netip"
)

var privateRanges = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// Parse accepts only canonical RFC 1918 IPv4 addresses.
func Parse(value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil || !addr.Is4() || addr.String() != value {
		return netip.Addr{}, fmt.Errorf("%q is not a canonical private IPv4 address", value)
	}
	for _, prefix := range privateRanges {
		if prefix.Contains(addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s is not an RFC 1918 private IPv4 address", value)
}
