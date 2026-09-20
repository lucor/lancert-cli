// Package target validates the private IPv4 addresses supported by Lancert.
package target

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
)

var privateRanges = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// Candidate is a private IPv4 address assigned to a local network interface.
type Candidate struct {
	Address   netip.Addr
	Interface string
}

type interfaceInfo struct {
	name      string
	up        bool
	addresses []net.Addr
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

// Discover returns the private IPv4 addresses assigned to active local interfaces.
func Discover() ([]Candidate, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	interfacesInfo := make([]interfaceInfo, 0, len(interfaces))
	for _, networkInterface := range interfaces {
		addresses, err := networkInterface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list addresses for interface %s: %w", networkInterface.Name, err)
		}
		interfacesInfo = append(interfacesInfo, interfaceInfo{
			name: networkInterface.Name, up: networkInterface.Flags&net.FlagUp != 0, addresses: addresses,
		})
	}
	return discover(interfacesInfo), nil
}

func discover(interfaces []interfaceInfo) []Candidate {
	candidates := make([]Candidate, 0)
	seen := make(map[netip.Addr]struct{})
	for _, networkInterface := range interfaces {
		if !networkInterface.up {
			continue
		}
		for _, address := range networkInterface.addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			addr := prefix.Addr().Unmap()
			if _, err := Parse(addr.String()); err != nil {
				continue
			}
			if _, found := seen[addr]; found {
				continue
			}
			seen[addr] = struct{}{}
			candidates = append(candidates, Candidate{Address: addr, Interface: networkInterface.name})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if comparison := candidates[i].Address.Compare(candidates[j].Address); comparison != 0 {
			return comparison < 0
		}
		return candidates[i].Interface < candidates[j].Interface
	})
	return candidates
}
