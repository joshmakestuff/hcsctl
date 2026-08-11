// netconfig: the pure half of the netconfig verb. Portable so the tests run on any OS; the
// nmcli invocation itself is in guest_linux.go.

package main

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// validateNetConfig fills defaults and rejects what nmcli would otherwise fail on with a
// worse message. The host validated too, but the agent is a wire endpoint and trusts nothing.
func validateNetConfig(nc *guestproto.NetConfig) error {
	if nc == nil {
		return fmt.Errorf("netconfig needs a payload")
	}
	if len(nc.Addresses) == 0 {
		return fmt.Errorf("netconfig needs at least one address")
	}
	for _, a := range nc.Addresses {
		if _, err := netip.ParsePrefix(a); err != nil {
			return fmt.Errorf("address %q is not CIDR: %v", a, err)
		}
	}
	if nc.Gateway != "" {
		if _, err := netip.ParseAddr(nc.Gateway); err != nil {
			return fmt.Errorf("gateway %q is not an address: %v", nc.Gateway, err)
		}
	}
	for _, d := range nc.DNS {
		if _, err := netip.ParseAddr(d); err != nil {
			return fmt.Errorf("dns %q is not an address: %v", d, err)
		}
	}
	if nc.Interface == "" {
		nc.Interface = "eth0"
	}
	return nil
}

// nmcliModArgs builds `nmcli con mod ...` for a validated config. Manual method through the
// connection profile, so NetworkManager owns the result -- see the package doc on
// guestproto.NetConfig for why raw ip commands are not an option.
func nmcliModArgs(nc *guestproto.NetConfig) []string {
	args := []string{"con", "mod", nc.Interface,
		"ipv4.method", "manual",
		"ipv4.addresses", strings.Join(nc.Addresses, ","),
	}
	if nc.Gateway != "" {
		args = append(args, "ipv4.gateway", nc.Gateway)
	}
	if len(nc.DNS) > 0 {
		args = append(args, "ipv4.dns", strings.Join(nc.DNS, ","))
	}
	return args
}

// observedAddresses is the post-apply attestation: what the interface actually holds, from
// the same enumeration `info` uses.
func observedAddresses(iface string) []guestproto.Address {
	all, err := addresses()
	if err != nil {
		return []guestproto.Address{}
	}
	out := []guestproto.Address{}
	for _, a := range all {
		if a.Interface == iface {
			out = append(out, a)
		}
	}
	return out
}
