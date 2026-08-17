// netconfig: the pure half of the netconfig verb. Portable so the tests run on any OS; the
// nmcli invocation is in guest_linux.go, the netsh invocation in guest_windows.go.

package main

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/joshmakestuff/hcsctl/internal/guestproto"
)

// validateNetConfig fills defaults and rejects what the mechanism would otherwise fail on
// with a worse message. The host validated too, but the agent is a wire endpoint and trusts
// nothing. IPv4 only: both measured mechanisms program IPv4 (nmcli ipv4.*, netsh interface
// ipv4), and an IPv6 config would silently measure nothing.
func validateNetConfig(nc *guestproto.NetConfig) error {
	if nc == nil {
		return fmt.Errorf("netconfig needs a payload")
	}
	if len(nc.Addresses) == 0 {
		return fmt.Errorf("netconfig needs at least one address")
	}
	for _, a := range nc.Addresses {
		p, err := netip.ParsePrefix(a)
		if err != nil {
			return fmt.Errorf("address %q is not CIDR: %v", a, err)
		}
		if !p.Addr().Is4() {
			return fmt.Errorf("address %q is not IPv4: this agent programs IPv4 only", a)
		}
	}
	if nc.Gateway != "" {
		g, err := netip.ParseAddr(nc.Gateway)
		if err != nil {
			return fmt.Errorf("gateway %q is not an address: %v", nc.Gateway, err)
		}
		if !g.Is4() {
			return fmt.Errorf("gateway %q is not IPv4: this agent programs IPv4 only", nc.Gateway)
		}
	}
	for _, d := range nc.DNS {
		a, err := netip.ParseAddr(d)
		if err != nil {
			return fmt.Errorf("dns %q is not an address: %v", d, err)
		}
		if !a.Is4() {
			return fmt.Errorf("dns %q is not IPv4: this agent programs IPv4 only", d)
		}
	}
	if nc.Interface == "" {
		nc.Interface = defaultInterface()
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

// netshCmds builds the netsh invocations for a validated config on the adapter with the
// given interface index. This exact shape is the measured Windows mechanism
// (2026-08-11): `set address source=static` holds address and dataplane through the
// whole observation window, and flips the interface off DHCP itself, so no service fights
// the result. name= takes the interface index, which sidesteps localized adapter names.
//
// The first address and DNS server go through `set` (replacing whatever the interface has);
// the rest go through `add`.
func netshCmds(nc *guestproto.NetConfig, ifIndex int) [][]string {
	name := "name=" + strconv.Itoa(ifIndex)
	var cmds [][]string
	for i, a := range nc.Addresses {
		p := netip.MustParsePrefix(a) // validated
		addr := "address=" + p.Addr().String()
		mask := "mask=" + maskString(p.Bits())
		if i == 0 {
			c := []string{"interface", "ipv4", "set", "address", name, "source=static", addr, mask}
			if nc.Gateway != "" {
				c = append(c, "gateway="+nc.Gateway)
			}
			cmds = append(cmds, c)
		} else {
			cmds = append(cmds, []string{"interface", "ipv4", "add", "address", name, addr, mask})
		}
	}
	for i, d := range nc.DNS {
		if i == 0 {
			cmds = append(cmds, []string{"interface", "ipv4", "set", "dnsservers", name,
				"source=static", "address=" + d, "register=none", "validate=no"})
		} else {
			cmds = append(cmds, []string{"interface", "ipv4", "add", "dnsservers", name,
				"address=" + d, "index=" + strconv.Itoa(i+1), "validate=no"})
		}
	}
	return cmds
}

// maskString renders a prefix length as the dotted mask netsh takes. netsh's CIDR spelling
// is unmeasured; the mask form is what the probe ran.
func maskString(bits int) string {
	return net.IP(net.CIDRMask(bits, 32)).String()
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
