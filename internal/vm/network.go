//go:build windows

package vm

// A VM's network adapter, and the HCN endpoint behind it (#43).
//
// A full VM is not a container here. A static HNS endpoint programs a container's network stack
// directly; a full VM's guest OS runs its own DHCP client and ignores it. So the VM attaches to
// an ICS network -- the Hyper-V Default Switch -- whose built-in DHCP serves an arbitrary guest
// image, and the address is read back from the endpoint afterwards.
//
// Nothing here creates a network. Reuse is the posture for the same reason the container path
// has it: creating one is risky and lives in #15.

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
)

// endpointFlagsEnableDhcp is 32. hcsshim's EndpointFlags enum defines only None (0) and
// RemoteEndpoint (1), so the value is carried here rather than imported.
//
// Measured (hcsspike/probes/hcn/vmlease.go, 2026-08-09): on an ICS network HNS returns Flags 32
// whether or not the request asks for it, so this is documentation of intent rather than the
// thing that makes DHCP work. It is set anyway, because a future non-ICS network would need it
// and a silently-defaulted flag is a bad thing to depend on.
//
// Do not "fix" this into a string. The HCN schema docs say flag enums "should be used as
// string" and HNS rejects that form with 0x803B001B InvalidJson. Go's EndpointFlags is a uint32
// and marshals numerically, which is the accepted form.
const endpointFlagsEnableDhcp hcn.EndpointFlags = 32

// networkDefault is the value of --network that asks this tool to choose, rather than naming a
// network. A network genuinely called "default" still wins, because names are matched first.
const networkDefault = "default"

// resolveVMNetwork picks the network an endpoint goes on. A name or id is taken at face value --
// if a caller names a NAT network, that is their measurement to make. `--network default` asks
// for the ICS network, which is the only type measured to serve a full VM's guest.
func resolveVMNetwork(want string) (*hcn.HostComputeNetwork, error) {
	nets, err := hcn.ListNetworks()
	if err != nil {
		return nil, fmt.Errorf("ListNetworks: %w", err)
	}

	for i := range nets {
		if strings.EqualFold(nets[i].Name, want) || strings.EqualFold(nets[i].Id, want) {
			return &nets[i], nil
		}
	}
	if !strings.EqualFold(want, networkDefault) {
		return nil, cli.Usagef("no network named or with id %q -- try `hcsctl network ls`, "+
			"or `--network default` for the Hyper-V Default Switch", want)
	}

	// Selection by name, not just by type. This host has two ICS networks -- the Default Switch
	// and WSL's firewalled one -- and picking the wrong one produces a VM that boots, leases an
	// address, and is unreachable. Measured here and in AspireHcs#4.
	var ics []hcn.HostComputeNetwork
	for i := range nets {
		if strings.EqualFold(string(nets[i].Type), "ICS") {
			ics = append(ics, nets[i])
		}
	}
	for i := range ics {
		if strings.EqualFold(ics[i].Name, defaultSwitchName) {
			return &ics[i], nil
		}
	}
	if len(ics) == 1 {
		return &ics[0], nil
	}
	if len(ics) > 1 {
		names := make([]string, 0, len(ics))
		for i := range ics {
			names = append(names, ics[i].Name)
		}
		// Guessing among several is how the WSL network gets picked. Make the caller say.
		return nil, cli.Usagef("no network named %q, and %d ICS networks to choose from (%s) -- "+
			"name one with --network", defaultSwitchName, len(ics), strings.Join(names, ", "))
	}
	return nil, cli.Usagef("no ICS network on this host, so `--network default` has nothing to "+
		"choose. The Hyper-V Default Switch is a Windows client SKU feature; name a network "+
		"explicitly with --network, or see `hcsctl network ls`")
}

const defaultSwitchName = "Default Switch"

// generateMAC builds a locally-administered address in Microsoft's Hyper-V OUI (00-15-5D), which
// is what the platform hands out for a synthetic NIC.
//
// It is generated once, at create, and lives in the store record. Regenerating it per boot would
// move the DHCP lease on every start, which is exactly the reachability that consumers depend on.
func generateMAC() (string, error) {
	var tail [3]byte
	if _, err := rand.Read(tail[:]); err != nil {
		return "", fmt.Errorf("generating a MAC address: %w", err)
	}
	return fmt.Sprintf("02-15-5D-%02X-%02X-%02X", tail[0], tail[1], tail[2]), nil
}

// createVMEndpoint puts a DHCP endpoint on the network. The endpoint carries no address at this
// point -- see addressesOf.
func createVMEndpoint(netw *hcn.HostComputeNetwork, name, mac string) (*hcn.HostComputeEndpoint, error) {
	ep := &hcn.HostComputeEndpoint{
		Name:               name,
		HostComputeNetwork: netw.Id,
		SchemaVersion:      hcn.V2SchemaVersion(),
		MacAddress:         mac,
		Flags:              endpointFlagsEnableDhcp,
	}
	created, err := ep.Create()
	if err != nil {
		return nil, fmt.Errorf("endpoint Create on %s: %w", netw.Name, err)
	}
	return created, nil
}

// deleteVMEndpoint removes an endpoint and verifies it is gone. Endpoints are host-global and
// outlive every process that could clean them up, so the post-condition matters more than the
// return value -- the same discipline as destroyScratch on the container path.
func deleteVMEndpoint(id string) error {
	ep, err := hcn.GetEndpointByID(id)
	if err != nil {
		if hcn.IsNotFoundError(err) {
			return nil
		}
		return fmt.Errorf("GetEndpointByID(%s): %w", id, err)
	}
	if err := ep.Delete(); err != nil {
		return fmt.Errorf("endpoint Delete(%s): %w", id, err)
	}
	if _, err := hcn.GetEndpointByID(id); err == nil {
		return fmt.Errorf("endpoint %s still exists after Delete returned success", id)
	} else if !hcn.IsNotFoundError(err) {
		return fmt.Errorf("confirming endpoint %s is gone: %w", id, err)
	}
	return nil
}

// addressesOf reports what the endpoint holds, as "ip/prefix" strings.
//
// An endpoint with no address is the ordinary case, not a failure: measured 2026-08-09
// (hcsspike/probes/hcn/vmlease.go), a freshly created endpoint with nothing attached to it has no
// IpConfigurations at all. Whether HNS fills them in when the endpoint is attached to a NIC, or
// only once the guest's DHCP client has leased one, is the open question in #43 -- so this
// returns whatever is there, and every caller reports an empty result honestly rather than
// waiting or inventing one.
func addressesOf(id string) ([]string, error) {
	ep, err := hcn.GetEndpointByID(id)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, 0, len(ep.IpConfigurations))
	for _, ip := range ep.IpConfigurations {
		addrs = append(addrs, fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength))
	}
	return addrs, nil
}
