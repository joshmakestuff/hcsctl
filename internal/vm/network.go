//go:build windows

package vm

// A VM's network adapter, and the HCN endpoint behind it.
//
// A full VM is not a container here. A static HNS endpoint programs a container's network stack
// directly; a full VM's guest OS runs its own DHCP client and ignores it. So the VM attaches to
// an ICS network -- the Hyper-V Default Switch -- whose built-in DHCP serves an arbitrary guest
// image, and the address is read back from the endpoint afterwards.
//
// Nothing here creates a network.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
)

type networkMode int

const (
	networkPrivate networkMode = iota
	networkDHCP
	networkStatic
)

func modeOf(netw *hcn.HostComputeNetwork) networkMode {
	if netw == nil || strings.EqualFold(string(netw.Type), "Private") {
		return networkPrivate
	}
	if strings.EqualFold(netw.Name, defaultSwitchName) {
		return networkDHCP
	}
	if netw.Type == hcn.NAT || strings.EqualFold(string(netw.Type), "ICS") {
		return networkStatic
	}
	return networkPrivate
}

func parseDNS(dnsCSV string) ([]string, error) {
	dns := []string{}
	if dnsCSV == "" {
		return dns, nil
	}
	for _, raw := range strings.Split(dnsCSV, ",") {
		d := strings.TrimSpace(raw)
		ip, err := netip.ParseAddr(d)
		if err != nil || !ip.Is4() {
			return nil, cli.Usagef("--dns entry %q is not an IPv4 address", d)
		}
		dns = append(dns, ip.String())
	}
	return dns, nil
}

// validateDNSForNetwork enforces the --dns/--network contract. dns is parseDNS's result.
func validateDNSForNetwork(dns []string, netw *hcn.HostComputeNetwork) error {
	if len(dns) == 0 {
		if netw != nil && modeOf(netw) == networkStatic {
			return cli.Usagef("--dns is required for NAT and non-Default-Switch ICS networks")
		}
		return nil
	}
	switch {
	case netw == nil:
		return cli.Usagef("--dns only means something with --network")
	case modeOf(netw) == networkStatic:
		return nil
	case modeOf(netw) == networkDHCP:
		return cli.Usagef("--dns is ignored on %q: its DHCP serves the guest", netw.Name)
	default:
		return cli.Usagef("--dns is ignored on private network %q: no guest addressing is programmed", netw.Name)
	}
}

// endpointFlagsEnableDhcp is 32. hcsshim's EndpointFlags enum defines only None (0) and
// RemoteEndpoint (1), so the value is carried here.
//
// On an ICS network HNS returns Flags 32 whether or not the request asks for it. It is set
// anyway: a non-ICS network needs it.
//
// Do not make this a string. The HCN schema docs say flag enums "should be used as string" and
// HNS rejects that form with 0x803B001B InvalidJson. Go's EndpointFlags is a uint32 and
// marshals numerically, which is the accepted form.
const endpointFlagsEnableDhcp hcn.EndpointFlags = 32

// networkDefault is the value of --network that asks this tool to choose, rather than naming a
// network. A network genuinely called "default" still wins, because names are matched first.
const networkDefault = "default"

// resolveVMNetwork picks the network an endpoint goes on. A name or id is taken at face value.
// `--network default` asks for the ICS network, the only type known to serve a full VM's guest.
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

	// Selection by name, not just by type. A host can have two ICS networks -- the Default
	// Switch and WSL's firewalled one -- and picking the wrong one produces a VM that boots,
	// leases an address, and is unreachable.
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
	return nil, cli.Usagef("no ICS network on this host, so `--network default` has nothing to " +
		"choose. The Hyper-V Default Switch is a Windows client SKU feature; name a network " +
		"explicitly with --network, or see `hcsctl network ls`")
}

const defaultSwitchName = "Default Switch"

// endpointName is derived from the VM id, so an endpoint left behind by a crashed run says which
// VM it belonged to without a lookup. HNS does not require it to be unique.
func endpointName(vmID string) string { return vmID + "-ep" }

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
//
// An empty id lets HNS assign one. A non-empty id asks for that exact id back, which HNS honours
// -- that is what makes a restart keep the endpoint id it was created with.
//
// A non-zero vlan tags the endpoint's switch port as access VLAN <vlan>. A switch whose other
// ports are access-tagged isolates an untagged port from them, so a VM joining such a network
// is unreachable without it.
func createVMEndpoint(netw *hcn.HostComputeNetwork, id, name, mac string, vlan uint32) (*hcn.HostComputeEndpoint, error) {
	ep := &hcn.HostComputeEndpoint{
		Id:                 id,
		Name:               name,
		HostComputeNetwork: netw.Id,
		SchemaVersion:      hcn.V2SchemaVersion(),
		MacAddress:         mac,
		Flags:              endpointFlagsEnableDhcp,
	}
	if vlan != 0 {
		settings, err := json.Marshal(hcn.VlanPolicySetting{IsolationId: vlan})
		if err != nil {
			return nil, err
		}
		ep.Policies = append(ep.Policies, hcn.EndpointPolicy{
			Type:     "VLAN",
			Settings: settings,
		})
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

// remakeVMEndpoint destroys the VM's endpoint and makes an identical one.
//
// An endpoint that has been attached to a compute system cannot be attached to another one: HCS
// rejects the document with 0x803b0014, "the system cannot find the device specified". HCS
// destroys a compute system when it exits, so every restart builds a new one and would hit that
// on the second boot of any VM with a NIC.
//
// The id, the MAC and the VLAN are all preserved. The id because callers hold it; the MAC
// because the ICS DHCP server keys the lease on it, so the guest comes back on the same
// address it had; the VLAN because losing it would silently isolate the port.
func remakeVMEndpoint(networkID, endpointID, name, mac string, vlan uint32) error {
	netw, err := hcn.GetNetworkByID(networkID)
	if err != nil {
		return fmt.Errorf("the network %s this vm's endpoint was on is gone: %w", networkID, err)
	}
	if err := deleteVMEndpoint(endpointID); err != nil {
		return err
	}
	if _, err := createVMEndpoint(netw, endpointID, name, mac, vlan); err != nil {
		return err
	}
	return nil
}

// addressesOf reports what the endpoint holds, as "ip/prefix" strings.
//
// An endpoint with no address is the ordinary case, not a failure: a freshly created endpoint
// with nothing attached to it has no IpConfigurations at all. This returns whatever is there,
// and every caller reports an empty result as-is rather than waiting or inventing one.
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
