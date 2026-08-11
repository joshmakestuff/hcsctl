//go:build windows

// Package network is the `hcsctl network` verb group: reading the Host Compute Network state
// that containers attach to.
//
// Read-only for now, and unelevated. Measured 2026-08-05 against HNS schema 16.0: listing
// networks, endpoints and namespaces all work from a filtered token. `hcn.GetGlobals` is the one
// call that needs elevation, which is why it is reported as optional detail rather than as the
// header it looks like it should be.
//
// Creating and deleting networks is deliberately absent. Windows permits one NAT network per
// host, hosts that run Docker already have it, and a second one plausibly breaks Docker and WSL.
// That is a decision to make explicitly, not a verb to add quietly.
package network

import (
	"fmt"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/joshmakestuff/hcsctl/internal/cli"
	"net/netip"
	"sort"
	"strings"
)

func Dispatch(a *cli.Args, e cli.Emit) (int, error) {
	switch a.Word(1) {
	case "ls":
		return list(a, e)
	case "endpoints":
		return endpoints(a, e)
	case "create":
		return create(a, e)
	case "rm":
		return remove(a, e)
	case "":
		return cli.Usage, cli.Usagef("network needs a subcommand: ls, endpoints, create, rm")
	default:
		return cli.Usage, cli.Usagef("unknown network subcommand %q (expected ls, endpoints, create, rm)", a.Word(1))
	}
}

type networkRow struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Subnets []string `json:"subnets"`
	// Endpoints is a count rather than a list: `network ls` is the overview, and `network
	// endpoints` is where you go when the count is surprising.
	Endpoints int `json:"endpoints"`
}

func list(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown(); err != nil {
		return cli.Usage, err
	}
	nets, err := hcn.ListNetworks()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListNetworks: %w", err)
	}

	// One enumeration of every endpoint, bucketed by network, rather than a per-network query.
	// ListEndpointsOfNetwork would be N round trips to say the same thing.
	perNetwork := map[string]int{}
	eps, epErr := hcn.ListEndpoints()
	if epErr != nil {
		e.Progress("ListEndpoints: %v -- endpoint counts omitted", epErr)
	}
	for _, ep := range eps {
		perNetwork[strings.ToLower(ep.HostComputeNetwork)]++
	}

	rows := make([]networkRow, 0, len(nets))
	for _, n := range nets {
		r := networkRow{
			ID: n.Id, Name: n.Name, Type: string(n.Type),
			Endpoints: perNetwork[strings.ToLower(n.Id)],
			Subnets:   []string{},
		}
		for _, ipam := range n.Ipams {
			for _, s := range ipam.Subnets {
				if s.IpAddressPrefix != "" {
					r.Subnets = append(r.Subnets, s.IpAddressPrefix)
				}
			}
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

	e.Result(map[string]any{"ok": true, "command": "network ls", "networks": rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no networks")
			return
		}
		fmt.Printf("%-26s %-12s %-20s %5s  %s\n", "NAME", "TYPE", "SUBNETS", "EPS", "ID")
		for _, r := range rows {
			fmt.Printf("%-26s %-12s %-20s %5d  %s\n",
				trunc(r.Name, 26), r.Type, strings.Join(r.Subnets, ","), r.Endpoints, r.ID)
		}
	})
	return cli.OK, nil
}

type endpointRow struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	NetworkID string   `json:"networkId"`
	Network   string   `json:"network"`
	Addresses []string `json:"addresses"`
	MAC       string   `json:"mac"`
}

func endpoints(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--network"); err != nil {
		return cli.Usage, err
	}
	nets, err := hcn.ListNetworks()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListNetworks: %w", err)
	}
	// Names, so the output is readable without a second lookup, and so --network can accept
	// either a name or an ID.
	nameByID := map[string]string{}
	for _, n := range nets {
		nameByID[strings.ToLower(n.Id)] = n.Name
	}

	var filterID string
	if want := a.Option("--network"); want != "" {
		for _, n := range nets {
			if strings.EqualFold(n.Name, want) || strings.EqualFold(n.Id, want) {
				filterID = strings.ToLower(n.Id)
				break
			}
		}
		if filterID == "" {
			return cli.Usage, cli.Usagef("no network named or with id %q -- try `hcsctl network ls`", want)
		}
	}

	eps, err := hcn.ListEndpoints()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListEndpoints: %w", err)
	}

	rows := make([]endpointRow, 0, len(eps))
	for _, ep := range eps {
		netID := strings.ToLower(ep.HostComputeNetwork)
		if filterID != "" && netID != filterID {
			continue
		}
		r := endpointRow{
			ID: ep.Id, Name: ep.Name, NetworkID: ep.HostComputeNetwork,
			Network: nameByID[netID], MAC: ep.MacAddress, Addresses: []string{},
		}
		for _, ip := range ep.IpConfigurations {
			r.Addresses = append(r.Addresses, fmt.Sprintf("%s/%d", ip.IpAddress, ip.PrefixLength))
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })

	e.Result(map[string]any{"ok": true, "command": "network endpoints", "endpoints": rows}, func() {
		if len(rows) == 0 {
			fmt.Println("no endpoints")
			return
		}
		fmt.Printf("%-26s %-20s %-19s %-18s %s\n", "NAME", "NETWORK", "ADDRESS", "MAC", "ID")
		for _, r := range rows {
			fmt.Printf("%-26s %-20s %-19s %-18s %s\n",
				trunc(r.Name, 26), trunc(r.Network, 20),
				strings.Join(r.Addresses, ","), r.MAC, r.ID)
		}
	})
	return cli.OK, nil
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "~"
}

// -- create -------------------------------------------------------------------------------

type networkMutationResult struct {
	OK      bool     `json:"ok"`
	Command string   `json:"command"`
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Subnets []string `json:"subnets"`
}

func create(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--name", "--type", "--subnet", "--gateway"); err != nil {
		return cli.Usage, err
	}
	name, err := a.Require("--name")
	if err != nil {
		return cli.Usage, err
	}
	kind, err := a.Require("--type")
	if err != nil {
		return cli.Usage, err
	}
	network, err := newNetwork(name, kind, a.Option("--subnet"), a.Option("--gateway"))
	if err != nil {
		return cli.Usage, err
	}

	existing, err := hcn.GetNetworkByName(name)
	switch {
	case err == nil:
		return cli.Failed, fmt.Errorf("network named %q already exists (id %s)", name, existing.Id)
	case !hcn.IsNotFoundError(err):
		return cli.Failed, fmt.Errorf("GetNetworkByName(%q): %w", name, err)
	}

	created, err := network.Create()
	if err != nil {
		return cli.Failed, fmt.Errorf("Create network %q: %w", name, err)
	}
	res := networkMutationResult{
		OK: true, Command: "network create", ID: created.Id, Name: created.Name,
		Type: string(created.Type), Subnets: networkSubnets(created),
	}
	e.Result(res, func() {
		fmt.Printf("created %s network %s (%s)\n", res.Type, res.Name, res.ID)
	})
	return cli.OK, nil
}

func newNetwork(name, kind, subnet, gateway string) (*hcn.HostComputeNetwork, error) {
	if strings.TrimSpace(name) == "" {
		return nil, cli.Usagef("--name must not be empty")
	}

	switch strings.ToLower(kind) {
	case "private":
		if subnet != "" || gateway != "" {
			return nil, cli.Usagef("--type private does not take --subnet or --gateway")
		}
		return &hcn.HostComputeNetwork{
			Name: name, Type: hcn.Private, SchemaVersion: hcn.SchemaVersion{Major: 2, Minor: 0},
		}, nil
	case "nat":
		if subnet == "" {
			return nil, cli.Usagef("--subnet is required for --type nat")
		}
		if gateway == "" {
			return nil, cli.Usagef("--gateway is required for --type nat")
		}
		prefix, nextHop, err := validateNatSubnet(subnet, gateway)
		if err != nil {
			return nil, err
		}
		return &hcn.HostComputeNetwork{
			Name: name, Type: hcn.NAT, SchemaVersion: hcn.SchemaVersion{Major: 2, Minor: 0},
			Ipams: []hcn.Ipam{{
				Type: "Static",
				Subnets: []hcn.Subnet{{
					IpAddressPrefix: prefix,
					Routes:          []hcn.Route{{NextHop: nextHop, DestinationPrefix: "0.0.0.0/0"}},
				}},
			}},
		}, nil
	default:
		return nil, cli.Usagef("--type must be nat or private, got %q", kind)
	}
}

func validateNatSubnet(subnet, gateway string) (string, string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() {
		return "", "", cli.Usagef("--subnet must be an IPv4 CIDR, got %q", subnet)
	}
	if prefix != prefix.Masked() {
		return "", "", cli.Usagef("--subnet must name the network address, got %q", subnet)
	}
	prefix = prefix.Masked()
	if prefix.Bits() == 0 || prefix.Bits() > 30 {
		return "", "", cli.Usagef("--subnet must leave a gateway and an address, got %q", subnet)
	}

	nextHop, err := netip.ParseAddr(gateway)
	if err != nil || !nextHop.Is4() {
		return "", "", cli.Usagef("--gateway must be an IPv4 address, got %q", gateway)
	}
	if !prefix.Contains(nextHop) {
		return "", "", cli.Usagef("--gateway %s is outside --subnet %s", nextHop, prefix)
	}

	networkAddress := prefix.Addr()
	bits := uint32(prefix.Bits())
	addresses := uint32(1) << (32 - bits)
	lastAddress := networkAddress.As4()
	value := uint32(lastAddress[0])<<24 | uint32(lastAddress[1])<<16 | uint32(lastAddress[2])<<8 | uint32(lastAddress[3])
	lastAddress = [4]byte{byte((value + addresses - 1) >> 24), byte((value + addresses - 1) >> 16),
		byte((value + addresses - 1) >> 8), byte(value + addresses - 1)}
	if nextHop == networkAddress || nextHop == netip.AddrFrom4(lastAddress) {
		return "", "", cli.Usagef("--gateway %s is not a usable address in --subnet %s", nextHop, prefix)
	}
	return prefix.String(), nextHop.String(), nil
}

func networkSubnets(network *hcn.HostComputeNetwork) []string {
	subnets := []string{}
	for _, ipam := range network.Ipams {
		for _, subnet := range ipam.Subnets {
			if subnet.IpAddressPrefix != "" {
				subnets = append(subnets, subnet.IpAddressPrefix)
			}
		}
	}
	return subnets
}

// -- rm -----------------------------------------------------------------------------------

func remove(a *cli.Args, e cli.Emit) (int, error) {
	if err := a.RejectUnknown("--id", "--name"); err != nil {
		return cli.Usage, err
	}
	id, name := a.Option("--id"), a.Option("--name")
	if (id == "") == (name == "") {
		return cli.Usage, cli.Usagef("network rm requires exactly one of --id or --name")
	}

	var (
		network *hcn.HostComputeNetwork
		err     error
	)
	if id != "" {
		network, err = hcn.GetNetworkByID(id)
	} else {
		network, err = hcn.GetNetworkByName(name)
	}
	if err != nil {
		return cli.Failed, err
	}

	endpoints, err := hcn.ListEndpoints()
	if err != nil {
		return cli.Failed, fmt.Errorf("ListEndpoints before deleting network %s: %w", network.Id, err)
	}
	count := 0
	for _, endpoint := range endpoints {
		if strings.EqualFold(endpoint.HostComputeNetwork, network.Id) {
			count++
		}
	}
	if count != 0 {
		return cli.Failed, fmt.Errorf("network %q (%s) has %d endpoint(s); remove them before deleting it",
			network.Name, network.Id, count)
	}

	if err := network.Delete(); err != nil {
		return cli.Failed, fmt.Errorf("Delete network %q (%s): %w", network.Name, network.Id, err)
	}
	if _, err := hcn.GetNetworkByID(network.Id); err == nil {
		return cli.Failed, fmt.Errorf("network %q (%s) still exists after Delete returned success", network.Name, network.Id)
	} else if !hcn.IsNotFoundError(err) {
		return cli.Failed, fmt.Errorf("GetNetworkByID(%s) after Delete: %w", network.Id, err)
	}

	res := networkMutationResult{
		OK: true, Command: "network rm", ID: network.Id, Name: network.Name,
		Type: string(network.Type), Subnets: networkSubnets(network),
	}
	e.Result(res, func() {
		fmt.Printf("removed %s network %s (%s)\n", res.Type, res.Name, res.ID)
	})
	return cli.OK, nil
}
